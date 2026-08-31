// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! FFI Utilities
//!
//! Provides utilities for safe FFI bindings, including:
//! - Handle-based API: Thread-safe handle management system
//! - Allocation tracking: Prevents double-free of raw pointers
//! - Buffer safety: Validates buffer sizes and pointer arithmetic

use std::{
    any::TypeId,
    collections::HashMap,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    os::raw::c_uchar,
    panic::AssertUnwindSafe,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use crate::{
    cimpl::cimpl_error::CimplError,
    error::Error,
    maybe_send_sync::{MaybeSend, MaybeSync},
};

// ============================================================================
// Pointer Registry - Tracks pointers with their cleanup functions
// ============================================================================

type CleanupFn = Box<dyn FnMut() + Send>;

/// Marks how a tracked allocation was created, so ownership can only ever be
/// reconstructed with the matching allocator.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Wrapper {
    Boxed,
    /// No production call site tracks an `Arc` today: `track_arc` and
    /// `arc_tracked!` are used only by tests. The variant and the checks that
    /// reference it exist so that adding one later cannot silently reconstruct
    /// an `Arc`-tracked entry with `Box::from_raw`.
    Arced,
}

/// One tracked object: where it lives, how to free it, and who is using it.
///
/// Held behind an `Arc` so a borrow outlives a concurrent free. When C frees a
/// handle the registry drops its own `Arc`, but a thread still using the object
/// holds another, and cleanup runs only when the last one goes.
struct EntryInner {
    /// Where the object actually lives, as a plain integer.
    ///
    /// Every checkout casts this back to a `*mut T` to hand out a reference.
    /// A pointer carries an address, but also permission to reach that particular allocation.
    /// Casting to an integer discards that permission, and casting
    /// back produces a pointer the compiler believes is allowed to reach nothing.
    ///
    /// Storing a `*mut ()` would keep the permission.
    /// It would also make the registry map neither `Send` nor `Sync`,
    /// but we need those here (alternative would be to impl them specifically).
    /// This might be reported by checkers as UB.
    real_addr: usize,
    type_id: TypeId,
    /// Which allocator created this object, so `untrack_owned` reconstructs it
    /// with the matching one. Handing an `Arc`-tracked entry to `Box::from_raw`
    /// is undefined behavior.
    wrapper: Wrapper,
    /// Which borrows of this object are outstanding right now.
    ///
    /// A C caller holds an opaque id, not a reference. This counter is what
    /// makes handing out `&mut T` manageable: a borrow is refused unless the
    /// counter permits it.
    ///
    /// - `0`: nobody is using the object, so any borrow may start.
    /// - `1..EXCLUSIVE`: that many readers hold a `TypedShared`. More readers
    ///   may join; a writer may not.
    /// - `EXCLUSIVE`: one writer holds a `TypedExclusive`. No other borrow of
    ///   any kind may start until it drops.
    ///
    /// `untrack` also refuses while this is non-zero, since ownership cannot
    /// move out from under a live borrow.
    ///
    /// This is *not* what decides when the object is freed since that is the
    /// `Arc`'s refcount, and the two move independently. Nor can it be
    /// inferred from `Arc::strong_count`, which any transient clone increases
    /// without a borrow existing.
    borrow_state: AtomicUsize,
    /// `Option` so `untrack` can take the closure out through a shared `Arc`,
    /// leaving nothing for `Drop` to run.
    cleanup: Mutex<Option<CleanupFn>>,
    /// The process that created this entry. A forked child inherits the map by
    /// copy-on-write, so without this it would free memory the parent still  owns.
    /// Written once at construction, read-only after.
    owner_pid: u32,
}

/// The current process id.
///
/// Never cache this, because a cached value returns the parent's id in a forked child.
/// On wasm32 there is no fork, so return a constant.
#[cfg(not(target_arch = "wasm32"))]
fn current_pid() -> u32 {
    // SAFETY: getpid takes no arguments and cannot fail.
    unsafe { libc::getpid() as u32 }
}

#[cfg(target_arch = "wasm32")]
fn current_pid() -> u32 {
    0
}

/// The `borrow_state` value meaning "one writer holds this object".
///
/// `usize::MAX` cannot be reached by counting readers:
/// every reader holds a live guard, so that many would need more memory than the address space has.
const EXCLUSIVE: usize = usize::MAX;

impl EntryInner {
    /// Formats an entry, hiding the real address when `hide_address` is set.
    ///
    /// Split out from `Debug` and taking the flag explicitly so both branches
    /// are reachable in one build: `cargo test` always compiles with
    /// `debug_assertions` on, and no CI job runs `cargo test --release`, so a
    /// `cfg!`-only branch here would never execute anywhere.
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>, hide_address: bool) -> std::fmt::Result {
        let borrow_state = self.borrow_state.load(Ordering::Relaxed);
        let mut out = f.debug_struct("EntryInner");
        // The real address is what the opaque handle id exists to hide, so a
        // release build that logs an entry (a panic message, a tracing span)
        // must not leak it.
        if hide_address {
            out.field("real_addr", &format_args!("<hidden>"));
        } else {
            out.field("real_addr", &format_args!("0x{:x}", self.real_addr));
        }
        out.field("type_id", &self.type_id)
            .field("wrapper", &self.wrapper)
            .field(
                "borrow_state",
                &match borrow_state {
                    0 => "free".to_string(),
                    EXCLUSIVE => "exclusive".to_string(),
                    n => format!("{n} shared"),
                },
            )
            .field(
                "cleanup",
                // try_lock: Debug must never block.
                &match self.cleanup.try_lock() {
                    Ok(guard) => {
                        if guard.is_some() {
                            "armed"
                        } else {
                            "defused"
                        }
                    }
                    Err(std::sync::TryLockError::Poisoned(_)) => "poisoned",
                    Err(std::sync::TryLockError::WouldBlock) => "locked",
                },
            )
            .field("owner_pid", &self.owner_pid)
            .finish()
    }
}

/// Disarms an entry that was built but never recorded, then drops it.
///
/// Both `track_*` paths return "the caller still owns the allocation" when the
/// registry lock is poisoned. The entry they built is still armed at that
/// point, so letting it drop would run the cleanup and free the object the
/// caller is being told to free itself -- a double free.
///
/// `Arc::into_inner` yields the value only when this is the last reference. It
/// is, at both call sites: the `Arc` is created locally and the only clone
/// would come from the map insert, which the poisoned path never reaches.
///
/// The `None` arm reports rather than hides. It cannot disarm the entry --
/// whoever holds the other reference owns it now, and the cleanup runs when
/// they drop it -- so all this can do is say that the invariant broke.
fn defuse_untracked_entry(entry: Arc<EntryInner>) {
    match Arc::into_inner(entry) {
        Some(mut entry) => {
            // take() alone disarms: dropping a Box<dyn FnMut()> drops the
            // closure's captures without running its body.
            if let Ok(cleanup) = entry.cleanup.get_mut() {
                cleanup.take();
            }
        }
        None => {
            // Unreachable today. Nothing can be done here: the other holder
            // owns the entry and will run its cleanup on drop, which is the
            // double free this function exists to prevent. Report it rather
            // than panic -- including in debug builds, which is what the
            // bindings load during development, and where a panic crossing the
            // extern "C" boundary would abort the host process.
            eprintln!(
                "c2pa: an untracked registry entry was still referenced; its cleanup \
                 may double free"
            );
        }
    }
}

// Log/Debug helper for registry entries.
impl std::fmt::Debug for EntryInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.debug_fmt(f, !cfg!(debug_assertions))
    }
}

impl Drop for EntryInner {
    fn drop(&mut self) {
        // Callers: never drop an Arc<EntryInner> while holding the registry
        // lock. Dropping the last one runs a cleanup closure, and a closure
        // that re-enters the registry then deadlocks against the non-reentrant
        // Mutex. Collect entries, release the lock, and let them drop after.

        // A forked child inherits every entry. Memory is not the reason to skip
        // cleanup here: fork() gives the child a private copy-on-write address
        // space, so freeing there cannot touch the parent's heap. The reason is
        // a cleanup closure that releases a resource the two processes share --
        // a file descriptor, an flock, a shared memory segment -- which the
        // child would release out from under the parent. No closure in this
        // crate does that today, so this is future-proofing for a caller-
        // supplied cleanup that does.
        //
        // This check is separate from the one on PointerRegistry because this
        // path reaches Drop by dropping an inherited Arc, without any registry
        // call to intercept.
        //
        // Skipping leaks the child's private copy. That is bounded: an exec()
        // replaces the address space, exit reclaims it, and a long-lived child
        // retains only what it inherited at fork time.
        if self.owner_pid != current_pid() {
            // get_mut, not lock: Drop has &mut self, so this cannot contend or
            // deadlock. take() alone defuses the closure -- dropping a
            // Box<dyn FnMut()> drops its captures without running its body.
            if let Ok(cleanup) = self.cleanup.get_mut() {
                cleanup.take();
            }
            return;
        }
        if let Some(mut cleanup) = self.cleanup.get_mut().ok().and_then(|c| c.take()) {
            // A cleanup closure runs caller-supplied code.
            // Unwinding out of here would cross the extern "C" boundary,
            // which is undefined behavior, and a panic raised while another thread
            // holds the registry lock poisons it for the rest of the process.
            if std::panic::catch_unwind(AssertUnwindSafe(&mut cleanup)).is_err() {
                eprintln!("c2pa: panic while freeing a tracked pointer, leaking pointer");
            }
        }
    }
}

/// A live shared borrow of a tracked entry.
///
/// Holding one keeps the object alive even if C frees the handle from another thread:
/// the registry drops its `Arc`, but cleanup runs only when the last one goes,
/// which is this guard.
pub struct SharedCheckout {
    entry: Arc<EntryInner>,
}

impl Drop for SharedCheckout {
    fn drop(&mut self) {
        // Releasing this is separate from dropping the Arc.
        // Without it a handle stays borrowed forever and every later checkout fails.
        self.entry.borrow_state.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A live exclusive borrow of a tracked entry.
/// At most one can exist, so &mut can be handed out.
pub struct ExclusiveCheckout {
    entry: Arc<EntryInner>,
}

impl Drop for ExclusiveCheckout {
    fn drop(&mut self) {
        self.entry.borrow_state.store(0, Ordering::Release);
    }
}

/// A shared borrow of a `T` behind a handle.
/// Dereferences to `&T` only.
pub struct TypedShared<T> {
    inner: SharedCheckout,
    // Not PhantomData<fn() -> T>: that is Send + Sync for every T, so a guard
    // over a !Sync object could be sent to another thread and produce a data
    // race from safe code. *const T makes the guard inherit T's own auto
    // traits, and the impls below re-add exactly what is sound.
    _marker: PhantomData<*const T>,
}

// A shared guard hands out &T, and &T crosses threads only when T: Sync.
//
// SAFETY: the guard exposes T only through Deref, so sending or sharing it is
// equivalent to sending or sharing a &T.
unsafe impl<T: Sync> Send for TypedShared<T> {}
unsafe impl<T: Sync> Sync for TypedShared<T> {}

/// An exclusive borrow of a `T` behind a handle.
/// Dereferences to `&mut T`.
pub struct TypedExclusive<T> {
    inner: ExclusiveCheckout,
    _marker: PhantomData<*const T>,
}

// An exclusive guard hands out &mut T. Moving it to another thread moves the
// object's only reference, which needs T: Send; sharing the guard itself only
// ever yields &T, which needs T: Sync.
//
// SAFETY: the exclusive claim guarantees this is the sole borrow, so the guard
// is equivalent to a &mut T for Send and a &T for Sync.
unsafe impl<T: Send> Send for TypedExclusive<T> {}
unsafe impl<T: Sync> Sync for TypedExclusive<T> {}

impl<T> Deref for TypedShared<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the entry was type-checked at checkout.
        unsafe { &*(self.inner.entry.real_addr as *const T) }
    }
}

impl<T> Deref for TypedExclusive<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: as TypedShared, and this guard holds the sole claim.
        unsafe { &*(self.inner.entry.real_addr as *const T) }
    }
}

impl<T> DerefMut for TypedExclusive<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the exclusive claim guarantees no other borrow of this entry exists.
        // This is the only reference to the object.
        unsafe { &mut *(self.inner.entry.real_addr as *mut T) }
    }
}

// Odd, per-pointer-width multiplicative constant (2^N / golden ratio) used by
// `scramble_to_odd_id`. Must be odd on whichever width `usize` actually is.
#[cfg(target_pointer_width = "64")]
const ID_MULTIPLIER: usize = 0x9e3779b97f4a7c15;
#[cfg(target_pointer_width = "32")]
const ID_MULTIPLIER: usize = 0x9e3779b9;
#[cfg(not(any(target_pointer_width = "64", target_pointer_width = "32")))]
compile_error!("PointerRegistry's handle scrambling needs a 32- or 64-bit usize");

/// Turns a plain sequential counter value into a scrambled, always-odd
/// handle id.
///
/// - **Always odd (and therefore never zero)**: real Rust allocations
///   always land on at least a 2-byte boundary, so their addresses are
///   always even. An odd id can therefore never collide with a real tracked
///   buffer address (see `track_by_address`).
/// - **Distinct within a `2^(usize::BITS - 1)` window, not fully bijective**:
///   `counter * 2 + 1` folds the counter's top bit, so `counter` and
///   `counter + 2^(usize::BITS - 1)` scramble to the same id. Ids repeat after
///   `2^(usize::BITS - 1)` allocations — 2^63 on 64-bit (unreachable), ~2.1
///   billion on 32-bit (wasm32 included). `track_by_id` refuses to mint past
///   that bound on 32-bit.
fn scramble_to_odd_id(counter: usize) -> usize {
    let odd = counter.wrapping_mul(2).wrapping_add(1);
    odd.wrapping_mul(ID_MULTIPLIER)
}

/// Registry that tracks pointers allocated from Rust and passed to C.
/// Each entry is associated with its real address, type, and a cleanup
/// function, enabling type validation and universal freeing via `cimpl_free()`.
///
/// Entries are stored under one of two kinds of key:
/// - An opaque, scrambled handle id (see `track_by_id`), used for objects C
///   only ever passes back into other FFI calls (`C2paBuilder`, `C2paSigner`,
///   `C2paStream`, ...). Because ids are never reused and are always odd, a
///   handle that outlives its object (e.g. a stale copy raced against
///   `cimpl_free` on another thread) can never alias a *different*,
///   newly-allocated object at a reused address — the
///   lookup simply fails.
/// - The real address itself (see `track_by_address`), used for buffers C
///   dereferences directly (`to_c_string`, `to_c_bytes`), where the pointer
///   handed to C must be a genuine, readable address. These are always even.
///
/// Both kinds share one map and one `cimpl_free()` path since freeing only
/// needs the key, not which kind it is — the odd/even split guarantees a key
/// of one kind can never be mistaken for the other.
///
/// The protection against reused addresses covers the handle-id half only.
/// Address-keyed buffers are keyed by the address the allocator returned, so
/// a stale buffer pointer whose memory has been freed and reallocated to
/// another tracked buffer resolves to the new entry. C must not use a buffer
/// pointer after freeing it; the registry cannot detect that case.
pub(crate) struct PointerRegistry {
    tracked: Mutex<HashMap<usize, Arc<EntryInner>>>,
    next_id: AtomicUsize,
    /// The process that created the registry.
    owner_pid: u32,
}

impl PointerRegistry {
    fn new() -> Self {
        Self {
            tracked: Mutex::new(HashMap::new()),
            next_id: AtomicUsize::new(0),
            owner_pid: current_pid(),
        }
    }

    /// Track a pointer under a freshly generated opaque handle id, so the
    /// value handed to C is never the real address (and so can never alias a
    /// different object that later reuses that address).
    ///
    /// Returns the id, or `None` when the pointer could not be tracked.
    ///
    /// Ownership on failure: this function never frees. On `None` the caller
    /// still owns the allocation and must reclaim it, the same contract
    /// `track_by_address` follows.
    #[must_use = "on None the caller still owns the allocation and must free it"]
    fn track_by_id(
        &self,
        real_addr: usize,
        type_id: TypeId,
        wrapper: Wrapper,
        cleanup: CleanupFn,
    ) -> Option<usize> {
        if real_addr == 0 {
            return None;
        }
        // Refuse before taking the lock, like every other entry point. A child
        // of a multi-threaded fork inherits the mutex in whatever state it had
        // at fork time, and only the forking thread survives -- so a lock
        // another thread held can never be released here. Returning 0 gives the
        // caller a NULL handle rather than a deadlock.
        if self.check_same_process().is_err() {
            // Set the error so a child that gets a NULL back can retrieve the
            // reason through c2pa_error(); without this the refusal is silent.
            CimplError::foreign_process().set_last();
            return None;
        }
        let counter = self.next_id.fetch_add(1, Ordering::Relaxed);
        // Past this point the scramble no longer yields distinct ids. Refusing
        // with a NULL handle is recoverable; a panic here would cross the
        // extern "C" boundary and abort the host application.
        #[cfg(target_pointer_width = "32")]
        if counter >= (usize::MAX >> 1) {
            eprintln!("c2pa: PointerRegistry id space exhausted");
            CimplError::tracking_refused("handle id space exhausted").set_last();
            return None;
        }
        let id = scramble_to_odd_id(counter);
        let entry = Arc::new(EntryInner {
            real_addr,
            type_id,
            wrapper,
            borrow_state: AtomicUsize::new(0),
            cleanup: Mutex::new(Some(cleanup)),
            owner_pid: current_pid(),
        });
        if let Ok(mut tracked) = self.tracked.lock() {
            if let Some(previous) = tracked.insert(id, entry) {
                // Ids come from a counter that never repeats within its period,
                // so an occupied slot means that guarantee broke. Defuse the
                // displaced entry rather than dropping it: its cleanup would
                // otherwise run here, under the lock, where a closure that
                // re-enters the registry deadlocks against the non-reentrant
                // Mutex. Leaking it keeps the process alive; a panic crossing
                // extern "C" would not.
                if let Ok(mut cleanup) = previous.cleanup.lock() {
                    // take() alone defuses: dropping a Box<dyn FnMut()> drops
                    // the closure's captures without running its body.
                    cleanup.take();
                }
                eprintln!(
                    "c2pa: handle id 0x{id:x} was minted twice, leaking the displaced object"
                );
            }
            return Some(id);
        }
        // A poisoned lock means the entry was never recorded. Defuse before the
        // entry drops: running the cleanup here would free the object while the
        // caller is being told it still owns it. Defusing rather than forgetting
        // also releases the Arc and its boxed closure instead of leaking them.
        defuse_untracked_entry(entry);
        CimplError::tracking_refused("registry lock poisoned").set_last();
        None
    }

    /// Track a pointer keyed by its own address. Only use this for buffers C
    /// dereferences directly (e.g. `to_c_string`/`to_c_bytes`), where the
    /// returned pointer must remain a real, readable address.
    /// Returns false when the address could not be tracked, so the caller can
    /// free it rather than hand C a pointer the registry never recorded.
    #[must_use = "an untracked buffer must not be handed to C"]
    fn track_by_address(&self, real_addr: usize, type_id: TypeId, cleanup: CleanupFn) -> bool {
        // See track_by_id: taking the inherited lock in a forked child would
        // deadlock, so refuse before reaching it.
        if self.check_same_process().is_err() {
            CimplError::foreign_process().set_last();
            return false;
        }
        if real_addr != 0 {
            // The odd/even split between the two key kinds is what guarantees an
            // address key can never alias a handle id.
            // Rust aligns real allocations, so this holds for every type tracked
            // here, but a zero-sized type allocates at 0x1 and a custom global
            // allocator need not align. Refuse rather than alias: the caller
            // frees the buffer, where a panic would cross extern "C" and abort.
            if !real_addr.is_multiple_of(2) {
                eprintln!(
                    "c2pa: refusing to track odd address 0x{real_addr:x}, it would collide with a handle id"
                );
                CimplError::tracking_refused("buffer address would collide with a handle id")
                    .set_last();
                return false;
            }
            let entry = Arc::new(EntryInner {
                real_addr,
                type_id,
                wrapper: Wrapper::Boxed,
                borrow_state: AtomicUsize::new(0),
                cleanup: Mutex::new(Some(cleanup)),
                owner_pid: current_pid(),
            });
            if let Ok(mut tracked) = self.tracked.lock() {
                if let Some(previous) = tracked.insert(real_addr, entry) {
                    // The allocator returned an address that is still tracked,
                    // so something freed the memory without untracking it. The
                    // stale cleanup closure now points at an allocation it no
                    // longer owns, so mitigate and report.
                    if let Ok(mut cleanup) = previous.cleanup.lock() {
                        cleanup.take();
                    }
                    eprintln!("c2pa: address 0x{real_addr:x} was re-tracked while still tracked");
                }
                return true;
            }
            // A poisoned lock means the entry was never recorded. Defuse before
            // the entry drops: running the cleanup here would free the buffer,
            // and the caller frees it again on false. Defusing rather than
            // forgetting also releases the Arc and its boxed closure.
            defuse_untracked_entry(entry);
            CimplError::tracking_refused("registry lock poisoned").set_last();
            return false;
        }
        // A null address is nothing to track, and nothing to free either.
        true
    }

    /// Test-only: resolve a handle id for type `T`, returning the real pointer.
    ///
    /// Production code borrows through `checkout_shared`/`checkout_exclusive`,
    /// which keep the object alive for the guard's lifetime. This returns a
    /// bare pointer with no claim on the entry, which is only safe in a test
    /// that controls every thread touching the handle.
    #[cfg(test)]
    fn resolve_typed<T: 'static>(&self, ptr: *mut T) -> Result<*mut T, Error> {
        Ok(self.resolve(ptr as usize, TypeId::of::<T>())? as *mut T)
    }

    /// Test-only: untrack a handle for type `T`, returning the real pointer.
    ///
    /// Production code uses `untrack_owned`, which reconstructs the value in
    /// one place. This hands back a raw pointer the caller must reconstruct.
    #[cfg(test)]
    fn untrack_typed<T: 'static>(&self, ptr: *mut T) -> Result<*mut T, Error> {
        let (real_addr, _wrapper) = self.untrack(ptr as usize, TypeId::of::<T>(), None)?;
        Ok(real_addr as *mut T)
    }

    /// Resolve a handle id to its real address, validating it is tracked
    /// with the expected type.
    ///
    /// Only `resolve_typed` calls this. Production code borrows through
    /// `checkout_shared`/`checkout_exclusive`, which hold a claim on the entry
    /// for the guard's lifetime; a bare address resolved here carries none, so
    /// a concurrent `cimpl_free` can free the object while the caller holds it.
    #[cfg(test)]
    #[must_use = "the id passed in is not a usable pointer, only the returned address is"]
    fn resolve(&self, id: usize, expected_type: TypeId) -> Result<usize, Error> {
        self.check_same_process()?;
        if id == 0 {
            return Err(Error::from(CimplError::null_parameter("pointer")));
        }

        let tracked = self
            .tracked
            .lock()
            .map_err(|_| Error::from(CimplError::mutex_poisoned()))?;
        match tracked.get(&id) {
            Some(entry) if entry.type_id == expected_type => Ok(entry.real_addr),
            Some(_) => Err(Error::from(CimplError::wrong_pointer_type(id as u64))),
            None => Err(Error::from(CimplError::untracked_pointer(id as u64))),
        }
    }

    /// Refuse a registry call made from a process that did not create the registry,
    /// which happens after `fork()` without an `exec()`.
    ///
    /// Call this *before* taking the `tracked` lock.
    /// A child of a multi-threaded fork inherits the mutex
    /// in whatever state it had at fork time.
    /// If another thread held it, no thread in the child can ever release it,
    /// iso taking the lock can deadlock.
    fn check_same_process(&self) -> Result<(), Error> {
        if self.owner_pid != current_pid() {
            return Err(Error::from(CimplError::foreign_process()));
        }
        Ok(())
    }

    /// Look up an entry and clone its `Arc`, checking the expected type.
    /// Shared by both checkout paths so the lock is taken once.
    fn lookup(&self, id: usize, expected_type: TypeId) -> Result<Arc<EntryInner>, Error> {
        self.check_same_process()?;
        if id == 0 {
            return Err(Error::from(CimplError::null_parameter("pointer")));
        }
        let tracked = self
            .tracked
            .lock()
            .map_err(|_| Error::from(CimplError::mutex_poisoned()))?;
        match tracked.get(&id) {
            Some(entry) if entry.type_id == expected_type => Ok(Arc::clone(entry)),
            Some(_) => Err(Error::from(CimplError::wrong_pointer_type(id as u64))),
            None => Err(Error::from(CimplError::untracked_pointer(id as u64))),
        }
    }

    /// Take a shared borrow. Any number may coexist; only an outstanding
    /// exclusive borrow refuses one.
    #[must_use = "the borrow ends when the returned guard is dropped"]
    fn checkout_shared(&self, id: usize, expected_type: TypeId) -> Result<SharedCheckout, Error> {
        let entry = self.lookup(id, expected_type)?;
        // Retry while another reader changes the count; give up only when the
        // entry is exclusively borrowed.
        let mut current = entry.borrow_state.load(Ordering::Acquire);
        loop {
            if current == EXCLUSIVE {
                return Err(Error::from(CimplError::pointer_in_use()));
            }
            match entry.borrow_state.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(SharedCheckout { entry }),
                Err(observed) => current = observed,
            }
        }
    }

    /// Take the exclusive borrow. Refused while any other borrow is
    /// outstanding, which is what makes `&mut T` from a handle sound.
    #[must_use = "the borrow ends when the returned guard is dropped"]
    fn checkout_exclusive(
        &self,
        id: usize,
        expected_type: TypeId,
    ) -> Result<ExclusiveCheckout, Error> {
        let entry = self.lookup(id, expected_type)?;
        match entry
            .borrow_state
            .compare_exchange(0, EXCLUSIVE, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(ExclusiveCheckout { entry }),
            Err(_) => Err(Error::from(CimplError::pointer_in_use())),
        }
    }

    /// Remove a handle id from tracking without running its cleanup function,
    /// returning the real address it referred to.
    ///
    /// Use this when an FFI function consumes a tracked pointer by calling
    /// `Box::from_raw()` — the pointer must be untracked first so the registry
    /// doesn't hold a stale entry that would cause a double-free on `cimpl_free()`
    /// or a false leak warning at shutdown.
    ///
    /// After untracking, the registry no longer knows about this pointer:
    /// - `cimpl_free()` will return an error (untracked pointer), not double-free
    /// - The leak detector will not report it at shutdown
    /// - The caller now owns the memory and must drop it (typically via `Box::from_raw()`)
    ///
    /// # When to use
    ///
    /// Any time a `box_tracked!` pointer is consumed by Rust rather than freed by C:
    /// - `c2pa_context_builder_set_signer`: signer is moved into the builder
    /// - `c2pa_context_builder_build`: builder is consumed to produce a context
    /// - `c2pa_reader_with_stream`: reader is consumed to produce a new reader
    /// - `c2pa_builder_with_definition`: builder is consumed to produce a new builder
    ///
    /// `required` is the wrapper kind the caller can reconstruct. The entry is
    /// removed only when every check passes, so a rejected call leaves the
    /// handle tracked and freeable.
    #[must_use = "dropping the returned address leaks the allocation"]
    fn untrack(
        &self,
        id: usize,
        expected_type: TypeId,
        required: Option<Wrapper>,
    ) -> Result<(usize, Wrapper), Error> {
        self.check_same_process()?;
        if id == 0 {
            return Err(Error::from(CimplError::null_parameter("pointer")));
        }

        let mut tracked = self
            .tracked
            .lock()
            .map_err(|_| Error::from(CimplError::mutex_poisoned()))?;

        match tracked.get(&id) {
            Some(entry) if entry.type_id == expected_type => {
                // Take the exclusive claim rather than observe the counter.
                // Merely reading it leaves a window: lookup() releases the map
                // lock before checkout_* acquires its claim, so a checkout in
                // that window would get a guard to memory this call is about to
                // move out of. Claiming closes it -- a concurrent checkout
                // either wins this CAS (and we refuse) or sees EXCLUSIVE (and
                // it refuses).
                //
                // Never test Arc::strong_count instead: a transient clone
                // inflates it without any borrow existing.
                if entry
                    .borrow_state
                    .compare_exchange(0, EXCLUSIVE, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    return Err(Error::from(CimplError::pointer_in_use()));
                }
                // Check the wrapper before removing, so a rejection does not
                // consume the entry and leak the allocation. The claim taken
                // above must be released here, or a rejected entry would stay
                // borrowed forever.
                if required.is_some_and(|required| required != entry.wrapper) {
                    entry.borrow_state.store(0, Ordering::Release);
                    return Err(Error::from(CimplError::wrong_wrapper_kind()));
                }

                let entry = tracked.remove(&id).expect("checked Some above");
                let real_addr = entry.real_addr;
                let wrapper = entry.wrapper;
                // Defuse before the entry can drop. Ownership is moving to the
                // caller, so running cleanup here would free memory the caller
                // is about to reconstruct.
                if let Ok(mut cleanup) = entry.cleanup.lock() {
                    cleanup.take();
                }
                drop(tracked); // Release before the Arc drops.
                drop(entry);
                Ok((real_addr, wrapper))
            }
            Some(_) => Err(Error::from(CimplError::wrong_pointer_type(id as u64))),
            None => Err(Error::from(CimplError::untracked_pointer(id as u64))),
        }
    }

    /// Free a tracked entry by calling its cleanup function
    pub fn free(&self, key: usize) -> Result<(), Error> {
        self.check_same_process()?;
        if key == 0 {
            return Ok(()); // NULL is always safe
        }

        let entry = {
            let mut tracked = self
                .tracked
                .lock()
                .map_err(|_| Error::from(CimplError::mutex_poisoned()))?;
            match tracked.remove(&key) {
                Some(entry) => entry,
                None => return Err(Error::from(CimplError::untracked_pointer(key as u64))),
            }
        }; // Release lock before the entry drops.

        // Dropping the last Arc runs the cleanup closure in EntryInner::drop.
        // It must happen outside the critical section above: a closure that
        // re-enters the registry would otherwise deadlock on the same Mutex.
        drop(entry);
        Ok(())
    }
}

/// Automatic leak detection at shutdown.
///
/// When the pointer registry is dropped (at program shutdown), it checks for any
/// tracked pointers that were never freed. This helps identify memory leaks caused
/// by missing `cimpl_free()` calls in C code.
///
/// # Example Output
///
/// ```text
/// ⚠️  WARNING: 3 pointer(s) were not freed at shutdown!
/// This indicates C code did not properly free all allocated pointers.
/// Each pointer should be freed exactly once with cimpl_free().
/// ```
///
/// This detection runs in **all builds** (debug, release, and test) to help catch
/// memory management bugs during development and integration testing.
impl Drop for PointerRegistry {
    fn drop(&mut self) {
        // A forked child inherits the whole map. Reporting it would print a
        // spurious leak report from every child, and the entries are not this
        // process's to account for.
        if self.owner_pid != current_pid() {
            return;
        }
        // Take the entries out and release the lock before they drop: each one
        // may run a cleanup closure that re-enters the registry.
        let leaked = {
            let mut tracked = self.tracked.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *tracked)
        };
        if !leaked.is_empty() {
            eprintln!(
                "\n⚠️  WARNING: {} pointer(s) were not freed at shutdown!",
                leaked.len()
            );
            eprintln!("This indicates C code did not properly free all allocated pointers.");
            eprintln!("Each pointer should be freed exactly once with cimpl_free().\n");
        }
        // Leak what C never freed, as before. Running cleanup at shutdown would
        // be a behavior change: these closures can touch other statics that may
        // already be gone, and the process is exiting anyway.
        for (_, entry) in leaked {
            if let Ok(mut cleanup) = entry.cleanup.lock() {
                cleanup.take();
            }
        }
    }
}

/// Get the global pointer registry
pub(crate) fn get_registry() -> &'static PointerRegistry {
    use std::sync::OnceLock;
    static REGISTRY: OnceLock<PointerRegistry> = OnceLock::new();
    REGISTRY.get_or_init(PointerRegistry::new)
}

// ============================================================================
// Tracking Functions for Different Wrapper Types
// ============================================================================

/// Track a Box-wrapped pointer
///
/// Use this when you allocate with `Box::into_raw()`.
/// The pointer will be freed with `Box::from_raw()` when `cimpl_free()` is called.
///
/// # Returns
/// Returns an opaque handle id disguised as `*mut T`, not the real pointer —
/// see `PointerRegistry::track_by_id`.
///
/// # Example
/// ```ignore
/// let ptr = track_box(Box::into_raw(Box::new(value)));
/// ```
pub fn track_box<T: 'static + MaybeSend>(ptr: *mut T) -> *mut T {
    let ptr_val = ptr as usize; // Store as usize to make it Send
    let cleanup = move || unsafe {
        drop(Box::from_raw(ptr_val as *mut T));
    };
    match get_registry().track_by_id(
        ptr_val,
        TypeId::of::<T>(),
        Wrapper::Boxed,
        Box::new(cleanup),
    ) {
        Some(id) => id as *mut T,
        // A null pointer is refused with nothing to reclaim.
        None if ptr.is_null() => std::ptr::null_mut(),
        None => {
            // The registry has no record of this allocation, so cimpl_free can
            // never reach it. Reclaim it here rather than leak; track_by_id has
            // already recorded why through set_last.
            // SAFETY: track_by_id never frees, so this is still the sole owner,
            // and ptr is non-null on this arm.
            unsafe { drop(Box::from_raw(ptr_val as *mut T)) };
            std::ptr::null_mut()
        }
    }
}

/// Track an Arc-wrapped pointer
///
/// Use this when you allocate with `Arc::into_raw()`.
/// The pointer will be freed with `Arc::from_raw()` when `cimpl_free()` is called.
///
/// # Returns
/// Returns an opaque handle id disguised as `*mut T`, not the real pointer —
/// see `PointerRegistry::track_by_id`.
///
/// # Example
/// ```ignore
/// let ptr = track_arc(Arc::into_raw(Arc::new(value)));
/// ```
pub fn track_arc<T: 'static + MaybeSend>(ptr: *mut T) -> *mut T {
    let ptr_val = ptr as usize; // Store as usize to make it Send
    let cleanup = move || unsafe {
        drop(Arc::from_raw(ptr_val as *const T));
    };
    match get_registry().track_by_id(
        ptr_val,
        TypeId::of::<T>(),
        Wrapper::Arced,
        Box::new(cleanup),
    ) {
        Some(id) => id as *mut T,
        None if ptr.is_null() => std::ptr::null_mut(),
        None => {
            // See track_box: untracked means unfreeable, so reclaim here.
            // SAFETY: track_by_id never frees, so this is still the sole owner,
            // and ptr is non-null on this arm.
            unsafe { drop(Arc::from_raw(ptr_val as *const T)) };
            std::ptr::null_mut()
        }
    }
}

/// Track an `Arc<Mutex<T>>`-wrapped pointer
///
/// Use this when you allocate with `Arc::into_raw(Arc::new(Mutex::new(value)))`.
/// The pointer will be freed with `Arc::from_raw()` when `cimpl_free()` is called.
///
/// # Returns
/// Returns an opaque handle id disguised as `*mut Mutex<T>`, not the real
/// pointer — see `PointerRegistry::track_by_id`.
///
/// # Example
/// ```ignore
/// let ptr = track_arc_mutex(Arc::into_raw(Arc::new(Mutex::new(value))));
/// ```
pub fn track_arc_mutex<T: 'static + MaybeSend>(ptr: *mut Mutex<T>) -> *mut Mutex<T> {
    let ptr_val = ptr as usize; // Store as usize to make it Send
    let cleanup = move || unsafe {
        drop(Arc::from_raw(ptr_val as *const Mutex<T>));
    };
    match get_registry().track_by_id(
        ptr_val,
        TypeId::of::<Mutex<T>>(),
        Wrapper::Arced,
        Box::new(cleanup),
    ) {
        Some(id) => id as *mut Mutex<T>,
        None if ptr.is_null() => std::ptr::null_mut(),
        None => {
            // See track_box: untracked means unfreeable, so reclaim here.
            // SAFETY: track_by_id never frees, so this is still the sole owner,
            // and ptr is non-null on this arm.
            unsafe { drop(Arc::from_raw(ptr_val as *const Mutex<T>)) };
            std::ptr::null_mut()
        }
    }
}

/// Borrow a tracked object for reading, keeping it alive for as long as the
/// returned guard lives.
///
/// The guard holds a claim on the entry, so unlike a bare resolved pointer: a concurrent
/// `cimpl_free` from another thread removes the handle but cannot free the
/// object until every guard is dropped.
///
/// Fails with `pointer_in_use` if the object is exclusively borrowed.
///
/// `T: MaybeSync` because two threads can each check out the same handle and
/// each dereference to `&T` without either guard crossing a thread boundary,
/// which is what the FFI actually does. The guards' auto-trait impls do not
/// cover that case; this bound does.
#[must_use = "the borrow ends when the returned guard is dropped"]
pub fn checkout_shared<T: 'static + MaybeSync>(ptr: *mut T) -> Result<TypedShared<T>, Error> {
    let inner = get_registry().checkout_shared(ptr as usize, TypeId::of::<T>())?;
    Ok(TypedShared {
        inner,
        _marker: PhantomData,
    })
}

/// Borrow a tracked object for writing. At most one borrow of any kind can be
/// outstanding, so the returned `&mut T` cannot alias.
///
/// Fails with `pointer_in_use` if any other borrow exists — including a caller
/// passing the same handle twice to one function, which was previously
/// undefined behavior.
/// `T: MaybeSend` because the `&mut T` handed out can reach a different thread
/// than the one that created the object.
#[must_use = "the borrow ends when the returned guard is dropped"]
pub fn checkout_exclusive<T: 'static + MaybeSend>(ptr: *mut T) -> Result<TypedExclusive<T>, Error> {
    let inner = get_registry().checkout_exclusive(ptr as usize, TypeId::of::<T>())?;
    Ok(TypedExclusive {
        inner,
        _marker: PhantomData,
    })
}

/// Checks that a handle is tracked and holds a `T`, without consuming it or
/// taking a borrow.
///
/// For functions that consume more than one handle: untracking is irreversible,
/// so a second `untrack_owned` failing after the first succeeded destroys the
/// first object while reporting failure. Validating every handle first turns
/// that into a clean refusal with nothing consumed.
///
/// This grants no claim on the entry, so it proves nothing about a later call
/// on another thread. It is for ordering checks within one function, not for
/// deciding that a handle is safe to use.
pub fn validate_handle<T: 'static>(ptr: *mut T) -> Result<(), Error> {
    get_registry().lookup(ptr as usize, TypeId::of::<T>())?;
    Ok(())
}

/// Take ownership of a tracked object, removing it from the registry and
/// returning the value itself.
///
/// This is the only place an allocation is reconstructed, so no caller has to
/// decide between `Box::from_raw` and `Arc::from_raw` — picking wrong is
/// undefined behavior, and returning the value instead of a pointer makes the
/// choice unrepresentable.
///
/// Fails if the object is currently borrowed (`PointerInUse`), if the handle is
/// untracked or the wrong type, or if it was tracked as an `Arc`
/// (`WrongWrapperKind`), where other clones may exist so no single owner can be
/// handed back.
pub fn untrack_owned<T: 'static>(ptr: *mut T) -> Result<T, Error> {
    let (real_addr, _) =
        get_registry().untrack(ptr as usize, TypeId::of::<T>(), Some(Wrapper::Boxed))?;
    // SAFETY: the entry was tracked by track_box, so the allocation came from
    // Box::into_raw with this exact T, and untrack removed it and defused its
    // cleanup only after confirming the wrapper, making this the sole owner.
    Ok(*unsafe { Box::from_raw(real_addr as *mut T) })
}

/// Universal free function for any tracked pointer
///
/// This is the universal free function exposed to C. It works for ANY pointer
/// that was allocated and tracked through cimpl, regardless of the wrapper type
/// (Box, Arc, etc.) or the underlying Rust type.
///
/// # Returns
/// - `0` on success
/// - `-1` on error (pointer not tracked, double-free, or invalid pointer)
///
/// When an error occurs, the error is set via [`crate::CimplError::set_last`] and can be
/// retrieved using the C2PA error handling functions.
///
/// # Test Mode Error Reporting
///
/// In test builds (`#[cfg(test)]`), this function will print detailed error information
/// to stderr when it fails. This helps catch memory management bugs during testing:
///
/// ```text
/// ⚠️  ERROR: cimpl_free failed for pointer 0x12345678: pointer not tracked
/// This usually means:
/// 1. The pointer was not allocated with box_tracked!/track_box
/// 2. The pointer was already freed (double-free)
/// 3. The pointer is invalid/corrupted
/// ```
///
/// **Important**: C code should check the return value to detect errors. Test failures
/// may indicate untracked allocations or incorrect pointer management.
///
/// # Safety
/// - Safe to call with NULL (returns 0, no error set)
/// - Safe to call with any tracked pointer
/// - **DO NOT** call on untracked pointers - will return -1 and set error
/// - **DO NOT** call twice on the same pointer - will return -1 and set error
///
/// # Example (C)
/// ```c
/// MyString* str = mystring_create("hello");
/// char* value = mystring_get_value(str);
///
/// // Always check return values in production code
/// if (cimpl_free(value) != 0) {
///     // Handle error - check C2PA error functions
/// }
/// if (cimpl_free(str) != 0) {
///     // Handle error
/// }
/// ```
#[no_mangle]
pub extern "C" fn cimpl_free(ptr: *mut std::ffi::c_void) -> i32 {
    match get_registry().free(ptr as usize) {
        Ok(()) => 0,
        Err(e) => {
            let error = CimplError::from(e);

            // In test builds, print error to stderr to make failures visible
            #[cfg(test)]
            {
                if ptr as usize != 0 {
                    eprintln!(
                        "\n⚠️  ERROR: cimpl_free failed for pointer 0x{:x}: {}\n\
                        This usually means:\n\
                        1. The pointer was not allocated with box_tracked!/track_box\n\
                        2. The pointer was already freed (double-free)\n\
                        3. The pointer is invalid/corrupted\n",
                        ptr as usize, error
                    );
                }
            }

            error.set_last();
            -1
        }
    }
}

// ============================================================================
// Buffer Safety Utilities
// ============================================================================

/// Validates that a buffer size is within safe bounds and doesn't cause integer overflow
/// when used with pointer arithmetic.
///
/// # Arguments
/// * `size` - Size to validate
/// * `ptr` - Pointer to validate against (for address space checks)
///
/// # Returns
/// * `true` if the size is safe to use
/// * `false` if the size would cause integer overflow
///
/// # Safety
/// Caller must ensure that `ptr` points to valid memory if not null.
/// This function performs pointer arithmetic with `ptr.add(size)` which requires
/// that the pointer and size are valid for the memory region being checked.
pub unsafe fn is_safe_buffer_size(size: usize, ptr: *const c_uchar) -> bool {
    // Combined checks for early return - improves branch prediction
    if size == 0 || size > isize::MAX as usize {
        return false;
    }

    // Check if the buffer would extend beyond address space to fail fast
    if !ptr.is_null() {
        let end_ptr = ptr.add(size);
        if end_ptr < ptr {
            return false; // Wrapped around
        }
    }

    true
}

/// Creates a safe slice from raw parts with bounds validation
///
/// # Arguments
/// * `ptr` - Pointer to the data
/// * `len` - Length of the data
/// * `param_name` - Name of the parameter for error reporting
///
/// # Returns
/// * `Ok(slice)` if the slice is safe to create
/// * `Err(Error)` if bounds validation fails
///
/// # Safety
/// Caller must ensure that:
/// - `ptr` points to valid, initialized memory for at least `len` bytes
/// - The memory remains valid for the lifetime of the returned slice
/// - The memory is not mutated while the slice exists
/// - `len` does not exceed the actual size of the allocated memory
pub unsafe fn safe_slice_from_raw_parts(
    ptr: *const c_uchar,
    len: usize,
    param_name: &str,
) -> Result<&[u8], Error> {
    if ptr.is_null() {
        return Err(Error::from(CimplError::null_parameter(param_name)));
    }

    if !is_safe_buffer_size(len, ptr) {
        return Err(Error::from(CimplError::invalid_buffer_size(
            len, param_name,
        )));
    }

    Ok(std::slice::from_raw_parts(ptr, len))
}

/// Converts a Rust String to a C string (*mut c_char)
///
/// The returned pointer is tracked for allocation safety and MUST be freed
/// by calling the appropriate free function (e.g., `cimpl_free`).
///
/// # Arguments
/// * `s` - The Rust String to convert
///
/// # Returns
/// * `*mut c_char` - Pointer to the C string, or null on error
///
/// # Safety
/// The returned pointer must be freed exactly once by C code
pub fn to_c_string(s: String) -> *mut std::os::raw::c_char {
    use std::ffi::CString;
    match CString::new(s) {
        Ok(c_str) => {
            let ptr = c_str.into_raw();
            let ptr_val = ptr as usize;
            let tracked = get_registry().track_by_address(
                ptr_val,
                TypeId::of::<CString>(),
                Box::new(move || unsafe {
                    drop(CString::from_raw(ptr_val as *mut std::os::raw::c_char))
                }),
            );
            if !tracked {
                // Never hand C a pointer the registry has no record of: it
                // could not be freed through cimpl_free and would leak.
                // SAFETY: nothing else took ownership of this allocation.
                unsafe { drop(CString::from_raw(ptr)) };
                return std::ptr::null_mut();
            }
            ptr
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Converts a `Vec <u8>` to a tracked C byte array pointer
///
/// The returned pointer is tracked for allocation safety and MUST be freed
/// by calling `free_c_bytes`.
///
/// # Arguments
/// * `bytes` - The byte vector to convert
///
/// # Returns
/// * `*const c_uchar` - Pointer to the byte array, or null if the vector is empty
///
/// # Safety
/// The returned pointer must be freed exactly once by calling `free_c_bytes`.
/// Returns null for empty vectors to avoid dangling pointers from zero-sized allocations.
pub fn to_c_bytes(bytes: Vec<u8>) -> *const c_uchar {
    let len = bytes.len();
    if len == 0 {
        return std::ptr::null();
    }

    let ptr = Box::into_raw(bytes.into_boxed_slice()) as *const c_uchar;
    let ptr_val = ptr as usize;
    let tracked = get_registry().track_by_address(
        ptr_val,
        TypeId::of::<Box<[u8]>>(),
        Box::new(move || {
            unsafe {
                // Reconstruct the slice with the original length
                drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                    ptr_val as *mut u8,
                    len,
                )))
            }
        }),
    );
    if !tracked {
        // As to_c_string: an untracked buffer cannot be freed through
        // cimpl_free, so free it here rather than leak it.
        // SAFETY: nothing else took ownership of this allocation.
        unsafe {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                ptr_val as *mut u8,
                len,
            )))
        };
        return std::ptr::null();
    }
    ptr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocation_tracking_double_free_string() {
        use std::ffi::CString;

        // Test that double-freeing a string is detected
        let test_string = CString::new("test allocation tracking").unwrap();
        let c_string = to_c_string(test_string.to_str().unwrap().to_string());
        assert!(!c_string.is_null());

        // First free should succeed
        let result1 = cimpl_free(c_string as *mut std::ffi::c_void);
        assert_eq!(result1, 0);

        // Second free should be detected and return error
        let result2 = cimpl_free(c_string as *mut std::ffi::c_void);
        assert_eq!(result2, -1);
    }

    #[test]
    fn test_to_c_string_basic() {
        // Test basic string conversion
        let rust_string = "Hello, C!".to_string();
        let c_string = to_c_string(rust_string);
        assert!(!c_string.is_null());

        // Clean up
        cimpl_free(c_string as *mut std::ffi::c_void);
    }

    #[test]
    fn test_to_c_bytes_basic() {
        // Test basic byte array conversion
        let bytes = vec![1, 2, 3, 4, 5];
        let ptr = to_c_bytes(bytes);
        assert!(!ptr.is_null());

        // Clean up
        cimpl_free(ptr as *mut std::ffi::c_void);
    }

    #[test]
    fn test_to_c_string_with_null_byte() {
        // Test that strings with embedded nulls return null
        let bad_string = "Hello\0World".to_string();
        let c_string = to_c_string(bad_string);
        assert!(c_string.is_null());
        // No need to free since it's null
    }

    #[test]
    fn test_untrack_removes_from_registry() {
        let ptr = track_box(Box::into_raw(Box::new(42i32)));
        assert!(get_registry().resolve_typed::<i32>(ptr).is_ok());

        let real_ptr = get_registry().untrack_typed::<i32>(ptr).unwrap();

        // No longer tracked - cimpl_free should fail
        let result = cimpl_free(ptr as *mut std::ffi::c_void);
        assert_eq!(result, -1);

        // Clean up manually since we took ownership (via the real pointer
        // untrack returned, not the opaque handle id)
        unsafe { drop(Box::from_raw(real_ptr)) };
    }

    #[test]
    fn test_untrack_wrong_type_fails() {
        let ptr = track_box(Box::into_raw(Box::new(42i32)));

        let result = get_registry().untrack_typed::<u64>(ptr as *mut u64);
        assert!(result.is_err());

        // Original pointer still tracked
        assert!(get_registry().resolve_typed::<i32>(ptr).is_ok());
        cimpl_free(ptr as *mut std::ffi::c_void);
    }

    #[test]
    fn test_untrack_null_pointer_fails() {
        let result = get_registry().untrack_typed::<i32>(std::ptr::null_mut());
        assert!(result.is_err());
    }

    #[test]
    fn test_untrack_unregistered_pointer_fails() {
        let ptr = Box::into_raw(Box::new(42i32));
        let result = get_registry().untrack_typed::<i32>(ptr);
        assert!(result.is_err());
        unsafe { drop(Box::from_raw(ptr)) };
    }

    #[test]
    fn test_untrack_already_untracked_fails() {
        let ptr = track_box(Box::into_raw(Box::new(42i32)));
        let real_ptr = get_registry().untrack_typed::<i32>(ptr).unwrap();

        // Second untrack fails
        let result = get_registry().untrack_typed::<i32>(ptr);
        assert!(result.is_err());

        unsafe { drop(Box::from_raw(real_ptr)) };
    }

    #[test]
    fn test_untrack_refuses_while_a_borrow_is_outstanding() {
        // Deterministic, not a race: take the borrow first and hold it, then
        // attempt the untrack. This passes against a `load`-based untrack too,
        // so it is not a regression test for the lookup/checkout window --
        // test_untrack_and_checkout_never_both_succeed covers that.
        for _ in 0..200 {
            let ptr = track_box(Box::into_raw(Box::new(1234i32)));

            let guard = checkout_shared::<i32>(ptr).expect("fresh handle");
            assert!(
                untrack_owned::<i32>(ptr).is_err(),
                "ownership moved out from under a live borrow"
            );
            drop(guard);

            assert_eq!(
                untrack_owned::<i32>(ptr).expect("borrow released"),
                1234,
                "untrack must succeed once the borrow ends"
            );
        }
    }

    #[test]
    fn test_untrack_claims_the_borrow_rather_than_observing_it() {
        // H-1 was that untrack READ borrow_state instead of claiming it. The
        // window is between lookup() releasing the map lock and checkout_*
        // taking its claim -- nanoseconds wide, and both paths serialize on the
        // map lock, so a stress test does not reach it reliably. (Two attempts
        // at one here never produced a single overlapping round; a passing
        // stress test would have been evidence of nothing.)
        //
        // What is checkable deterministically is the property the CAS provides:
        // a successful untrack leaves the entry claimed EXCLUSIVE, so any
        // checkout arriving afterwards is refused rather than handed a guard to
        // an object whose ownership has moved. A load-based untrack leaves the
        // counter at 0 and the late checkout succeeds.
        let ptr = track_box(Box::into_raw(Box::new(1234i32)));
        let addr = ptr as usize;

        // Hold a clone of the entry so it outlives its removal from the map,
        // which is what a checkout already past lookup() would be holding.
        let entry = get_registry()
            .lookup(addr, TypeId::of::<i32>())
            .expect("fresh handle");

        assert_eq!(
            untrack_owned::<i32>(addr as *mut i32).expect("nothing borrowed yet"),
            1234
        );

        assert_eq!(
            entry.borrow_state.load(Ordering::Acquire),
            EXCLUSIVE,
            "untrack must leave the entry claimed, so a checkout already past \
             lookup() is refused instead of borrowing a moved-out object"
        );

        // A checkout holding that entry now refuses, which is the outcome the
        // claim exists to produce.
        assert!(
            entry
                .borrow_state
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err(),
            "a shared claim was still available after ownership moved out"
        );
    }
    #[test]
    fn test_untrack_claim_is_released_when_the_wrapper_is_wrong() {
        // untrack now CLAIMS the borrow before checking the wrapper. The
        // rejection path must hand that claim back, or an Arc-tracked entry
        // becomes permanently unborrowable and unfreeable.
        let arc = Arc::new(5i32);
        let ptr = track_arc(Arc::into_raw(arc) as *mut i32);

        assert!(
            untrack_owned::<i32>(ptr).is_err(),
            "Arc entry must be refused"
        );

        // Still borrowable, so the claim was released.
        assert!(
            checkout_shared::<i32>(ptr).is_ok(),
            "the rejected entry stayed exclusively claimed"
        );
        assert_eq!(cimpl_free(ptr as *mut std::ffi::c_void), 0);
    }

    #[test]
    fn test_untrack_refused_while_checked_out() {
        let ptr = track_box(Box::into_raw(Box::new(42i32)));
        let guard = checkout_shared::<i32>(ptr).unwrap();

        assert!(
            untrack_owned::<i32>(ptr).is_err(),
            "ownership must not move while borrowed"
        );
        // The refusal must leave the entry tracked, not half-removed.
        assert!(get_registry().resolve_typed::<i32>(ptr).is_ok());

        drop(guard);
        assert_eq!(untrack_owned::<i32>(ptr).unwrap(), 42);
    }

    #[test]
    fn test_untrack_owned_round_trip_defuses_cleanup() {
        use std::sync::atomic::AtomicUsize as Counter;

        static CLEANUPS: Counter = Counter::new(0);
        struct Counted(i32);
        impl Drop for Counted {
            fn drop(&mut self) {
                CLEANUPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        CLEANUPS.store(0, Ordering::SeqCst);
        let ptr = track_box(Box::into_raw(Box::new(Counted(7))));

        let value = untrack_owned::<Counted>(ptr).unwrap();
        assert_eq!(value.0, 7);
        // Still alive: ownership moved to the caller, cleanup was defused.
        assert_eq!(CLEANUPS.load(Ordering::SeqCst), 0);

        // Freeing the handle afterwards is an error, not a double free.
        assert_eq!(cimpl_free(ptr as *mut std::ffi::c_void), -1);
        assert_eq!(CLEANUPS.load(Ordering::SeqCst), 0);

        drop(value);
        assert_eq!(CLEANUPS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_untrack_owned_rejects_arc_tracked_entry() {
        // An Arc-tracked entry may have other clones, so no single owner can be
        // handed back. Reconstructing it with Box::from_raw would be UB.
        let arc = Arc::new(5i32);
        let ptr = track_arc(Arc::into_raw(arc) as *mut i32);

        let err = untrack_owned::<i32>(ptr).unwrap_err();
        assert!(
            err.to_string().starts_with("WrongWrapperKind:"),
            "expected WrongWrapperKind, got {err}"
        );

        // Rejected, so the entry is still tracked and still freeable.
        assert_eq!(cimpl_free(ptr as *mut std::ffi::c_void), 0);
    }

    #[test]
    fn test_free_while_checked_out_defers_cleanup() {
        use std::sync::atomic::AtomicBool;

        static DROPPED: AtomicBool = AtomicBool::new(false);
        struct Tracked;
        impl Drop for Tracked {
            fn drop(&mut self) {
                DROPPED.store(true, Ordering::SeqCst);
            }
        }

        DROPPED.store(false, Ordering::SeqCst);
        let ptr = track_box(Box::into_raw(Box::new(Tracked)));
        let guard = checkout_shared::<Tracked>(ptr).unwrap();

        // C frees the handle while the borrow is live.
        assert_eq!(cimpl_free(ptr as *mut std::ffi::c_void), 0);
        assert!(!DROPPED.load(Ordering::SeqCst), "freed while borrowed");

        drop(guard);
        assert!(
            DROPPED.load(Ordering::SeqCst),
            "not freed after last borrow"
        );
    }

    #[test]
    fn test_cleanup_reentering_registry_does_not_deadlock() {
        // The cleanup closure of one entry frees another. If any entry were
        // dropped while the registry lock was held, this would deadlock.
        let inner = track_box(Box::into_raw(Box::new(7i32)));
        let inner_addr = inner as usize;

        struct Reenter(usize);
        impl Drop for Reenter {
            fn drop(&mut self) {
                cimpl_free(self.0 as *mut std::ffi::c_void);
            }
        }

        let outer = track_box(Box::into_raw(Box::new(Reenter(inner_addr))));
        assert_eq!(cimpl_free(outer as *mut std::ffi::c_void), 0);

        // The inner entry was freed by the outer's cleanup.
        assert!(get_registry().resolve_typed::<i32>(inner).is_err());
    }

    #[test]
    fn test_second_exclusive_checkout_refused_then_released() {
        let ptr = track_box(Box::into_raw(Box::new(1i32)));

        let first = checkout_exclusive::<i32>(ptr).unwrap();
        assert!(
            checkout_exclusive::<i32>(ptr).is_err(),
            "two exclusive borrows must not coexist"
        );

        drop(first);
        assert!(
            checkout_exclusive::<i32>(ptr).is_ok(),
            "claim must be released on drop"
        );

        cimpl_free(ptr as *mut std::ffi::c_void);
    }

    #[test]
    fn test_nested_checkout_of_different_ids_succeeds() {
        // The reentrancy pattern used by C2paStream: a guard on one handle held
        // while checking out a second, different handle.
        let outer = track_box(Box::into_raw(Box::new(1i32)));
        let inner = track_box(Box::into_raw(Box::new(2i32)));

        let outer_guard = checkout_exclusive::<i32>(outer).unwrap();
        let inner_guard = checkout_exclusive::<i32>(inner).unwrap();
        assert_eq!(*outer_guard, 1);
        assert_eq!(*inner_guard, 2);

        drop(inner_guard);
        drop(outer_guard);
        cimpl_free(outer as *mut std::ffi::c_void);
        cimpl_free(inner as *mut std::ffi::c_void);
    }

    #[test]
    fn test_concurrent_shared_checkouts_all_succeed() {
        let ptr = track_box(Box::into_raw(Box::new(42i32)));
        let addr = ptr as usize;

        let failures = std::sync::Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let failures = std::sync::Arc::clone(&failures);
                scope.spawn(move || {
                    for _ in 0..5_000 {
                        match checkout_shared::<i32>(addr as *mut i32) {
                            Ok(guard) => assert_eq!(*guard, 42),
                            Err(_) => {
                                failures.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                });
            }
        });

        assert_eq!(
            failures.load(Ordering::Relaxed),
            0,
            "shared borrows must never refuse each other"
        );
        cimpl_free(ptr as *mut std::ffi::c_void);
    }

    #[test]
    fn test_guards_are_send() {
        // A guard over a thread-safe T must stay Send, or work-stealing
        // runtimes break. The bound is deliberately conditional: a guard over a
        // !Sync T must NOT be Send, which is what stops two &T reaching two
        // threads. Only concrete Sync types belong here -- asserting the
        // blanket property would re-assert the soundness hole.
        fn assert_send<T: Send>() {}
        assert_send::<TypedShared<i32>>();
        assert_send::<TypedExclusive<i32>>();

        // On wasm32 MaybeSend/MaybeSync are no-op impls, so nothing constrains
        // this there. Fine while wasm is single-threaded.
    }

    #[test]
    fn test_guard_outliving_free_across_threads_cleans_up_once() {
        use std::sync::atomic::AtomicUsize as Counter;

        static CLEANUPS: Counter = Counter::new(0);
        struct Counted;
        impl Drop for Counted {
            fn drop(&mut self) {
                CLEANUPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        CLEANUPS.store(0, Ordering::SeqCst);
        let ptr = track_box(Box::into_raw(Box::new(Counted)));
        let addr = ptr as usize;

        // Created on this thread, freed on a second, dropped on a third.
        let guard = checkout_shared::<Counted>(ptr).unwrap();
        std::thread::spawn(move || {
            cimpl_free(addr as *mut std::ffi::c_void);
        })
        .join()
        .unwrap();
        std::thread::spawn(move || drop(guard)).join().unwrap();

        assert_eq!(CLEANUPS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_panicking_cleanup_is_contained() {
        struct Panics;
        impl Drop for Panics {
            fn drop(&mut self) {
                panic!("cleanup panic");
            }
        }

        let ptr = track_box(Box::into_raw(Box::new(Panics)));
        // cimpl_free is reached from C, so without catch_unwind in
        // EntryInner::drop the panic from the cleanup closure would unwind
        // across the extern "C" boundary and abort the process.
        assert_eq!(cimpl_free(ptr as *mut std::ffi::c_void), 0);

        // The registry lock survived, so later calls still work.
        let after = track_box(Box::into_raw(Box::new(5i32)));
        assert!(get_registry().resolve_typed::<i32>(after).is_ok());
        cimpl_free(after as *mut std::ffi::c_void);
    }

    #[test]
    fn test_stale_handle_does_not_alias_new_allocation() {
        let ptr1 = track_box(Box::into_raw(Box::new(1i32)));
        assert!(get_registry().resolve_typed::<i32>(ptr1).is_ok());
        assert_eq!(cimpl_free(ptr1 as *mut std::ffi::c_void), 0);

        let ptr2 = track_box(Box::into_raw(Box::new(2i32)));

        assert_ne!(ptr1, ptr2);
        assert!(get_registry().resolve_typed::<i32>(ptr1).is_err());
        assert!(get_registry().resolve_typed::<i32>(ptr2).is_ok());

        cimpl_free(ptr2 as *mut std::ffi::c_void);
    }

    #[test]
    fn test_track_by_id_refusal_leaves_the_object_for_the_caller() {
        // N-1: a refused track must not free. track_box reclaims the
        // allocation itself, so the object is dropped exactly once and the
        // caller gets NULL rather than a handle nothing can free.
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        struct Payload;
        impl Drop for Payload {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        DROPS.store(0, Ordering::SeqCst);
        // A registry owned by another process refuses every track_by_id, which
        // is the fork-refusal path a multiprocessing child takes.
        let foreign = PointerRegistry {
            tracked: Mutex::new(HashMap::new()),
            next_id: AtomicUsize::new(0),
            owner_pid: current_pid().wrapping_add(1),
        };

        let raw = Box::into_raw(Box::new(Payload));
        let ptr_val = raw as usize;
        let id = foreign.track_by_id(
            ptr_val,
            TypeId::of::<Payload>(),
            Wrapper::Boxed,
            Box::new(move || unsafe { drop(Box::from_raw(ptr_val as *mut Payload)) }),
        );

        assert!(id.is_none(), "a foreign-process registry must refuse");
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            0,
            "track_by_id must not free; the caller still owns the allocation"
        );
        // The refusal records why, rather than leaving a stale message from an
        // unrelated call for C to read. This test writes the thread-local error
        // slot as a result, which is deliberate.
        assert!(
            CimplError::last_message().is_some_and(|message| message.contains("ForeignProcess")),
            "the refusal must record its reason"
        );

        // What track_box does with that None:
        unsafe { drop(Box::from_raw(raw)) };
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            1,
            "the caller's reclaim is the one and only free"
        );
    }

    #[test]
    fn test_track_by_address_refusal_leaves_the_buffer_for_the_caller() {
        // N-2: the refusal path must not run the cleanup closure. If it does,
        // the buffer is freed here and the caller frees it again on `false`.
        static FREED: AtomicUsize = AtomicUsize::new(0);

        FREED.store(0, Ordering::SeqCst);
        let foreign = PointerRegistry {
            tracked: Mutex::new(HashMap::new()),
            next_id: AtomicUsize::new(0),
            owner_pid: current_pid().wrapping_add(1),
        };

        let mut buffer = [0u8; 8];
        let addr = buffer.as_mut_ptr() as usize & !1usize;
        let tracked = foreign.track_by_address(
            addr,
            TypeId::of::<u8>(),
            Box::new(|| {
                FREED.fetch_add(1, Ordering::SeqCst);
            }),
        );

        assert!(!tracked, "a foreign-process registry must refuse");
        assert_eq!(
            FREED.load(Ordering::SeqCst),
            0,
            "the refusal path must leave the buffer for the caller to free"
        );
        // As above: the refusal records its reason, and this test writes the
        // thread-local error slot as a result.
        assert!(
            CimplError::last_message().is_some_and(|message| message.contains("ForeignProcess")),
            "the refusal must record its reason"
        );
    }

    #[test]
    fn test_poisoned_lock_refusal_does_not_free_the_buffer() {
        // N-2 proper: the double free lives on the poisoned-lock path, which is
        // reached only after the EntryInner has been built. The fork refusal
        // returns before that, so it cannot exercise this.
        static FREED: AtomicUsize = AtomicUsize::new(0);

        FREED.store(0, Ordering::SeqCst);
        let registry = PointerRegistry {
            tracked: Mutex::new(HashMap::new()),
            next_id: AtomicUsize::new(0),
            owner_pid: current_pid(),
        };

        // Poison the map lock the way a panicking thread would.
        let poisoner = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = registry.tracked.lock().unwrap();
            panic!("poison the registry lock");
        }));
        assert!(poisoner.is_err(), "the poisoning panic must have happened");
        assert!(registry.tracked.is_poisoned(), "lock must be poisoned");

        let mut buffer = [0u8; 8];
        let addr = buffer.as_mut_ptr() as usize & !1usize;
        let tracked = registry.track_by_address(
            addr,
            TypeId::of::<u8>(),
            Box::new(|| {
                FREED.fetch_add(1, Ordering::SeqCst);
            }),
        );

        assert!(!tracked, "a poisoned lock recorded nothing, so refuse");
        assert_eq!(
            FREED.load(Ordering::SeqCst),
            0,
            "the entry must not run its cleanup here: false tells the caller to \
             free, and running it too would be a double free"
        );
    }

    #[test]
    fn test_poisoned_lock_refusal_does_not_free_the_object() {
        // The track_by_id half of the same contract.
        static FREED: AtomicUsize = AtomicUsize::new(0);

        FREED.store(0, Ordering::SeqCst);
        let registry = PointerRegistry {
            tracked: Mutex::new(HashMap::new()),
            next_id: AtomicUsize::new(0),
            owner_pid: current_pid(),
        };

        let poisoner = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = registry.tracked.lock().unwrap();
            panic!("poison the registry lock");
        }));
        assert!(poisoner.is_err(), "the poisoning panic must have happened");

        let id = registry.track_by_id(
            0x1234,
            TypeId::of::<i32>(),
            Wrapper::Boxed,
            Box::new(|| {
                FREED.fetch_add(1, Ordering::SeqCst);
            }),
        );

        assert!(id.is_none(), "a poisoned lock recorded nothing, so refuse");
        assert_eq!(
            FREED.load(Ordering::SeqCst),
            0,
            "track_by_id must never free: the caller owns the allocation on None"
        );
    }

    #[test]
    fn test_inherited_entry_drop_does_not_run_cleanup() {
        // N-6: the only way to reach EntryInner::drop's fork branch is to drop
        // an inherited Arc directly. cimpl_free cannot get there --
        // check_same_process refuses first -- so this is the branch's only
        // coverage.
        static RAN: AtomicUsize = AtomicUsize::new(0);

        RAN.store(0, Ordering::SeqCst);
        let inherited = Arc::new(EntryInner {
            real_addr: 0xdead_beef,
            type_id: TypeId::of::<i32>(),
            wrapper: Wrapper::Boxed,
            borrow_state: AtomicUsize::new(0),
            cleanup: Mutex::new(Some(Box::new(|| {
                RAN.fetch_add(1, Ordering::SeqCst);
            }))),
            // A pid that is not this process: what a forked child inherits.
            owner_pid: current_pid().wrapping_add(1),
        });

        drop(inherited);
        assert_eq!(
            RAN.load(Ordering::SeqCst),
            0,
            "an entry inherited across fork must not run its cleanup"
        );

        // Same entry owned by this process: the cleanup does run, so the test
        // above is not passing because the closure is simply never reachable.
        let owned = Arc::new(EntryInner {
            real_addr: 0xdead_beef,
            type_id: TypeId::of::<i32>(),
            wrapper: Wrapper::Boxed,
            borrow_state: AtomicUsize::new(0),
            cleanup: Mutex::new(Some(Box::new(|| {
                RAN.fetch_add(1, Ordering::SeqCst);
            }))),
            owner_pid: current_pid(),
        });
        drop(owned);
        assert_eq!(
            RAN.load(Ordering::SeqCst),
            1,
            "an entry owned by this process must run its cleanup"
        );
    }

    #[test]
    fn test_handle_ids_are_always_odd() {
        // The odd/even split is what makes track_by_address's even-address
        // check meaningful: an id can never be mistaken for a buffer address.
        for _ in 0..64 {
            let ptr = track_box(Box::into_raw(Box::new(7i32)));
            assert_eq!(
                ptr as usize % 2,
                1,
                "handle ids must be odd, got 0x{:x}",
                ptr as usize
            );
            cimpl_free(ptr as *mut std::ffi::c_void);
        }
    }

    #[test]
    fn test_entry_debug_reports_borrow_state_and_cleanup() {
        struct Shown<'a>(&'a EntryInner, bool);
        impl std::fmt::Debug for Shown<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.debug_fmt(f, self.1)
            }
        }

        let entry = EntryInner {
            real_addr: 0x1000,
            type_id: TypeId::of::<i32>(),
            wrapper: Wrapper::Boxed,
            borrow_state: AtomicUsize::new(0),
            cleanup: Mutex::new(Some(Box::new(|| {}))),
            owner_pid: current_pid(),
        };

        let free = format!("{entry:?}");
        assert!(
            free.contains(r#"borrow_state: "free""#),
            "expected borrow_state free: {free}"
        );
        assert!(
            free.contains(r#"cleanup: "armed""#),
            "expected cleanup armed: {free}"
        );

        entry.borrow_state.store(EXCLUSIVE, Ordering::Relaxed);
        let exclusive = format!("{entry:?}");
        assert!(
            exclusive.contains(r#"borrow_state: "exclusive""#),
            "expected borrow_state exclusive: {exclusive}"
        );

        entry.borrow_state.store(3, Ordering::Relaxed);
        let shared = format!("{entry:?}");
        assert!(
            shared.contains(r#"borrow_state: "3 shared""#),
            "expected 3 shared readers: {shared}"
        );

        // Both address branches, in one build. The release behaviour is the one
        // with the security rationale, and no CI job runs a release test, so
        // asserting it through cfg! alone would assert nothing.
        let shown = format!("{:?}", Shown(&entry, false));
        assert!(
            shown.contains(r#"real_addr: 0x1000"#),
            "the visible branch must print the address: {shown}"
        );

        let hidden = format!("{:?}", Shown(&entry, true));
        assert!(
            hidden.contains(r#"real_addr: <hidden>"#),
            "the hidden branch must mask the address: {hidden}"
        );
        assert!(
            !hidden.contains("0x1000"),
            "the hidden branch leaked the address: {hidden}"
        );
    }
}
