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
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, PoisonError, Weak,
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

/// Type for tracked allocations:
/// - an actual address
/// - the allocator (Arc/Box)
type TakenEntry = (usize, Wrapper);

/// The allocator/creator needs to be known,
/// to reconstruct the concrete type and free it.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Wrapper {
    Boxed,
    Arced,
}

/// A tracked handle.
///
/// `Arc` helps to handle concurrent frees,
/// and C frees the `Arc`-backed handle only when the `Arc` drops.
struct EntryInner {
    /// Location of the handle.
    real_addr: usize,
    type_id: TypeId,
    /// Allocator, needed for `untrack_owned` handling.
    wrapper: Wrapper,
    /// Which borrows of this object are outstanding right now.
    ///
    /// A C caller holds an opaque id, not a reference.
    /// This counter is what makes handing out `&mut T` manageable:
    /// a borrow is refused unless the counter permits it.
    ///
    /// - `0`: nobody is using the object, so any borrow may start.
    /// - low bits `1..`: that many readers hold a `TypedShared`.
    /// - `WRITER_PENDING` bit: a writer is waiting for the readers to drain.
    ///   New shared borrows are refused while it is set (that refusal is what
    ///   lets a consuming call through under sustained read load), existing
    ///   readers just drain. Only the writer that set the bit clears it.
    /// - `EXCLUSIVE` (all bits): one writer holds a `TypedExclusive`. No
    ///   other borrow of any kind may start until it drops.
    ///
    /// `untrack` also takes this exclusively, since ownership cannot
    /// move out from under a live borrow.
    ///
    /// The `Arc`'s refcount frees the object; this field and the refcount
    /// move independently.
    /// It can't be inferred from `Arc::strong_count` either,
    /// since any transient clone increases the strong count without a borrow existing.
    borrow_state: AtomicUsize,
    /// `Option` so `untrack` can take the closure out through a shared `Arc`,
    /// leaving nothing for `Drop` to run.
    cleanup: Mutex<Option<CleanupFn>>,
    /// Process creating the registry, written on process creation.
    owner_pid: u32,
}

/// Current process id.
#[cfg(not(target_arch = "wasm32"))]
fn current_pid() -> u32 {
    // SAFETY: getpid takes no arguments and cannot fail.
    unsafe { libc::getpid() as u32 }
}

/// No fork, so return 0 as a constant.
#[cfg(target_arch = "wasm32")]
fn current_pid() -> u32 {
    0
}

/// usize::MAX is used as the exclusive-write marker,
/// since a read-only borrow count should never reach usize::MAX
/// (would need more memory than available).
const EXCLUSIVE: usize = usize::MAX;

/// A writer is waiting for this handle.
const WRITER_PENDING: usize = 1 << (usize::BITS - 1);

/// Timeout to wait for a handle, to avoid livelocks/demand collisions.
#[cfg(not(target_arch = "wasm32"))]
const WRITER_WAIT: std::time::Duration = std::time::Duration::from_millis(10);

/// Timeout for a transient exclusive borrow.
#[cfg(not(target_arch = "wasm32"))]
const READER_WAIT: std::time::Duration = std::time::Duration::from_millis(1);

impl EntryInner {
    /// Take a shared borrow (with timeout, errors if timing out).
    fn try_borrow_shared(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        let deadline = std::time::Instant::now() + READER_WAIT;
        let mut current = self.borrow_state.load(Ordering::Acquire);
        loop {
            if current == EXCLUSIVE || current & WRITER_PENDING != 0 {
                #[cfg(target_arch = "wasm32")]
                return false;
                #[cfg(not(target_arch = "wasm32"))]
                {
                    if std::time::Instant::now() >= deadline {
                        return false;
                    }
                    std::thread::yield_now();
                    current = self.borrow_state.load(Ordering::Acquire);
                    continue;
                }
            }
            match self.borrow_state.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    /// Take an exclusive borrow (with timeout, errors if timing out).
    /// Wait a timeout for readers to drain.
    fn try_borrow_exclusive(&self) -> bool {
        if self
            .borrow_state
            .compare_exchange(0, EXCLUSIVE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return true;
        }
        #[cfg(target_arch = "wasm32")]
        {
            false
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.try_borrow_exclusive_slow()
        }
    }

    /// Even on wasm32, we may need to wait for draining readers.
    #[cfg(not(target_arch = "wasm32"))]
    fn try_borrow_exclusive_slow(&self) -> bool {
        let deadline = std::time::Instant::now() + WRITER_WAIT;
        let mut owns_pending = false;
        let mut current = self.borrow_state.load(Ordering::Acquire);
        loop {
            if owns_pending {
                // Take it once all known borrows are gone.
                if current == WRITER_PENDING {
                    match self.borrow_state.compare_exchange_weak(
                        WRITER_PENDING,
                        EXCLUSIVE,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return true,
                        Err(observed) => {
                            current = observed;
                            continue;
                        }
                    }
                }
            } else if current == 0 {
                match self.borrow_state.compare_exchange_weak(
                    0,
                    EXCLUSIVE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return true,
                    Err(observed) => {
                        current = observed;
                        continue;
                    }
                }
            } else if current != EXCLUSIVE && current & WRITER_PENDING == 0 {
                // No writer is waiting.
                match self.borrow_state.compare_exchange_weak(
                    current,
                    current | WRITER_PENDING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        owns_pending = true;
                        current |= WRITER_PENDING;
                        continue;
                    }
                    Err(observed) => {
                        current = observed;
                        continue;
                    }
                }
            }
            // Wait for deadline...
            if std::time::Instant::now() >= deadline {
                if owns_pending {
                    // Let readers read again.
                    self.borrow_state
                        .fetch_and(!WRITER_PENDING, Ordering::AcqRel);
                }
                return false;
            }
            std::thread::yield_now();
            current = self.borrow_state.load(Ordering::Acquire);
        }
    }

    /// Take a clean up closure but do not run it (avoid double-free).
    fn cancel_cleanup(&self) {
        self.cleanup
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    /// As `cancel_cleanup`, for exclusive access.
    fn cancel_cleanup_mut(&mut self) {
        self.cleanup
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    /// Debug log (hides addresses in release build).
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>, hide_address: bool) -> std::fmt::Result {
        let borrow_state = self.borrow_state.load(Ordering::Relaxed);
        let mut out = f.debug_struct("EntryInner");
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
                    n if n & WRITER_PENDING != 0 => {
                        format!("{} shared (writer pending)", n & !WRITER_PENDING)
                    }
                    n => format!("{n} shared"),
                },
            )
            .field(
                "cleanup",
                &match self.cleanup.try_lock() {
                    Ok(guard) => {
                        if guard.is_some() {
                            "armed"
                        } else {
                            "defused"
                        }
                    }
                    Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                        if poisoned.get_ref().is_some() {
                            "armed"
                        } else {
                            "defused"
                        }
                    }
                    Err(std::sync::TryLockError::WouldBlock) => "locked",
                },
            )
            .field("owner_pid", &self.owner_pid)
            .finish()
    }
}

/// Remove an entry that was built but never recorded, then drop it.
fn discard_untracked_entry(entry: Arc<EntryInner>) {
    match Arc::into_inner(entry) {
        Some(mut entry) => {
            // Dropping a Box<dyn FnMut()> drops the closure's captures without running its body.
            entry.cancel_cleanup_mut();
        }
        None => {
            eprintln!("c2pa: an untracked registry entry was still referenced");
        }
    }
}

/// Debug log for the registry.
impl std::fmt::Debug for EntryInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.debug_fmt(f, !cfg!(debug_assertions))
    }
}

impl Drop for EntryInner {
    fn drop(&mut self) {
        // Never drop an Arc<EntryInner> while holding the registry lock:
        // a clean up closure could enter the registry still, and deadlock.

        if self.owner_pid != current_pid() {
            self.cancel_cleanup_mut();
            return;
        }
        if let Some(mut cleanup) = self
            .cleanup
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            // Catch so there is no panic in another registry (could poison the lock).
            if std::panic::catch_unwind(AssertUnwindSafe(&mut cleanup)).is_err() {
                eprintln!("c2pa: panic while freeing a tracked pointer, leaking pointer");
            }
        }
    }
}

/// Shared (multi-read) borrow of a handle.
/// Holding one keeps the object behind the handle live.
pub struct SharedCheckout {
    entry: Arc<EntryInner>,
}

impl Drop for SharedCheckout {
    /// Drop to make sure the handle gets un-borrowed.
    fn drop(&mut self) {
        self.entry.borrow_state.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Exclusive borrow of a handle.
/// There can be only 1 exclusive borrow at most at a point in time.
pub struct ExclusiveCheckout {
    entry: Arc<EntryInner>,
}

impl Drop for ExclusiveCheckout {
    /// Drop to make sure the exclusive handle gets un-borrowed.
    fn drop(&mut self) {
        self.entry.borrow_state.store(0, Ordering::Release);
    }
}

/// Shared borrow of a `T` behind a handle.
/// Dereferences to `&T` only.
pub struct TypedShared<T> {
    inner: SharedCheckout,
    // PhantomData to not turn things into Send/Sync
    _marker: PhantomData<*const T>,
}

unsafe impl<T: Sync> Send for TypedShared<T> {}
unsafe impl<T: Sync> Sync for TypedShared<T> {}

/// Exclusive borrow of a `T` behind a handle.
/// Dereferences to `&mut T`.
pub struct TypedExclusive<T> {
    inner: ExclusiveCheckout,
    _marker: PhantomData<*const T>,
}

unsafe impl<T: Send> Send for TypedExclusive<T> {}
unsafe impl<T: Sync> Sync for TypedExclusive<T> {}

impl<T> Deref for TypedShared<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*std::ptr::with_exposed_provenance::<T>(self.inner.entry.real_addr) }
    }
}

impl<T> Deref for TypedExclusive<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*std::ptr::with_exposed_provenance::<T>(self.inner.entry.real_addr) }
    }
}

impl<T> DerefMut for TypedExclusive<T> {
    // DerefMut, so no other borrow of this can exist at a given point in time.
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *std::ptr::with_exposed_provenance_mut::<T>(self.inner.entry.real_addr) }
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
///   `2^(usize::BITS - 1)` allocations: 2^63 on 64-bit (unreachable), ~2.1
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
///   newly-allocated object at a reused address: the
///   lookup simply fails.
/// - The real address itself (see `track_by_address`), used for buffers C
///   dereferences directly (`to_c_string`, `to_c_bytes`), where the pointer
///   handed to C must be a genuine, readable address. These are always even.
///
/// Both kinds share one map and one `cimpl_free()` path since freeing only
/// needs the key, not which kind it is — the odd/even split guarantees they
/// can never collide with each other.
pub(crate) struct PointerRegistry {
    tracked: Mutex<HashMap<usize, Arc<EntryInner>>>,
    next_id: AtomicUsize,
    /// Marker so we know we ran out of ids.
    id_space_exhausted: AtomicBool,
    /// Process id for registry-creating process.
    owner_pid: u32,
}

impl PointerRegistry {
    fn new() -> Self {
        Self {
            tracked: Mutex::new(HashMap::new()),
            next_id: AtomicUsize::new(0),
            id_space_exhausted: AtomicBool::new(false),
            owner_pid: current_pid(),
        }
    }

    /// Track a pointer under a freshly generated opaque handle id, so the
    /// value handed to C is never the real address (and so can never alias a
    /// different object that later reuses that address).
    #[must_use = "None returned: caller still owns pointer and must free it"]
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
        if self.check_same_process().is_err() {
            CimplError::foreign_process().set_last();
            return None;
        }
        let counter = self.next_id.fetch_add(1, Ordering::Relaxed);
        // Make sure the counter can still hand out unique ids.
        if counter >= (usize::MAX >> 1) || self.id_space_exhausted.load(Ordering::Relaxed) {
            self.id_space_exhausted.store(true, Ordering::Relaxed);
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
                // so an occupied slot means that guarantee broke.
                previous.cancel_cleanup();
                eprintln!(
                    "c2pa: handle id 0x{id:x} was minted twice, leaking the displaced object"
                );
            }
            return Some(id);
        }
        // Poisoned lock = no record.
        discard_untracked_entry(entry);
        CimplError::tracking_refused("registry lock poisoned").set_last();
        None
    }

    /// Track a pointer by address.
    /// Only use this for buffers C dereferences directly (e.g. `to_c_string`/`to_c_bytes`),
    /// where the returned pointer must be a readable address.
    /// Returns false when the address could not be tracked, so the caller can free it.
    fn track_by_address(&self, real_addr: usize, type_id: TypeId, cleanup: CleanupFn) -> bool {
        if self.check_same_process().is_err() {
            CimplError::foreign_process().set_last();
            return false;
        }
        if real_addr != 0 {
            // Handles and addresses should not be able to alias each other.
            if !real_addr.is_multiple_of(2) {
                eprintln!("c2pa: odd address can not be tracked");
                CimplError::tracking_refused("buffer address could collide with a handle id")
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
                    // Something already freed the memory.
                    previous.cancel_cleanup();
                    eprintln!("c2pa: attempt to retrack an already tracked address");
                }
                return true;
            }
            // A poisoned lock means the entry was never recorded.
            discard_untracked_entry(entry);
            CimplError::tracking_refused("registry lock poisoned").set_last();
            return false;
        }
        // Nothing to track or free.
        true
    }

    /// Check if a new handle can be tracked by the registry.
    /// A handle could be not trackable if the id space is exhausted.
    fn ensure_trackable(&self) -> Result<(), Error> {
        self.check_same_process()?;
        if self.id_space_exhausted.load(Ordering::Relaxed)
            || self.next_id.load(Ordering::Relaxed) >= (usize::MAX >> 1)
        {
            return Err(Error::from(CimplError::tracking_refused(
                "id space of handles exhausted",
            )));
        }
        drop(
            self.tracked
                .lock()
                .map_err(|_| Error::from(CimplError::mutex_poisoned()))?,
        );
        Ok(())
    }

    /// Refuse a registry call made from a process that did not create the registry,
    /// which happens after `fork()` without an `exec()`.
    ///
    /// Call this before taking the `tracked` lock.
    fn check_same_process(&self) -> Result<(), Error> {
        if self.owner_pid != current_pid() {
            return Err(Error::from(CimplError::foreign_process()));
        }
        Ok(())
    }

    /// Lookup the registry entry (behind an `Arc`).
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

    /// Multiple calls may check out a shared borrow at once, as long as no
    /// exclusive borrow is pending.
    #[must_use = "the borrow ends when the returned guard is dropped"]
    fn checkout_shared(&self, id: usize, expected_type: TypeId) -> Result<SharedCheckout, Error> {
        let entry = self.lookup(id, expected_type)?;
        if entry.try_borrow_shared() {
            Ok(SharedCheckout { entry })
        } else {
            Err(Error::from(CimplError::pointer_in_use()))
        }
    }

    /// An exclusive handle id checkout is requested.
    /// Gives up acquiring it after a timeout if another one is pending.
    #[must_use = "the borrow ends when the returned guard is dropped"]
    fn checkout_exclusive(
        &self,
        id: usize,
        expected_type: TypeId,
    ) -> Result<ExclusiveCheckout, Error> {
        let entry = self.lookup(id, expected_type)?;
        // As checkout_shared: no registry lock held across the wait.
        if entry.try_borrow_exclusive() {
            Ok(ExclusiveCheckout { entry })
        } else {
            Err(Error::from(CimplError::pointer_in_use()))
        }
    }

    /// Remove a handle id from tracking without running its cleanup function,
    /// returning the real address it referred to.
    ///
    /// Use this whenever an FFI function consumes a tracked pointer via
    /// `Box::from_raw()`: the pointer must be untracked first,
    /// or the registry holds a stale entry that double-frees on
    /// `cimpl_free()` or reports a false leak at shutdown.
    ///
    /// # When to use
    ///
    /// Any time a `box_tracked!` pointer is consumed by Rust rather than freed by C:
    /// - `c2pa_context_builder_set_signer`: signer is moved into the builder
    /// - `c2pa_context_builder_build`: builder is consumed to produce a context
    /// - `c2pa_reader_with_stream`: reader is consumed to produce a new reader
    /// - `c2pa_builder_with_definition`: builder is consumed to produce a new builder
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

        let entry = {
            let tracked = self
                .tracked
                .lock()
                .map_err(|_| Error::from(CimplError::mutex_poisoned()))?;
            match tracked.get(&id) {
                Some(entry) if entry.type_id == expected_type => {
                    if required.is_some_and(|required| required != entry.wrapper) {
                        return Err(Error::from(CimplError::wrong_wrapper_kind()));
                    }
                    Arc::clone(entry)
                }
                Some(_) => return Err(Error::from(CimplError::wrong_pointer_type(id as u64))),
                None => return Err(Error::from(CimplError::untracked_pointer(id as u64))),
            }
        };

        // Release the lock so a borrow-handled holder can use it.
        if !entry.try_borrow_exclusive() {
            return Err(Error::from(CimplError::pointer_in_use()));
        }
        // Get the lock again, verify we can continue.
        let mut tracked = match self.tracked.lock() {
            Ok(tracked) => tracked,
            Err(_) => {
                entry.borrow_state.store(0, Ordering::Release);
                return Err(Error::from(CimplError::mutex_poisoned()));
            }
        };
        match tracked.get(&id) {
            Some(current) if Arc::ptr_eq(current, &entry) => {}
            _ => {
                drop(tracked);
                entry.borrow_state.store(0, Ordering::Release);
                return Err(Error::from(CimplError::untracked_pointer(id as u64)));
            }
        }
        let removed = tracked.remove(&id).expect("checked Some above");
        let real_addr = removed.real_addr;
        let wrapper = removed.wrapper;
        removed.cancel_cleanup();
        drop(tracked);
        drop(removed);
        drop(entry);
        Ok((real_addr, wrapper))
    }

    /// Take ownership of two handles atomically:
    /// either both are removed, or neither is
    /// and the registry is left exactly as it was.
    ///
    /// The two handles must differ. One object cannot be consumed twice, and
    /// rejecting it here means callers do not have to compare handles
    /// themselves.
    #[must_use = "dropping the returned addresses leaks both allocations"]
    fn untrack_pair(
        &self,
        first: usize,
        second: usize,
        expected_type: TypeId,
        required: Option<Wrapper>,
    ) -> Result<(TakenEntry, TakenEntry), Error> {
        self.check_same_process()?;
        if first == 0 || second == 0 {
            return Err(Error::from(CimplError::null_parameter("pointer")));
        }
        if first == second {
            // One object cannot be handed over twice. Refusing before the lock
            // keeps the borrow bookkeeping below single-entry.
            return Err(Error::from(CimplError::tracking_refused(
                "the same handle was passed for two parameters",
            )));
        }

        let (first_entry, second_entry) = {
            let tracked = self
                .tracked
                .lock()
                .map_err(|_| Error::from(CimplError::mutex_poisoned()))?;

            // The pair needs to be taken or rejected together, not only half.
            for id in [first, second] {
                match tracked.get(&id) {
                    Some(entry) if entry.type_id == expected_type => {
                        if required.is_some_and(|required| required != entry.wrapper) {
                            return Err(Error::from(CimplError::wrong_wrapper_kind()));
                        }
                    }
                    Some(_) => return Err(Error::from(CimplError::wrong_pointer_type(id as u64))),
                    None => return Err(Error::from(CimplError::untracked_pointer(id as u64))),
                }
            }
            (
                Arc::clone(tracked.get(&first).expect("validated above")),
                Arc::clone(tracked.get(&second).expect("validated above")),
            )
        };

        // Take them in canonical (lower id first) order, not the caller's: two
        // calls with the arguments reversed would otherwise each hold one
        // borrow and wait out the deadline on the other, failing both.
        let (lower_entry, higher_entry) = if first < second {
            (&first_entry, &second_entry)
        } else {
            (&second_entry, &first_entry)
        };
        if !lower_entry.try_borrow_exclusive() {
            return Err(Error::from(CimplError::pointer_in_use()));
        }
        if !higher_entry.try_borrow_exclusive() {
            lower_entry.borrow_state.store(0, Ordering::Release);
            return Err(Error::from(CimplError::pointer_in_use()));
        }

        // Get both again, verify they are still available.
        let mut tracked = match self.tracked.lock() {
            Ok(tracked) => tracked,
            Err(_) => {
                first_entry.borrow_state.store(0, Ordering::Release);
                second_entry.borrow_state.store(0, Ordering::Release);
                return Err(Error::from(CimplError::mutex_poisoned()));
            }
        };
        for (id, entry) in [(first, &first_entry), (second, &second_entry)] {
            match tracked.get(&id) {
                Some(current) if Arc::ptr_eq(current, entry) => {}
                _ => {
                    drop(tracked);
                    first_entry.borrow_state.store(0, Ordering::Release);
                    second_entry.borrow_state.store(0, Ordering::Release);
                    return Err(Error::from(CimplError::untracked_pointer(id as u64)));
                }
            }
        }
        let first_removed = tracked.remove(&first).expect("checked above");
        first_removed.cancel_cleanup();
        let second_removed = tracked.remove(&second).expect("checked above");
        second_removed.cancel_cleanup();
        let taken = (
            (first_removed.real_addr, first_removed.wrapper),
            (second_removed.real_addr, second_removed.wrapper),
        );

        drop(tracked); // Release before the Arcs drop.
        drop(first_removed);
        drop(second_removed);
        drop(first_entry);
        drop(second_entry);
        Ok(taken)
    }

    /// Free an entry, run cleanup.
    /// `c2pa_free` eventually lands here.
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
        drop(entry);
        Ok(())
    }

    /// Free the entry at `key`, but only if it is still the entry the
    /// caller last saw.
    ///
    /// # Arguments
    /// * `key` - Handle id or address to free. Address keys are where this
    ///   check matters: the allocator can hand the same address to an
    ///   unrelated later allocation.
    /// * `expected` - The entry the caller last saw at `key`.
    fn free_if_still_tracked_entry(
        &self,
        key: usize,
        expected: &Arc<EntryInner>,
    ) -> Result<(), Error> {
        self.check_same_process()?;
        if key == 0 {
            return Ok(());
        }

        let entry = {
            let mut tracked = self
                .tracked
                .lock()
                .map_err(|_| Error::from(CimplError::mutex_poisoned()))?;
            match tracked.get(&key) {
                Some(current) if Arc::ptr_eq(current, expected) => {
                    tracked.remove(&key).expect("checked Some above")
                }
                _ => return Ok(()),
            }
        };

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
        if self.owner_pid != current_pid() {
            return;
        }

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
        // Leak what C never freed, in case they touch statics.
        for (_, entry) in leaked {
            entry.cancel_cleanup();
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
/// Returns an opaque handle id disguised as `*mut T`, not the real pointer;
/// see `PointerRegistry::track_by_id`.
///
/// # Example
/// ```ignore
/// let ptr = track_box(Box::into_raw(Box::new(value)));
/// ```
pub fn track_box<T: 'static + MaybeSend>(ptr: *mut T) -> *mut T {
    let ptr_val = ptr.expose_provenance(); // Store as usize to make it Send
    let cleanup = move || unsafe {
        drop(Box::from_raw(std::ptr::with_exposed_provenance_mut::<T>(
            ptr_val,
        )));
    };
    match get_registry().track_by_id(
        ptr_val,
        TypeId::of::<T>(),
        Wrapper::Boxed,
        Box::new(cleanup),
    ) {
        Some(id) => id as *mut T,
        None if ptr.is_null() => std::ptr::null_mut(),
        None => {
            // Case of untracked allocations.
            unsafe {
                drop(Box::from_raw(std::ptr::with_exposed_provenance_mut::<T>(
                    ptr_val,
                )))
            };
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
/// Returns an opaque handle id disguised as `*mut T`, not the real pointer;
/// see `PointerRegistry::track_by_id`.
///
/// # Example
/// ```ignore
/// let ptr = track_arc(Arc::into_raw(Arc::new(value)));
/// ```
pub fn track_arc<T: 'static + MaybeSend>(ptr: *mut T) -> *mut T {
    let ptr_val = ptr.expose_provenance(); // Store as usize to make it Send
    let cleanup = move || unsafe {
        drop(Arc::from_raw(std::ptr::with_exposed_provenance::<T>(
            ptr_val,
        )));
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
            // Handle untracked case.
            unsafe {
                drop(Arc::from_raw(std::ptr::with_exposed_provenance::<T>(
                    ptr_val,
                )))
            };
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
/// pointer; see `PointerRegistry::track_by_id`.
///
/// # Example
/// ```ignore
/// let ptr = track_arc_mutex(Arc::into_raw(Arc::new(Mutex::new(value))));
/// ```
pub fn track_arc_mutex<T: 'static + MaybeSend>(ptr: *mut Mutex<T>) -> *mut Mutex<T> {
    let ptr_val = ptr.expose_provenance(); // Store as usize to make it Send
    let cleanup = move || unsafe {
        drop(Arc::from_raw(
            std::ptr::with_exposed_provenance::<Mutex<T>>(ptr_val),
        ));
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
            // Handle case of untracked addresses.
            unsafe {
                drop(Arc::from_raw(
                    std::ptr::with_exposed_provenance::<Mutex<T>>(ptr_val),
                ))
            };
            std::ptr::null_mut()
        }
    }
}

/// Borrow a tracked object for reading (keeps it alive for how long it is used).
///
/// Unlike a bare resolved pointer, the guard holds a borrow on the entry: a
/// concurrent `cimpl_free` from another thread removes the handle but cannot
/// free the object until every guard is dropped.
#[must_use = "the borrow ends when the returned guard is dropped"]
pub fn checkout_shared<T: 'static + MaybeSync>(ptr: *mut T) -> Result<TypedShared<T>, Error> {
    let inner = get_registry().checkout_shared(ptr as usize, TypeId::of::<T>())?;
    Ok(TypedShared {
        inner,
        _marker: PhantomData,
    })
}

/// Borrow a tracked object for writing exclusively.
#[must_use = "the borrow ends when the returned guard is dropped"]
pub fn checkout_exclusive<T: 'static + MaybeSend>(ptr: *mut T) -> Result<TypedExclusive<T>, Error> {
    let inner = get_registry().checkout_exclusive(ptr as usize, TypeId::of::<T>())?;
    Ok(TypedExclusive {
        inner,
        _marker: PhantomData,
    })
}

/// Take ownership of a pair of objects at once.
pub fn untrack_owned_pair<T: 'static>(first: *mut T, second: *mut T) -> Result<(T, T), Error> {
    let ((first_addr, _), (second_addr, _)) = get_registry().untrack_pair(
        first as usize,
        second as usize,
        TypeId::of::<T>(),
        Some(Wrapper::Boxed),
    )?;

    Ok((
        *unsafe { Box::from_raw(std::ptr::with_exposed_provenance_mut::<T>(first_addr)) },
        *unsafe { Box::from_raw(std::ptr::with_exposed_provenance_mut::<T>(second_addr)) },
    ))
}

/// Take ownership of the handle, remove it from registry, return the value.
pub fn untrack_owned<T: 'static>(ptr: *mut T) -> Result<T, Error> {
    let (real_addr, _) =
        get_registry().untrack(ptr as usize, TypeId::of::<T>(), Some(Wrapper::Boxed))?;
    // SAFETY: tracked by track_box, so this came from Box::into_raw with this exact T; untrack
    // confirmed the wrapper before removing it and defusing its cleanup: the sole owner.
    Ok(*unsafe { Box::from_raw(std::ptr::with_exposed_provenance_mut::<T>(real_addr)) })
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

/// Validates that a buffer size is within safe bounds and doesn't cause
/// integer overflow when combined with the buffer's address.
///
/// # Arguments
/// * `size` - Size to validate
/// * `ptr` - Pointer to validate against (for address space checks)
///
/// # Returns
/// * `true` if the size is safe to use
/// * `false` if the size is zero, exceeds `isize::MAX`, or would wrap
pub fn is_safe_buffer_size(size: usize, ptr: *const c_uchar) -> bool {
    if size == 0 || size > isize::MAX as usize {
        return false;
    }
    ptr.addr().checked_add(size).is_some()
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

/// C-visible buffers are aligned.
const C_BUFFER_ALIGN: usize = 2;

/// Type label for buffers from `to_c_string`.
struct CStringBuffer;

/// Type label for buffers from `to_c_bytes`.
struct ByteBuffer;

/// Registry type label for the string arrays built by `track_string_array`.
struct StringArray;

/// Check if tracking a new handle is possible.
pub(crate) fn ensure_trackable() -> Result<(), Error> {
    get_registry().ensure_trackable()
}

/// Track an array of C string pointers.
pub(crate) fn track_string_array(
    ptrs: Vec<*mut std::os::raw::c_char>,
) -> *const *const std::os::raw::c_char {
    if ptrs.is_empty() {
        return std::ptr::null();
    }
    let len = ptrs.len();
    let raw = Box::into_raw(ptrs.into_boxed_slice()) as *mut *mut std::os::raw::c_char;
    let addr = raw.expose_provenance();

    let rebuild = move || unsafe {
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            std::ptr::with_exposed_provenance_mut::<*mut std::os::raw::c_char>(addr),
            len,
        ))
    };

    let members: Vec<(usize, Weak<EntryInner>)> = {
        let strings = rebuild();
        let recorded = strings
            .iter()
            .map(|s| {
                let key = s.expose_provenance();
                let weak = get_registry()
                    .tracked
                    .lock()
                    .ok()
                    .and_then(|tracked| tracked.get(&key).map(Arc::downgrade))
                    .unwrap_or_default();
                (key, weak)
            })
            .collect();
        std::mem::forget(strings);
        recorded
    };

    fn free_members(members: &[(usize, Weak<EntryInner>)]) {
        for (key, weak) in members {
            if let Some(entry) = weak.upgrade() {
                let _ = get_registry().free_if_still_tracked_entry(*key, &entry);
            }
        }
    }

    let cleanup_members = members.clone();
    let cleanup = move || {
        let strings = rebuild();
        free_members(&cleanup_members);
        drop(strings);
        // Dropping the box deallocates the array itself.
    };

    if !get_registry().track_by_address(addr, TypeId::of::<StringArray>(), Box::new(cleanup)) {
        // The caller should see nothing to reclaim.
        free_members(&members);
        drop(unsafe {
            Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                std::ptr::with_exposed_provenance_mut::<*mut std::os::raw::c_char>(addr),
                len,
            ))
        });
        return std::ptr::null();
    }
    raw as *const *const std::os::raw::c_char
}

/// C-visible buffer with an alignment we control,
/// so addresses can not be odd anywhere (would collide with handle ids space).
fn alloc_even_buffer(bytes: &[u8], nul_terminated: bool) -> *mut u8 {
    let total = bytes.len() + usize::from(nul_terminated);
    if total == 0 {
        return std::ptr::null_mut();
    }
    let Ok(layout) = std::alloc::Layout::from_size_align(total, C_BUFFER_ALIGN) else {
        return std::ptr::null_mut();
    };
    let ptr = unsafe { std::alloc::alloc(layout) };
    if ptr.is_null() {
        return ptr;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
        if nul_terminated {
            ptr.add(bytes.len()).write(0);
        }
    }
    ptr
}

/// Free a buffer created by `alloc_even_buffer`, with its total size.
///
/// # Safety
/// `addr` must be the exposed address of a currently live `alloc_even_buffer`
/// allocation of exactly `total` bytes.
/// Should not be used after this call.
unsafe fn dealloc_even_buffer(addr: usize, total: usize) {
    let layout = std::alloc::Layout::from_size_align(total, C_BUFFER_ALIGN)
        .expect("the layout was valid when the buffer was allocated");
    std::alloc::dealloc(std::ptr::with_exposed_provenance_mut(addr), layout);
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
/// * `*mut c_char` - Pointer to the C string, or null on error (interior NUL
///   byte, allocation failure, or a tracking refusal)
///
/// # Safety
/// The returned pointer must be freed exactly once by C code
pub fn to_c_string(s: String) -> *mut std::os::raw::c_char {
    if s.as_bytes().contains(&0) {
        CimplError::other("NUL byte in string").set_last();
        return std::ptr::null_mut();
    }
    let total = s.len() + 1;
    let ptr = alloc_even_buffer(s.as_bytes(), true);
    if ptr.is_null() {
        CimplError::other("string buffer could not be allocated").set_last();
        return std::ptr::null_mut();
    }
    let ptr_val = ptr.expose_provenance();
    let tracked = get_registry().track_by_address(
        ptr_val,
        TypeId::of::<CStringBuffer>(),
        // SAFETY: ptr_val is this allocation's address.
        Box::new(move || unsafe { dealloc_even_buffer(ptr_val, total) }),
    );
    if !tracked {
        unsafe { dealloc_even_buffer(ptr_val, total) };
        return std::ptr::null_mut();
    }
    ptr as *mut std::os::raw::c_char
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

    let ptr = alloc_even_buffer(&bytes, false);
    if ptr.is_null() {
        CimplError::other("could not allocate the byte buffer").set_last();
        return std::ptr::null();
    }
    drop(bytes);
    let ptr_val = ptr.expose_provenance();
    let tracked = get_registry().track_by_address(
        ptr_val,
        TypeId::of::<ByteBuffer>(),
        // SAFETY: ptr_val is this allocation's exposed address and len its
        // exact size; the registry runs the closure at most once.
        Box::new(move || unsafe { dealloc_even_buffer(ptr_val, len) }),
    );
    if !tracked {
        // As to_c_string: an untracked buffer is unfreeable through cimpl_free, so free it here.
        // SAFETY: nothing else took ownership of this allocation.
        unsafe { dealloc_even_buffer(ptr_val, len) };
        return std::ptr::null();
    }
    ptr
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PointerRegistry inspection test helpers.
    impl PointerRegistry {
        /// Resolve a handle id for type `T`, returning the real pointer.
        fn resolve_typed<T: 'static>(&self, ptr: *mut T) -> Result<*mut T, Error> {
            Ok(std::ptr::with_exposed_provenance_mut(
                self.resolve(ptr as usize, TypeId::of::<T>())?,
            ))
        }

        /// Untrack a handle for type `T`, returning the real pointer.
        fn untrack_typed<T: 'static>(&self, ptr: *mut T) -> Result<*mut T, Error> {
            let (real_addr, _wrapper) = self.untrack(ptr as usize, TypeId::of::<T>(), None)?;
            Ok(std::ptr::with_exposed_provenance_mut(real_addr))
        }

        /// Resolve a handle id to its real address.
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
    }

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
    fn test_untrack_refuses_while_a_borrow_is_pending() {
        for _ in 0..10 {
            let ptr = track_box(Box::into_raw(Box::new(1234i32)));

            let guard = checkout_shared::<i32>(ptr).expect("fresh handle");
            assert!(untrack_owned::<i32>(ptr).is_err());
            drop(guard);

            assert_eq!(untrack_owned::<i32>(ptr).expect("borrow released"), 1234);
        }
    }

    #[test]
    fn test_untrack_takes_the_borrow_rather_than_observing_it() {
        let ptr = track_box(Box::into_raw(Box::new(1234i32)));
        let addr = ptr as usize;

        let entry = get_registry()
            .lookup(addr, TypeId::of::<i32>())
            .expect("fresh handle");

        assert_eq!(
            untrack_owned::<i32>(addr as *mut i32).expect("nothing borrowed yet"),
            1234
        );

        assert_eq!(entry.borrow_state.load(Ordering::Acquire), EXCLUSIVE);

        assert!(
            entry
                .borrow_state
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err(),
            "a shared borrow was still available after ownership moved out"
        );
    }

    #[test]
    fn test_untrack_releases_the_registry_entry() {
        let ptr = track_box(Box::into_raw(Box::new(77i32)));
        let weak = get_registry()
            .tracked
            .lock()
            .expect("registry lock")
            .get(&(ptr as usize))
            .map(Arc::downgrade)
            .expect("entry tracked");

        assert_eq!(untrack_owned::<i32>(ptr).expect("nothing borrowed yet"), 77);

        assert!(
            weak.upgrade().is_none(),
            "registry entry still here"
        );
    }

    #[test]
    fn test_untrack_leaves_a_rejected_entry_borrowable() {
        let arc = Arc::new(5i32);
        let ptr = track_arc(Arc::into_raw(arc) as *mut i32);

        assert!(
            untrack_owned::<i32>(ptr).is_err(),
            "Arc entry must be refused"
        );

        assert!(checkout_shared::<i32>(ptr).is_ok());
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
        // All or nothing, no half-states.
        assert!(get_registry().resolve_typed::<i32>(ptr).is_ok());

        drop(guard);
        assert_eq!(untrack_owned::<i32>(ptr).unwrap(), 42);
    }

    #[test]
    fn test_untrack_owned_rejects_arc_tracked_entry() {
        // An Arc entry may have other clones, so it cannot be treated as single-owned.
        let arc = Arc::new(5i32);
        let ptr = track_arc(Arc::into_raw(arc) as *mut i32);

        let err = untrack_owned::<i32>(ptr).unwrap_err();
        assert!(
            err.to_string().starts_with("WrongWrapperKind:"),
            "expected WrongWrapperKind, got {err}"
        );

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

        assert_eq!(cimpl_free(ptr as *mut std::ffi::c_void), 0);
        assert!(!DROPPED.load(Ordering::SeqCst), "freed while borrowed");

        drop(guard);
        assert!(
            DROPPED.load(Ordering::SeqCst),
            "not freed after last borrow"
        );
    }

    #[test]
    fn test_reentering_cleanup_does_not_deadlock() {
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
            "the borrow must be released on drop"
        );

        cimpl_free(ptr as *mut std::ffi::c_void);
    }

    #[test]
    fn test_nested_checkout_of_different_ids_succeed() {
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
    fn test_concurrent_shared_checkouts_succeed() {
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

        assert_eq!(failures.load(Ordering::Relaxed), 0);
        cimpl_free(ptr as *mut std::ffi::c_void);
    }

    #[test]
    fn test_guards_are_send() {
        // Guards do not change Send/Sync nature.
        fn assert_send<T: Send>() {}
        assert_send::<TypedShared<i32>>();
        assert_send::<TypedExclusive<i32>>();
    }

    #[test]
    fn test_guard_cleans_up_once() {
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
    fn test_panicking_cleanup_is_handled() {
        struct Panics;
        impl Drop for Panics {
            fn drop(&mut self) {
                panic!("cleanup panic");
            }
        }

        let ptr = track_box(Box::into_raw(Box::new(Panics)));
        assert_eq!(cimpl_free(ptr as *mut std::ffi::c_void), 0);

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
    fn test_untrack_pair_refuses_the_same_handle_twice() {
        let ptr = track_box(Box::into_raw(Box::new(11i32)));
        assert!(untrack_owned_pair::<i32>(ptr, ptr).is_err());
        assert_eq!(
            untrack_owned::<i32>(ptr).expect("still tracked after the refusal"),
            11
        );
    }

    #[test]
    fn test_untrack_pair_takes_all_or_nothing() {
        let first = track_box(Box::into_raw(Box::new(44i32)));
        let second = track_box(Box::into_raw(Box::new(55i32)));

        let (a, b) = untrack_owned_pair::<i32>(first, second).expect("both tracked");
        assert_eq!((a, b), (44, 55), "values came back in argument order");

        assert!(untrack_owned::<i32>(first).is_err());
        assert!(untrack_owned::<i32>(second).is_err());
    }

    #[test]
    fn test_c_buffers_have_even_addresses() {
        // Odd/even key split requires even buffer addresses to avoid confusion.
        for i in 0..8 {
            let s = to_c_string(format!("even {i}"));
            assert!(!s.is_null(), "tracking must not refuse the address");
            assert_eq!(s as usize % 2, 0, "string buffer address must be even");
            assert_eq!(cimpl_free(s as *mut std::ffi::c_void), 0);

            let b = to_c_bytes(vec![i as u8; 3]);
            assert!(!b.is_null(), "tracking must not refuse the address");
            assert_eq!(b as usize % 2, 0, "byte buffer address must be even");
            assert_eq!(cimpl_free(b as *mut std::ffi::c_void), 0);
        }
    }
}
