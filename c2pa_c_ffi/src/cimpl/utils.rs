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

use crate::{cimpl::cimpl_error::CimplError, error::Error, maybe_send_sync::MaybeSend};

// ============================================================================
// Pointer Registry - Tracks pointers with their cleanup functions
// ============================================================================

type CleanupFn = Box<dyn FnMut() + Send>;

/// Marks how a tracked allocation was created, so ownership can only ever be
/// reconstructed with the matching allocator.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Wrapper {
    Boxed,
    Arced,
}

/// One tracked entry, held behind an `Arc` for borrow semantics.
/// Arc will help us handle lifetimes of pointers.
struct EntryInner {
    real_addr: usize,
    type_id: TypeId,
    /// Read by `untrack_owned`,
    /// which must not hand an `Arc`-tracked entry to `Box::from_raw`,
    /// for correct reconstruction of handle type .
    #[allow(dead_code)] // Read from step 2 on.
    wrapper: Wrapper,
    /// Borrow claim: 0 is free, n is n shared readers, `EXCLUSIVE` is one
    /// writer. Gates aliasing and untrack, never cleanup timing, which belongs
    /// to the `Arc`. Do not infer it from `Arc::strong_count`: a transient
    /// clone inflates that count without any borrow existing.
    #[allow(dead_code)] // Read from step 2 on.
    claims: AtomicUsize,
    /// `Option` so `untrack` can take the closure out through a shared `Arc`,
    /// leaving nothing for `Drop` to run.
    cleanup: Mutex<Option<CleanupFn>>,
}

/// Sentinel `claims` value for a single exclusive borrow.
#[allow(dead_code)] // Read by the checkout paths added in step 2.
const EXCLUSIVE: usize = usize::MAX;

impl Drop for EntryInner {
    fn drop(&mut self) {
        // Never drop an Arc<EntryInner> while holding the registry lock.
        // Dropping the last one runs a cleanup closure, and a closure that
        // re-enters the registry then deadlocks against the non-reentrant
        // Mutex. Collect entries, release the lock, and let them drop after.
        if let Some(mut cleanup) = self.cleanup.get_mut().ok().and_then(|c| c.take()) {
            // A cleanup closure runs caller-supplied code. Unwinding out of
            // here would cross the extern "C" boundary, which is undefined
            // behavior, and a panic raised while another thread holds the
            // registry lock poisons it for the rest of the process. Leaking
            // the allocation is the bounded outcome.
            if std::panic::catch_unwind(AssertUnwindSafe(&mut cleanup)).is_err() {
                eprintln!("c2pa: panic while freeing a tracked pointer; leaking it");
            }
        }
    }
}

/// A live shared borrow of a tracked entry.
///
/// Holding one keeps the object alive even if C frees the handle from another
/// thread: the registry drops its `Arc`, but cleanup runs only when the last
/// one goes, which is this guard.
pub struct SharedCheckout {
    entry: Arc<EntryInner>,
}

impl Drop for SharedCheckout {
    fn drop(&mut self) {
        // Releasing the claim is separate from dropping the Arc. Without it a
        // handle stays borrowed forever and every later checkout fails.
        self.entry.claims.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A live exclusive borrow of a tracked entry. At most one can exist, which is
/// what makes handing out `&mut T` sound.
pub struct ExclusiveCheckout {
    entry: Arc<EntryInner>,
}

impl Drop for ExclusiveCheckout {
    fn drop(&mut self) {
        self.entry.claims.store(0, Ordering::Release);
    }
}

/// A shared borrow of a `T` behind a handle. Dereferences to `&T` only.
pub struct TypedShared<T> {
    inner: SharedCheckout,
    // Not PhantomData<*mut T>: that would make the guard !Send and break
    // multi-threaded callers for no benefit. fn() -> T is covariant in T and
    // carries no Send/Sync implications of its own.
    _marker: PhantomData<fn() -> T>,
}

/// An exclusive borrow of a `T` behind a handle. Dereferences to `&mut T`.
pub struct TypedExclusive<T> {
    inner: ExclusiveCheckout,
    _marker: PhantomData<fn() -> T>,
}

impl<T> Deref for TypedShared<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the entry was type-checked at checkout, and the shared claim
        // held by this guard prevents any exclusive borrow from coexisting.
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
        // SAFETY: the exclusive claim guarantees no other borrow of this entry
        // exists, so this is the only reference to the object.
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
///   billion on 32-bit (wasm32 included). `track_by_id` asserts against that
///   bound on 32-bit.
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
/// needs the key, not which kind it is — the odd/even split guarantees they
/// can never collide with each other.
/// Addresses are stored as `usize` and cast back on resolve, which loses
/// pointer provenance. That is undefined behavior under strict provenance and
/// is diagnosable by Miri even where it works in practice. Storing `*mut ()`
/// would fix it but changes the map's `Send`/`Sync` story, so it is recorded
/// here rather than changed.
pub struct PointerRegistry {
    tracked: Mutex<HashMap<usize, Arc<EntryInner>>>,
    next_id: AtomicUsize,
}

impl PointerRegistry {
    fn new() -> Self {
        Self {
            tracked: Mutex::new(HashMap::new()),
            next_id: AtomicUsize::new(0),
        }
    }

    /// Track a pointer under a freshly generated opaque handle id, so the
    /// value handed to C is never the real address (and so can never alias a
    /// different object that later reuses that address). Returns the id, or 0
    /// if `real_addr` is null.
    fn track_by_id(
        &self,
        real_addr: usize,
        type_id: TypeId,
        wrapper: Wrapper,
        cleanup: CleanupFn,
    ) -> usize {
        if real_addr == 0 {
            return 0;
        }
        let counter = self.next_id.fetch_add(1, Ordering::Relaxed);
        #[cfg(target_pointer_width = "32")]
        assert!(counter < (usize::MAX >> 1), "PointerRegistry id space exhausted");
        let id = scramble_to_odd_id(counter);
        let entry = Arc::new(EntryInner {
            real_addr,
            type_id,
            wrapper,
            claims: AtomicUsize::new(0),
            cleanup: Mutex::new(Some(cleanup)),
        });
        if let Ok(mut tracked) = self.tracked.lock() {
            // Ids come from a counter that never repeats within its period, so
            // an occupied slot means that guarantee broke. Dropping the
            // returned entry would run its cleanup under the lock and leave the
            // next free aimed at the wrong object.
            let previous = tracked.insert(id, entry);
            assert!(
                previous.is_none(),
                "PointerRegistry minted a duplicate handle id"
            );
        }
        // Silently ignore poisoned mutex - this is a best-effort tracking system
        id
    }

    /// Track a pointer keyed by its own address. Only use this for buffers C
    /// dereferences directly (e.g. `to_c_string`/`to_c_bytes`), where the
    /// returned pointer must remain a real, readable address.
    fn track_by_address(&self, real_addr: usize, type_id: TypeId, cleanup: CleanupFn) {
        if real_addr != 0 {
            // The odd/even split between the two key kinds is what guarantees an
            // address key can never alias a handle id. Rust aligns real
            // allocations, so this holds for every type tracked here, but a
            // zero-sized type allocates at 0x1 and a custom global allocator
            // need not align at all. Fail loudly rather than alias silently.
            assert!(
                real_addr.is_multiple_of(2),
                "tracked buffer address must be even; odd addresses collide with handle ids"
            );
            let entry = Arc::new(EntryInner {
                real_addr,
                type_id,
                wrapper: Wrapper::Boxed,
                claims: AtomicUsize::new(0),
                cleanup: Mutex::new(Some(cleanup)),
            });
            if let Ok(mut tracked) = self.tracked.lock() {
                if let Some(previous) = tracked.insert(real_addr, entry) {
                    // The allocator returned an address that is still tracked,
                    // so something freed the memory without untracking it. The
                    // stale cleanup closure now points at an allocation it no
                    // longer owns, so defuse it and report rather than let it
                    // free memory the new entry owns.
                    if let Ok(mut cleanup) = previous.cleanup.lock() {
                        cleanup.take();
                    }
                    eprintln!(
                        "c2pa: address 0x{real_addr:x} was re-tracked while still tracked; \
                         the earlier entry was freed without being untracked"
                    );
                }
            }
            // Silently ignore poisoned mutex - this is a best-effort tracking system
        }
    }

    /// Resolve a handle id to its real address, validating it is tracked
    /// with the expected type.
    #[must_use = "the id passed in is not a usable pointer, only the returned address is"]
    pub fn resolve(&self, id: usize, expected_type: TypeId) -> Result<usize, Error> {
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

    /// Look up an entry and clone its `Arc`, checking the expected type.
    /// Shared by both checkout paths so the lock is taken once.
    fn lookup(&self, id: usize, expected_type: TypeId) -> Result<Arc<EntryInner>, Error> {
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
        let mut current = entry.claims.load(Ordering::Acquire);
        loop {
            if current == EXCLUSIVE {
                return Err(Error::from(CimplError::pointer_in_use()));
            }
            match entry.claims.compare_exchange_weak(
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
        match entry.claims.compare_exchange(
            0,
            EXCLUSIVE,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
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
    #[must_use = "dropping the returned address leaks the allocation"]
    pub fn untrack(&self, id: usize, expected_type: TypeId) -> Result<usize, Error> {
        if id == 0 {
            return Err(Error::from(CimplError::null_parameter("pointer")));
        }

        let mut tracked = self
            .tracked
            .lock()
            .map_err(|_| Error::from(CimplError::mutex_poisoned()))?;

        match tracked.get(&id) {
            Some(entry) if entry.type_id == expected_type => {
                let entry = tracked.remove(&id).expect("checked Some above");
                let real_addr = entry.real_addr;
                // Take the cleanup closure out before the entry can drop.
                // Ownership is moving to the caller, so running it here would
                // free memory the caller is about to reconstruct.
                if let Ok(mut cleanup) = entry.cleanup.lock() {
                    cleanup.take();
                }
                drop(tracked); // Release before the Arc drops.
                drop(entry);
                Ok(real_addr)
            }
            Some(_) => Err(Error::from(CimplError::wrong_pointer_type(id as u64))),
            None => Err(Error::from(CimplError::untracked_pointer(id as u64))),
        }
    }

    /// Free a tracked entry by calling its cleanup function
    pub fn free(&self, key: usize) -> Result<(), Error> {
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
    let id = get_registry().track_by_id(
        ptr_val,
        TypeId::of::<T>(),
        Wrapper::Boxed,
        Box::new(cleanup),
    );
    id as *mut T
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
    let id = get_registry().track_by_id(
        ptr_val,
        TypeId::of::<T>(),
        Wrapper::Arced,
        Box::new(cleanup),
    );
    id as *mut T
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
    let id = get_registry().track_by_id(
        ptr_val,
        TypeId::of::<Mutex<T>>(),
        Wrapper::Arced,
        Box::new(cleanup),
    );
    id as *mut Mutex<T>
}

/// Validate that a pointer is tracked and has the expected type, returning
/// the real pointer to dereference (the value passed in is an opaque handle
/// id, not the real address — see `PointerRegistry::track_by_id`).
#[must_use = "the handle passed in is not a usable pointer, only the returned one is"]
pub fn validate_pointer<T: 'static>(ptr: *mut T) -> Result<*mut T, Error> {
    let real_addr = get_registry().resolve(ptr as usize, TypeId::of::<T>())?;
    Ok(real_addr as *mut T)
}

/// Borrow a tracked object for reading, keeping it alive for as long as the
/// returned guard lives.
///
/// Unlike `validate_pointer`, which returns a bare pointer whose validity ends
/// with the call, the guard holds a claim on the entry: a concurrent
/// `cimpl_free` from another thread removes the handle but cannot free the
/// object until every guard is dropped.
///
/// Fails with `pointer_in_use` if the object is exclusively borrowed.
#[must_use = "the borrow ends when the returned guard is dropped"]
pub fn checkout_shared<T: 'static>(ptr: *mut T) -> Result<TypedShared<T>, Error> {
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
#[must_use = "the borrow ends when the returned guard is dropped"]
pub fn checkout_exclusive<T: 'static>(ptr: *mut T) -> Result<TypedExclusive<T>, Error> {
    let inner = get_registry().checkout_exclusive(ptr as usize, TypeId::of::<T>())?;
    Ok(TypedExclusive {
        inner,
        _marker: PhantomData,
    })
}

/// Remove a pointer from tracking without running its cleanup function.
///
/// Use this in FFI functions that consume a tracked pointer (take ownership
/// back from C into Rust). Untracking must happen *before* `Box::from_raw()`
/// so the registry doesn't hold a stale entry that would cause a double-free
/// on `cimpl_free()` or a false leak warning at shutdown.
///
/// After this call, the pointer is no longer managed by the registry. The
/// caller owns the underlying allocation and must drop it — typically by
/// calling `Box::from_raw()` on the *returned* real pointer immediately after
/// untracking (the value passed in is an opaque handle id, not the real
/// address). The `untrack_or_return_*!` macros do this for you, yielding the
/// owned value directly.
///
/// # Example
///
/// ```rust,ignore
/// // FFI function that consumes a signer to configure a builder:
/// let signer = untrack_or_return_int!(signer_ptr, C2paSigner); // sole owner now
/// builder.set_signer(signer.signer);                           // inner value moved into builder
/// // C2paSigner wrapper dropped here — no double-free risk
/// ```
#[must_use = "dropping the returned pointer leaks the allocation"]
pub fn untrack_pointer<T: 'static>(ptr: *mut T) -> Result<*mut T, Error> {
    let real_addr = get_registry().untrack(ptr as usize, TypeId::of::<T>())?;
    Ok(real_addr as *mut T)
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
            get_registry().track_by_address(
                ptr_val,
                TypeId::of::<CString>(),
                Box::new(move || unsafe {
                    drop(CString::from_raw(ptr_val as *mut std::os::raw::c_char))
                }),
            );
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
    get_registry().track_by_address(
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
    fn test_untrack_pointer_removes_from_registry() {
        let ptr = track_box(Box::into_raw(Box::new(42i32)));
        assert!(validate_pointer::<i32>(ptr).is_ok());

        let real_ptr = untrack_pointer::<i32>(ptr).unwrap();

        // No longer tracked - cimpl_free should fail
        let result = cimpl_free(ptr as *mut std::ffi::c_void);
        assert_eq!(result, -1);

        // Clean up manually since we took ownership (via the real pointer
        // untrack_pointer returned, not the opaque handle id)
        unsafe { drop(Box::from_raw(real_ptr)) };
    }

    #[test]
    fn test_untrack_wrong_type_fails() {
        let ptr = track_box(Box::into_raw(Box::new(42i32)));

        let result = untrack_pointer::<u64>(ptr as *mut u64);
        assert!(result.is_err());

        // Original pointer still tracked
        assert!(validate_pointer::<i32>(ptr).is_ok());
        cimpl_free(ptr as *mut std::ffi::c_void);
    }

    #[test]
    fn test_untrack_null_pointer_fails() {
        let result = untrack_pointer::<i32>(std::ptr::null_mut());
        assert!(result.is_err());
    }

    #[test]
    fn test_untrack_unregistered_pointer_fails() {
        let ptr = Box::into_raw(Box::new(42i32));
        let result = untrack_pointer::<i32>(ptr);
        assert!(result.is_err());
        unsafe { drop(Box::from_raw(ptr)) };
    }

    #[test]
    fn test_untrack_already_untracked_fails() {
        let ptr = track_box(Box::into_raw(Box::new(42i32)));
        let real_ptr = untrack_pointer::<i32>(ptr).unwrap();

        // Second untrack fails
        let result = untrack_pointer::<i32>(ptr);
        assert!(result.is_err());

        unsafe { drop(Box::from_raw(real_ptr)) };
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
        assert!(DROPPED.load(Ordering::SeqCst), "not freed after last borrow");
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
        assert!(validate_pointer::<i32>(inner).is_err());
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
        // A guard that is !Send would break work-stealing runtimes. This fails
        // to compile rather than at runtime if PhantomData<*mut T> creeps back.
        fn assert_send<T: Send>() {}
        assert_send::<TypedShared<i32>>();
        assert_send::<TypedExclusive<i32>>();
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
        // Without catch_unwind in EntryInner::drop this aborts the process,
        // because a panic escaping a Drop during unwinding cannot unwind again.
        assert_eq!(cimpl_free(ptr as *mut std::ffi::c_void), 0);

        // The registry lock survived, so later calls still work.
        let after = track_box(Box::into_raw(Box::new(5i32)));
        assert!(validate_pointer::<i32>(after).is_ok());
        cimpl_free(after as *mut std::ffi::c_void);
    }

    #[test]
    fn test_stale_handle_does_not_alias_new_allocation() {
        let ptr1 = track_box(Box::into_raw(Box::new(1i32)));
        assert!(validate_pointer::<i32>(ptr1).is_ok());
        assert_eq!(cimpl_free(ptr1 as *mut std::ffi::c_void), 0);

        let ptr2 = track_box(Box::into_raw(Box::new(2i32)));

        assert_ne!(ptr1, ptr2);
        assert!(validate_pointer::<i32>(ptr1).is_err());
        assert!(validate_pointer::<i32>(ptr2).is_ok());

        cimpl_free(ptr2 as *mut std::ffi::c_void);
    }
}
