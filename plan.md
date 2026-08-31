# Fixing the findings in `c_ffi_opaque_ids-2-review.md`

## Context

An adversarial review of this branch (11 commits on top of PR #2559) reports two HIGH
soundness bugs, seven MEDIUMs, and a set of LOW/nit items. The review was static only —
it states plainly that nothing was compiled or run.

I verified every finding against the source, and reproduced the ones that are claims about
runtime behavior. **All confirmed.** Two are defects I introduced in this session that
break the central guarantee the branch exists to provide:

- **H-1**: `untrack` observes `borrow_state` under the map lock, but `checkout_*` acquires
  the claim *after* `lookup` releases it. *Reproduced*: a standalone model of the three
  functions had both a live shared guard and an ownership transfer succeed for the same
  object in **199 of 200 runs**. The guard then points at memory `untrack_owned` has moved
  out of and dropped — the exact use-after-free the design exists to prevent.
- **H-2**: `PhantomData<fn() -> T>` is `Send + Sync` for every `T`, and `checkout_shared`
  has no `Sync` bound. *Reproduced*: a program with **no `unsafe` in it** compiled and ran
  two `&Cell<i32>` on two threads through the public API.

M-4 is the reviewer correcting me: my comment claimed a child freeing an inherited
allocation would "free an allocation the parent still owns". *Measured*: after a child
freed the allocation and churned its heap, the parent's copy was intact. `fork()` gives a
private copy-on-write address space, so the stated rationale is false.

Goal: fix both HIGHs, undo the concurrency regression (M-2), correct the wrong rationale,
and clear the CI blockers — without expanding scope further.

---

## Step 1 — H-1: make `untrack` claim the borrow, not observe it

`c2pa_c_ffi/src/cimpl/utils.rs`, in `untrack`.

Replace the `borrow_state.load(...) != 0` check with a CAS that *takes* the exclusive
claim, and remove from the map only if it succeeds:

```rust
// Take the claim rather than observe it. A concurrent checkout either wins
// this CAS (and we return PointerInUse) or sees EXCLUSIVE and refuses. Merely
// reading the counter leaves a window: lookup() releases the map lock before
// checkout_* acquires its claim, so a checkout in that window would hand out a
// guard to memory this call is about to move out of.
if entry
    .borrow_state
    .compare_exchange(0, EXCLUSIVE, Ordering::AcqRel, Ordering::Acquire)
    .is_err()
{
    return Err(Error::from(CimplError::pointer_in_use()));
}
```

The claim is never released, which is correct: the entry is being removed and the object
handed to the caller, so nothing may borrow it again. On the `wrong_wrapper_kind` early
return the claim **must** be released (`store(0, Release)`) before returning, or a rejected
`Arc` entry becomes permanently unborrowable.

**Test** (`utils.rs` test module): N threads racing `checkout_shared` against `untrack_owned`
on one handle; assert that for every iteration **exactly one** of the two succeeds, never
both. This must fail against the current `load`-based code — verify by reverting the CAS.

---

## Step 2 — H-2: stop the guards laundering `Send`/`Sync`

Same file. The guards must not be more thread-safe than the `T` they hand out.

```rust
pub struct TypedShared<T> {
    inner: SharedCheckout,
    // Not PhantomData<fn() -> T>: that is Send + Sync for every T, so the guard
    // would let a !Sync object be shared across threads. *const T makes the
    // guard inherit T's own auto traits, and the impls below re-add exactly
    // what is sound.
    _marker: PhantomData<*const T>,
}

// A shared guard hands out &T, and &T crosses threads only when T: Sync.
unsafe impl<T: Sync> Send for TypedShared<T> {}
unsafe impl<T: Sync> Sync for TypedShared<T> {}

// An exclusive guard hands out &mut T, which is Send when T: Send.
unsafe impl<T: Send> Send for TypedExclusive<T> {}
unsafe impl<T: Sync> Sync for TypedExclusive<T> {}
```

Then narrow `test_guards_are_send` to concrete `Sync` types (`i32`, `C2paBuilder`) rather
than asserting the blanket property, which is the thing being removed.

Note on wasm32: `MaybeSend`/`MaybeSync` are no-op impls there, so nothing constrains this.
Fine while wasm is single-threaded; say so in a comment rather than leaving it silent.

**Test:** a `trybuild` compile-fail case, or at minimum the narrowed `assert_send`. The
`Cell<i32>` program in Context must stop compiling.

---

## Step 3 — M-2: revert the nine over-exclusive borrows

`c2pa_c_ffi/src/c_api.rs` lines 1418, 1891, 1971, 2010, 2154, 2197, 2224, 2314, 2769.

Each binds without `mut`, which is the compiler's own signal that only `&T` is reached.
Change `deref_mut_or_return_int!` to `deref_or_return_int!` at each.

The signer sites matter most: `c2pa_builder_sign` calls `signer.as_ref()` and
`c2pa_signer_reserve_size` calls `signer.reserve_size()`, both `&self`. Taking the
exclusive claim makes two threads signing with one signer handle fail with `PointerInUse`
— a pattern that works today. This is a regression this branch introduced, not a
pre-existing bug.

**Test:** two threads calling `c2pa_signer_reserve_size` on one handle concurrently, both
succeeding.

---

## Step 4 — M-1: delete `extract_context`

`c2pa_c_ffi/src/c2pa_stream.rs:115-120`. It calls `untrack_owned::<StreamContext>`, but no
site tracks a context under that `TypeId` — the three construction sites use
`TestC2paStream` or `()`. Every path returns `Err`, so `.expect()` panics. It is `pub` with
zero callers, and even a matching type would hand back a ZST while leaking the real
allocation.

Delete it. If a test helper is wanted later, it belongs behind `#[cfg(test)]` with the
concrete type.

---

## Step 5 — M-4 and M-3: correct the fork rationale, close the track paths

**M-4, the wrong comment.** Rewrite the `EntryInner::drop` justification to state what is
actually true: a child gets a private copy-on-write address space, so freeing there cannot
touch the parent's heap. The check is worth keeping only for a cleanup closure that
releases a genuinely process-shared resource (a file, an `flock`, shared memory) — no
closure in this crate does today, so say that it is future-proofing rather than implying a
live hazard. Do not claim double-free of parent memory.

Keep the check. Cost is not the reason to drop it: *measured* `getpid()` at **1.90 ns/call**
on this machine, so the review's "real syscall per FFI call" does not hold here, though it
may on glibc ≥ 2.25.

**M-3, the gap.** `track_by_id` and `track_by_address` take the lock with no
`check_same_process()`, so `c2pa_reader_new()` or `c2pa_error()` in a forked child can
deadlock on an inherited mutex — the very hazard the guard exists for. Add the check to
both. Then make `CimplError::foreign_process`'s message match the behavior: creation is
refused too, not only use.

**LOW, same area — the fork tests can hang CI.** `test_forked_child_dropping_inherited_entry_does_not_free`
takes `get_registry().tracked.lock()` *in the child*. If another test thread holds it at
fork time the child blocks forever and `waitpid` never returns. Move both fork tests into a
dedicated `tests/fork.rs` with `harness = false`, or serialize them; they also call
non-async-signal-safe code (allocation, `eprintln!`) after fork.

---

## Step 6 — M-5: don't drop an entry while holding the lock

`utils.rs`, `track_by_id`. The comment names the hazard and the code then does it: when the
assert fires, `previous` unwinds *before* the lock guard, so cleanup runs under the lock and
a re-entrant closure deadlocks mid-panic.

Match the sibling in `track_by_address`, which already gets this right — defuse the stale
cleanup and `eprintln!` rather than assert. That also removes a process abort from a path
reachable through `extern "C"`.

Same block: a **poisoned lock** silently skips the insert and still returns the id to C, so
the caller holds a handle the registry never recorded. Read paths propagate
`mutex_poisoned()`; write paths swallow it. Make the write paths propagate too.

---

## Step 7 — docs, CI, and dead surface

- **`cargo +nightly fmt --all -- --check` currently fails** (*verified*), which fails
  `tier-1a.yml`. Run `cargo +nightly fmt --all`.
- **Stale macro names in `macros.rs` module docs** — 11 references to `checkout_or_return_*!`
  / `checkout_mut_or_return_*!`, which no longer exist after the names were reclaimed. This
  is the crate's only guidance on which macro to use, so it must name the real ones.
- **`///` and `//` interleaved** in the `borrow_state` doc (`utils.rs:76, 81, 83`) — the
  three `//` lines are exactly the ones explaining the values, and they vanish from rustdoc.
- **M-7, the overclaiming doc**: `to_c_string`/`to_c_bytes` hand C the real address, so
  buffer pointers remain ABA-prone. The registry doc block claims the odd/even split
  prevents aliasing, which holds only for the id half. State the limit plainly.
- **`assert!` severity in `track_by_address`**: a release `assert!` on an odd address aborts
  the host from `extern "C"`, while the sibling failure only warns. Pick one; downgrading to
  a warning matches the neighbour.
- **`validate_pointer` / `untrack_pointer`**: zero non-test callers, both bypass the borrow
  model. Make them `pub(crate)` or delete them.
- **`Wrapper::Arced` is unreachable** in production (zero `track_arc`/`arc_tracked!`
  callers). Keep as future-proofing, but say so, since it currently reads as guarding a live
  hazard.
- **`Debug for EntryInner` prints the real address**, undoing opacity for anything that logs
  an entry. Print the handle id, or gate the address behind `#[cfg(debug_assertions)]`.
- **`.gitignore`**: drop the three committed scratch entries
  (`pointer-registry-pitfalls.md`, `registry.md`, `current-plan.md`) and restore the
  trailing newline. Use `.git/info/exclude` instead.
- **`test_panicking_cleanup_is_contained`'s comment** misstates the mechanism: the abort
  comes from a panic crossing `extern "C"`, not from a panic escaping a `Drop` during
  unwinding.

---

## Step 8 — M-6 (partial): `#[non_exhaustive]` on `C2paError`

`c2pa_c_ffi/src/error.rs`. The enum is `pub` and gains `PointerInUse`, `WrongWrapperKind`
and `ForeignProcess` on this branch, so any downstream `match` breaks. Adding
`#[non_exhaustive]` forces downstream matches to carry a wildcard arm, which makes this and
every future variant additive.

That is itself a one-time break for any existing exhaustive `match` — unavoidable, and
better paid once now than on every future variant.

*Verified*: `#[non_exhaustive]` does not apply inside the defining crate, so `code()`
(`error.rs:70`) and the other in-crate matches stay exhaustive and compile unchanged. The
cost falls only on downstream crates.

**Who this actually protects.** Only downstream *Rust* crates that `match` on `C2paError`.
The C bindings never see the enum: `c2pa_error()` returns a string (`c_api.rs:489-491`) and
the numeric code is not exported to C at all. So this does nothing for c2pa-python or
c2pa-cpp.

**What those bindings do see** is the behavior change, and they degrade gracefully rather
than break. c2pa-python parses the `"ErrorType: message"` prefix through an if/elif chain
(`c2pa.py:1781`) ending in a catch-all `raise C2paError(error_str)`, so a new
`"PointerInUse: ..."` string surfaces as the base exception instead of a typed one. Worth
a follow-up in that repo to add the typed arm; not a break here.

**Not doing the other half:** no CHANGELOG entry, per your standing instruction. The
behavior change — calls that previously succeeded now returning `PointerInUse` — therefore
has no written record.

---

## Deliberately not doing

- **Splitting the branch.** The review recommends landing #2559 alone and splitting this
  into three PRs. That is your call, not a code fix.
- **Squashing the 11 WIP commits.** Yours to do at merge.

---

## Verification

After each step: `cargo test -p c2pa-c-ffi --lib` and
`cargo clippy -p c2pa-c-ffi --all-targets`, both clean.

For H-1 and H-2 specifically, the fix is not proven by a passing test — it is proven by the
reproductions in Context failing to compile or race afterwards:

- H-1: the 199/200 race model must drop to 0/200, and the new hammer test must fail if the
  CAS is reverted to a `load`.
- H-2: the `Cell<i32>` program must stop compiling.

Finally `cargo +nightly fmt --all -- --check` must pass, since it currently does not.
