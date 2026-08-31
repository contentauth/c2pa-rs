# Re-review — `mathern/c_ffi_opaque_ids-2` (round 3)

**Reviewed:** `3fe201c3..f45e1fba` (3 new commits: `CHild can still deadlock on fork`,
`CLean up unused types`, `Clean up debug notes`), +480/−241 across 10 files, plus a new
`c2pa_c_ffi/tests/fork.rs` (154 lines).

Focus as requested: **deadlocks, livelocks, memory leaks.** Static review again — still no
Rust toolchain here, so nothing was compiled or run.

---

## Verdict

Both HIGHs from round 2 are properly fixed, and most of the MEDIUMs are. The fix for one
of them, though, **introduced a double free and a memory leak**, and the new
`tests/fork.rs` **will not compile on Windows**, which is a Tier-1 target that runs
`cargo test` at workspace root.

Net: closer, but not mergeable. Three blockers below (N-1, N-2, N-3), all in code added by
these three commits.

---

## Round-2 items: verified fixed

| # | Item | Status |
|---|---|---|
| H-1 | `untrack` races `checkout_*` | **Fixed correctly.** `utils.rs:641-647` now CASes `0 → EXCLUSIVE` instead of `load`ing. Both interleavings check out: if the checkout's CAS lands first, untrack's CAS fails → `PointerInUse`; if untrack's lands first, the checkout sees `EXCLUSIVE` and refuses. The rejection path at `:652-655` correctly hands the claim back with `store(0)`, and `test_untrack_claim_is_released_when_the_wrapper_is_wrong` covers exactly the leak that omission would have caused. Good. |
| H-2 | Guards unconditionally `Send + Sync` | **Fixed, half of it.** `PhantomData<*const T>` plus `unsafe impl<T: Sync> Send/Sync for TypedShared<T>` and `unsafe impl<T: Send> Send` / `<T: Sync> Sync for TypedExclusive<T>` is exactly right — those four bounds match `&T`/`&mut T`. See N-4 for the half that's still open. |
| M-1 | `extract_context` always panics | **Fixed** by deleting it (`c2pa_stream.rs`). Nothing called it. |
| M-2 | 9 sites exclusive where shared suffices | **Fixed**, all nine, and `test_signer_reserve_size_is_concurrent_across_threads` is a good regression test. `grep 'let [a-z_]* = deref_mut_or_return'` now returns nothing. |
| M-3 | Fork guard skips `track_*` | **Fixed** — `check_same_process` added at `utils.rs:393` and `:447`, before the lock in both. But see N-1. |
| M-4 | Wrong COW rationale in `EntryInner::drop` | **Fixed** — the comment at `:183-198` now says memory is *not* the reason and names the real one (a shared external resource). Honest. But the check is now entirely untested (N-6). |
| M-5 | Duplicate-id `assert!` drops under the lock | **Fixed** — `:415-429` defuses and leaks instead of panicking, and no longer aborts across `extern "C"`. |
| M-6 | CHANGELOG + `non_exhaustive` | **Half.** `#[non_exhaustive]` added (`error.rs:20`) and used correctly — it restricts matching, not construction. **`c2pa_c_ffi/CHANGELOG.md`'s `## [Unreleased]` is still empty**, and this update *adds* breaking changes: `#[non_exhaustive]` itself breaks downstream exhaustive matches, and `validate_pointer`/`untrack_pointer` are now removed from the public API entirely. |
| M-7 | Buffer ABA overclaimed | **Fixed** — `:350-357` now says plainly that the protection covers the handle-id half only. |
| LOW | `validate_pointer`/`untrack_pointer` public | **Fixed** — `pub(crate)`, dropped from `cimpl/mod.rs`, with a comment saying why. |
| LOW | `assert!` in `track_by_address` aborts | **Fixed** — refuses and returns `false` (`:457-462`). |
| LOW | `Wrapper::Arced` dead | **Fixed** — documented as deliberate future-proofing at `:44-48`. |
| LOW | Stale `checkout_*_or_return!` macro names | **Fixed** — all 10 occurrences in `macros.rs`. |
| LOW | `Debug` prints the real address | **Fixed** — `<hidden>` outside `debug_assertions` (`:132-144`). Untested though; the test that covered `Debug` was deleted (N-7). |
| NIT | fmt violations | Appear resolved: no runs of >1 blank line anywhere in the changed files, and the mangled comment blocks in the `c_api.rs` tests are gone. The remaining >100-char lines are pre-existing doc comments, which rustfmt leaves alone (`wrap_comments` is off). Couldn't run `cargo +nightly fmt --check`. |
| NIT | `.gitignore` scratch files | **Fixed** — reverted. |
| NIT | `///`/`//` mixing, typos | Mostly fixed. `"The\n// The stale cleanup closure"` at `utils.rs:474-475` is still doubled. |
| NIT | `test_panicking_cleanup` comment | **Fixed** — now correctly attributes the abort to the `extern "C"` boundary. |
| NIT | 11 WIP commits | Now 14. |

---

## New blockers

### N-1. Memory leak: `track_box` / `track_arc` / `track_arc_mutex` leak the object when `track_by_id` refuses
`utils.rs:774-786`, `:801-813`, `:828-840` vs `:385-404`

`track_by_id` gained three early returns that fire **before** the `EntryInner` is
constructed:

```rust
if real_addr == 0 { return 0; }
if self.check_same_process().is_err() { return 0; }     // ← fork refusal
let counter = self.next_id.fetch_add(1, Ordering::Relaxed);
#[cfg(target_pointer_width = "32")]
if counter >= (usize::MAX >> 1) { eprintln!(...); return 0; }   // ← id exhaustion
```

On both, the `cleanup: CleanupFn` parameter is dropped without ever running (it captures
only a `usize`, so dropping the box does nothing). The callers then do:

```rust
pub fn track_box<T: 'static + MaybeSend>(ptr: *mut T) -> *mut T {
    ...
    let id = get_registry().track_by_id(ptr_val, ..., Box::new(cleanup));
    id as *mut T          // id == 0 → NULL, and nobody owns *ptr any more
}
```

`box_tracked!` already did `Box::into_raw(Box::new(obj))` before this, so the allocation is
now unowned and unreachable. **Every `box_tracked!` in a forked child leaks.**

This is exactly the bug the same commit fixed for the other half — `to_c_string`
(`:1106-1125`) and `to_c_bytes` (`:1148-1175`) now reconstruct and drop the buffer when
`track_by_address` returns `false`. `track_box` didn't get the same treatment.

It is not hypothetical: `tests/fork.rs:139` does exactly this and asserts the NULL,
so the new test leaks on purpose without noticing:

```rust
let p = track_box(Box::into_raw(Box::new(7i32)));
if !p.is_null() { unsafe { libc::_exit(1) }; }
```

A `multiprocessing`-style worker that keeps calling `c2pa_reader_new()` /
`c2pa_builder_from_json()` leaks one object per call, forever.

Fix: mirror `to_c_string`. Reconstruct on failure —
`if id == 0 { unsafe { drop(Box::from_raw(ptr_val as *mut T)) }; return std::ptr::null_mut(); }`
in `track_box`, and the `Arc::from_raw` equivalent in the two Arc variants. Better still,
have `track_by_id` return `Option<usize>` so `#[must_use]` forces the caller to decide,
the way `track_by_address` now does.

### N-2. Double free: `track_by_address`'s poisoned-lock path frees the buffer, then tells the caller to free it too
`utils.rs:463-487` with `:1116-1122` and `:1164-1174`

```rust
let entry = Arc::new(EntryInner { ..., cleanup: Mutex::new(Some(cleanup)), ... });
if let Ok(mut tracked) = self.tracked.lock() {
    ...
    return true;
}
// A poisoned lock means the entry was never recorded. Reporting
// that lets the caller free the buffer ...
return false;
```

On the poisoned path `entry` is still owned by this scope. `return false` drops it →
strong count 1 → `EntryInner::drop` → `owner_pid` matches → `cleanup.get_mut().take()`
yields `Some` → `catch_unwind` runs it → `drop(CString::from_raw(ptr_val))`. **The buffer
is freed here.** The caller then sees `tracked == false` and does it again:

```rust
if !tracked {
    // SAFETY: nothing else took ownership of this allocation.
    unsafe { drop(CString::from_raw(ptr)) };
    return std::ptr::null_mut();
}
```

The `SAFETY` comment is wrong on this one path. Same shape in `to_c_bytes`.

Note the two `track_*` functions now have **opposite** poisoned-lock conventions:
`track_by_id`'s `entry` also drops at `:435`, which *frees* the object and returns 0 — so
there the caller must **not** free, while here it must. Neither doc comment mentions the
drop side effect; both say only "the entry was never recorded".

Reachability: the registry mutex can only poison if a thread panics while holding it, and
this update removed the two `assert!`s that were the reachable way to do that. So it is
close to unreachable today — but it is a newly written error path that is wrong in the
worse direction (double free rather than leak), and `PointerRegistry::drop` still carries
`unwrap_or_else(|e| e.into_inner())`, i.e. the code does not treat poisoning as impossible.

Fix: `std::mem::forget(entry)` before `return false` (or build the `EntryInner` only after
the lock is acquired), and make `track_by_id`'s poisoned path match — defuse rather than
run, and document which side owns the allocation on each return.

### N-3. `tests/fork.rs` does not compile on Windows
`c2pa_c_ffi/tests/fork.rs:26`, `Cargo.toml:53-58`

```rust
#![cfg(not(target_arch = "wasm32"))]
```

`libc::fork`, `libc::waitpid`, `libc::WIFEXITED` and `libc::WEXITSTATUS` are Unix-only.
The `libc` crate's Windows module exposes `_exit` and `getpid` (as `_getpid`) but none of
those four. `docs/support-tiers.md:83` lists `x86_64-pc-windows-msvc` as Tier 1, and
`tier-1a.yml:237/262` and `tier-1b.yml:115/146` run bare `cargo test` at workspace root
with `windows-latest` / `windows-11-arm` in the matrix. `c2pa_c_ffi` is a workspace
member, so the test target is built there.

Fix: `#![cfg(unix)]`.

While there: the `[[test]]` block's comment says

```toml
# ... so these must not share a binary with the parallel unit
# tests. Own binary, and run it with --test-threads=1.
```

The own-binary half is automatic for anything in `tests/` — the `[[test]]` entry adds
nothing there. The `--test-threads=1` half **isn't enforced anywhere**: no `harness =
false`, no serialization attribute, no CI flag. libtest will run the two `#[test]` fns
concurrently by default, so `forked_child_registry_calls_are_refused` can fork while
`forked_child_can_create_handles_without_deadlocking`'s holder thread is alive. If the
single-threaded requirement is real, enforce it (`harness = false` with a hand-rolled
`main`, or collapse the three into one `#[test]`); if it isn't, drop the claim.

---

## Deadlock inventory

I traced every path that takes a lock. **No deadlock found in the current code**, but two
things are worth stating explicitly:

- **Registry mutex, non-reentrant.** Cleanup closures now run outside it on every path:
  `free` (`:682-696`, explicit scope), `PointerRegistry::drop` (`:727-730`, drains first),
  `untrack` (`:663-667`, defuse under the lock then `drop(tracked)` then `drop(entry)`),
  `track_by_id`'s duplicate-id branch (`:423-425`, defused so the later drop is inert),
  `track_by_address`'s re-track branch (`:477-479`, same). `test_cleanup_reentering_registry_does_not_deadlock`
  covers the main one. The `assert!` that used to unwind with a live entry under the lock
  is gone. Clear.
- **Per-entry `cleanup` mutex.** Taken in `EntryInner::drop`, `untrack`, both `track_*`,
  `PointerRegistry::drop`, and `Debug` (`try_lock`, correctly). In every case the guard's
  scope ends before the `Arc` drops, so `EntryInner::drop` is never reached while this
  thread holds that entry's `cleanup` lock. Clear — but fragile: the fork branch of
  `EntryInner::drop` (`:199-203`) uses `self.cleanup.lock()` where the non-fork branch two
  lines later uses `self.cleanup.get_mut()`. `Drop` has `&mut self`, so `get_mut()` is
  available and cannot deadlock by construction. Use it in both.
- **Lock ordering.** `untrack` is the only place that holds the map lock while touching
  `borrow_state`, and `checkout_*` never holds the map lock while spinning on
  `borrow_state` (`lookup` releases it first). No cycle.
- **Fork.** The remaining hazard is the allocator's own lock, not the registry's — see
  N-5.

## Livelock / starvation inventory

No livelock. Two notes:

- `checkout_shared`'s `compare_exchange_weak` loop (`:556-575`) has exactly two exits
  (success, or observing `EXCLUSIVE`) and re-reads on every failure. Terminates.
- **Writer starvation is real and now more reachable.** `checkout_exclusive` and `untrack`
  both need `borrow_state == 0`. A steady stream of overlapping shared checkouts never
  lets it return to 0, so both fail indefinitely with `PointerInUse`. This is surfaced as
  an error rather than a block, so it is not a livelock *in this crate* — but the nine
  downgrades from M-2 make it much easier to construct (e.g. a thread pool hammering
  `c2pa_signer_reserve_size` can make `c2pa_context_builder_set_signer` fail forever), and
  a binding that retries `PointerInUse` in a tight loop turns it into a livelock in the
  caller. Worth one sentence in the C header docs: `PointerInUse` means "another call is
  using this handle", and must not be retried without backing off or restructuring.

## Memory leak inventory

- **N-1** — unintended, blocker.
- **N-2** — the inverse, blocker.
- **Deliberate and documented:** the duplicate-id branch (`:415-429`), everything
  inherited by a forked child (`EntryInner::drop`), everything unfreed at shutdown
  (`PointerRegistry::drop`). All fine.
- **A callback that never returns** leaves its guard alive forever. `cimpl_free` still
  succeeds (it doesn't consult `borrow_state`), so the entry leaves the map and the
  cleanup is deferred to a guard drop that never happens — a permanent leak, not a hang.
  The "Callback contract" doc blocks in `c_api.rs` and `c2pa_stream.rs` describe this
  accurately.
- **Two unnecessary `std::mem::forget` calls**, `utils.rs:200` and `:424`. Dropping a
  `Box<dyn FnMut() + Send>` never invokes the closure — it just deallocates it, and the
  captures here are a single `usize`. `cleanup.take()` on its own already defuses. The
  `forget` additionally leaks the closure box: once per inherited entry in a forked child,
  on top of the leak that is intentional there. Small, but it also reads as if the author
  believed dropping the box would run it, which would make `track_by_address:478` (plain
  `take()`) look like a bug when it isn't.

---

## Remaining issues from round 2 that these commits did not close

### N-4. `checkout_shared<T: 'static>` still has no `Sync` bound
`utils.rs:867`

The H-2 fix stops a guard from being *sent* to another thread when `T: !Sync`. It does not
stop the case the FFI actually produces: two threads independently calling
`checkout_shared` on the same handle, each building its own guard on its own stack, each
dereferencing to `&T`. Neither guard crosses a thread boundary, so the new auto-trait
impls never come into play — and `&T` on two threads still needs `T: Sync`.

M-2's nine downgrades from exclusive to shared *increase* reliance on this. It happens to
hold: `C2paSigner`'s `Box<dyn C2paSignerObject>` carries `MaybeSync`, `C2paStream` has an
explicit `unsafe impl Sync`, `C2paContext = Arc<Context>` needs `Context: Send + Sync` to
satisfy `track_box`'s `MaybeSend`, and `c2pa::Builder`'s fields are all plain data plus
`Arc<Context>`. But nothing in the type system says so, and a future `Builder` field with
interior mutability would break it silently.

Add `T: MaybeSync` to `checkout_shared` (and `T: MaybeSend` to `checkout_exclusive`) and
the nine downgrades become compiler-checked rather than argued.

### N-5. `tests/fork.rs` does not construct the hazard it names, and allocates in the child
`tests/fork.rs:110-152`

`forked_child_can_create_handles_without_deadlocking` says it holds the registry lock
across the fork "by keeping a checkout alive". It doesn't: `checkout_shared` takes the map
lock inside `lookup` and releases it before returning, so holding a `SharedCheckout` holds
no lock at all. At fork time no thread holds `tracked`, so the test passes with or without
the `check_same_process` guards it exists to verify.

That guard is a genuine improvement, but the honest framing is "the guard is a
precondition check; the deadlock it prevents can't be constructed from the public API,
which is itself the point." The other two tests already prove the refusal via
`ForeignProcess`.

Separately, both children allocate (`Box::new`, `to_c_string`, the `Error` values built on
the refusal paths) and `cimpl_free` prints to stderr under `cfg(test)`. `malloc` after
`fork()` in a multi-threaded process is not async-signal-safe; if any harness thread holds
glibc's arena lock at fork time, the child hangs and `waitpid` never returns. The
`--test-threads=1` note was the intended mitigation and isn't wired up (N-3). This is the
residual CI-hang risk, moved from the registry lock to the allocator's.

### N-6. The `EntryInner::drop` fork check is now completely untested
`utils.rs:199-203`, `tests/fork.rs:76-108`

The old unit test reached into `get_registry().tracked` — a private field, reachable only
from the in-module test — removed the entry, and dropped the `Arc` directly, which is the
only way to reach `EntryInner::drop` in a child. Moving to an integration test lost that
access, so `forked_child_does_not_run_cleanup_for_inherited_entries` now goes through
`cimpl_free`, which `check_same_process` refuses **before** the drop path. The comment
admits it ("refused before the lock; what this proves is that no cleanup ran in the child
regardless of path"), which means it duplicates
`forked_child_registry_calls_are_refused` and covers nothing new.

Given M-4 established that the only justification left for this check is a hypothetical
caller-supplied closure touching a process-shared resource — and no closure in the crate
does — the choice is: delete the check and its `getpid()` per entry drop, or keep a
`#[cfg(test)]` unit test in `utils.rs` that drops an inherited `Arc` directly. Right now
it's untested code guarding a case that cannot occur.

### N-7. Two invariant tests were deleted, including the only test of the odd-id rule

`test_tag_does_not_collide_with_tracked_addresses` and
`test_entry_debug_reports_claim_and_cleanup_state` are gone from `utils.rs`, and neither
reappears in `tests/fork.rs`. The first contained the only assertion anywhere that handle
ids are odd:

```rust
assert_eq!(ptr as usize % 2, 1, "handle ids must be odd");
```

That is the load-bearing property of the whole odd/even split — it is what makes
`track_by_address`'s even-address check meaningful and what the registry doc block at
`:340-357` rests on. Nothing tests it now. The second was the only coverage of
`Debug for EntryInner`, which this same update rewrote to add the
`cfg!(debug_assertions)` branch.

Both look like collateral from the fork-test move rather than deliberate removals.
Restore them (neither depends on fork).

### N-8. `to_c_bytes` can now return NULL with a non-zero length, and no caller checks
`utils.rs:1164-1174`, `c_api.rs:2025, 2073, 2122, 2178, 2277, 2323, 2535`

Before this update, `to_c_bytes` returned NULL only for an empty input, so
`len > 0 ⟹ ptr != NULL` held. Now it also returns NULL on fork refusal, odd address, and
poisoned lock. Seven call sites do:

```rust
*manifest_bytes_ptr = to_c_bytes(manifest_bytes);
...
len       // returned to C, unchanged
```

so C gets a positive length and a NULL pointer, and `memcpy(dst, *manifest_bytes_ptr, len)`
segfaults. Same class: `c2pa_error()` (`c_api.rs:489`) is now `to_c_string(...)` that can
return NULL, and `test_c2pa_error_no_error` asserts it never does — so in a forked child,
C code doing `printf("%s", c2pa_error())` crashes, and the child can't even retrieve the
message explaining why everything else is failing.

Also `c2pa_mime_types_to_c_array` (`c_api.rs:2839-2845`) maps `to_c_string` over the list
and will happily embed a NULL element. That one is count-delimited so it doesn't truncate,
but a caller iterating and printing will crash.

These are all refusal-path-only, but the refusal path is now a *supported, tested*
behaviour rather than an impossibility. Either check the NULL at each site and return `-1`,
or (simpler) have the fork refusal set `CimplError::foreign_process()` via `set_last` so
the function can return a proper error instead of a half-populated success. Right now
`box_tracked!` returning NULL in a child sets no error at all.

### N-9. `c2pa_c_ffi/CHANGELOG.md` `## [Unreleased]` is still empty

Now carrying more breaking changes than in round 2: the three new `C2paError` variants,
`#[non_exhaustive]` on `C2paError` (breaks downstream exhaustive matches on its own),
removal of `validate_pointer` and `untrack_pointer` from the public API, and the
behavioural change where previously-succeeding calls return `-1` / `PointerInUse`.

---

## Nits

- `utils.rs:474-475` — `"so something freed the memory without untracking it. The\n// The stale cleanup closure ..."`. The doubled "The" survived the cleanup pass.
- `utils.rs:199-203` — use `self.cleanup.get_mut()` in the fork branch of `EntryInner::drop`,
  matching the line below it. `Drop` has `&mut self`; `lock()` there can only ever be a
  liability.
- `test_untrack_never_races_a_concurrent_checkout` (`utils.rs:1287-1316`) does not exercise
  a race — the comment says so itself ("With untrack merely reading the counter this still
  passes"). Both halves also pass against the *unfixed* code, so it is not a regression
  test for H-1. The fix is right; it just isn't covered. A `loom` model of
  `untrack` vs `checkout_shared`, or a two-thread stress test where the untracking thread
  writes a canary into the value and the checkout thread asserts it never observes the
  canary, would actually pin it.
- `validate_pointer` and `untrack_pointer` are now `pub(crate)` with
  `#[cfg_attr(not(test), allow(dead_code))]` — i.e. genuinely unused outside tests. Now
  that nothing depends on them, deleting them is cleaner than silencing the lint; the
  utils tests can call `get_registry().resolve(...)` and `untrack(...)` directly.
- 14 unsquashed WIP commits, three of them now with typos in the subject (`CHild`, `CLean`).
  `pr_title.yml` lints the PR title, not these.

---

## Where each comment goes

**Review body:** the verdict, N-3 (Windows/CI — it blocks the build, not a line), N-9
(CHANGELOG), the commit-squash nit.

**Inline:**

| finding | file:line |
|---|---|
| N-1 | `utils.rs:785` (the `id as *mut T` return), cross-ref `:393` |
| N-2 | `utils.rs:487` (the `return false`), cross-ref `:1119` and `:435` |
| N-4 | `utils.rs:867` |
| N-5 | `tests/fork.rs:122` (the "holds the registry lock" comment) |
| N-6 | `tests/fork.rs:79` |
| N-7 | `utils.rs:1286` (where the deleted tests were) |
| N-8 | `c_api.rs:2025` (one comment, list the other six + `:489`) |
| `get_mut` in Drop | `utils.rs:200` |
| unnecessary `forget` | `utils.rs:200`, `utils.rs:424` |
| doubled "The" | `utils.rs:474` |
| race test doesn't race | `utils.rs:1290` |
| delete `validate_pointer`/`untrack_pointer` | `utils.rs:851` |
| `[[test]]` comment overclaims | `Cargo.toml:53` |
