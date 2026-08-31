# Review round 4 — `mathern/c_ffi_opaque_ids-2`

**Reviewed:** `f45e1fba..96e26c9e` — one commit,
`fix: One use after free, same at two points in code`, +977/−156 across 7 files.

Static review. No Rust toolchain in this environment, so nothing here was compiled or
run — which matters more this round than last, see B-6.

---

## Verdict

Every round-3 finding is addressed, several of them well. Then the same commit invented a
new one that is worse than most of what it fixed, shipped a test whose name claims
coverage it does not provide, committed my review document into the source tree, and left
the CHANGELOG empty for the fourth consecutive round.

The commit message says "One use after free, same at two points in code." The commit
deletes two public functions, adds two generic bounds that can break the build, changes
the return contract of eight exported `extern "C"` functions, adds ten tests, and adds a
402-line markdown file to the repository root. If a reviewer trusted that subject line
they would review none of it.

**Not mergeable.** Six blockers.

---

## Blockers

### B-1. `c2pa_error()` now returns a hardcoded lie
`c_api.rs:488-508`

```rust
pub unsafe extern "C" fn c2pa_error() -> *mut c_char {
    let ptr = to_c_string(Error::last_message());
    if ptr.is_null() {
        // to_c_string could not track the buffer, which happens in a forked child.
        return UNREPORTABLE_ERROR.as_ptr() as *mut c_char;
    }
    ptr
}

static UNREPORTABLE_ERROR: &CStr =
    c"ForeignProcess: handles cannot be created or used in a forked child";
```

"which happens in a forked child" is one of **four** ways `to_c_string` returns NULL, and
it is the only one this string describes:

1. fork refusal (`utils.rs:464-467`) — the message is right;
2. poisoned registry lock (`utils.rs:505-508`) — nothing to do with fork;
3. odd buffer address (`utils.rs:477-483`) — nothing to do with fork;
4. **`CString::new` failing on an interior NUL byte** (`utils.rs:1129`) — nothing to do
   with fork, nothing to do with the registry, and reachable in a plain single-process
   parent with no threads.

Case 4 is the one that matters. Any error message containing a `\0` — a JUMBF label, a
path, or a JSON fragment lifted from an attacker-supplied asset and folded into a
`c2pa::Error` string — makes `c2pa_error()` report that the caller forked. It didn't. The
real message is still sitting in the thread-local (`CimplError::last_message` peeks, it
does not take), so the API is now capable of holding the correct diagnosis and handing
back a fabricated one instead.

An error-reporting function that fabricates errors is worse than one that returns NULL.
NULL is at least honest.

Pick one: return NULL and fix the C-side contract, or thread the actual reason through
(the refusal sites already know it — see B-4), or fall back to a per-thread static buffer
you fill with the truncated real message. Do not hardcode one cause and print it for all
four.

### B-2. The sentinel violates the odd/even invariant the rest of the file enforces, and points into read-only memory
`c_api.rs:498, 507`

Two things wrong with `UNREPORTABLE_ERROR.as_ptr() as *mut c_char`:

**It is `*mut` into `.rodata`.** The C signature is `char*`. C callers are entitled to
write through a `char*` — `strtok`, in-place case folding, a binding that null-terminates
early. Any of those segfaults on a string literal. If this pointer must not be written,
the return type has to say `const char*`, which is an ABI change to a function every
consumer calls.

**Its address is unconstrained.** String literal data has alignment 1, so this pointer can
be odd. Handle ids are always odd. `track_by_address` (`utils.rs:477-483`) *refuses to
track an even-addressed-only buffer* precisely to keep the two keyspaces disjoint:

```rust
// Refuse rather than alias: the caller frees the buffer, ...
if !real_addr.is_multiple_of(2) {
```

This commit then hands C a pointer that skipped that check and can be fed straight into
`cimpl_free`'s keyspace. The comment at `:496-497` waves it off — "c2pa_free rejects it as
untracked and never frees" — which is true only as long as the address happens not to
equal a live handle id. On 64-bit that is 2^-63 and I would not raise it. On 32-bit and
wasm32 the id space is 2^31 and the docs at `utils.rs:326-333` already concede ids repeat
within it, so "never" is doing work the code does not support.

The design's entire claim is that this collision is *structurally* impossible, not merely
improbable. This is the first pointer in the crate for which that stops being true, and it
is in the one function C calls on every error path.

Trivially fixable: `static MSG: [u8; N]` behind a `#[repr(align(2))]` newtype, or don't
return a fake pointer at all.

### B-3. The doc comment on `c2pa_error()` — and therefore the generated C header — is now wrong

Unchanged, directly above the new code:

```
/// # Safety
/// The returned value MUST be released by calling release_string
/// and it is no longer valid after that call.
```

The function now sometimes returns a pointer that must **not** be released, and the code
relies on `c2pa_free` silently failing to make that safe. `cbindgen` generates the public
header from these comments. Every C consumer is now being told to free a static.

Worse, in a forked child the loop is closed: `c2pa_error()` returns the static; the caller
frees it; `free` hits `check_same_process`, returns -1, and **sets a new last error**;
the caller calls `c2pa_error()` again and gets the same static. The child can never
retrieve any error but this one, forever.

If the contract now has an exception, the doc has to state it and the header has to carry
it.

### B-4. `test_track_box_reclaims_the_object_when_the_registry_refuses` tests the branch it is named after *not* executing
`utils.rs:1710-1735`, against `utils.rs:818-836`

The N-1 fix is:

```rust
match get_registry().track_by_id(...) {
    Some(id) => id as *mut T,
    None if ptr.is_null() => std::ptr::null_mut(),          // ← arm A: no reclaim
    None => { unsafe { drop(Box::from_raw(ptr_val as *mut T)) }; ... }   // ← arm B: the fix
}
```

The test:

```rust
// Drive track_box's None arm directly: a null pointer is the one
// refusal reachable without a fork or a poisoned lock, and it takes the
// same path every other refusal does.
let refused = track_box(std::ptr::null_mut::<Payload>());
assert!(refused.is_null(), "a refused track must return NULL");
```

A null pointer takes **arm A**. Arm B — the `Box::from_raw` that is the entire fix — is
never executed by this test or any other. The comment asserting they are "the same path"
is false about the two lines directly above it.

`test_track_by_id_refusal_leaves_the_object_for_the_caller` (`:1665-1708`) does correctly
prove that `track_by_id` never frees, and then performs the reclaim by hand — so what is
covered is the half you can drive through a locally-constructed `PointerRegistry`, and
what is not covered is the half that goes through the global one.

It is testable. `tests/fork.rs` already forks: put a `static DROPS: AtomicUsize` and a
`Drop` payload in the child, call `track_box`, assert `DROPS == 1` before `_exit`. That
exercises arm B end to end on the exact path the fix exists for.

Until then, delete the misleading test rather than leave a green check next to a claim it
does not support.

### B-5. `c_ffi_opaque_ids-2-review-round3.md` is committed to the repository root

402 lines, 22.9 KB, at the top level of `c2pa-rs`, in the same commit as the code it
critiques.

Two rounds ago this branch added `pointer-registry-pitfalls.md`, `registry.md` and
`current-plan.md` to `.gitignore`; that was flagged and reverted. The response this round
was to commit the working document instead of ignoring it. `c2pa_c_ffi/Cargo.toml` has no
`exclude`, so anything at the workspace root that `cargo package` picks up ships to
crates.io.

Delete it. Review artifacts live in the PR.

### B-6. The two new generic bounds are unverifiable by reading, and nothing here shows a green build
`utils.rs:930, 945`

```rust
pub fn checkout_shared<T: 'static + MaybeSync>(...)
pub fn checkout_exclusive<T: 'static + MaybeSend>(...)
```

This is the right fix and I asked for it. It is also the one change in this commit that
can fail to compile, and the failure lands on the nine sites the previous round downgraded
from exclusive to shared. `checkout_shared` is now instantiated for `c2pa::Reader`,
`c2pa::Builder`, `c2pa::Settings`, `Arc<Context>`, `C2paSigner` and `C2paStream`. If any
one of them is `!Sync`, `c2pa_builder_to_archive`, `c2pa_signer_reserve_size` and seven
others stop building.

I traced what I could — `Builder`'s fields (`sdk/src/builder.rs:413-455`) and `Reader`'s
(`sdk/src/reader.rs:93-115`) are plain data plus `Arc<Context>`/`Arc<Store>`, and the
`RefCell` in `settings/mod.rs:46` is a `thread_local!`, not a field — so it very likely
holds. "Very likely" is not a review outcome for a change that either compiles or doesn't.

Post a CI run. Every round of this branch has been reviewed without a build, and this is
the first change where reading is genuinely not sufficient.

---

## Medium

### M-1. `return -1` after the asset has already been signed
`c_api.rs:2041-2048`, and five more at `:2095, :2149, :2212, :2317, :2369`, plus
`:2587`

```rust
*manifest_bytes_ptr = to_c_bytes(manifest_bytes);
if (*manifest_bytes_ptr).is_null() {
    // ... Returning len here would hand back a positive length with a NULL pointer.
    return -1;
}
```

Correct as far as it goes — the round-3 finding was that `len > 0` with a NULL pointer is
a crash — but note what `-1` now means for `c2pa_builder_sign` and `c2pa_builder_sign_context`:
**the signing succeeded and the destination stream has been fully written**, and the only
thing that failed was handing back a copy of the manifest bytes. The caller cannot tell
that apart from "signing failed". A caller that retries on -1 signs twice; a caller that
discards on -1 throws away a valid signed asset.

If the buffer can't be returned, the honest signal is a distinct code, or leaving the out-
param NULL and returning the length with the failure recorded in the error slot and
documented. At minimum, say so in the doc comment for the two functions that mutate
`dest`.

### M-2. Only one of four refusal paths sets an error
`utils.rs:404-407` and `:464-467` (set), vs `:414-419`, `:449-455`, `:477-483`,
`:503-508` (silent)

The fork refusal calls `CimplError::foreign_process().set_last()`. The 32-bit exhaustion
path, the odd-address path and both poisoned-lock paths do not. So `c2pa_reader_new()`
returning NULL after a poisoned lock leaves whatever unrelated error was in the slot from
the previous call, and C reads a stale message that describes a different failure.

The comment at `:2046` — "The error is already set" — is only true for one of the four
reasons it covers. Set an error on every refusal, or on none and document NULL as the
signal.

### M-3. The `<hidden>` branch of the `Debug` impl has no CI coverage
`utils.rs:132-146`, `utils.rs:1901-1908`

```rust
if cfg!(debug_assertions) { format!("0x{:x}", self.real_addr) } else { "<hidden>".to_string() }
```

`test_entry_debug_reports_borrow_state_and_cleanup` branches on the same `cfg!` and only
asserts `<hidden>` in the else arm. `cargo test` builds with the test profile, which has
`debug_assertions = true`; `Cargo.toml:20-28` does not override it, and neither
`tier-1a.yml` nor `tier-1b.yml` runs `cargo test --release` anywhere.

So the branch with the security rationale — don't leak the real address into release logs
— is the branch no CI job ever executes. Either add a `--release` test job for this crate
or restructure so both arms are reachable in one build (a runtime flag, or assert on a
helper function you can call with the flag forced).

### M-4. Two idioms for the same job, three lines apart, one of which leaks
`utils.rs:435-445` vs `utils.rs:450-453`

Duplicate-id branch:

```rust
if let Ok(mut cleanup) = previous.cleanup.lock() {
    // take() alone defuses: dropping a Box<dyn FnMut()> drops
    // the closure's captures without running its body.
    cleanup.take();
}
```

Poisoned-lock branch, in the same function:

```rust
std::mem::forget(entry);
```

Both are correct. The second leaks the `Arc<EntryInner>` and its boxed closure on top of
the object it is deliberately not freeing, and it does so *after* the first comment has
already explained that `take()` alone is sufficient. Defuse and drop, as above, and the
poisoned path stops leaking ~100 bytes per call. Same at `:507`.

### M-5. Six-fold verbatim comment, and an unnecessary re-read through the caller's pointer
`c_api.rs:2043-2047` and five identical copies

Last round the finding was a four-line comment pasted twenty times in the test module.
That was fixed, and the same commit introduced a new five-line comment pasted six times.
Say it once, at a helper.

Also, all six do:

```rust
*manifest_bytes_ptr = to_c_bytes(manifest_bytes);
if (*manifest_bytes_ptr).is_null() {
```

which writes the caller's out-param, then reads it back through the raw pointer to decide
whether to fail. Check a local and only publish on success:

```rust
let bytes = to_c_bytes(manifest_bytes);
if bytes.is_null() { return -1; }
*manifest_bytes_ptr = bytes;
```

That also stops clobbering the caller's out-param on the failure path, which the current
form does before returning -1.

---

## Low

- **`*count = 0` derefs a caller pointer with no null check** (`c_api.rs:2913`). The
  pre-existing `*count = mime_ptrs.len()` below has the same problem, so this isn't new —
  but the commit doubled it rather than fixing it. One `if count.is_null()` at the top
  covers both.
- **`PointerRegistry` is still publicly reachable.** `lib.rs:30` does `pub use cimpl::*`
  and `cimpl/mod.rs:63` declares `pub mod utils`, so `c2pa_c::cimpl::utils::PointerRegistry`
  with its `pub fn resolve` and `pub fn free` is in the public rustdoc. It has private
  fields and no constructor, so it is unusable — it is just noise in the API surface that
  has now survived four rounds. `pub(crate) mod utils` or `pub(crate) struct`.
- **The restored `Debug` test is weaker than the one it replaces.** The deleted version
  asserted `borrow_state: "free"` and `cleanup: "armed"`; the new one
  (`utils.rs:1877-1882`) asserts `contains("free")` and `contains("armed")`, which would
  pass on a `Debug` impl that emitted those substrings anywhere. Restore the field-
  qualified form.
- **Unit tests now write the global error slot.** `test_track_by_id_refusal_leaves_the_object_for_the_caller`
  and `test_track_by_address_refusal_leaves_the_buffer_for_the_caller` construct a foreign
  `PointerRegistry`, which reaches the new `set_last` call. It is thread-local so it won't
  cross tests under the default harness, but a test that mutates process-visible state as
  a side effect of asserting something unrelated is a trap for the next person.
- **The `[[test]]` block now carries nothing but a comment** (`Cargo.toml:53-58`). `name`
  and `path` both match what autodiscovery would produce. Move the comment into
  `tests/fork.rs` — where an identical one already lives at `:14-27` — and delete the
  block.
- **`Debug` allocates a `String` per call** to pass through `format_args!`
  (`utils.rs:136-144`). Branch on the whole `.field(...)` call instead of on its argument.
- **`track_by_id` burns an id before the poisoned-lock return** (`:412` then `:453`).
  Harmless, but on 32-bit it consumes from a space the same file says is exhaustible.
- **15 unsquashed commits**, three with typos in the subject (`CHild`, `CLean`), and the
  latest one materially misdescribing its own contents.

---

## Still not done, fourth round running

**`c2pa_c_ffi/CHANGELOG.md`'s `## [Unreleased]` is empty.**

This has been raised in rounds 2, 3 and now 4. What is unreleased and undocumented:

- three new `C2paError` variants;
- `#[non_exhaustive]` on `C2paError`, which breaks every downstream exhaustive match on
  its own;
- `validate_pointer` and `untrack_pointer` removed from the public API (they were `pub` on
  `main`);
- `checkout_shared`/`checkout_exclusive` gaining trait bounds;
- calls that previously succeeded now returning `-1` / `PointerInUse` when a handle is
  passed twice or shared across threads;
- `c2pa_builder_sign` and five siblings gaining a new `-1` return condition;
- `c2pa_error()` gaining a return value the caller must not free;
- `c2pa_reader_supported_mime_types` / `c2pa_builder_supported_mime_types` gaining a NULL
  return.

That is a release note, not a line item. `semver-checks.yml` will not catch any of it —
it targets `stable`/`v0.*`, not a main PR, which was in the round-1 notes.

---

## Verified fixed

Credit where it is due — the round-3 list is fully addressed, and three of the fixes are
better than what I asked for.

| # | Item | Status |
|---|---|---|
| N-1 | `track_box` leaks on refusal | **Fixed, and better than requested.** `track_by_id` returns `Option<usize>` with `#[must_use = "on None the caller still owns the allocation and must free it"]` and an explicit ownership contract in the doc (`utils.rs:381-390`) — the API-level fix, not a patch at the three call sites. All three `track_*` reclaim. Coverage is the problem, not the code: see B-4. |
| N-2 | `track_by_address` double free on poisoned lock | **Fixed correctly** (`utils.rs:503-508`), and `track_by_id`'s sibling path made to match (`:450-453`), which is what made the two conventions consistent. `test_poisoned_lock_refusal_does_not_free_the_buffer` and `..._the_object` poison a locally-built registry with a real `catch_unwind` panic and assert the cleanup counter stays at 0. That is the right test, and it would have caught the bug. |
| N-3 | `tests/fork.rs` breaks Windows | **Fixed** — `#![cfg(unix)]` with a comment naming Tier-1 Windows as the reason. |
| N-4 | `checkout_shared` missing `Sync` bound | **Fixed** (`utils.rs:930, 945`), with a doc comment that correctly explains why the guards' auto-trait impls don't cover the two-threads-two-guards case. Modulo B-6. |
| N-5 | Fork test's premise was false | **Fixed honestly.** The holder-thread theatre is gone and `tests/fork.rs:127-136` now says outright that the check is a precondition, that no public API holds the registry lock across a call, and that this is *why* pid-checking beats trying to make the lock fork-safe. Better than deleting it. |
| N-6 | `EntryInner::drop` fork branch untested | **Fixed properly.** `test_inherited_entry_drop_does_not_run_cleanup` (`utils.rs:1817-1866`) builds an entry with a foreign pid, drops it, asserts the closure didn't run — **and then repeats with the current pid and asserts it did**. The positive control is what makes it a test rather than a tautology. |
| N-7 | Deleted invariant tests | **Restored.** `test_handle_ids_are_always_odd` is back and now loops 64 times instead of asserting once. |
| N-8 | `to_c_bytes` NULL with `len > 0` | **Fixed at all seven sites** plus `c2pa_mime_types_to_c_array`, which now frees the partial array rather than returning a NULL element. See M-1/M-5 for what the fix costs. |
| — | H-1 regression test | **Now real.** `test_untrack_claims_the_borrow_rather_than_observing_it` (`utils.rs:1341-1381`) holds an entry past `lookup`, untracks, and asserts `borrow_state == EXCLUSIVE` and that a late `compare_exchange(0, 1)` fails — the observable consequence of claiming rather than reading. A `load`-based untrack fails it. The comment is also candid that a stress test was attempted and never reached the window, which is the correct thing to write down. The old test was renamed to `test_untrack_refuses_while_a_borrow_is_outstanding` with a note saying it does *not* cover H-1. Both changes are right. |
| — | `get_mut` in `Drop`, stray `mem::forget`, doubled "The", `mod.rs` comment, dead `//pub use` | All fixed. |
| — | `validate_pointer`/`untrack_pointer` | **Deleted**, replaced by `#[cfg(test)] PointerRegistry::{resolve_typed, untrack_typed}`. Cleaner than the `pub(crate)` + `allow(dead_code)` I suggested. |

---

## Where each comment goes

**Review body:** the verdict, B-5 (committed markdown), B-6 (post a CI run), the CHANGELOG
section, the commit-message and squash points.

**Inline:**

| finding | file:line |
|---|---|
| B-1 | `c_api.rs:494` (the "which happens in a forked child" comment) |
| B-2 | `c_api.rs:498` and `c_api.rs:507` |
| B-3 | `c_api.rs:485` (the unchanged `# Safety` block) |
| B-4 | `utils.rs:1722` (the "same path every other refusal does" comment) |
| M-1 | `c_api.rs:2046` |
| M-2 | `utils.rs:406` (the one place that sets it), cross-ref `:414`, `:479`, `:505` |
| M-3 | `utils.rs:1901` |
| M-4 | `utils.rs:452` |
| M-5 | `c_api.rs:2043` (one comment, list the other five) |
| `*count` null deref | `c_api.rs:2913` |
| `PointerRegistry` public | `cimpl/mod.rs:63` |
| weakened `Debug` assertions | `utils.rs:1878` |
| tests write the error slot | `utils.rs:1686` |
| vestigial `[[test]]` | `Cargo.toml:53` |
| `Debug` allocation | `utils.rs:136` |
