# Review round 5 — `mathern/c_ffi_opaque_ids-2`

**Reviewed:** `96e26c9e..019cf601` — five commits, +603/−540 across 8 files.

```
af9e8aa0 fix: Review notes
fca2559e fix: c2pa_error memory handling for error message
84ff62c3 fix: Handling of empty buffers
e28e4484 fix: Remove panicking debug
019cf601 fix: Handle the 2 signers in c2pa_identity_signer_create
```

Static review. No toolchain here; nothing compiled or run. B-6 from last round —
post a CI run for the `MaybeSync`/`MaybeSend` bounds — is still outstanding and still
uncheckable by reading.

---

## Verdict

The round-4 blockers are all addressed, and three of the fixes are better than what I
asked for. `debug_fmt(&self, f, hide_address)` with a `Shown` wrapper in the test is a
cleaner answer to the untestable-`cfg!`-branch problem than the release CI job I
suggested. `a_refused_track_reclaims_the_object` in `tests/fork.rs` runs the arm the
deleted test never touched. `error_message_fallback` reports the message that is actually
in the slot instead of inventing a cause.

Then `019cf601` shipped a fix that does not hold, wrapped in a doc comment that promises
it does.

Four blockers. Two of them are the same mistake this branch has now made three times:
writing a stronger guarantee in a comment than the code delivers, and deleting or
mis-scoping the thing that would have caught it.

---

## Blockers

### B-1. `c2pa_identity_signer_create` still consumes the first signer on a concurrent failure, and the new doc says it can't
`c_api.rs:2843-2861`, `utils.rs:1010-1024`

```rust
ok_or_return_null!(validate_handle::<C2paSigner>(c2pa_signer_ptr));
ok_or_return_null!(validate_handle::<C2paSigner>(identity_signer_ptr));
if std::ptr::eq(c2pa_signer_ptr, identity_signer_ptr) { ... return null }

let referenced_assertions = cstr_array_or_return_null!(referenced_assertions);
let roles = cstr_array_or_return_null!(roles);

let c2pa_signer = untrack_or_return_null!(c2pa_signer_ptr, C2paSigner);
let identity_signer = untrack_or_return_null!(identity_signer_ptr, C2paSigner);
```

`validate_handle` takes **no claim** on the entry — its own doc says so:

> This grants no claim on the entry, so it proves nothing about a later call on another
> thread. It is for ordering checks within one function, not for deciding that a handle is
> safe to use.

So between the two `validate_handle` calls and the two `untrack_owned` calls, another
thread can `c2pa_free(identity_signer_ptr)` or consume it. The first `untrack_or_return_null!`
then succeeds, the second fails, and `c2pa_signer` — the caller's C2PA signer, already
moved out of the registry — is dropped by scope exit while the function returns NULL.
That is the exact failure this commit exists to eliminate.

Meanwhile the new rustdoc on the function (`c_api.rs:2805-2807`) says:

> On failure nothing is consumed: both handles are validated before either is taken, so a
> rejected call leaves the caller owning both, still freeable.

and the `# Safety` block adds "If this returns NULL, both remain valid and the caller
still owns them." Neither is true under concurrency. The API documentation is now a
stronger promise than the implementation, on exactly the axis this whole branch exists to
harden — the premise everywhere else in the module is that the registry turns concurrent
misuse into an error rather than into damage.

The registry already has the right shape for a real fix. `untrack` (`utils.rs:641-647`)
CASes `0 → EXCLUSIVE` **while holding the map lock**, which is what made H-1 correct two
rounds ago. A two-handle version — claim both under one lock acquisition, remove both, or
release both and refuse — is roughly twenty lines and makes the doc true. Do that, or
delete the two doc sentences and say plainly that concurrent free of a handle being
consumed is the caller's problem.

The single-threaded duplicate-handle case is genuinely fixed and the two new tests are
good. That is not what the doc claims.

### B-2. `validate_handle` is `validate_pointer` with a different return type
`utils.rs:1010-1024`, `cimpl/mod.rs:74-77`

Two commits ago `validate_pointer` was deleted because it returned something with no claim
on the entry — round 3, LOW: "they bypass the borrow model." The replacement:

```rust
pub fn validate_handle<T: 'static>(ptr: *mut T) -> Result<(), Error> {
    get_registry().lookup(ptr as usize, TypeId::of::<T>())?;
    Ok(())
}
```

`validate_pointer` returned a claimless pointer. `validate_handle` returns a claimless
*fact*, which decays at the same rate for the same reason. It is `pub`, re-exported from
`cimpl/mod.rs` (behind `#[doc(hidden)]`, which hides it from rustdoc but not from the API
surface), and has exactly one caller — the function in B-1, in-crate.

The doc comment is admirably honest about the limitation, which is not the same as the
limitation being acceptable in an exported symbol. `pub(crate)` at minimum. Better: don't
have it at all, and add the two-handle untrack that B-1 needs, which needs no new public
surface.

### B-3. Freeing the fallback pointer destroys the error it was created to preserve
`c_api.rs:540-542`, against `utils.rs:1096-1118`

The new doc on `c2pa_error`:

> - It must not be freed. Passing it to c2pa_free is harmless and returns -1, so a caller
>   that frees unconditionally is still correct.

`cimpl_free` on the error path:

```rust
Err(e) => {
    let error = CimplError::from(e);
    ...
    error.set_last();
    -1
}
```

So the canonical C sequence —

```c
char *e = c2pa_error();
log_it(e);
c2pa_free(e);
```

— replaces the real diagnosis with `UntrackedPointer: ...` for every subsequent reader.
The whole point of the fallback is that the message survives when the buffer can't be
allocated; freeing it discards the message. In a forked child, where the fallback is the
normal path, this means any caller following the documented free-it pattern loses every
error after the first read.

`test_c2pa_error_reports_a_message_containing_an_interior_nul` (`c_api.rs:3759-3762`) ends
with exactly this call:

```rust
// Freeing the fallback is harmless and reports failure rather than
// corrupting the registry.
assert_eq!(unsafe { c2pa_free(error as *const c_void) }, -1);
```

and then stops. The test performs the clobber and asserts only the return code, so it
demonstrates the behaviour without noticing it.

"Harmless" is wrong. Either make `free` of an untracked pointer leave the slot alone,
say in the doc that freeing the fallback clears the error, or return a pointer that `free`
recognises and no-ops on.

### B-4. The fallback buffer's alignment is load-bearing, and the reason given for it is false
`c_api.rs:498-510`

> Being a `[u8; N]` rather than a string literal matters twice: the storage is writable
> ... and it is at least 2-aligned, so its address stays out of the odd handle-id keyspace
> that `track_by_address` protects.

A `[u8; N]` has alignment **1**. Nothing about being a byte array makes it even.

What actually makes the address even is that it lives inside `RefCell<[u8; 256]>`, whose
alignment is 8 because of the `Cell<isize>` borrow flag — an implementation detail of
`RefCell` under `repr(Rust)`, where field order and offsets are explicitly unspecified.
The property holds today. It is guaranteed by nothing.

And it is load-bearing: it is the only thing keeping this pointer out of the odd keyspace
that `track_by_address` (`utils.rs:520-529`) *refuses odd addresses* to protect. The whole
odd/even discipline exists to make handle-id collision structurally impossible; this is
the second time in three rounds that a special-case pointer has been handed to C on the
strength of an argument rather than a type.

`test_c2pa_error_reports_a_message_containing_an_interior_nul` does assert `% 2 == 0`, so
a regression fires — but it fires on a property whose stated justification is wrong, which
is how a future refactor to `Cell<[u8; 256]>` or a plain `static mut` gets written in the
first place.

Fix it in the type:

```rust
#[repr(align(2))]
struct ErrorFallback([u8; ERROR_FALLBACK_LEN]);
```

Then the comment is true and the test is a belt on a functioning brace.

---

## Medium

### M-1. A test was deleted in a commit whose subject describes a `debug_assert!`
`e28e4484`

That commit's stated purpose is removing a `debug_assert!(false, ...)` from
`defuse_untracked_entry`. It also deletes `test_error_fallback_truncates_on_a_char_boundary`:

```rust
let long = "\u{4e00}".repeat(200); // 3 bytes each, 600 total
let ptr = error_message_fallback(&long);
let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
assert!(bytes.len() < ERROR_FALLBACK_LEN, ...);
assert!(std::str::from_utf8(bytes).is_ok(), "truncation split a character");
```

That was the only coverage of the boundary walk at `c_api.rs:522-526`, which is the one
part of `error_message_fallback` that can hand C an invalid string if it is wrong. The
walk looks correct to me. It is now untested, and nothing in the subject, the body, or the
diff comments mentions that a test was removed.

This is the third commit on this branch whose subject materially misdescribes its
contents: `One use after free, same at two points in code` (which also removed two public
functions and changed eight `extern "C"` return contracts), `Handling of empty buffers`
(which also introduced `defuse_untracked_entry`), and now this. Since release-plz builds
the changelog from these subjects, the published record of this work will be wrong — that
is the reason the commit-message point survives the decision not to hand-edit the
CHANGELOG, not a reason it goes away.

If the test was deleted because it was wrong, say so and say why. If it was collateral,
restore it.

### M-2. Wrong error type for the duplicate-handle case, produced by a pointless round trip
`c_api.rs:2846-2851`

```rust
if std::ptr::eq(c2pa_signer_ptr, identity_signer_ptr) {
    CimplError::from(Error::from(CimplError::pointer_in_use())).set_last();
```

Two things.

**The conversion.** `CimplError → C2paError → CimplError`, where the middle step
(`error.rs:194`) reconstructs the variant by *string-parsing* `"PointerInUse: ..."`.
`CimplError::pointer_in_use().set_last()` is the same result in one step and does not
depend on the parser recognising its own output. If `from_type_and_message` ever stops
matching, this silently degrades to `Other` and the C-visible message gains a second
prefix.

**The type is wrong.** Nothing is borrowed. The caller passed one handle for two
parameters — an invalid argument. `PointerInUse` tells a C caller "another call is using
this handle", which implies retrying will help. It will not; the condition is permanent
for that call. This same commit added `CimplError::tracking_refused(reason)`
(`cimpl_error.rs:139-142`) for "the registry refused this, here is why," and then reached
past it for a variant that means something else.

### M-3. The six-line comment is still pasted six times — now alongside the module doc it points at
`c_api.rs:2113-2118, 2179-2184, 2237-2242, 2302-2307, 2410-2415, 2465-2470`

Round 4's finding was a five-line comment duplicated six times at the `to_c_bytes` sites.
The response was to add a "Returning byte buffers" section to the module docs
(`c_api.rs:14-26`) — good — and then keep all six copies, each now a line longer and each
ending with a pointer to the section that says the same thing:

```rust
// Publish only on success: see "Returning byte buffers" in the
// module docs. to_c_bytes also returns NULL for an empty buffer, which
// is success with nothing to hand back -- Builder::placeholder does
// exactly that for a format needing no placeholder -- so only a NULL
// with a non-zero length is a refusal.
```

Six identical five-line blocks whose content is "see the module docs". Either the module
docs are the single source and these become one line each, or extract
`publish_bytes(out: *mut *const c_uchar, bytes: Vec<u8>) -> Result<i64, ()>` and the
comment lives on the helper. The publish-on-success change itself is right, and the
`len > 0` refinement in `84ff62c3` is a real bug catch.

### M-4. The empty-placeholder regression was in the tree for a full round with no test to catch it
`c_api.rs:5551-5615`, `84ff62c3`

Round 4's `if (*manifest_bytes_ptr).is_null() { return -1; }` turned
`Builder::placeholder`'s documented `Ok(Vec::new())` into a `-1`, at six call sites. That
shipped, I reviewed it and did not catch it, and no existing test caught it either — the
suite had no coverage of `c2pa_builder_placeholder` for a format that needs no
placeholder. Credit for finding it.

The replacement test is coupled to SDK behaviour this crate does not own. It sets
`prefer_box_hash: true` and then asserts `c2pa_builder_needs_placeholder(builder,
"image/jpeg") == 0` — with a message conceding the test proves nothing otherwise, which is
the right instinct. But the contract under test is `c2pa_c_ffi`'s (`NULL` + `len == 0` is
success), and it is now guarded by a test that fails the day the SDK changes when box
hashing applies to JPEG. That is a `c2pa_c_ffi` failure caused by an `sdk` change.

Pin the contract where it lives: assert `to_c_bytes(Vec::new()).is_null()` in `utils.rs`,
and unit-test the `len > 0` guard directly. Keep the integration test as a bonus, not as
the only proof.

### M-5. `MutexPoisoned` and `InvalidBufferSize` change C-visible error strings, in a commit about the identity signer
`error.rs:57-66, 101-106, 194-197, 242-250`

Codes 6 and 7 moved from collapsing into `C2paError::Other` to having their own variants.
`Other` renders as `"Other: {0}"`, so `c2pa_error()` previously returned
`"Other: MutexPoisoned: thread panic detected"` and now returns
`"MutexPoisoned: thread panic detected"`.

This is a better string and `test_cimpl_typed_errors_keep_their_type` pins it. It is also
a change to text that C consumers and the Python/Node bindings may match on, arriving in
`019cf601 fix: Handle the 2 signers in c2pa_identity_signer_create` with no mention
anywhere. See M-1 on why the subject line matters here.

---

## Low

- **`std::ptr::eq` on two things that are not pointers** (`c_api.rs:2846`). These are
  opaque handle ids that were never addresses; the whole design is that they aren't.
  `c2pa_signer_ptr as usize == identity_signer_ptr as usize` says what is meant and does
  not read as a pointer-identity comparison.
- **`c2pa_error()` allocates twice per call** (`c_api.rs:535-536`). `message.clone()`
  exists solely so `error_message_fallback` can see the message on a branch that fires
  essentially never, on the hottest diagnostic path in every binding. Give `to_c_string` a
  `&str` overload, or build the `CString` from `&message` directly.
- **A test constructs an error with code 0** (`c_api.rs:3735`). `CimplError::new(0, ...)`,
  where `cimpl_error.rs:159` documents code 0 as "No error set". It works because
  `set_last` doesn't validate; it encodes a self-contradictory state into a test that
  otherwise pins good behaviour.
- **`error_message_fallback` returns a pointer derived from a `RefMut` that is dropped
  before the function returns** (`c_api.rs:519-537`). Sound — the `thread_local` data
  outlives the borrow — but the pointer escaping the `with` closure and the `borrow_mut`
  scope is the kind of thing that wants an explicit rationale comment, and there isn't
  one. There is also no `try_borrow_mut`: a C caller that somehow re-enters `c2pa_error`
  while the borrow is live gets a panic across `extern "C"`. Reachable only through a
  signal handler or a callback, but this is a crate that spent two rounds removing
  panics from FFI paths.
- **`c2pa_version()` can still return NULL** (`c_api.rs:494`) with no documentation and no
  handling. It is the function bindings call at load time to smoke-test the library.
- **20 commits**, five of them since the last review.

---

## Verified fixed

| # | Item | Status |
|---|---|---|
| B-1 (r4) | `c2pa_error()` fabricated a fork diagnosis | **Fixed.** The fallback reports the message actually in the slot, and the comment at `:539-543` enumerates all four NULL causes instead of naming one. Interior NULs are replaced with `?` rather than dropping the message — the right call, since a NUL is *why* `CString::new` failed. `test_c2pa_error_reports_a_message_containing_an_interior_nul` asserts the real text survives and that the output contains no "fork". |
| B-2 (r4) | `*mut` into `.rodata`, unconstrained address | **Fixed in behaviour** — writable thread-local storage, and the test pins evenness. The stated reason is wrong; see B-4 above. |
| B-3 (r4) | Doc contradicted the implementation | **Fixed thoroughly.** `# Safety` now names all three consequences — must not be freed, overwritten by the next call on this thread, does not outlive the thread — including the worker-exits-with-a-dangling-pointer case, which `e28e4484` added on its own. Modulo B-3 above: one of the three claims is not accurate. |
| B-4 (r4) | Test drove the wrong `track_box` arm | **Fixed properly.** The bogus test is gone and `a_refused_track_reclaims_the_object` (`tests/fork.rs:167-186`) runs the reclaim arm in a forked child with a `Drop` sentinel and reports through the exit code. The doc comment explains why this is the only place the arm is reachable — which is the reasoning the deleted test was missing. |
| B-5 (r4) | Review markdown committed to repo root | **Deleted.** |
| M-1 (r4) | `-1` after the asset is already signed | **Fixed by documenting, which is the right call.** Both `c2pa_builder_sign` and `c2pa_builder_sign_context` gained a `# Returning -1 after the asset is written` section saying `dest` may hold a complete signed asset and "Do not retry blindly on -1: a retry signs the asset a second time." |
| M-2 (r4) | Only one of four refusal paths set an error | **Fixed.** New `CimplError::tracking_refused(reason)` (code 11) with a distinct reason string at each of the four sites, plus the `TrackingRefused` variant and round-trip test. |
| M-3 (r4) | `<hidden>` branch had no CI coverage | **Fixed better than asked.** `debug_fmt(&self, f, hide_address)` split out with the flag explicit, `Debug` delegating with `!cfg!(debug_assertions)`, and a `Shown(&entry, bool)` wrapper in the test exercising both branches in one build. The comment says exactly why. Cleaner than adding a release test job. |
| M-4 (r4) | Two idioms for defusing, one leaked | **Fixed.** `defuse_untracked_entry` with `Arc::into_inner`, one call site each, no `mem::forget`, and an honest `None` arm that reports rather than pretends. |
| M-5 (r4) | Six-fold comment / re-read through the out-param | **Half.** The publish-on-success restructure is done at all seven sites and the module doc is a real improvement. The duplication is worse; see M-3 above. |
| LOW (r4) | `*count` null deref | **Fixed** — one check at the top of `c2pa_mime_types_to_c_array`. |
| LOW (r4) | `PointerRegistry` in the public API | **Fixed** — `pub(crate)`, and `resolve` is now `#[cfg(test)] fn`. |
| LOW (r4) | Weakened `Debug` assertions | **Fixed** — back to field-qualified `borrow_state: "free"` etc. |
| LOW (r4) | Vestigial `[[test]]` block | **Removed**, with the rationale moved into `tests/fork.rs`'s module docs where it belongs. |
| LOW (r4) | Tests write the global error slot | **Addressed by owning it** — the two tests now assert on the slot deliberately, with a comment saying the write is intended. Fine. |

---

## Still outstanding from round 4

**B-6: post a CI run.** The `checkout_shared<T: MaybeSync>` / `checkout_exclusive<T: MaybeSend>`
bounds either compile against `c2pa::Reader`, `Builder`, `Settings`, `Arc<Context>`,
`C2paSigner` and `C2paStream`, or they don't, and the failure lands on the nine sites this
branch downgraded to shared borrows. Five rounds of review without a build is enough.

---

## Where each comment goes

**Review body:** the verdict, B-6, M-1 (commit hygiene), M-5.

**Inline:**

| finding | file:line |
|---|---|
| B-1 | `c_api.rs:2857` (the first `untrack_or_return_null!`), cross-ref the doc at `:2805` |
| B-2 | `utils.rs:1021` |
| B-3 | `c_api.rs:541` (the "harmless" bullet), cross-ref `utils.rs:1117` |
| B-4 | `c_api.rs:504` (the "at least 2-aligned" claim) |
| M-2 | `c_api.rs:2849` |
| M-3 | `c_api.rs:2113` (one comment, list the other five) |
| M-4 | `c_api.rs:5586` (the `needs == 0` assertion) |
| `ptr::eq` | `c_api.rs:2846` |
| double allocation | `c_api.rs:535` |
| error code 0 in a test | `c_api.rs:3735` |
| `RefMut` escape / no `try_borrow_mut` | `c_api.rs:520` |
| `c2pa_version` NULL | `c_api.rs:494` |
