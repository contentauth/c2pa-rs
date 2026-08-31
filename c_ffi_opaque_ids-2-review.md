# Adversarial review — `mathern/c_ffi_opaque_ids-2` vs PR #2559

**Scope reviewed:** `145b754a..3fe201c3` (11 commits on top of the PR #2559 head), i.e. what
this branch *adds* to the open PR. Base for reference is `b3cd390a` (main).

| | #2559 (`gpeacock/c_ffi_opaque_ids`) | this branch |
|---|---|---|
| files | 4 | 8 |
| diff vs `145b754a` | — | +1392 / −148 |
| diff vs main | +216 / −71 | +1564 / −175 |

Static review only — no Rust toolchain in this environment, so nothing here was compiled
or run. Everything below was traced through the source; where a claim depends on
something I could not execute, I say so.

---

## Verdict

**Worthwhile in substance, wrong as a single PR, and not correct as it stands.**

PR #2559 does one thing: stop handing C the real address. That closes the ABA-on-free
window for *handle-typed* objects and nothing else. This branch does something much
bigger — it replaces the address-with-a-typecheck model with a real borrow model:
`Arc<EntryInner>` + a `borrow_state` counter + RAII guards (`TypedShared`/`TypedExclusive`),
`untrack_owned` returning `T` by value instead of a pointer, a `Wrapper` tag so an
`Arc`-tracked entry can't be `Box::from_raw`'d, panic containment in cleanup, and
fork-awareness.

The core of that is genuinely better than #2559 and fixes things #2559 does not:

- `checkout_exclusive` makes `&mut T`-from-a-handle actually sound instead of
  "sound if C behaves". `test_sign_rejects_same_stream_as_source_and_dest` is a real
  UB case in today's shipped API that now returns an error.
- Free-during-use is now deferred instead of being a use-after-free: the registry drops
  its `Arc`, the guard holds the object up. `test_free_while_checked_out_defers_cleanup`
  and `test_guard_outliving_free_across_threads_cleans_up_once` cover it.
- `untrack_owned` removes the Box-vs-Arc choice from callers entirely. That was the
  MEDIUM I raised on #2559 about `untrack_pointer(p)?;` still compiling while discarding
  the real pointer — this is the right fix, better than the `#[must_use]` I asked for.
- The tests are the biggest single improvement. #2559 had no test for any new invariant;
  this has ~20, including the stale-handle, cross-thread, re-entrant-cleanup, and
  panicking-cleanup cases.

Three of my five round-1 MEDIUMs on #2559 are addressed here (`scramble_to_odd_id` period
documented honestly, the odd-address invariant now enforced, `#[must_use]` added, tests
added). One is not (buffer ABA — see M-7). The CHANGELOG one is not (M-6).

But:

1. There is a **real race between `untrack` and `checkout_*`** (H-1) that breaks the
   central guarantee of the new design.
2. `TypedShared<T>` / `TypedExclusive<T>` are **unconditionally `Send + Sync`** (H-2),
   which is a soundness hole reachable from safe Rust.
3. `C2paStream::extract_context` — a `pub` fn — **can never succeed** on this branch (M-1).
4. Nine call sites take an exclusive borrow where the code provably only uses a shared
   one, which turns ordinary concurrent C usage into `PointerInUse` errors (M-2).
5. The fork hardening is built on a **factually wrong premise** (M-4) and is incomplete
   anyway (M-3). It costs a `getpid()` on every registry operation and every entry drop.

**Recommendation:** land #2559 as-is — it is small, urgent, and reviewable. Split this
branch into (a) borrow guards + `untrack_owned` + `Wrapper`, (b) fork handling (I'd drop
it), (c) docs/tests. Fix H-1 and H-2 before (a) merges. Squash the 11 WIP commits
(`fix: Process stamping`, `fix: Name callback contract 2`, …) — the PR title/body will be
the only record of what this does.

---

## HIGH

### H-1. `untrack` can race a concurrent checkout and hand the same object to two owners
`utils.rs:445-459` (`lookup`), `utils.rs:464-503` (`checkout_shared`/`checkout_exclusive`),
`utils.rs:546-561` (`untrack`)

The borrow claim is acquired **after** the map lock is released:

```rust
fn checkout_shared(&self, id, ty) -> Result<SharedCheckout, Error> {
    let entry = self.lookup(id, ty)?;              // takes + RELEASES self.tracked
    let mut current = entry.borrow_state.load(Acquire);
    loop { ... compare_exchange(current, current + 1, ...) }   // outside the lock
}
```

`untrack` checks `borrow_state` *under* the lock:

```rust
if entry.borrow_state.load(Ordering::Acquire) != 0 {
    return Err(... pointer_in_use ...);
}
let entry = tracked.remove(&id).expect("checked Some above");
```

Interleaving:

| thread A (`c2pa_signer_reserve_size`) | thread B (`c2pa_context_builder_set_signer`) |
|---|---|
| `lookup(id)` → `Arc` clone, lock released | |
| | `untrack(id)`: `borrow_state == 0` ✓, remove, defuse cleanup |
| | returns `real_addr`; `untrack_owned` does `Box::from_raw` and moves the value out |
| CAS `0 → 1` succeeds, returns `TypedShared` | |
| `deref` → `&*(real_addr as *const T)` | value already dropped by B |

The `Arc` keeps `EntryInner` alive, so the *entry* is fine — but the **object** at
`real_addr` has been moved out of and dropped. This is exactly the use-after-free the
design exists to prevent, and it is reachable through every `untrack_or_return_*!` site
(`c2pa_context_builder_set_signer`, `c2pa_context_builder_set_http_resolver`,
`c2pa_reader_with_stream`, `c2pa_builder_with_archive`, …).

`free()` does **not** have this problem — it removes the entry but leaves the object owned
by the `Arc`, so a late checkout is still valid. Only the ownership-transfer path is racy.

Fix: make `untrack` take the claim rather than observe it —
`borrow_state.compare_exchange(0, EXCLUSIVE, AcqRel, Acquire)`, and only remove from the
map if that succeeds. A concurrent `checkout_shared` then either wins the CAS (untrack
returns `PointerInUse`) or sees `EXCLUSIVE` and refuses. Alternatively, do the CAS inside
`lookup` while the map lock is still held.

Worth adding a loom or `thread::scope` hammer test for `untrack` vs `checkout` — the
existing concurrency tests only exercise checkout-vs-checkout and free-vs-guard.

### H-2. The guards erase `T`'s `Send`/`Sync`, so `checkout_shared` can produce a data race in safe Rust
`utils.rs:222-236`, `utils.rs:765`, `utils.rs:780`

```rust
pub struct TypedShared<T> {
    inner: SharedCheckout,                 // Arc<EntryInner>: Send + Sync
    _marker: PhantomData<fn() -> T>,       // Send + Sync for all T
}
```

`fn() -> T` is `Send + Sync` regardless of `T`, and `SharedCheckout` holds only an `Arc`
of an all-`Send + Sync` struct. So `TypedShared<T>` and `TypedExclusive<T>` are `Send` and
`Sync` **for every `T`** — `test_guards_are_send` asserts this as a feature, and the
comment at :226 explains it was deliberate.

`checkout_shared<T: 'static>` has no `Sync` bound. So:

```rust
let p = track_box(Box::into_raw(Box::new(Cell::new(0i32))));  // Cell<i32>: Send, !Sync
let a = checkout_shared::<Cell<i32>>(p).unwrap();
let b = checkout_shared::<Cell<i32>>(p).unwrap();
thread::spawn(move || b.set(1));
a.set(2);                                                      // data race, no `unsafe`
```

`track_box` requires `MaybeSend` (= `Send` off wasm), but `Sync` is never required
anywhere, and two `&T` on two threads needs it. In-crate this is latent rather than live —
`C2paStream` has an explicit `unsafe impl Sync`, and `C2paReader`/`C2paBuilder`/
`C2paSettings` are presumably `Sync` — but the crate ships as an `rlib` and all of
`checkout_shared`, `checkout_exclusive`, `TypedShared`, `TypedExclusive` are re-exported
at the crate root (`cimpl/mod.rs:74-76`).

Fix: `checkout_shared<T: 'static + MaybeSync>`, `checkout_exclusive<T: 'static + MaybeSend>`;
or, better, make the guards' auto traits honest with
`unsafe impl<T: Sync> Send for TypedShared<T> {}` + `PhantomData<*const T>`, and drop the
blanket assertion in `test_guards_are_send` to `assert_send::<TypedShared<i32>>()` only.
Note that the wasm32 arm of `MaybeSend`/`MaybeSync` is a no-op impl, so on wasm32 nothing
constrains this at all — fine while wasm is single-threaded, worth a comment.

---

## MEDIUM

### M-1. `C2paStream::extract_context` can never succeed — it always panics
`c2pa_stream.rs:115-120`

```rust
pub fn extract_context(&mut self) -> Box<StreamContext> {
    let context_ptr = std::mem::replace(&mut self.context, std::ptr::null_mut());
    let context = crate::untrack_owned::<StreamContext>(context_ptr).expect("always box_tracked!");
    Box::new(context)
}
```

`untrack_owned::<StreamContext>` requires `entry.type_id == TypeId::of::<StreamContext>()`.
There is no site in the repo that tracks a context under that type:

- `c2pa_stream.rs:412` — `box_tracked!(self) as *mut StreamContext` → `TypeId::of::<TestC2paStream>()`
- `c2pa_stream.rs:583` — `box_tracked!(test_stream) as *mut StreamContext` → same
- `c_api.rs:3018` — `box_tracked!(()) as *mut StreamContext` → `TypeId::of::<()>()`
- a real C caller's `context` is not tracked at all → `UntrackedPointer`

Every path returns `Err`, so `.expect(...)` panics. On main this was silently wrong rather
than loud (`Box::from_raw` on a ZST never touches the allocator), and there are no in-repo
callers, so nothing catches it — but this is `pub` on a `pub` type and the doc comment
added at :111-114 asserts an invariant that no construction site satisfies.

Also note that even if the type matched, `StreamContext` is a unit struct (`:27`), so
`untrack_owned` would untrack the entry and hand back a ZST while the real `TestC2paStream`
allocation leaks *and* becomes unfreeable. Either delete `extract_context` (nothing calls
it) or make it `untrack_owned::<TestC2paStream>` behind a `#[cfg(test)]` helper.

### M-2. Nine sites take an exclusive borrow where a shared one is provably enough
`c_api.rs:1418, 1891, 1971, 2010, 2154, 2197, 2224, 2314, 2769`

Each of these is `let x = deref_mut_or_return_*!(...)` with **no `mut`** on the binding,
which means the code only ever reaches `T` through `Deref`, i.e. `&T`. (This is the
compiler's own signal — the branch adds `mut` at ~30 other sites where `&mut` is actually
needed, so these are the ones that aren't.)

| line | fn | handle |
|---|---|---|
| 1418 | `c2pa_reader_resource_to_stream` | `C2paReader` |
| 1891 | `c2pa_builder_to_archive` | `C2paBuilder` |
| 1971 | `c2pa_builder_write_ingredient_archive` | `C2paBuilder` |
| 2010 | `c2pa_builder_sign` | `C2paSigner` |
| 2154 | `c2pa_builder_sign_data_hashed_embeddable` | `C2paSigner` |
| 2197 | `c2pa_builder_needs_placeholder` | `C2paBuilder` |
| 2224 | `c2pa_builder_hash_type` | `C2paBuilder` |
| 2314 | `c2pa_builder_sign_embeddable` | `C2paBuilder` |
| 2769 | `c2pa_signer_reserve_size` | `C2paSigner` |

The signer ones matter most. `c2pa_builder_sign` does
`builder.sign(c2pa_signer.signer.as_ref(), …)` and `c2pa_signer_reserve_size` does
`c2pa_signer.signer.reserve_size()` — both `&self`. Taking the exclusive claim means:

- **two threads signing different assets with one signer handle**: one gets `-1` /
  `PointerInUse`. That's a normal server pattern and it works today.
- **`c2pa_signer_reserve_size` called while a sign is in flight** (including from inside
  the host's own signing callback): same.

These should be `deref_or_return_*!`. Without that, "we made concurrency safe" reads to
callers as "we made concurrency fail".

### M-3. The fork guard is incomplete — the two `track_*` paths take the lock without it
`utils.rs:338-366`, `utils.rs:371-406`, vs `utils.rs:436-441`

`check_same_process` is documented "Call this *before* taking the `tracked` lock… taking
the lock can deadlock". `resolve`, `lookup`, `untrack` and `free` all honour that.
`track_by_id` and `track_by_address` do not — they go straight to `self.tracked.lock()`.

So in a fork-without-exec child (the `multiprocessing` case the tests call out),
`c2pa_reader_new()`, any `box_tracked!`, and `c2pa_error()` (→ `to_c_string` →
`track_by_address`) can all deadlock on an inherited held mutex. That's the same hazard,
through the paths the guard doesn't cover.

Separately: `owner_pid` is the *registry's* pid, so a handle a child creates is
immediately unresolvable and unfreeable by that same child. Whether that's intended isn't
stated anywhere user-facing; `CimplError::foreign_process` says "handles cannot be used in
a forked child", which is stronger than the code (creation succeeds, use doesn't). If
fork is going to be refused, refuse it in `track_*` too and say so in the C header docs.

### M-4. The rationale for skipping cleanup in a forked child is wrong
`utils.rs:159-180`

> A forked child inherits every entry. Running cleanup here would free an allocation the
> parent still owns and release external resources (file descriptors, sockets) twice.

`fork()` gives the child a copy-on-write **private** address space. Freeing an inherited
allocation in the child mutates the child's copy; the parent's heap is untouched. Closing
an inherited fd in the child removes the child's descriptor, not the parent's. So neither
stated consequence follows. `test_forked_child_dropping_inherited_entry_does_not_free`
proves the check works, not that the check is needed — the `Sentinel` it guards is the
child's own copy.

The one real fork hazard is the inherited-mutex deadlock, and that's `check_same_process`'s
job (M-3), not `EntryInner::drop`'s. The residual case that *would* justify the drop check
is a cleanup closure touching a genuinely process-shared resource (a file on disk, an
`flock`, shared memory) — but every closure in this crate is `Box::from_raw` /
`Arc::from_raw`, so none qualify.

Cost of keeping it: `libc::getpid()` on **every** `EntryInner::drop` and every registry
entry point. glibc removed pid caching in 2.25, so that's a real syscall per FFI call, on
a path that codspeed measured as flat for #2559. I'd drop the `EntryInner::drop` check,
keep `check_same_process` (extended per M-3), and cache nothing.

### M-5. The duplicate-id `assert!` drops an entry while holding the registry lock
`utils.rs:353-363`

```rust
if let Ok(mut tracked) = self.tracked.lock() {
    // Dropping the returned entry would run its cleanup under the lock,
    // and leave the next free aimed at the wrong object.
    let previous = tracked.insert(id, entry);
    assert!(previous.is_none(), "PointerRegistry minted a duplicate handle id");
}
```

The comment identifies the hazard and the code then does it. When the assert fires,
`previous: Option<Arc<EntryInner>>` is a live local in the innermost scope; unwinding drops
it **before** the `tracked` guard, so `EntryInner::drop` runs its cleanup closure with the
lock held. If that closure re-enters the registry (the case
`test_cleanup_reentering_registry_does_not_deadlock` exists for), it deadlocks — mid-panic.
And because this is inside `extern "C"` reachable code, the panic aborts anyway on
Rust ≥ 1.81, so the assert is a process abort either way.

Use `std::mem::forget(previous)` before the assert, or `debug_assert!` + `eprintln!`.

Related, same block: if the lock is **poisoned**, the `if let Ok(...)` silently skips the
insert and still returns `id` to C. The caller now holds a handle the registry has never
heard of — every later call fails `UntrackedPointer` and the object leaks. Read paths
(`resolve`, `free`) propagate `mutex_poisoned()`; write paths swallow it. That asymmetry
is worth fixing now that a panic-under-lock is reachable (above).

### M-6. No CHANGELOG entry, and `C2paError` gains three variants without `#[non_exhaustive]`
`error.rs:40-49`, `CHANGELOG.md` (`## [Unreleased]` is empty)

`C2paError` is `pub` and not `#[non_exhaustive]`, so `PointerInUse` / `WrongWrapperKind` /
`ForeignProcess` are a breaking change for any downstream `match`. On top of that, this
branch changes **runtime behaviour visible to shipped bindings**: calls that previously
succeeded now return `-1` with `PointerInUse:` (aliased streams, a shared signer under
M-2, a re-entrant call from a callback). c2pa-python and c2pa-c callers will see this.

That needs a `## [Unreleased]` entry naming the new error strings and the aliasing rule,
and probably a heads-up in the bindings repos. This was also unaddressed on #2559
(`semver-checks.yml` lists `c2pa-c-ffi` but only runs on `stable`/`v0.*` targets, so it
won't fire on a main PR — that hasn't changed).

### M-7. Address-keyed buffers still ABA; the registry doc now overclaims
`utils.rs:293-307`, `utils.rs:371-406`, `utils.rs:997-1052`

The doc block says the odd/even split means "a handle that outlives its object … can never
alias a *different*, newly-allocated object at a reused address". That's true for the
`track_by_id` half and false for the `track_by_address` half, which the same doc block
describes two paragraphs later. `to_c_string`/`to_c_bytes` still hand C the real address,
so: `c2pa_free(s)` → allocator reuses the address → next `to_c_string` lands there →
a stale `char*` copy passed to `c2pa_free` frees the live string. Same `CString` type, so
the `TypeId` check passes.

I raised this on #2559; the new `"was re-tracked while still tracked"` warning at :399
covers a *different* bug (memory freed without untracking), not this one. Either fix it
(shadow buffer allocations behind ids and copy on hand-off) or say plainly in the doc that
buffer pointers remain ABA-prone and only handles don't.

---

## LOW

- **`validate_pointer` and `untrack_pointer` are now dead in production but still `pub`.**
  `utils.rs:750`, `utils.rs:811`, re-exported at `cimpl/mod.rs:74-76`. Grep shows zero
  non-test callers on this branch. Both bypass the entire borrow model —
  `validate_pointer` returns a bare `*mut T` with no claim (so a downstream user can build
  aliasing `&mut`), and `untrack_pointer` reintroduces exactly the Box-vs-Arc choice that
  `untrack_owned` was written to remove. Make them `pub(crate)` or delete them; the tests
  can use `resolve` directly.

- **`assert!` in `track_by_address` aborts the process.** `utils.rs:378-381`. This is the
  `debug_assert_eq!(real_addr & 1, 0)` I suggested on #2559, upgraded to a release
  `assert!` inside a path reachable from `extern "C"` — a custom `#[global_allocator]`
  returning an odd address takes down the host application. The sibling failure right
  below it (`insert` returning `Some`) only `eprintln!`s. Pick one severity.

- **`Wrapper::Arced` is unreachable in production.** `arc_tracked!` (`macros.rs:418`) and
  `track_arc`/`track_arc_mutex` (`utils.rs:705, 732`) have no callers outside
  `test_untrack_owned_rejects_arc_tracked_entry`. So the `Wrapper` enum, the
  `required: Option<Wrapper>` parameter and `CimplError::wrong_wrapper_kind` are all dead
  weight today. Fine to keep as future-proofing, but say so — right now it reads as
  guarding a live hazard.

- **Module docs reference macros that don't exist.** `macros.rs:87, 93, 96, 105, 106, 113,
  139, 194, 203, 345`. The doc block introduced here tells contributors to use
  `checkout_or_return_null!`, `checkout_or_return_int!`, `checkout_mut_or_return!`,
  `checkout_mut_or_return_int!`. None of those exist — the macros are `deref_or_return_*!`
  and `deref_mut_or_return_*!`. This is the *only* guidance in the crate on which macro to
  reach for, so it needs to match. (If the rename was intended, do the rename; the
  `deref_*` names are now misleading anyway since they no longer deref.)

- **The fork tests can hang CI.** `utils.rs:1165-1247`. `libc::fork()` is called from the
  cargo test harness, which is multi-threaded and whose other tests hammer the same global
  registry mutex. `test_forked_child_dropping_inherited_entry_does_not_free` then does
  `get_registry().tracked.lock()` **in the child** — if any other test thread held that
  lock at fork time, the child blocks forever and `waitpid` never returns. That is
  precisely the hazard `check_same_process`'s doc comment describes. Both children also
  call non-async-signal-safe code after fork (allocation, `eprintln!` under `cfg(test)`,
  `Mutex`), which is UB per POSIX. Gate these behind a serial-test lock, or run them in a
  dedicated single-test binary (`tests/fork.rs` with `harness = false`).

- **`Debug for EntryInner` prints the real address.** `utils.rs:128`. Minor, but it
  undoes the opacity goal for anything that logs an entry.

---

## Nits

- **`cargo +nightly fmt --all -- --check` will fail** (`tier-1a.yml:562`,
  `blank_lines_upper_bound = 1`): triple blank lines at `utils.rs:1277-1279` and
  `macros.rs:477-480`, and the mangled comment blocks in `c_api.rs` around lines
  3231-3240, 3305-3314 where a 4-line comment got blank lines interleaved between every
  line. That same 4-line comment is then pasted ~20 times across the test module — it
  should be said once, near a helper (`fn take_c_string(p: *mut c_char) -> CString`), and
  the tests should call the helper.
- **`.gitignore:22-25`** adds `pointer-registry-pitfalls.md`, `registry.md`,
  `current-plan.md` — personal scratch files, not repo artifacts. Also drops the trailing
  newline. Use a global gitignore or `.git/info/exclude`.
- **`///` and `//` are interleaved inside one doc comment** on `borrow_state`
  (`utils.rs:76, 81, 83`). Compiles, but those three lines silently vanish from rustdoc,
  and they're the ones explaining what the counter values mean.
- **Typos in new comments:** "iso taking the lock" (:435), "a ero-sized type" (:376),
  "The\n// The stale cleanup closure" (:394-395), "the parent still  owns" (:97),
  "and a custom global allocator don't need to align" (:376).
- **`test_panicking_cleanup_is_contained`'s comment misstates the mechanism**
  (`utils.rs:1510-1511`): it says the abort comes from "a panic escaping a Drop during
  unwinding", but `cimpl_free` is called normally here — the abort comes from a panic
  crossing the `extern "C"` boundary. Same conclusion, wrong reason, and the wrong reason
  is the one a future reader will act on.
- **11 unsquashed WIP commits** with non-descriptive messages. `.commitlintrc.yml` /
  `pr_title.yml` govern the PR title, not the history, but a reviewer bisecting this later
  gets nothing from `fix: Process stamping`.

---

## Checked and clear

- `scramble_to_odd_id` (`utils.rs:284-287`): `2c+1` then `* ID_MULTIPLIER` (odd) — odd × odd
  is odd, so the odd-id invariant holds on both widths, and multiplication by an odd
  constant mod 2^N is a bijection. The doc at :278-283 now states the 2^(N-1) period
  honestly and the 32-bit `assert!` at :339-343 bounds it. My round-1 MEDIUM here is fixed.
- Error codes 8/9/10 don't collide with the existing 1-7 in `cimpl_error.rs`, and the
  `CimplError → C2paError` round trip works via the existing `From<&str>`
  (`error.rs:233-243`), which parses `"PointerInUse: …"` back through
  `from_type_and_message`. `code()` isn't exposed to C, so no C-ABI break from the codes
  themselves (the *behaviour* change is still M-6).
- `usize::is_multiple_of` (`utils.rs:379`) is stable since 1.87; workspace MSRV is 1.88.
  No MSRV break.
- `libc::getpid()` compiles on Windows — `libc` maps it to `_getpid` (libc
  `src/windows/mod.rs:539-540`), and `libc = "0.2"` was already a direct dependency. The
  `#[cfg(target_arch = "wasm32")] → 0` arm is consistent with `owner_pid = 0`, so the check
  is always a no-op there.
- Production stream I/O does **not** hit the registry per chunk: `C2paStream::{read,seek,
  write,flush}` (`c2pa_stream.rs:136-243`) call the C function pointers directly. Only
  `TestC2paStream`'s callbacks do a checkout per call, so the added `getpid` + mutex cost
  is per FFI entry point, not per byte. (Still worth a codspeed run — #2559 measured flat
  and this adds a syscall to every entry point.)
- `EXCLUSIVE = usize::MAX` can't be reached by counting readers on either width: each
  `SharedCheckout` is a live stack value, and `Arc::clone` aborts on strong-count overflow
  at `isize::MAX` first. The comment at :119-120 is right.
- `free()` correctly releases the map lock before the `Arc` drops (`utils.rs:586-600`), and
  `PointerRegistry::drop` drains before dropping (`:631-634`) — the re-entrant-cleanup
  deadlock is genuinely avoided on those paths. Only `track_by_id`'s panic path isn't (M-5).
- `checkout_shared` vs `checkout_exclusive` vs `checkout_exclusive` are all mutually
  correct — they contend on one atomic. Only `untrack`, which observes rather than claims,
  is racy (H-1).
- `drop_c_stream` (`c2pa_stream.rs:432-437`): the `if let` scope does end before the outer
  `cimpl_free`, so the guard is released first and the two frees stay ordered. The added
  comment is accurate.
- `c2pa_context_builder_set_signer` / `set_http_resolver`: the builder really is validated
  before the signer/resolver is consumed, so the new doc promise at `c_api.rs:731-733` and
  `843-846` holds, and `test_set_signer_leaves_signer_owned_when_builder_is_invalid` tests
  the right thing.
- The `CString::from_raw` → `CStr::from_ptr` + `c2pa_free` test conversion is a real bug
  fix, not churn: the old tests freed registry-tracked memory behind the registry's back,
  leaving stale address-keyed entries. Good catch by the author.
- `TestStream` is `#[cfg(test)]`, so the `stream_mut() -> TypedExclusive<C2paStream>`
  signature change is not a public API break.

---

## Where each comment goes

**Review body** (not tied to a diff line): the verdict / split recommendation, M-6
(CHANGELOG + `non_exhaustive` + bindings impact), the commit-squash nit, and the
`cargo fmt --check` nit.

**Inline** (all inside diff hunks):

| finding | file:line |
|---|---|
| H-1 | `utils.rs:552` (the `borrow_state.load` in `untrack`), cross-ref `utils.rs:464` |
| H-2 | `utils.rs:226` (the `PhantomData` comment) and `utils.rs:765` |
| M-1 | `c2pa_stream.rs:118` |
| M-2 | `c_api.rs:2010` and `c_api.rs:2769` (one comment, list the other seven) |
| M-3 | `utils.rs:353` and `utils.rs:390` |
| M-4 | `utils.rs:166` |
| M-5 | `utils.rs:358` |
| M-7 | `utils.rs:296` |
| `validate_pointer`/`untrack_pointer` | `utils.rs:750`, `utils.rs:811` |
| `assert!` severity | `utils.rs:378` |
| `Wrapper::Arced` dead | `utils.rs:44` |
| stale macro names | `macros.rs:96` |
| fork tests | `utils.rs:1168` |
| `Debug` prints real address | `utils.rs:128` |
| `///`/`//` mixing + typos | `utils.rs:76`, `utils.rs:376`, `utils.rs:435` |
| `test_panicking_cleanup` comment | `utils.rs:1510` |
| `.gitignore` | `.gitignore:22` |
| duplicated test comment block | `c_api.rs:3231` |
