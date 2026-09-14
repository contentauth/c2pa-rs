# Adversarial review — PR #2575, `feat: Update opaque ids handling in C FFI (add checkout mechanism)`

Branch `mathern/c_ffi_opaque_ids_concurrent` @ `a82b5b69` → base `gpeacock/c_ffi_opaque_ids` @ `6ba9b6dc`
(8 files, +2124/−459; `c2pa_c_ffi/src/cimpl/utils.rs` is effectively a rewrite at +1575).

Brief: memory issues, memory corruption, livelocks, deadlocks, dangling pointers. Confirm before reporting.

## Method

Static tracing of the whole registry plus, for the first time in this PR series, **execution**. The
container has rustc 1.75 and no network for the workspace's dependency graph, so the crate itself
cannot be built. Instead I extracted `cimpl/utils.rs` verbatim into a standalone crate, stubbed the
four crate-internal imports (`CimplError`, `Error`, `MaybeSend`, `MaybeSync`), and downgraded three
std APIs that post-date 1.75 (`with_exposed_provenance*` → casts, `expose_provenance`/`addr` →
`as usize`, `is_multiple_of` → `% 2`). Nothing in the borrow state machine, the registry, or the
drop ordering was touched. Harness source is in the appendix; run output:

```
T1  sanity ...................... ok
T2  exclusion stress ............ writes=314830 (refused 447) reads=1859 (refused 5976) torn=0
T3  free vs borrow .............. use-after-free=0 leaked=0
T4  AB/BA inversion ............. succeeded=16903 PointerInUse=199
T5  reads during a long write ... refused=20/20 avg_block=1.002181ms
T6  writer-pending .............. writer_got=false new_reader_blocked=true reader_ok_after=true
T7  address ABA ................. stale free returned 0 (it freed the *new* buffer); the live
                                  buffer's own handle then returned -1
T8  untrack vs free ............. double_ownership=0 orphaned=0
T9  panic with a live borrow .... reusable_after_panic=true
T10 second sign, same signer .... result=PointerInUse after 10.004634ms
T11 re-entrant checkout ......... result=PointerInUse after 1.004459ms
T12 refusal cost ................ 100 refused exclusive checkouts: wall=250ms cpu=0.24s
```

## What holds up

The design is sound and the implementation matches it. Specifically confirmed, not assumed:

- **No torn state, no overlapping exclusive borrows.** T2: 8 threads for 1.5s, writers mutating two
  fields non-atomically through `&mut`, readers requiring them to agree. 300k+ writes, zero torn
  reads, zero overlaps (asserted with a separate in-flight counter inside the borrow).
- **Deferred cleanup is correct.** T3: 2000 rounds of `cimpl_free` racing a live `SharedCheckout`.
  Zero reads of a dropped object, zero leaks. The object drops exactly when the last guard goes,
  and `SharedCheckout::drop` releases the borrow *before* dropping the `Arc`, so the cleanup never
  runs under a live borrow.
- **`untrack` vs `free` cannot double-own or orphan.** T8: 3000 rounds. Exactly one of the two wins;
  when `untrack` loses the map re-check it resets the borrow and its `Arc` drop runs the cleanup, so
  the object is still freed once. The two-phase `untrack` (clone `Arc` → release map lock → CAS the
  borrow → re-lock and `Arc::ptr_eq`) closes the round-2 HIGH properly.
- **`WRITER_PENDING` is never stranded.** T6: only the writer that set the bit can clear it, and the
  timeout path does clear it. A reader arriving afterwards succeeds.
- **Panic with a live guard releases the borrow** (T9), and a panicking cleanup is contained
  (`catch_unwind` in `EntryInner::drop`) without poisoning the registry.
- **No deadlock and no unbounded livelock anywhere.** Every wait is bounded by `READER_WAIT` (1ms)
  or `WRITER_WAIT` (10ms); measured at exactly those bounds (T10/T11). The lock ordering is clean:
  the map lock is never held across an `Arc<EntryInner>` drop that could run a cleanup — verified at
  every drop site (`free` 823, `untrack` 708-710, `untrack_pair` 801-805, `free_if_still_tracked_entry`
  856-858, `PointerRegistry::drop` 886-900). The two sites that *do* drop an entry under the lock
  (`track_by_id` 530-535, `track_by_address` 565-569) call `cancel_cleanup()` first, so the drop is
  inert. The `cleanup` mutex is a leaf — nothing acquires another lock while holding it.
- **Guards carry the right auto-trait bounds.** `PhantomData<*const T>` plus
  `unsafe impl<T: Sync> Send for TypedShared<T>` / `unsafe impl<T: Send> Send for TypedExclusive<T>`
  is correct, and `checkout_shared` requires `MaybeSync` while `checkout_exclusive` requires
  `MaybeSend`. The round-2 data-race-in-safe-Rust hole is closed.
- Handle ids are odd, buffer addresses are forced even via `alloc_even_buffer` (align 2), so the two
  key spaces cannot collide. The round-1 odd-address hole is closed and now enforced, not asserted.

Everything below is what's left.

---

## Findings

| # | Sev | Where | What |
|---|-----|-------|------|
| 1 | **High** | `c_api.rs:2684` | `Vec::set_len` past capacity from a C callback's return value → heap corruption |
| 2 | **Low** | [IGNORE, known accepted issue] `cimpl/utils.rs:543` | Address-keyed ABA: a stale `char*` frees a different, live buffer (reproduced) |
| 3 | HIGH | `c_api.rs:2606` | Only site not converted to `out_bytes_or_return_int!`: returns len > 0 with a NULL buffer |
| 4 | HIGH | `c_api.rs:2030, 2176`, doc at `c_api.rs:2620-2628` | Signer taken exclusively; doc claims calls "serialize", they fail instead (measured 10ms → `PointerInUse`) |
| 5 | Medium | [IGNORE, trade-off] `cimpl/utils.rs:130-247` | Refusal path is a `yield_now` busy-spin; readers starve under write load |
| 6 | Medium | `c_api.rs:2026-2030` | No canonical ordering across the four checkouts → AB/BA mutual abort |
| 7 | Medium | [IGNORE, never made it to a release]`cimpl/cimpl_error.rs:75-82` | Error codes 6 and 7 silently changed meaning |
| 8 | Low | various | See "Minor" |

---

### 1. HIGH — `signed_bytes.set_len(signed_size)` is unbounded (`c_api.rs:2668-2686`)

```rust
let signed_len_max = data.len() * 2;
let mut signed_bytes: Vec<u8> = vec![0; signed_len_max];
let signed_size = unsafe { (callback)(context, data.as_ptr(), data.len(),
                                      signed_bytes.as_mut_ptr(), signed_len_max) };
if signed_size < 0 { return Err(c2pa::Error::CoseSignature); }
signed_bytes.set_len(signed_size as usize);   // <-- only the sign was checked
```

A host callback that returns any value greater than `signed_len_max` sets the `Vec`'s length past its
capacity. Everything after that is UB: the manifest is built from a slice running off the end of the
allocation, and the `Vec`'s eventual free passes a bogus length to the allocator. A host that returns
the size it *wanted* to write rather than what it did write — an easy mistake given the API hands the
callback a `signed_len_max` it is told to validate itself — corrupts the heap.

The sibling path already gets this right: `CallbackCredentialHolder::sign` at `c_api.rs:2817-2821`
checks `signed_size > self.reserve_size` and then uses `truncate`.

**Honest scoping: this is pre-existing on `main`** (`bb9fc5c3`, same line). It is not introduced by
this PR. I'm raising it because it is the single worst memory-safety hole in the file this PR
rewrites for memory safety, and because the fix is three lines.

**Fix** — no `unsafe` needed at all, since `vec![0; n]` is fully initialized:

```rust
if signed_size < 0 {
    return Err(c2pa::Error::CoseSignature);
}
let signed_size = signed_size as usize;
if signed_size > signed_len_max {
    // The callback wrote more than the buffer it was handed, or is reporting a
    // size it did not write. Either way the buffer contents can't be trusted.
    return Err(c2pa::Error::CoseSignature);
}
signed_bytes.truncate(signed_size);
```

Placement: inline on `c_api.rs:2684`.

---

### 2. LOW — address-keyed entries still ABA; reproduced

`track_by_address` (`utils.rs:543`) keys `to_c_string` / `to_c_bytes` / `track_string_array` buffers
by their real address. Addresses are recycled by the allocator, so a stale pointer C still holds can
key an entry belonging to a *different, live* buffer. T7 does exactly this:

1. `to_c_string(...)` → address `A`, `cimpl_free(A)` → 0.
2. Allocate new strings until one lands on `A` again (took under 64 iterations every run).
3. `cimpl_free(A)` with the **stale** pointer → returns **0**, and frees the new buffer.
4. `cimpl_free(new_ptr)` → **-1**: the legitimate owner's pointer is now dangling, and its next
   read is a use-after-free.

The registry doc comment (`utils.rs:460-474`) argues the odd/even split makes both key spaces safe.
It only makes them non-*colliding with each other*; it says nothing about an address colliding with
its own past, and a reader will come away with the wrong impression. The PR clearly knows the hazard —
`free_if_still_tracked_entry` (`utils.rs:838-860`) exists precisely to compare `Arc::ptr_eq` before
freeing — but that guard is only reachable from `track_string_array`'s cleanup, where the caller
happens to still hold the `Weak`. The public `cimpl_free` path has only the address, so it can't use it.

**Fix (concrete, and it also catches plain double-free).** Give buffers from `alloc_even_buffer` a
small header carrying a magic and the entry's generation, and hand C the pointer past it:

```rust
#[repr(C)]
struct BufHeader { magic: u64, generation: u64 }
const BUF_MAGIC: u64 = 0xC2PA_BUF_HDR_u64;   // any fixed constant
const C_BUFFER_ALIGN: usize = 16;            // room for the header, still even
```

- `alloc_even_buffer` allocates `size_of::<BufHeader>() + total`, writes the header, returns
  `ptr.add(size_of::<BufHeader>())`.
- `PointerRegistry` gets `buffer_generation: AtomicU64`; `track_by_address` stamps the entry and the
  header with the same value.
- `free` reads the header **only after** the map lookup succeeded — which proves the allocation is
  live, so the read is not itself a UAF — and rejects the free when `magic` or `generation` disagree.
- `dealloc_even_buffer` poisons `magic` before deallocating.

That turns the reproducer's step 3 into a clean `-1` instead of freeing someone else's buffer. If you
would rather not pay 16 bytes per string, the minimum acceptable alternative is to **correct the
registry doc comment** to say plainly that address-keyed buffers remain ABA-prone and that a
double-free of a recycled address is undetectable, and to consider auditing whether
`to_c_string`/`to_c_bytes` could return id-keyed handles with an accessor instead (a bigger ABI
change, but it would retire the second key space entirely).

Placement: review body — the rationale spans `utils.rs:456-474` and `utils.rs:539-574`, both inside
the diff, so an inline comment on 543 works too.

---

### 3. HIGH — `c2pa_builder_compose_manifest` missed the `out_bytes_or_return_int!` conversion

`c_api.rs:2604-2607`:

```rust
let len = result_bytes.len() as i64;
if !result_bytes_ptr.is_null() {
    *result_bytes_ptr = to_c_bytes(result_bytes);   // may be NULL
}
len
```

`to_c_bytes` returns NULL on allocation failure or on a tracking refusal (id-space exhaustion,
foreign process). The caller gets a positive length and a NULL pointer and reads `len` bytes from
address 0. This is exactly the hazard the new `out_bytes_or_return_int!` macro was introduced to
close, and every other out-parameter site in the file was converted — I grepped all four remaining
`to_c_bytes` call sites; this is the only unconverted one (`c_api.rs:3051` returns the pointer
directly, where NULL is the documented error signal).

**Fix:**

```rust
let result_bytes = ok_or_return_int!(result);
out_bytes_or_return_int!(result_bytes, result_bytes_ptr)
```

The `ptr_or_return_int!(result_bytes_ptr)` on `c_api.rs:2592` then makes the macro's own null check
redundant but harmless; drop it if you want the "pass NULL to query the length" behaviour the sibling
functions document.

Placement: inline on `c_api.rs:2606`.

---

### 4. HIGH — the signer is checked out exclusively, and the doc says the opposite

`c_api.rs:2620-2628` (new doc block on `c2pa_signer_create`) states:

> A signer gets borrowed exclusively for the duration of the sign call (so callbacks do not run in
> parallel). If a signer is shared across multiple calls, they serialize to make sure they can't
> interfere with each other.

They do not serialize. `deref_mut_or_return_int!(signer_ptr, C2paSigner)` at `c_api.rs:2030` and
`c_api.rs:2176` takes `EXCLUSIVE`, and a second caller waits out `WRITER_WAIT` and then **fails**.
T10 measures it: with one thread holding the signer for a 300ms "sign", the second
`checkout_exclusive` returned `PointerInUse` after **10.004ms**. Signing is exactly the operation
most likely to be slow (TSA round trip, remote signer HTTP), and one signer shared across a worker
pool is the normal way to use this API. Under this PR that pattern returns errors.

The exclusivity isn't needed: `c2pa_builder_sign` only does `c2pa_signer.signer.as_ref()`
(`c_api.rs:2033`), and `c2pa_builder_sign_data_hashed_embeddable` likewise (`c_api.rs:2192`). The
same type is already checked out *shared* at `c_api.rs:3014`, which proves `C2paSigner: Sync` and
that the change compiles.

**Fix:**

```rust
// c_api.rs:2030 and c_api.rs:2176
let c2pa_signer = deref_or_return_int!(signer_ptr, C2paSigner);
```

and rewrite the doc block to say what the code then does: a signer may be used by any number of
concurrent calls; what is refused is a call that arrives while the signer is being *consumed*
(`c2pa_identity_signer_create*`).

While there: `c_api.rs:2591` takes the builder exclusively for `Builder::compose_manifest`, which is
`&self` (`sdk/src/builder.rs:3640`) — another leftover from the shared/exclusive sweep. (I checked
`Builder::sign`: it is genuinely `&mut self` at `sdk/src/builder.rs:3263`, so the builder's exclusive
checkout in `c2pa_builder_sign` is right.)

Placement: inline on `c_api.rs:2030`, `c_api.rs:2176`, `c_api.rs:2591`, and on the doc block.

---

### 5. MEDIUM — the wait is a busy-spin, and readers starve

`try_borrow_shared` (`utils.rs:130-158`) and `try_borrow_exclusive_slow` (`utils.rs:182-247`) both
spin on `std::thread::yield_now()` until a deadline. Two consequences, both measured:

- **It burns a core.** T12: 100 refused exclusive checkouts across 4 threads cost 250ms wall and
  **0.24s CPU** — the wait is ~100% spin, no idling. Each refused caller burns up to 10ms of CPU
  before being told "no".
- **Readers starve under sustained write load.** The `WRITER_PENDING` bit refuses *new* readers while
  a writer waits, which is deliberate (it's what lets a consuming call through). The cost is visible
  in T2: writers were refused 447 times out of ~315k attempts (0.1%), readers 5976 times out of
  ~7800 (76%). And T5: with one long exclusive borrow live, **20 of 20** reader checkouts failed,
  each after ~1.0ms of spinning. Translated to the API: while `c2pa_builder_sign` runs, every
  concurrent `c2pa_builder_*` read on that builder fails, and the C caller cannot distinguish that
  from a real error.

Neither is a livelock in the strict sense — progress is guaranteed and I could not construct a
starvation loop — but a C caller that retries on `PointerInUse` (the obvious reaction) gets a retry
loop that burns CPU proportional to contention.

**Fix.** Replace the deadline spins with a `Condvar` on the entry: waiters park, and
`SharedCheckout::drop` / `ExclusiveCheckout::drop` notify. That removes the CPU burn, removes the
arbitrary 1ms/10ms constants, and turns "refused" into "waited its turn", which is what the docs
already claim happens. Keep a (much longer) timeout if you want a hard upper bound on a wedged C
callback, and keep the current immediate-refusal behaviour under `cfg(target_arch = "wasm32")` where
there is no other thread to wait for.

If a `Condvar` is out of scope for this PR, then at minimum: document the refusal semantics on every
`extern "C"` function that can return `PointerInUse` (right now `C2PA_POINTER_IN_USE` is a code a C
caller can receive from almost any function, with no guidance), and say in the header that it is
retryable.

Placement: review body (the design point), plus inline on `utils.rs:120-126` where the constants are
defined.

---

### 6. MEDIUM — no canonical ordering across a call's checkouts

`untrack_pair` (`utils.rs:762-769`) explicitly canonicalises to lower-id-first, with a good comment
explaining why. `c2pa_builder_sign` does not: it takes builder → source → dest → signer in caller
order (`c_api.rs:2026-2030`). Two threads calling with source/dest swapped each grab one stream and
wait out the other. T4: 199 mutual `PointerInUse` aborts against 16903 successes over 2s. Bounded,
so not a deadlock, but it's the retry-forever shape from finding 5 with a mutual-abort generator
attached.

`distinct_or_return_int!` correctly covers same-handle aliasing — I checked all three functions taking
two `*mut C2paStream` (`c2pa_reader_with_fragment:1210`, `c2pa_builder_sign:2017`,
`c2pa_builder_sign_context:2070`) and all three have it — but distinctness is a different property
from ordering.

**Fix.** Add the pair helper next to `untrack_pair` and use it for the two same-type stream
parameters:

```rust
/// Check out two handles of the same type, lower id first, so two calls with
/// the arguments reversed can't each hold one and wait out the other.
#[must_use = "the borrows end when the returned guards are dropped"]
pub fn checkout_exclusive_pair<T: 'static + MaybeSend>(
    first: *mut T,
    second: *mut T,
) -> Result<(TypedExclusive<T>, TypedExclusive<T>), Error> {
    if (first as usize) < (second as usize) {
        let a = checkout_exclusive::<T>(first)?;
        let b = checkout_exclusive::<T>(second)?;
        Ok((a, b))
    } else {
        let b = checkout_exclusive::<T>(second)?;
        let a = checkout_exclusive::<T>(first)?;
        Ok((a, b))
    }
}
```

(The early `?` is safe: the first guard drops on the error path and releases its borrow.)

Placement: inline on `c_api.rs:2028-2029` and `c_api.rs:2080-2081`.

---

### 7. MEDIUM — two error codes silently changed meaning

`cimpl/cimpl_error.rs:75-82`:

| Code | Before this PR | After |
|------|----------------|-------|
| 6 | `MutexPoisoned` (constructor deleted) | `INVALID_BUFFER_SIZE` |
| 7 | `InvalidBufferSize` | `POINTER_IN_USE` |

A C caller that switches on the numeric code keeps compiling and starts mis-handling errors. This is
a second, undocumented ABI break alongside the `C2paStream` one the PR description calls out.

**Fix:** keep `INVALID_BUFFER_SIZE = 7`, retire 6 with a comment saying it was `MutexPoisoned` and
must not be reused, and give the four new conditions fresh numbers (11-14). `error.rs:80-90` maps the
same values and needs the matching edit. If the renumbering is intentional, it belongs in the PR
description next to the `C2paStream` break, and the commit subject needs `feat!:` / a
`BREAKING CHANGE:` footer so release-plz bumps correctly — the commit subject is the changelog entry
here, so that's the only place it can be recorded.

Placement: inline on `cimpl/cimpl_error.rs:81-82`.

---

### 8. Minor / nits

- **`Box::leak` per signer** (`c_api.rs:2914`). Documented as deliberate ("the cost of matching that
  trait"), but it is unbounded: a host that creates a signer per request leaks a string per request.
  `CredentialHolder::sig_type` returning `&'static str` is the real constraint — worth an issue
  against the identity crate rather than a permanent leak here. At minimum, intern the handful of
  known `sig_type` values and only leak on an unrecognised one.
- **`SharedCheckout` / `ExclusiveCheckout` are re-exported** (`cimpl/mod.rs:74-77`) but have no public
  constructor, no `Deref`, and no accessor. They're unusable downstream; exporting only the typed
  guards would keep the surface honest.
- **`untrack_or_return!` evaluates `$ptr` twice** (`macros.rs:442-444`: once in `ptr_or_return!`, once
  in `untrack_owned`). Same nit as `deref_or_return!` in round 1. Bind it first.
- **`out_bytes_or_return_int!` leaves `*out_ptr` untouched on its `-1` path** (`macros.rs:752-763`).
  A C caller that doesn't zero-initialise its out-param and ignores the return reads a stale pointer.
  Write NULL before returning -1.
- **`free()` deliberately takes no borrow**, so a `cimpl_free` that lands between another thread's
  `lookup` and its `try_borrow_*` lets that call proceed on a handle C considers freed (the object
  stays alive under the guard, so it is memory-safe — T3 confirms). That's the right trade, but it
  is the one place where the "a thread can't release something it doesn't own" framing in the PR
  description overstates what's enforced: ownership is protected, visibility isn't. Worth one
  sentence in the registry doc.

---

## Verdict

The concurrency model is correct as far as I can drive it, and the two round-2 HIGHs and all three
round-3 blockers are genuinely fixed, not papered over. What's left is one pre-existing heap-corruption
bug in the signer callback (finding 1), one reproduced double-free-by-proxy in the address-keyed half
of the registry (finding 2), one missed conversion (finding 3), and a cluster of ergonomics problems
where the refusal semantics are stricter than the docs claim and stricter than callers will expect
(findings 4-6). Findings 1 and 3 are small enough to land in this PR; finding 2 and the `Condvar`
rework in finding 5 are each their own change.

Per the standing note on this repo, no CHANGELOG edits are proposed — release-plz generates it from
commit subjects, which is why finding 7 asks for `feat!:` or a `BREAKING CHANGE:` footer instead.

---

## Appendix — reproducing

The harness lives in `/home/claude/harness` in this session. To rebuild it from a checkout:

```bash
git clone https://github.com/contentauth/c2pa-rs.git && cd c2pa-rs
git checkout mathern/c_ffi_opaque_ids_concurrent
# copy c2pa_c_ffi/src/cimpl/utils.rs (minus its #[cfg(test)] module) into a fresh bin crate as
# src/registry.rs, add the shim module below, then: cargo run --release
```

`src/shim.rs` supplies the four imports `utils.rs` needs — `MaybeSend`/`MaybeSync` as blanket
`Send`/`Sync` traits, and `Error`/`CimplError` as newtypes over `String` with the constructor names
the registry calls (`foreign_process`, `null_parameter`, `wrong_pointer_type`, `untracked_pointer`,
`pointer_in_use`, `wrong_wrapper_kind`, `tracking_refused`, `invalid_buffer_size`, `other`,
`set_last`). On a toolchain ≥ 1.87 no source edits to `utils.rs` are needed at all.

The twelve checks are described inline in the run output above; the two that found bugs are T7
(address ABA, finding 2) and T10 (shared-signer refusal, finding 4). T2/T4/T5/T12 produce the
contention numbers quoted in finding 5 — note that T2's ratios swing with scheduling (the container
has one core); the writer/reader asymmetry was stable across every run, the absolute counts were not.
