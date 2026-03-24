# Progress and Cancellation API

## Overview

The SDK reports progress during multistep long-running operations (signing, reading, verification) via an optional callback registered on a `Context`. The primary purposes of the callback are:

1. **Liveness** — confirming to the caller that the SDK is still making forward progress and is not hung.
2. **Cancellation** — giving the caller a safe opportunity to stop the operation at any phase boundary.

The callback receives the current phase, a step counter, and an optional total. It is not designed as a basis for time-remaining estimates; individual phases can take anywhere from microseconds to seconds depending on asset size and hardware, so a raw step count cannot be reliably translated into elapsed or remaining time.

Returning `false` (or `0` in C) from the callback requests cancellation; the SDK will stop at the next safe checkpoint and return `Error::OperationCancelled`.

Cancellation can also be requested externally — from a different thread — by calling `Context::cancel()` / `c2pa_context_cancel()` without going through the callback at all.

---

## Phases

Progress is reported as a sequence of named phases, each represented by the `ProgressPhase` enum (`#[repr(u8)]` for stable FFI values):

| Value | Rust variant | When it fires |
|-------|-------------|---------------|
| 0 | `Reading` | Parsing and extracting JUMBF manifest data from an asset stream |
| 1 | `VerifyingManifest` | Verifying the structure and integrity of a manifest store entry |
| 2 | `VerifyingSignature` | Verifying a COSE signature and certificate chain (fires twice per claim: step 1 before COSE parse, step 2 after OCSP/full verification) |
| 3 | `VerifyingIngredient` | Verifying one ingredient's embedded manifest (step = ingredient index, total = total ingredient count) |
| 4 | `VerifyingAssetHash` | Re-hashing the asset bytes to verify hash-binding assertions |
| 5 | `AddingIngredient` | Adding an ingredient to the manifest being built |
| 6 | `Thumbnail` | Generating a thumbnail during signing |
| 7 | `Hashing` | Hashing asset data to build the hash-binding assertion |
| 8 | `Signing` | Signing the claim with COSE (including any remote TSA timestamp fetch) |
| 9 | `Embedding` | Embedding the signed JUMBF manifest store into the output asset |
| 10 | `FetchingRemoteManifest` | Fetching a remote manifest over the network |
| 11 | `Writing` | Streaming the asset with the placeholder JUMBF to the output stream |

### Typical phase sequences

**Signing a new asset:**
`AddingIngredient` (0–N times) → `Thumbnail` → `Hashing` → `Signing` → `Writing` → `Embedding`

**Reading / verifying an existing asset:**
`Reading` → `VerifyingManifest` → `VerifyingSignature` (×2 steps per claim) → `VerifyingIngredient` (×N) → `VerifyingAssetHash`

---

## Callback Signature

### Rust

```rust
fn(phase: ProgressPhase, step: u32, total: u32) -> bool
```

- `phase` — the current phase (see table above). Callers should derive user-visible text from this value; no localised string is provided by the SDK.
- `step` — monotonically increasing counter within the current phase, starting at `1`. Resets to `1` at the start of each new phase. Use it as a liveness heartbeat: as long as `step` keeps rising, the SDK is making progress. Do not assume any particular unit (bytes, chunks, etc.) — the unit is phase-specific and may change between SDK versions.
- `total` — interpreted as follows:
  - `0` — indeterminate; the total is not known in advance. Display a spinner and use the rising `step` value as a liveness signal.
  - `1` — single-shot phase; the callback itself is the notification. No subdivision is meaningful.
  - `> 1` — determinate; `step / total` gives a completion fraction suitable for a progress bar.
- Return `true` to continue, `false` to cancel.

The closure must be `Send + Sync` on non-WASM targets. On WASM (single-threaded) those bounds are not required.

### C

```c
typedef int (*C2paProgressCallback)(
    const void *user_data,   /* opaque pointer supplied by the caller          */
    uint8_t     phase,       /* numeric ProgressPhase discriminant             */
    uint32_t    step,        /* monotonically increasing step counter (1-based) */
    uint32_t    total        /* 0=indeterminate, 1=single-shot, >1=determinate */
);
```

Return non-zero to continue, zero to cancel.

---

## Rust API

### Setting a callback (builder pattern)

```rust
use c2pa::{Context, ProgressPhase};

let ctx = Context::new()
    .with_progress_callback(|phase, step, total| {
        match phase {
            ProgressPhase::Hashing => {
                // total may be 0 (indeterminate) for streaming assets
                if total > 0 {
                    println!("Hashing: {}/{}", step, total);
                } else {
                    println!("Hashing…");
                }
            }
            ProgressPhase::Signing => println!("Signing…"),
            _ => println!("{:?}", phase),
        }
        true // return false to cancel
    });
```

### Setting a callback (mutable setter, for FFI adapters)

```rust
use c2pa::{Context, ProgressPhase};

let mut ctx = Context::new();
ctx.set_progress_callback(|phase, step, total| {
    println!("{phase:?} {step}/{total}");
    true
});
```

### Out-of-band cancellation from another thread

```rust
use c2pa::Context;
use std::sync::Arc;

let ctx = Arc::new(Context::new());
let ctx_bg = ctx.clone();

// In another thread (e.g. when the user clicks "Cancel"):
std::thread::spawn(move || {
    ctx_bg.cancel();
});

// The signing or reading operation using `ctx` will return
// Err(Error::OperationCancelled) at the next safe checkpoint.
```

Both mechanisms can be combined: the callback can cancel based on phase or elapsed time, while the flag lets any thread cancel at any point.

---

## C API

### Functions

```c
/**
 * Attach a progress callback to a context builder.
 *
 * @param builder   A valid C2paContextBuilder pointer (not yet built).
 * @param user_data Opaque void* passed as the first argument on every callback
 *                  invocation. Pass NULL if the callback needs no user data.
 *                  Must remain valid for the entire lifetime of the built context.
 * @param callback  Function pointer matching C2paProgressCallback.
 * @return 0 on success, non-zero on error (call c2pa_error() for details).
 */
int c2pa_context_builder_set_progress_callback(
    C2paContextBuilder         *builder,
    const void                 *user_data,
    C2paProgressCallback        callback
);

/**
 * Request cancellation of any in-progress operation on this context.
 *
 * Thread-safe — may be called from any thread that holds a valid C2paContext
 * pointer. The SDK returns an OperationCancelled error at the next safe
 * checkpoint.
 *
 * @param ctx A valid, non-null C2paContext pointer.
 * @return 0 on success, non-zero if ctx is null or invalid.
 */
int c2pa_context_cancel(C2paContext *ctx);
```

### Phase constants

Define these in your application (or include the generated SDK header):

```c
#define C2PA_PHASE_READING                 0
#define C2PA_PHASE_VERIFYING_MANIFEST      1
#define C2PA_PHASE_VERIFYING_SIGNATURE     2
#define C2PA_PHASE_VERIFYING_INGREDIENT    3
#define C2PA_PHASE_VERIFYING_ASSET_HASH    4
#define C2PA_PHASE_ADDING_INGREDIENT       5
#define C2PA_PHASE_THUMBNAIL               6
#define C2PA_PHASE_HASHING                 7
#define C2PA_PHASE_SIGNING                 8
#define C2PA_PHASE_EMBEDDING               9
#define C2PA_PHASE_FETCHING_REMOTE_MANIFEST 10
#define C2PA_PHASE_WRITING                 11
```

---

### Example 1: Simple progress display

```c
#include <stdio.h>
#include "c2pa.h"

static const char *phase_label(uint8_t phase) {
    switch (phase) {
        case C2PA_PHASE_READING:                  return "Reading";
        case C2PA_PHASE_VERIFYING_MANIFEST:       return "Verifying manifest";
        case C2PA_PHASE_VERIFYING_SIGNATURE:      return "Verifying signature";
        case C2PA_PHASE_VERIFYING_INGREDIENT:     return "Verifying ingredient";
        case C2PA_PHASE_VERIFYING_ASSET_HASH:     return "Verifying asset hash";
        case C2PA_PHASE_ADDING_INGREDIENT:        return "Adding ingredient";
        case C2PA_PHASE_THUMBNAIL:                return "Generating thumbnail";
        case C2PA_PHASE_HASHING:                  return "Hashing";
        case C2PA_PHASE_SIGNING:                  return "Signing";
        case C2PA_PHASE_EMBEDDING:                return "Embedding";
        case C2PA_PHASE_FETCHING_REMOTE_MANIFEST: return "Fetching remote manifest";
        case C2PA_PHASE_WRITING:                  return "Writing";
        default:                                  return "Unknown";
    }
}

/* Return non-zero to continue; zero to cancel. */
static int my_progress_cb(const void *user_data,
                           uint8_t phase,
                           uint32_t step,
                           uint32_t total)
{
    (void)user_data; /* unused in this example */

    if (total == 0) {
        /* Indeterminate — show a spinner label */
        printf("[...] %s\n", phase_label(phase));
    } else if (total == 1) {
        /* Single-shot phase */
        printf("[---] %s\n", phase_label(phase));
    } else {
        /* Multi-step phase — render a simple bar */
        int pct = (int)((double)step / (double)total * 100.0);
        printf("[%3d%%] %s %u/%u\n", pct, phase_label(phase), step, total);
    }
    return 1; /* continue */
}

int main(void) {
    C2paContextBuilder *builder = c2pa_context_builder_new();

    if (c2pa_context_builder_set_progress_callback(builder, NULL, my_progress_cb) != 0) {
        fprintf(stderr, "set_progress_callback: %s\n", c2pa_error());
        c2pa_free(builder);
        return 1;
    }

    C2paContext *ctx = c2pa_context_builder_build(builder);
    /* builder is consumed — do not use it after this point */

    /* Use ctx with c2pa_reader_new() / c2pa_builder_sign() … */

    c2pa_free(ctx);
    return 0;
}
```

---

### Example 2: Cancellation from a GUI thread

A common pattern is to sign or read on a background worker thread while letting the main/UI thread cancel the operation when the user clicks a "Cancel" button. The C API supports this by allowing `c2pa_context_cancel()` to be called from any thread.

```c
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include "c2pa.h"

/* Shared state visible to both the worker and the UI thread. */
typedef struct {
    C2paContext   *ctx;          /* protected by a mutex in real code    */
    atomic_int     user_cancelled; /* set by the UI thread               */
} WorkerState;

/* Progress callback — checks the user_cancelled flag each phase. */
static int cancel_aware_cb(const void *user_data,
                            uint8_t phase,
                            uint32_t step,
                            uint32_t total)
{
    const WorkerState *state = (const WorkerState *)user_data;
    (void)step; (void)total;

    printf("Phase %u\n", (unsigned)phase);

    if (atomic_load(&state->user_cancelled)) {
        printf("User requested cancel — stopping at phase %u.\n", (unsigned)phase);
        return 0; /* cancel */
    }
    return 1; /* continue */
}

/* Out-of-band cancel: the UI thread sets this when the user clicks Cancel. */
void ui_thread_on_cancel(WorkerState *state) {
    atomic_store(&state->user_cancelled, 1);

    /* Belt-and-suspenders: also set the cancel flag on the context so that
       cancellation fires even between callback checkpoints. */
    c2pa_context_cancel(state->ctx);
}

void *worker_thread(void *arg) {
    WorkerState *state = (WorkerState *)arg;

    C2paContextBuilder *builder = c2pa_context_builder_new();
    c2pa_context_builder_set_progress_callback(builder, state, cancel_aware_cb);

    state->ctx = c2pa_context_builder_build(builder);
    /* builder consumed */

    /* Sign or read using state->ctx … */
    /* If cancelled, the operation returns an OperationCancelled error. */

    c2pa_free(state->ctx);
    state->ctx = NULL;
    return NULL;
}
```

**Key points:**
- `c2pa_context_cancel()` is thread-safe and may be called while a signing or reading operation is in progress.
- The callback return value and the cancel flag are checked at the same checkpoint; either one is sufficient to stop the operation.
- Using both (as in the example above) ensures the fastest possible response to a cancellation request.

---

### Example 3: Tracking per-ingredient verification progress

`VerifyingIngredient` is a multi-step phase — `step` is the 1-based ingredient index and `total` is the number of ingredients. This lets you show a determinate progress bar during deep verification.

```c
static int ingredient_progress_cb(const void *user_data,
                                   uint8_t phase,
                                   uint32_t step,
                                   uint32_t total)
{
    if (phase == C2PA_PHASE_VERIFYING_INGREDIENT && total > 0) {
        int pct = (int)((double)step / (double)total * 100.0);
        /* Update a GUI progress bar to `pct`. */
        update_progress_bar((int *)user_data, pct);
    }
    return 1;
}
```

Similarly, `VerifyingSignature` fires with `total=2`: step 1 before COSE parsing and step 2 after full OCSP/signature verification.

---

## Error handling

When either the callback returns zero (C) / `false` (Rust), or `cancel()` is called, the ongoing operation returns `Error::OperationCancelled` (Rust) or a corresponding C error string via `c2pa_error()`. Callers should check for this specific error and treat it as a normal, user-initiated termination rather than a failure.

```rust
match builder.sign(ctx, format, input, output) {
    Ok(_) => { /* success */ }
    Err(c2pa::Error::OperationCancelled) => { /* user cancelled — clean up and continue */ }
    Err(e) => { /* real error */ }
}
```

```c
if (c2pa_builder_sign(builder, ctx, ...) != 0) {
    const char *err = c2pa_error();
    if (strstr(err, "OperationCancelled")) {
        /* user cancelled */
    } else {
        fprintf(stderr, "Sign failed: %s\n", err);
    }
}
```

---

## Notes

- **Purpose** — callbacks are liveness and cancellation checkpoints, not a time-remaining API. Do not use `step`/`total` to estimate how long an operation will take; phase durations vary widely with asset size and hardware.
- **`step` semantics** — `step` is monotonically increasing within a phase and resets to `1` at the start of each new phase. Its unit is phase-specific (e.g. chunk index for `Hashing`, ingredient index for `VerifyingIngredient`) and should be treated as opaque unless `total > 1`, in which case `step / total` is a meaningful fraction.
- **Thread safety** — on non-WASM targets the Rust callback closure must be `Send + Sync`. C function pointers are inherently `Send + Sync`. The `user_data` pointer passed to the C API must remain valid for the entire lifetime of the context and must be safe to access from whichever thread runs the operation.
- **No re-entrancy** — do not call SDK functions from inside the progress callback.
- **`#[non_exhaustive]`** — `ProgressPhase` is marked `#[non_exhaustive]`. Future SDK versions may add new phases; always include a default/wildcard arm in any match or switch statement.