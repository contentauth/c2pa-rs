# C2PA C API

This is the C API wrapper for the [C2PA Rust SDK](../sdk). It provides a C-compatible interface for working with Content Credentials, and supports the same formats as Rust. 
You can also use this crate in Rust code to write C-compatible bindings with the exposed types.

## Overview

The C2PA C API enables you to integrate content authenticity features into an application using C or any language that can interface with C libraries.

The code in `c2pa_c_ffi` provides a standard exported C-based interface.
Dynamic library binaries for Linux, macOS, and Windows export this API.
Consumers can use the API without any specific knowledge of Rust, following well-known rules for linking to C-based libraries.

### Change from previous versions

The C interface was previously part of the `c2pa-c` repo, which has been renamed to `c2pa-cpp` to clarify that it provides a C++ API. The C interface is useful to other bindings, so it was exported as a Rust JSON API. But that led to things like `c2pa-python` importing from `c2pa-c` and then re-exporting a Python API via [UniFFI](https://mozilla.github.io/uniffi-rs/latest/). The UniFFI tools have severe limitations in what they represent, such as the inability to have mutable parameters, and there are other limitations with the tools for binding Rust to C++, Swift, and other languages. 

However, binding to C APIs is a well-established and mature practice. Every language has well-documented methods for binding to C, and Rust has built-in support for it. A solid C interface enables leveraging that work to provide other language bindings.

Bindings must still be written for each language, but since there are so many examples of this, AI engines are very good at writing the code, resulting in well-formed, well-documented bindings, though some manual effort is required to fix some things. Instead of unreadable, incomprehensible auto-generated binding glue, the result is well-structured code bindings that can be customized as needed.

### Caveats

The C language is not object-oriented, does not perform garbage collection, and does not natively support things like exception handling. The API may use unsafe pointer references, so take care with pointers and memory management.

For these reasons, you shouldn't use the C API directly for application code. Instead, use higher-level structures in other languages to ensure that references to native structures are correctly managed and freed.

## Building locally

Pre-requisite: You must have the Rust toolchain (cargo) installed.

To build and test locally, run:

```sh
make test
```

The build will have two features activated: `rust_native_crypto` and `file_io`.
Note that running the `make test` command will also check formatting of the code.

## Progress and cancellation

During multi-step long-running operations (such as signing, reading, and verification), the SDK reports progress via an optional callback registered on a `Context`. The primary purposes of the callback are:

- **Liveness**: confirming to the caller that the SDK is still making forward progress and is not hung.
- **Cancellation**: giving the caller a safe opportunity to stop the operation at any phase boundary.

The callback receives the current phase, a step counter, and an optional total. Returning `0` from the callback requests cancellation; the SDK will stop at the next safe checkpoint and return an `OperationCancelled` error.

You can also request cancellation externally (from a different thread) by calling `c2pa_context_cancel()` without going through the callback at all.

> [!WARNING]
> Do not use this API for time-remaining estimates. A raw step count does not reliably translate into elapsed or remaining time.

For the full progress and cancellation API reference (including the Rust API), see [Progress and cancellation API](../docs/progress_callbacks.md).

### Phase constants

The SDK reports progress as a sequence of named phases. Define these constants in your application (or include the generated SDK header):

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

> [!NOTE]
> `ProgressPhase` is marked `#[non_exhaustive]` in Rust. Future SDK versions may add new phases, so always include a `default` arm in any `switch` statement.

#### Typical phase sequences

**Signing a new asset:**
`AddingIngredient` (0-N times) -> `Thumbnail` -> `Hashing` -> `Signing` -> `Writing` -> `Embedding`

**Reading / verifying an existing asset:**
`Reading` -> `VerifyingManifest` -> `VerifyingSignature` (x2 steps per claim) -> `VerifyingIngredient` (xN) -> `VerifyingAssetHash`

### Callback signature

```c
typedef int (*C2paProgressCallback)(
    const void *user_data,   /* opaque pointer supplied by the caller          */
    uint8_t     phase,       /* numeric ProgressPhase discriminant             */
    uint32_t    step,        /* monotonically increasing step counter (1-based) */
    uint32_t    total        /* 0=indeterminate, 1=single-shot, >1=determinate */
);
```

- `phase`: the current phase (see constants above). Callers should derive user-visible text from this value; no localized string is provided by the SDK.
- `step`: monotonically increasing counter within the current phase, starting at `1`. Resets to `1` at the start of each new phase. Use it as a liveness heartbeat: as long as `step` keeps rising, the SDK is making progress. Do not assume any particular unit; for example, `Hashing` uses chunk index and `VerifyingIngredient` uses ingredient index. The unit is phase-specific and may change between SDK versions.
- `total`: interpreted as follows:
  - `0`: indeterminate; the total is not known in advance. Display a spinner and use the rising `step` value as a liveness signal.
  - `1`: single-shot phase; the callback itself is the notification. No subdivision is meaningful.
  - `> 1`: determinate; `step / total` gives a completion fraction suitable for a progress bar.
- Return non-zero to continue, zero to cancel.

> [!NOTE]
> Do not call SDK functions from inside the progress callback.

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

### Examples

#### Simple progress display

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

#### Cancellation from a GUI thread

A common pattern is to sign or read on a background worker thread while letting the main/UI thread cancel the operation when the user clicks a **Cancel** button. The C API supports this by allowing `c2pa_context_cancel()` to be called from any thread.

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

#### Tracking per-ingredient verification progress

`VerifyingIngredient` is a multi-step phase: `step` is the 1-based ingredient index and `total` is the number of ingredients. This lets you show a determinate progress bar during verification.

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

Similarly, `VerifyingSignature` fires with `total=2`: step one before COSE parsing and step two after full OCSP/signature verification.

## Error handling

When either the callback returns zero or `c2pa_context_cancel()` is called, the ongoing operation returns an error. Callers should check for the `OperationCancelled` error and treat it as a normal, user-initiated termination rather than a failure.

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
