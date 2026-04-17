# Progress and cancellation API

## Overview

During multi-step long-running operations (such as signing, reading, and verification), the SDK reports progress via an optional callback registered on a `Context`. The primary purposes of the callback are:

- **Liveness** — confirming to the caller that the SDK is still making forward progress and is not hung.
- **Cancellation** — giving the caller a safe opportunity to stop the operation at any phase boundary.

The callback receives the current phase, a step counter, and an optional total. Returning `false` from the callback requests cancellation; the SDK will stop at the next safe checkpoint and return `Error::OperationCancelled`.

You can also request cancellation externally (from a different thread) by calling `Context::cancel()` without going through the callback at all.

For the C API version of this interface, see the [C2PA C API README](../c2pa_c_ffi/README.md#progress-and-cancellation).

> [!WARNING]
> Do not use this API for time-remaining estimates. A raw step count does not reliably translate into elapsed or remaining time.

## Phases

The SDK reports progress as a sequence of named phases, each represented by the `ProgressPhase` enum:

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

> [!NOTE]
> `ProgressPhase` is marked `#[non_exhaustive]`. Future SDK versions may add new phases: Always include a default/wildcard arm in any `match` or `switch` statement.

### Typical phase sequences

**Signing a new asset:**
`AddingIngredient` (0–N times) → `Thumbnail` → `Hashing` → `Signing` → `Writing` → `Embedding`

**Reading / verifying an existing asset:**
`Reading` → `VerifyingManifest` → `VerifyingSignature` (×2 steps per claim) → `VerifyingIngredient` (×N) → `VerifyingAssetHash`

## Callback signature

```rust
fn(phase: ProgressPhase, step: u32, total: u32) -> bool
```

- `phase` — the current phase (see table above). Callers should derive user-visible text from this value; no localized string is provided by the SDK.
- `step` — monotonically increasing counter within the current phase, starting at `1`. Resets to `1` at the start of each new phase. Use it as a liveness heartbeat: as long as `step` keeps rising, the SDK is making progress. Do not assume any particular unit; for example, `Hashing` uses chunk index and `VerifyingIngredient` uses ingredient index. The unit is phase-specific and may change between SDK versions.
- `total` — interpreted as follows:
  - `0` — indeterminate; the total is not known in advance. Display a spinner and use the rising `step` value as a liveness signal.
  - `1` — single-shot phase; the callback itself is the notification. No subdivision is meaningful.
  - `> 1` — determinate; `step / total` gives a completion fraction suitable for a progress bar.
- Return `true` to continue, `false` to cancel.

The closure must be `Send + Sync` on non-WASM targets. On WASM (single-threaded) those bounds are not required.

> [!NOTE]
> Do not call SDK functions from inside the progress callback.

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

## Error handling

When the callback returns `false` or `cancel()` is called, the ongoing operation returns `Error::OperationCancelled`. Callers should check for this specific error and treat it as a normal, user-initiated termination rather than a failure.

```rust
match builder.sign(ctx, format, input, output) {
    Ok(_) => { /* success */ }
    Err(c2pa::Error::OperationCancelled) => { /* user cancelled — clean up and continue */ }
    Err(e) => { /* real error */ }
}
```
