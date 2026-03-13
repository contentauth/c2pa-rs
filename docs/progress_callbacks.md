# Progress Callback API

## Overview

The SDK reports progress during long-running operations (signing, reading, verification) via an optional callback on `Context`. The callback receives the current phase and a completion fraction. Returning `false` (or `0` in C) requests cancellation; the operation stops at the next safe point and returns `Error::OperationCancelled`.

## Rust API

**Types:**
- `ProgressPhase` – enum of phases: `Ingredients`, `Thumbnail`, `Hashing`, `Signing`, `Embedding`, `Verification`, `RemoteFetch` (`#[repr(u8)]` for FFI)
- `ProgressCallbackFunc` – `dyn Fn(ProgressPhase, f32) -> bool` (closure type)

**Context methods:**
- `with_progress_callback(callback)` – set the callback (builder pattern)
- `set_progress_callback(callback)` – set the callback (mutable)
- `cancel()` – request cancellation from any thread
- `is_cancelled()` – check if cancellation was requested

**Callback signature:** `(phase: ProgressPhase, pct: f32) -> bool`
- `phase` – current phase (caller maps to localized text)
- `pct` – fraction complete in range 0.0–1.0 (e.g. 0.75 = 75%)
- Return `true` to continue, `false` to cancel

**Example:**
```rust
let ctx = Context::new()
    .with_progress_callback(|phase, pct| {
        println!("{:?} {:.0}%", phase, pct * 100.0);
        true  // return false to cancel
    });

let ctx = Arc::new(ctx);
// From another thread: ctx.cancel();
```

## C FFI

- `c2pa_context_builder_set_progress_callback(builder, user_data, callback)` – attach callback and user data
- `c2pa_context_cancel(ctx)` – request cancellation

**C callback:** `int (*)(void* context, uint8_t phase, float pct)`
- Return non-zero to continue, zero to cancel
- `phase` matches `ProgressPhase` discriminants (0–6)
- `pct` is 0.0–1.0

## When It Fires

Callbacks fire at phase boundaries during Builder and Reader operations (e.g. after ingredients, thumbnail, hashing, signing, embedding). There are no callbacks inside long I/O loops yet; finer-grained progress would require additional implementation work.
