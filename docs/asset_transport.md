# The asset transport layer

This guide describes `asset_transport`: the abstraction `Reader` uses to get asset bytes,
instead of opening the local filesystem directly.

**This layer only reads today.** There is no write path. `SyncAssetTransport` and
`AsyncAssetTransport` each expose one method, `open`/`open_async`, and both trait docs say so
directly: a write path would arrive as further methods on the same traits, not a redesign.
Everything below describes reading.

## Overview

Before `asset_transport`, `Reader::with_file` opened `std::fs::File` directly. Now it builds an
`AssetRequest` and hands it to whatever transport is configured on the `Context`: the local
filesystem by default, or a caller-supplied transport for anything else (an in-memory buffer, a
network fetch, a custom store). The reader code does not know or care which.

## The traits

```rust
pub trait SyncAssetTransport: MaybeSend + MaybeSync {
    fn open(&self, request: &AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError>;
}

pub trait AsyncAssetTransport: MaybeSend + MaybeSync {
    async fn open_async(&self, request: &AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError>;
}
```

Two traits, not one, because a sync implementation is not automatically usable from an async
context. WASM has no blocking I/O, so an async-only build needs `AsyncAssetTransport`. A plain
Rust caller reading from disk only needs `SyncAssetTransport`. A transport can implement both.

## `AssetRef` and `AssetRequest`

`AssetRef` names what to open:

- `Path(&Path)` - a filesystem path.
- `Uri(&str)` - an absolute URI.
- `Custom(&str)` - a reference whose shape only the handler understands. It is untrusted.
  The handler must guard against path traversal itself.

`AssetRequest` wraps an `AssetRef` with an `AssetRequestKind`: `Asset` (the default) or
`Sidecar`. A transport that keys on the reference (a real filesystem path, a real URL) does not
need this. A transport that does not (one wired to a single in-memory buffer, say) does: without
it, a sidecar lookup for a manifest-less asset would get the asset bytes back a second time,
mistaken for a manifest.

## The local filesystem transport

`LocalAssetTransport` is the default. Unrooted, it opens `Path`, `Custom` (treated as a path),
and `file:` `Uri` references directly. Rooted (`LocalAssetTransport::rooted_at(root)`), it
confines every reference to `root`, rejecting anything outside it with
`AssetTransportError::OutsideRoot`.

`rooted_at`'s containment is not atomic against an attacker who can write into `root` between
the check and the open. It is not a multi-tenant sandbox.

**A build without `file_io` still has a default transport, and it always refuses.** With
`file_io` on, the default is the real local filesystem transport. With `file_io` off, the
default is `UnconfiguredAssetTransport`. It refuses every read with
`AssetTransportError::NotConfigured`. A build without `file_io` gets no local reads unless it
registers its own transport.

## Registering a transport on `Context`

```rust
let context = Context::new()
    .with_asset_transport(MyTransport)
    .with_asset_transport_async(MyAsyncTransport);
```

`Context` tracks four states, and registering one kind never silently drops the other:

```mermaid
stateDiagram-v2
    [*] --> Default
    Default --> SyncOnly: set_asset_transport
    Default --> AsyncOnly: set_asset_transport_async
    SyncOnly --> Both: set_asset_transport_async
    AsyncOnly --> Both: set_asset_transport
```

`Default` means neither is registered. The sync path lazily builds the transport described
above (local filesystem, or unconfigured). Re-registering the same kind again just replaces
that transport in place. The diagram only shows the moves between states.

Registering only an async transport opts the sync path out of the filesystem default.
`Context::asset_transport()` then returns `Err(AssetTransportError::NoSyncTransport)`.
It does not fall back to reading disk.

## How `Reader::with_file` uses it

For an asset with an embedded manifest, `with_file` does one open:

1. Build `AssetRequest::new(AssetRef::Path(path))`.
2. Open it: through the sync transport, or the async transport when reading async (falling back
   to sync if none is registered).
3. Parse a manifest store from the returned bytes.

When there is no embedded manifest, a second open follows: a sidecar request for the same path
with a `.c2pa` extension and `AssetRequestKind::Sidecar`, through the same transport. A sidecar
`NotFound` becomes `JumbfNotFound` (no manifest at all). Anything returned is checked against a
real JUMBF superbox header before it is trusted, since a transport that ignores the request
reference could otherwise answer the sidecar request with the asset bytes again.

A cancellation checkpoint sits before and after the primary open, and before the sidecar open, so
`Context::cancel()` can interrupt a long transport read between operations.

## Errors

`AssetTransportError` distinguishes what went wrong: `NotFound`, `PermissionDenied`,
`UnsupportedReference`, `OutsideRoot`, `NoSyncTransport`, `NotConfigured`, `Timeout`,
`RangeNotSatisfiable`, plus `Io` and `Other` for anything else. Across the C FFI these carry
their own codes (118 and up), separate from the generic I/O code (105) a missing or unreadable
asset used before this layer existed.
