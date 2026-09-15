# The asset transport layer

This guide describes `asset_transport`: the abstraction `Reader` uses to get asset bytes, instead of opening the local filesystem directly.

**This layer only reads today.** There is no write path. `SyncAssetTransport` and `AsyncAssetTransport` each expose one method, `open`/`open_async`, and both trait docs say so directly: a write path would arrive as further methods on the same traits, not a redesign.

## Overview

A request to read asset bytes builds an `AssetRequest` and hands it to whatever transport is configured on the `Context`: the local filesystem by default, or a caller-supplied transport for anything else (an in-memory buffer, a network fetch, a custom store). The reader code does not know which: it gets handed bytes.

A transport is the byte-moving layer below a resolver. It moves bytes and does not interpret references. `ResourceResolver`, which resolves manifest-internal identifiers rather than external assets, is a separate thing and stays as is.

## The traits

```rust
pub trait SyncAssetTransport: MaybeSend + MaybeSync {
    fn open(&self, request: &AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError>;
}

pub trait AsyncAssetTransport: MaybeSend + MaybeSync {
    async fn open_async(&self, request: &AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError>;
}
```

## `AssetRef` and `AssetRequest`

`AssetRef` names what to open:

- `Path(&Path)`: a filesystem path.
- `Uri(&str)`: an absolute URI.
- `Custom(&str)`: a reference whose shape only the (related custom) handler understands.

`AssetRequest` wraps an `AssetRef` with an `AssetRequestKind`: `Asset` (the default) or `Sidecar`. A transport that keys on the reference (a real filesystem path, a real URL) does not need this. A transport that does not (one wired to a single in-memory buffer, say) does: without it, a sidecar lookup for a manifest-less asset would get the asset bytes back a second time, mistaken for a manifest.

## The local filesystem transport

`LocalAssetTransport` is the default. Unrooted, it opens `Path`, `Custom` (treated as a path), and `file:` `Uri` references directly. Rooted (`LocalAssetTransport::rooted_at(root)`), it confines every reference to `root`, rejecting anything outside it with `AssetTransportError::OutsideRoot`.

**A build without `file_io` still has a default transport, and it always refuses.** With `file_io` on, the default is the real local filesystem transport. With `file_io` off, the default is `UnconfiguredAssetTransport`. It refuses every read with `AssetTransportError::NotConfigured`. A build without `file_io` gets no local reads unless it registers its own transport.

## Registering an asset transport on `Context`

```rust
let context = Context::new()
    .with_asset_transport(MyTransport)
    .with_asset_transport_async(MyAsyncTransport);
```

`Context` tracks four states, and registering one kind never silently drops an explicitly registered transport of the other kind:

```mermaid
stateDiagram-v2
    [*] --> Default
    Default --> SyncOnly: set_asset_transport
    Default --> AsyncOnly: set_asset_transport_async
    SyncOnly --> Both: set_asset_transport_async
    AsyncOnly --> Both: set_asset_transport
    SyncOnly --> Default: clear_asset_transport
    AsyncOnly --> Default: clear_asset_transport_async
    Both --> AsyncOnly: clear_asset_transport
    Both --> SyncOnly: clear_asset_transport_async
```

`Default` means neither is registered. The sync path lazily builds the transport described above (local filesystem, or unconfigured). `with_*`/`set_*` add or replace a transport, `clear_*` drops one. Re-registering the same kind just replaces it in place.

Registering only an async transport opts the sync path out of the filesystem default. `Context::asset_transport()` then returns `Err(AssetTransportError::NoSyncTransport)`. It does not fall back to reading disk.

## How `Reader::with_file` uses it

For an asset with an embedded manifest, `with_file` does one open:

1. Build `AssetRequest::new(AssetRef::Path(path))`.
2. Open it: through the sync transport, or the async transport when reading async (falling back to sync if none is registered).
3. Parse a manifest store from the returned bytes.

A cancellation checkpoint sits before and after the primary open, and before the sidecar open, so `Context::cancel()` can interrupt a long transport read between operations.

## The transport and the HTTP resolver

Remote manifest fetching does not go through the asset transport. It goes through the HTTP resolver (`Context::resolver`/`resolver_async`, `http_resolve`), which is request/response shaped: it sends an `http::Request`, reads a capped `Vec` from the response, and applies the redirect and host allow-list hardening. The asset transport is seek shaped: it hands back a seekable stream of asset bytes.

So registering an asset transport does not redirect remote manifest fetching. A caller who wants their own network stack for both registers an async transport for assets and an async HTTP resolver for manifests.

The two relate by layering, not merging. A future HTTP-backed asset transport implements `AsyncAssetTransport` and delegates to `Context::resolver_async` internally, reusing that hardening rather than duplicating it, while manifest fetch stays on the resolver where the response shape fits.

## Errors

`AssetTransportError` distinguishes what went wrong: `NotFound`, `PermissionDenied`, `UnsupportedReference`, `OutsideRoot`, `NoSyncTransport`, `NotConfigured`, `Timeout`, `RangeNotSatisfiable`, plus `Io` and `Other` for anything else.
