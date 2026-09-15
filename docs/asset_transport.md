# The asset transport layer

This guide describes `asset_transport`: the abstraction `Reader` uses to get asset bytes, instead of opening the local filesystem directly.

**This layer only reads today.** There is no write path. `SyncAssetTransport` and `AsyncAssetTransport` each expose one method, `open`/`open_async`, and both trait docs say so directly: a write path would arrive as further methods on the same traits, not a redesign.

A transport hands back either a whole seekable stream or a byte-range source; see [Range transports](#range-transports).

## Overview

A request to read asset bytes builds an `AssetRequest` and hands it to whatever transport is configured on the `Context`: the local filesystem by default, or a caller-supplied transport for anything else (an in-memory buffer, a network fetch, a custom store). The reader code does not know which: it gets handed bytes.

A transport is the byte-moving layer below a resolver. It moves bytes and does not interpret references. `ResourceResolver`, which resolves manifest-internal identifiers rather than external assets, is a separate thing and stays as is.

## The traits

```rust
pub trait SyncAssetTransport: MaybeSend + MaybeSync {
    fn open(&self, request: AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError>;
}

pub trait AsyncAssetTransport: MaybeSend + MaybeSync {
    async fn open_async(&self, request: AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError>;
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

## Range transports

`SyncAssetTransport` hands back a whole seekable stream. A source that is expensive to read end to end — a large object behind a network fetch — can instead serve byte ranges and let the parse pull only what it reads.

```rust
pub trait SyncRangeTransport: MaybeSend + MaybeSync {
    fn info(&self) -> Result<RangeInfo, AssetTransportError>;
    fn read_range(&self, offset: u64, len: u64, expect: Option<&ObjectVersion>)
        -> Result<RangeChunk, AssetTransportError>;
}
```

`AsyncRangeTransport` is the same pair as `info_async`/`read_range_async`.

`RangeTransportSource::new(factory)` turns a range transport into an ordinary `SyncAssetTransport`, so the reader needs no separate path:

```rust
let context = Context::new()
    .with_asset_transport(RangeTransportSource::new(|_request| Ok(MyRanges::open()?)));
```

Behind it, `ResolvedAsset::from_ranges(transport, config)` wraps the transport in a window cache presented to the parse as a seekable stream. Reads inside a cached segment are served from memory; a miss fetches a window of `RangeConfig::window` bytes, so seek-heavy access does not re-request bytes it already holds. The object length is discovered on the first read, not in the constructor. `from_ranges_async` stores an async transport, which the synchronous accessors refuse with `AsyncOnlyAsset`.

`size()` on a `ResolvedAsset` is an open-time hint the transport may declare. The length a range read seeks against is `RangeInfo::len`, discovered on the first read; the two can disagree.

`RangeConfig` bounds the traffic and the memory: `window` (minimum bytes per miss), `max_request` (cap on one request), `max_cached` (eviction budget), and `hash_chunk` (bytes held at once while hashing for verification). Chain from `Default`, since the struct is `#[non_exhaustive]`:

```rust
let config = RangeConfig::default().with_hash_chunk(1024 * 1024);
```

**A read that spans several requests can see the object change underneath it.** `RangeInfo` and `RangeChunk` carry an optional `ObjectVersion` (an ETag, say); `read_range` takes the version the read is anchored on and reports the one that served the bytes. The stream adopts the version from its first response and holds every later response to it, so a mismatch is `VersionChanged` rather than silently mixed content. A response longer than the requested `len` is rejected too: that is the signature of a server that ignored `Range` and returned the whole object, whose bytes would otherwise be cached at the wrong offset. A transport that cannot report a version passes `None` and gives up the version protection.

For an HTTP-backed implementation, two helpers are pure over values a fetch already produced:

- `validate_range_status(status, reference, expect, served)` accepts `206`, maps `416` to `RangeNotSatisfiable`, and maps `412` and a `200` whose validator disagrees to `VersionChanged`. A `200` that matches still fails — a whole-body response cannot be trusted to sit at the requested offset.
- `content_range_total(value)` parses the total length out of a `Content-Range` header: `bytes 0-1023/4096` yields `Some(4096)`, an unknown total (`*`) yields `None`.

## The transport and the HTTP resolver

Remote manifest fetching does not go through the asset transport. It goes through the HTTP resolver (`Context::resolver`/`resolver_async`, `http_resolve`), which is request/response shaped: it sends an `http::Request`, reads a capped `Vec` from the response, and applies the redirect and host allow-list hardening. The asset transport is seek shaped: it hands back a seekable stream of asset bytes.

So registering an asset transport does not redirect remote manifest fetching. A caller who wants their own network stack for both registers an async transport for assets and an async HTTP resolver for manifests.

The two relate by layering, not merging. A future HTTP-backed asset transport implements `AsyncAssetTransport` and delegates to `Context::resolver_async` internally, reusing that hardening rather than duplicating it, while manifest fetch stays on the resolver where the response shape fits.

## Errors

`AssetTransportError` distinguishes what went wrong: `NotFound`, `PermissionDenied`, `UnsupportedReference`, `OutsideRoot`, `NoSyncTransport`, `AsyncOnlyAsset`, `NotConfigured`, `Timeout`, `RangeNotSatisfiable`, `ShortRead`, `VersionChanged`, plus `Io` and `Other` for anything else.

`ShortRead` and `VersionChanged` come from the range path: a response shorter than the requested window, and an object that changed underneath a read that spans several requests.

`NoSyncTransport` and `AsyncOnlyAsset` are deliberately separate. The first is a fact about the `Context` — no sync transport is registered, and every read on it fails the same way. The second is a fact about one asset: the `Context` is fine and the open succeeded, but this asset is backed by an async range transport and has no blocking view.

**Range failures reach the caller as `Error::IoError`.** `RangeStream` implements `Read`/`Seek`, so `VersionChanged`, `ShortRead` and the rest become `io::Error` the moment the parser touches them. The original is preserved as the source and is downcastable:

```rust
if let Error::IoError(e) = err {
    if let Some(te) = e.get_ref().and_then(|s| s.downcast_ref::<AssetTransportError>()) {
        // VersionChanged, ShortRead, ...
    }
}
```

Through the C FFI this flattening is lossy: `from_c2pa_error` matches `IoError` before `AssetTransport`, so a range failure surfaces as code `105` (`Io`) rather than `119`/`120`. `RangeNotSatisfiable` is reachable for a transport implementor calling `validate_range_status` directly, not through a range read.
