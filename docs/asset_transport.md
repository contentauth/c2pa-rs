# The asset transport layer

This guide describes `asset_transport`: the abstraction `Reader` uses to get asset bytes, so it never opens the local filesystem directly.

There is no write path. `SyncAssetTransport` and `AsyncAssetTransport` each expose one method, `open`/`open_async`. A write path would arrive as further methods on the same traits.

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

A build without `file_io` still has a default transport, and every read against it fails. With `file_io` on, the default is the real local filesystem transport. With `file_io` off, the default is `UnconfiguredAssetTransport`, and every read returns `AssetTransportError::NotConfigured`. A build without `file_io` gets no local reads unless it registers its own transport.

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
```

`Default` means neither is registered. The sync path lazily builds the transport described above (local filesystem, or unconfigured). `with_*`/`set_*` add or replace a transport. Re-registering the same kind just replaces it in place.

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

`SyncRangeAssetTransport::new(factory)` turns a range transport into an ordinary `SyncAssetTransport`, so the reader needs no separate path. Its async twin, `AsyncRangeAssetTransport::new`, does the same for an `AsyncRangeTransport`. Both take a `factory: Fn(&AssetRequest<'_>) -> Result<R, AssetTransportError>` that runs once per open, and both carry a `.with_config(config)` builder for a non-default `RangeConfig`:

```rust
let context = Context::new().with_asset_transport(
    SyncRangeAssetTransport::new(|_request| -> Result<MyRanges, AssetTransportError> {
        MyRanges::open()
    })
    .with_config(RangeConfig::default()),
);
```

Behind it, `ResolvedAsset::from_ranges(transport, config)` wraps the transport in a window cache presented to the parse as a seekable stream. Reads inside a cached segment are served from memory; a miss fetches a window of `RangeConfig::window` bytes, so seek-heavy access does not re-request bytes it already holds. The object length is discovered on the first read, not in the constructor. `AsyncRangeAssetTransport` stores an async transport through `ResolvedAsset::from_ranges_async`, which the synchronous accessors refuse with `AsyncOnlyAsset`.

The length a range read seeks against is `RangeInfo::len`, discovered on the first read.

`RangeConfig` bounds the traffic and the memory: `window` (minimum bytes per miss), `max_request` (cap on one request), `max_cached` (eviction budget), and `max_whole_object` (the largest object the whole-object fallback will read, `None` to disable that rung). The first three are `NonZeroU64`, so a zero cannot reach them. Chain from `Default`, since the struct is `#[non_exhaustive]`:

```rust
const WINDOW: NonZeroU64 = match NonZeroU64::new(32 * 1024) {
    Some(window) => window,
    None => NonZeroU64::MIN,
};
let config = RangeConfig::default().with_window(WINDOW);
```

Bytes held at once while hashing come from settings, not from here: `Core::hash_buffer_size_in_kb`.

A read that spans several requests can see the object change underneath it. `RangeInfo` and `RangeChunk` carry an optional `ObjectVersion` (an ETag, say); `read_range` takes the version the read is anchored on and reports the one that served the bytes. The stream adopts the version from its first response and holds every later response to it, so a mismatch returns `VersionChanged` instead of assembling bytes from two versions of the object. A response longer than the requested `len` is rejected too: that is the signature of a server that ignored `Range` and returned the whole object, whose bytes would otherwise be cached at the wrong offset. A transport that cannot report a version passes `None` and gives up the version protection.

For an HTTP-backed implementation, the `http_range` module is pure over values a fetch already produced, so a transport does not restate the RFC 9110 rules:

- `RangeResponse::into_chunk(reference, requested, total, expect)` is the one call a transport needs. It applies the status, encoding and `Content-Range` rules in that order and yields a `RangeChunk`, or the reason the response fails the contract.
- `headers(offset, len, if_range)` builds `Range` and, only for a quoted entity-tag, `If-Range` (RFC 9110 13.1.5 forbids a date there).
- `validate_status(status, reference, requested, total, expect, served)` accepts `206`; accepts a `200` only when the whole object was asked for and returned, which RFC 9110 14.2 permits; maps `416` to `RangeNotSatisfiable` carrying the total the origin states; and maps `412` and a `200` whose validator disagrees to `VersionChanged`.
- `content_range(value)` parses a `Content-Range`, rejecting what RFC 9110 14.4 makes invalid.
- `content_encoding_ok(value)` refuses a range whose bytes are encoded: RFC 9110 14.1.2 defines a range over the encoded bytes, so its offsets do not address the object.

## The transport and the HTTP resolver

Remote manifest fetching does not go through the asset transport. It goes through the HTTP resolver (`Context::resolver`/`resolver_async`, `http_resolve`), which is request/response shaped: it sends an `http::Request`, reads a capped `Vec` from the response, and applies the redirect and host allow-list hardening. The asset transport is seek shaped: it hands back a seekable stream of asset bytes.

So registering an asset transport does not redirect remote manifest fetching. A caller who wants their own network stack for both registers an async transport for assets and an async HTTP resolver for manifests.

A future HTTP-backed asset transport implements `AsyncAssetTransport` and calls `Context::resolver_async` internally, so it reuses the resolver's redirect and host allow-list hardening. Manifest fetch stays on the resolver, where the request/response shape fits.

## Errors

`AssetTransportError` distinguishes what went wrong: `NotFound`, `PermissionDenied`, `UnsupportedReference`, `OutsideRoot`, `NoSyncTransport`, `AsyncOnlyAsset`, `NotConfigured`, `RangeNotSatisfiable`, `ShortRead`, `VersionChanged`, `WorkingSetTooLarge`, `AttemptsExhausted`, `WholeObjectTooLarge`, `UnverifiableOverRanges`, plus `Io` and `Other` for anything else.

`ShortRead` and `VersionChanged` come from the range path: a response shorter than the requested window, and an object that changed underneath a read that spans several requests. `WholeObjectTooLarge` comes from the whole-object rung described above, when the object exceeds `RangeConfig::max_whole_object`.

`NoSyncTransport` and `AsyncOnlyAsset` are separate. The first is a fact about the `Context`: no sync transport is registered, and every read on it fails the same way. The second is a fact about one asset: the `Context` is fine and the open succeeded, but this asset is backed by an async range transport and has no blocking view.

The synchronous and asynchronous range paths surface a failure differently. `RangeStream` implements `Read`/`Seek`, so on the sync path `VersionChanged`, `ShortRead` and the rest become `io::Error` the moment the parser touches them, and the original is preserved as the source and is downcastable:

```rust
if let Error::IoError(e) = err {
    if let Some(te) = e.get_ref().and_then(|s| s.downcast_ref::<AssetTransportError>()) {
        // VersionChanged, ShortRead, ...
    }
}
```

The async driven path (`drive_async` and the code built on it) returns `AssetTransportError` directly and propagates it into `Error::AssetTransport`, never through `io::Error`. A caller reading over an async range transport matches on `Error::AssetTransport` instead of downcasting an `io::Error`.

Through the C FFI this flattening is lossy: `from_c2pa_error` matches `IoError` before `AssetTransport`, so a range failure surfaces as code `105` (`Io`) rather than `120`. `RangeNotSatisfiable` is reachable for a transport implementor calling `validate_status` directly, not through a range read.
