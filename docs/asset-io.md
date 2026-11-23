# Experimental asset-io integration

Enable the non-default `unstable_asset_io` Cargo feature to use this integration.
It is covered by the [experimental features policy](experimental-features.md).

## Direct save

The internal `Store::save_to_stream_asset_io` path, gated by the `unstable_asset_io`
feature, parses the source once and hashes output bytes during a single write
pass. It then updates the hard binding and signs with the given signer, writing
the signer's dynamic assertions into slots reserved before the manifest is sized.
When embedding is requested, the signed manifest replaces the placeholder by
patching the output rather than rewriting the asset.

Pass an empty destination stream. Optional post-sign verification may reread
the output, and container checksum repair may read manifest segments; the
write-time hash does not require rereading the output.

### Hard bindings

This path preserves an explicitly supplied DataHash, BoxHash, or BMFF binding and its
hash algorithm. Without a binding it chooses: BMFF for ISO BMFF, BoxHash for a
container made entirely of named boxes when `builder.prefer_box_hash` is `true`,
otherwise DataHash. The setting defaults to `false`, as with `save_to_stream`.
Container-owned DataHash exclusions are recalculated for the
output; requested box maps and BMFF selectors must be supported rather than
silently replaced.

An update manifest has no hard binding; it is signed and written once, and ISO
BMFF keeps the original store in place beside the update. A compressed manifest
needs a binding that does not depend on the store's size (BoxHash); with any
other binding it is saved uncompressed, as `save_to_stream` does.

### Embedding and remote references

The claim's existing remote-manifest options control output:

| Option | Embedded store | XMP remote reference |
| --- | --- | --- |
| `NoRemote` | Replaced/added | Removed |
| `SideCar` | Removed | Removed |
| `Remote(url)` | Removed | Set to `url` |
| `EmbedWithRemote(url)` | Replaced/added | Set to `url` |

Unrelated JUMBF and XMP properties are retained. Embedding requires the container
to define an embedding and a writer; adding a remote reference requires XMP
support. An unrecognized format can be copied with a DataHash sidecar, but cannot
embed or carry a remote reference.

Every mode returns the signed manifest bytes. The caller must persist/upload
sidecar and remote manifests; this path does not do so. Only embedded mode
patches the output.

Manifest-only `.c2pa` archives retain the compatibility BoxHash containing only
the excluded C2PA store. They accept an empty source and write the signed store
once, so a discarded destination such as `std::io::empty()` is also supported;
the signed bytes are still returned.

### Routing

The context's handler registry decides how a format is saved: an asset-io
container directly, a format served by a legacy handler through
`save_to_stream`, and a format with no handler as a sidecar.
Unknown formats use a private, unregistered pass-through handler that describes
the asset as unnamed payload bytes. They share the normal write-and-hash pipeline
but cannot embed a manifest or write XMP.

### Merkle trees

When `core.merkle_tree_chunk_size_in_kb` is set, a default ISO BMFF hash covers the
`mdat` media with Merkle trees, as `Store::save_to_stream` does, and the output
matches its Merkle maps and proof boxes. Nothing is read twice and no extra stream
is needed:

- The `mdat` boxes are the same in the output as in the source, so their sizes give
  every tree's shape. The Merkle maps and the `merkle` proof boxes, which follow the
  last `mdat`, get their final size before anything is written. The proof boxes are
  written as zeros.
- The leaves are hashed in blocks as the output is written, in the same pass as the
  rest of the hash. They fill in the Merkle maps, and the proof boxes are then
  patched in place. Proof boxes are excluded from the flat hash, so patching them
  does not change it.
- `core.merkle_tree_max_proofs` rows of each tree are kept in the proof boxes. A new
  set replaces the proofs the asset has; without a Merkle setting they are kept when
  it is re-signed.

A BMFF hash the caller already computed is signed as given even with Merkle maps;
its proof boxes must already be in the asset. Merkle maps without a computed hash
are rejected.

### Current limitations

The deprecated `url` field of a data or BMFF hash is ignored, as C2PA 2.5 directs
consumers to do: a binding built from the assertion is written without it. The path
is synchronous; async signers use `save_to_stream_async`.

For callback behavior, see [Progress and cancellation API](progress_callbacks.md#typical-phase-sequences).

## BMFF hashing and verification

`BmffHash` (`sdk/src/assertions/bmff_hash/`) keeps its hashing, Merkle and
verification code in one copy and reads boxes through one of two parsers:

- `asset_io_parser.rs`, with `unstable_asset_io`: the box tree from `Structure::walk`
  and the Merkle proof boxes from the structure's items. Exclusion selectors,
  including indexed ones, are evaluated here, for verification and for the
  direct-save binding alike.
- `legacy_parser.rs`, without it: the existing `asset_handlers/bmff_io.rs`
  parser, unchanged.

Tests build both and require them to report the same boxes, Merkle proof
boxes and exclusion ranges on every BMFF fixture, on assets with flat-file
Merkle proof boxes and on signed fragments. Since everything downstream is
shared, the two paths then produce the same hashes, proofs and results.

Still read through `bmff_io.rs` either way, until asset-io provides them:
timed-media sample tables (`BmffSampleReader`), and the framing of Merkle
proof boxes the SDK writes itself (`write_c2pa_box`).

`Builder::sign` and everything built on it use the direct-save pipeline above.
Fragmented BMFF signing (`Builder::sign_fragmented_files`) does not: it still uses
the legacy BMFF code.

## Differences from the legacy handlers

With `unstable_asset_io`, the legacy handlers' unit tests run against the asset-io
adapter (`test_handler(format)` in each test module). Where the results differ,
the tests state the asset-io result. Callers that match on error variants or
messages, or that depend on the legacy handlers rejecting an asset, may see
different results.

### Accepted input the legacy handlers rejected (fixes)

| Format | Input | Legacy | asset-io |
| --- | --- | --- | --- |
| JPEG | Data after EOI (SOI, fill bytes, EOI, trailing bytes) | `InvalidAsset` | Read; the trailing bytes are their own region |
| JPEG | XMP larger than one APP1 segment | `InvalidAsset` | Written as extended XMP |
| RIFF | Deeply nested chunks (`riff_bomb_1000.wav`) | `InvalidAsset` | Read and written, with nesting bounded |

### Different errors for the same rejection

These are more specific errors, but a caller matching the legacy variant or
message sees a change.

| Format | Input | Legacy | asset-io |
| --- | --- | --- | --- |
| MP3, FLAC | Stream too short for an ID3 header | `IoError` | `InvalidAsset` (too small to be audio) |
| MP3, FLAC | Unsupported ID3 version | `InvalidAsset` / `UnsupportedType` | `NotImplemented` |
| MP3 | A few bytes of MPEG sync with no ID3 tag | `JumbfNotFound` | `UnsupportedType`; a real MP3 without an ID3 tag reads as unsigned |
| MP3, FLAC | Patch with a store of another size | `InvalidAsset` ("store size mismatch") | `InvalidAsset` (different message) |
| ISO BMFF | C2PA box with an unknown purpose | `C2PAValidation` | `InvalidAsset`; the box is not parsed, so its XMP is not read |
| ISO BMFF | `original` without `update`, or the reverse | `C2PAValidation` | `InvalidAsset` |
| SVG | Two manifest elements with content | `InvalidAsset` | `TooManyManifestStores` |
| SVG | `xml` prefix bound to another namespace | Read | `InvalidAsset` (not well-formed XML) |

All of these still reject the asset, so none can fall back to a remote manifest.

JPEG parse errors use the normal error mapping rather than being rewritten to
`UnsupportedType` when the signature does not match. Malformed input is reported
as `InvalidAsset`, and underlying I/O errors remain `IoError`.

### Region layout

`get_object_locations` reports finer regions: each ID3 frame and the audio in
MP3 and FLAC, and each GIF block. The manifest region and the total coverage
are the same.

### Open: ISO BMFF `mdat` past the end of the file

asset-io clamps an `mdat` box whose size runs past the end of the file to the
bytes present, to accept truncated recordings. ISO/IEC 14496-12 allows a box to
run to the end of the file only with a size of 0, and the legacy handler
rejects the asset (`InvalidAsset`). Clamping lets c2pa-rs read and sign files
that other validators reject, so strict rejection, with clamping as an opt-in
for repair tools, is likely the better default. Tracked in
[contentauth/asset-io#44](https://github.com/contentauth/asset-io/issues/44).

### Known gaps

- asset-io cannot add a manifest or XMP to a QuickTime file without an `ftyp`
  box (for example one starting with `wide` or `mdat`), which the legacy
  handler supports
  ([contentauth/asset-io#43](https://github.com/contentauth/asset-io/issues/43)).
- asset-io's PDF writer cannot re-sign an already signed PDF: a new store must
  extend the existing one.
