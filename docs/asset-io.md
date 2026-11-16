# Experimental asset-io integration

## Direct save

The internal `Store::save_to_stream_asset_io` path, gated by the `asset_io`
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
container made entirely of named boxes, otherwise DataHash. The BoxHash default
can be turned off (`DirectSaveOptions`) to compare with `save_to_stream`, which
uses DataHash. Container-owned DataHash exclusions are recalculated for the
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

### Routing

The context's handler registry decides how a format is saved: an asset-io
container directly, a format served by a legacy handler through
`save_to_stream`, and a format with no handler as a sidecar.

### Current limitations

Merkle BMFF bindings, remote BMFF hashes and indexed BMFF selectors are rejected
explicitly. The path is synchronous; async signers use `save_to_stream_async`.

For callback behavior, see [Progress and cancellation API](progress_callbacks.md#typical-phase-sequences).
