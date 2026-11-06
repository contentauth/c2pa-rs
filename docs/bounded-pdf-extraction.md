# Bounded PDF credential extraction

With the `pdf` feature, the built-in reader uses a seek-based extraction path for
PDFs **strictly larger than 67,108,864 bytes (64 MiB)**. Files at that size or below
retain the existing document-loader path. The same routing applies to `pdf`,
`application/pdf`, files, and `Read + Seek` streams, including C seek callbacks.
The threshold is a provisional routing threshold, **not a measured safe maximum**.

The oversized path searches a bounded final window for `startxref`, follows the
cross-reference chain, resolves the effective catalog, and reads only:

- Catalog `/AF` file specifications with `/AFRelationship /C2PA_Manifest` and
  their `/EF /F` stream.
- Catalog `/Metadata` XML, when metadata is requested.

It does not load, memory-map, repair-scan, render, or mutate the document. It does
not traverse every page, annotation, name tree, image, font, or attachment.
Associated-file insertion in the existing PDF implementation registers both
annotation and embedded-file credentials in catalog `/AF`.

## Supported navigation

Classic xref subsections, xref streams (`W` and sparse `Index` ranges), hybrid
`XRefStm`, and incremental `Prev` chains are supported. Newest entries take
precedence, including free entries; references must match their generations.
Forward `Prev` navigation, as used in linearized layouts, is supported without
traversing hint tables. Indirect dictionaries, arrays, names, and stream lengths
are resolved selectively, including objects in bounded `ObjStm` containers.
Object streams validate `N`, `First`, IDs, selected slots, and object boundaries.
Xref stream keys must be direct, as required by ISO 32000 section 7.5.8.2.

Flate and LZW use the existing `flate2` and `weezl` decoder dependencies through
their incremental APIs, with strict error and output-limit checks. ASCIIHex,
ASCII85, and RunLength are checked while decoding; filter arrays and matching
`DecodeParms` arrays are supported. Eight-bit TIFF and PNG predictors are
supported for structural streams. Other predictor bit depths, unsupported
filters, external stream data, encryption, and repair-required documents return
explicit errors instead of a missing-credential result.

## Pilot budgets

| Resource | Bound |
| --- | --- |
| Tail search and reusable read window | 256 KiB |
| Encoded structural object | 256 KiB |
| Encoded filtered stream | 8 MiB |
| Decoded structural stream | 8 MiB |
| Decoded XMP | 4 MiB |
| Decoded manifest store | 32 MiB, or the tighter Context manifest limit |
| Aggregate parser allocation ledger | 64 MiB |
| Cumulative input read work | 512 MiB |
| Cumulative filter input/output work | 128 MiB |
| Seek/read pairs | 8,192, plus fixed setup seeks |
| Xref entries per revision and effective index | 65,536 each |
| Combined syntax/xref work items | 262,144 |
| Main xref revisions | 64 |
| Indirect-object resolutions | 4,096 |
| Syntax and indirect-reference depth | 64 |
| Array/dictionary items | 16,384 |
| Object-stream members | 4,096 |
| Filter stages | 8 |
| Name / numeric token | 4 KiB / 64 bytes |

Counts bound sparse declarations, fragmented indexes, and repeated resolution
without allocating by declared `/Size`. No document/object cache is retained.
Offsets and extents use checked arithmetic. The allocation ledger charges byte
vector capacity before growth, conservative syntax/index overhead, read windows,
and decoder scratch. It is cumulative, not refunded after objects are released,
so it is deliberately stricter than a live-buffer limit. A document can hit the
aggregate limit before hitting an individual stream or count limit.

These are **parser budgets, not process RSS guarantees**. Allocator overhead,
JUMBF processing, certificates, and other validation allocations are outside this
ledger. Signature and asset-hash verification remain enabled. Hash verification
can legitimately read the complete asset using the existing fixed chunk cap
(currently 256 MiB); extraction skipping an unrelated stream does not mean its
bytes are exempt from hash verification.

## Absence, errors, and remote credentials

Embedded credentials take precedence. Only completed embedded inspection returns
`JumbfNotFound` to the remote-metadata fallback. That fallback now uses the
Context's registered reader and a fallible metadata adapter. PDF parse, UTF-8,
XML, unsupported-layout, I/O, and resource-limit failures propagate; malformed
metadata is not treated as completed absence. Resource limits use
`Error::PdfResourceLimit`. Unsupported remote locator schemes are explicit errors.
Credential properties are matched by XML namespace, including prefix aliases,
text/CDATA, escaped values, and `rdf:resource` provenance. Conflicting properties,
unbound prefixes, and malformed XML are rejected. DTDs, XML versions other than
1.0, escaped namespace bindings, and structured credential properties are
explicitly unsupported.

Remote fetching continues through the existing Context resolver, including
fetch-disabled behavior and the default resolver's allowed-host policy. In
0.91.0 a custom resolver replaces the default resolver stack; custom resolvers
remain responsible for their own restrictions. No global/shared stream-result
cache is used; a second bounded metadata pass is intentional.

`C2paReader::read_xmp_result` has a default adapter for existing handlers. Legacy
infallible metadata APIs retain their `Option` shape and log PDF failures; Reader
and fallible ingredient/Store paths use the fallible Context-aware surface.
Signing, mutation, rendering, and recovery of images/watermarks are not changed.

## Focused regression proof

The SDK's `asset_handlers::pdf_bounded::tests` module generates sparse PDF layouts,
including assets larger than 1,162,403,076 bytes. It checks exact threshold
routing, bounded read requests, unrelated-stream skipping, xref/object-stream
layouts, incremental replacement/removal, limits, malformed input, and remote
policy/dispatch. A generated signed PDF goes through the full Reader with
validation enabled; modifying hashed asset bytes produces a hash mismatch.
`bounded_pdf_through_c_seek_callbacks` covers the actual C callback stream adapter
using a generated sparse file.

```sh
cargo test -p c2pa --lib --no-default-features \
  --features pdf,rust_native_crypto,file_io,fetch_remote_manifests \
  asset_handlers::pdf_bounded::tests -- --test-threads=1
cargo test -p c2pa-c-ffi --lib --no-default-features \
  --features rust_native_crypto bounded_pdf_through_c_seek_callbacks
```

The original implementation targets matching `c2pa` and `c2pa-c-ffi` 0.91.0
release commit `e7cc666c3409bdaf4cea8e49046dfbf8290dff89`; its tested commit is
`a7f01e946f79a2ce9a491039e192f1aa81a71cee`. The branch subsequently merged main
commit `09976fd6febd86168904ba14dad95b9f5bfd6c9e`, adopting main's `0.92.0-dev`
workspace version and split Store modules. The original 0.91.0 commit remains
available for release-pinned integrations.

Main's raw manifest-range lookup for hash-exclusion validation also uses bounded
navigation on oversized PDFs. Unfiltered manifest streams return their exact
content range; filtered streams explicitly report that decoded bytes have no
raw byte range, matching the existing locator's unsupported outcome. Signing
and mutation still use the existing document-loader path.
