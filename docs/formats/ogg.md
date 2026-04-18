# OGG C2PA Support

This document describes how C2PA manifest storage is implemented for OGG containers (Vorbis, Opus) in c2pa-rs.

## Spec reference

- **C2PA Specification v2.3**: [Section A.3.5 – Embedding manifests into OGG Vorbis](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html) states that the C2PA Manifest Store shall be embedded in its own dedicated logical bitstream within the OGG container. The first packet of this stream starts with the 5-byte identifier `\x00c2pa`, and the manifest store data follows immediately after.
- **Hash binding**: [Section 18.7.3.7](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html) defines how OGG logical bitstreams map to the box hash model. Each logical bitstream is treated as a single "box" named `Stream-{serial}`, where `serial` is the bitstream serial number as a decimal ASCII string. The C2PA manifest bitstream uses the standard `C2PA` box name.
- **OGG container**: [RFC 3533](https://www.rfc-editor.org/rfc/rfc3533) – The Ogg Encapsulation Format Version 0.

## OGG structure

An OGG file consists of interleaved **pages**, each belonging to a **logical bitstream** identified by a unique 32-bit serial number. Pages carry **packets** using a lacing mechanism (segments of up to 255 bytes).

Layout after C2PA embedding:

1. **C2PA BOS page** – Beginning-of-stream page for the manifest bitstream. First packet starts with `\x00c2pa` followed by JUMBF manifest data.
2. **C2PA continuation/EOS pages** – If the manifest exceeds ~65 KB, it spans multiple pages. The last page carries the EOS flag.
3. **Audio BOS page(s)** – Original Vorbis or Opus identification header.
4. **Audio data pages** – Original audio content, unmodified.

This ordering ensures each bitstream's pages are contiguous, which is required for BoxHash byte-range verification.

**BOS page identification**:
- Vorbis: first packet starts with `\x01vorbis`
- Opus: first packet starts with `OpusHead`
- C2PA: first packet starts with `\x00c2pa`

## No external crate dependencies

OGG page parsing and writing are implemented directly in the handler. The OGG page format is simple (27-byte fixed header + segment table + body), and the CRC-32 uses a precomputed lookup table for the OGG-specific polynomial `0x04c11db7` (direct / non-reflected, per RFC 3533). No external OGG parsing crate is required.

## Implementation summary

- **Module**: `sdk/src/asset_handlers/ogg_io.rs`.
- **Handler**: `OggIO` with `supported_types()` returning `["ogg", "audio/ogg", "opus", "audio/opus"]`.
- **Traits**: `CAIReader`, `CAIWriter`, `AssetIO`, `AssetPatch`, `AssetBoxHash`.
- **Note**: `RemoteRefEmbed` is not implemented — the C2PA specification does not define XMP or remote reference embedding for OGG containers.
- **Flow**:
  - **Read**: Parse all pages, find the BOS page whose first packet starts with `\x00c2pa`, collect all pages with that serial number, reconstruct the packet, strip the 5-byte magic prefix, return the JUMBF bytes.
  - **Write**: Parse all pages, remove any existing C2PA bitstream, build new C2PA pages from the manifest data (handling fragmentation across pages for large manifests), write output with C2PA pages first followed by audio pages grouped by serial for contiguous BoxHash ranges.
  - **BoxHash**: Each logical bitstream maps to a `BoxMap` entry. Audio streams are named `Stream-{serial}` (decimal). The C2PA stream uses the `C2PA` label. If no C2PA stream exists, a placeholder entry is inserted with `excluded: true`.
  - **Patch**: For same-size manifest replacement, C2PA pages are overwritten in-place with recomputed CRC checksums.

## Opus support

While the C2PA v2.3 specification only names "OGG Vorbis", the embedding mechanism operates at the OGG container level (a separate logical bitstream) and is codec-agnostic. This implementation supports both Vorbis and Opus containers. The handler registers both `ogg`/`audio/ogg` and `opus`/`audio/opus` MIME types.

## Files touched

- `sdk/src/asset_handlers/ogg_io.rs` – OGG handler with inline page parser, CRC-32, and tests.
- `sdk/src/asset_handlers/mod.rs` – `pub mod ogg_io`.
- `sdk/src/error.rs` – `OggError` and `Error::OggError`.
- `sdk/src/jumbf_io.rs` – register `OggIO` in CAI_READERS, CAI_WRITERS, and handler tests.
- `sdk/src/utils/mime.rs` – `"opus"` / `"audio/opus"` in `extension_to_mime` and `format_to_extension`.
- `sdk/tests/fixtures/sample1.ogg` – minimal valid OGG Vorbis fixture.
- `sdk/tests/fixtures/sample1.opus` – minimal valid OGG Opus fixture.
- `docs/supported-formats.md` – added OGG and Opus to the format table.
