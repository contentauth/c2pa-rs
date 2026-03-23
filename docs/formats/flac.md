# FLAC C2PA Support

This document describes how C2PA manifest storage is implemented for FLAC files in C2PA-RS.

## Spec reference

- **C2PA Specification**: [Appendix A.3.4 – Embedding manifests into ID3](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html) states that the C2PA Manifest Store shall be embedded in an "ID3v2-compatible, compressed audio file (e.g., MP3 or FLAC)" as the **Encapsulated object data of a General Encapsulated Object (GEOB)** (id3.org id3v2.3.0).
- **GEOB**: The MIME type for the GEOB must be the JUMBF media type: `application/c2pa`. The implementation also recognizes the deprecated `application/x-c2pa-manifest-store` for reading.

## FLAC structure

FLAC layout:

1. **Optional ID3v2** block at the very beginning of the file.
2. **FLAC stream**: 4-byte magic `fLaC`, followed by metadata blocks and audio frames.

So the file layout is: `[optional ID3v2][fLaC stream]`.

**Detection**:

- If the first 3 bytes are `ID3`, an ID3v2 tag is present; its size is read from the ID3 header and the remainder is treated as the FLAC stream.
- If the first 4 bytes are `fLaC`, there is no ID3 block; the file is a pure FLAC stream.

## Crates

- **id3**: Used to read and write the optional prepended ID3v2 tag and the GEOB frame that holds the C2PA manifest (same approach as [sdk/src/asset_handlers/mp3_io.rs](../sdk/src/asset_handlers/mp3_io.rs)).
The FLAC stream is validated by checking that the first 4 bytes after the optional ID3v2 block are `fLaC`. The FLAC stream is not modified when writing—only the optional ID3 block is added or replaced.

## Implementation summary

- **Module**: `sdk/src/asset_handlers/flac_io.rs`.
- **Handler**: `FlacIO` with `supported_types()` returning `["flac", "audio/flac"]`.
- **Traits**: `CAIReader`, `CAIWriter`, `AssetIO`, `AssetPatch`, `RemoteRefEmbed` (XMP in ID3 PRIV frame, same as MP3).
- **Shared ID3 logic**: The bulk of ID3 read/write operations (GEOB frame handling, XMP embedding, object-location computation, patching) is delegated to `sdk/src/asset_handlers/id3_helper.rs`, which is shared with the MP3 handler. `FlacIO` only adds FLAC-specific header detection and stream validation on top.
- **Flow**:
  - **Read**: Detect ID3 vs pure FLAC via `read_header()`; if ID3, use `id3_helper` to find the GEOB frame and extract the manifest; if no ID3 or no GEOB, return no manifest. After the optional ID3, the first 4 bytes of the remainder are checked for the `fLaC` marke
  - **Write**: Delegate to `id3_helper::write_cai_with_id3`, which builds or replaces the ID3 block with a GEOB containing the manifest, then appends the FLAC stream.
  - **Object locations**: `add_required_frame` ensures a placeholder GEOB exists before calling `id3_helper::get_object_locations`, so positions can be computed even on files without an existing manifest.

## Files touched

- `sdk/src/asset_handlers/flac_io.rs` – new FLAC handler.
- `sdk/src/asset_handlers/id3_helper.rs` – shared ID3v2 logic (GEOB read/write, XMP embed, patching, object locations, test helpers); used by both FLAC and MP3 handlers.
- `sdk/src/asset_handlers/mod.rs` – `pub mod flac_io`.
- `sdk/src/error.rs` – `FlacError` and `Error::FlacError`.
- `sdk/src/jumbf_io.rs` – register `FlacIO` in CAI_READERS, CAI_WRITERS, and handler tests.
- `sdk/src/utils/mime.rs` – `"flac"` / `"audio/flac"` in `extension_to_mime` and `format_to_extension`.
- `sdk/tests/fixtures/sample1.flac` – minimal valid FLAC fixture (metadata only, no ID3).
