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
- **metaflac**: Used to validate the FLAC container (the stream after the optional ID3v2). The remainder of the file (starting with `fLaC`) is parsed with `metaflac::Tag::read_from` to ensure it is valid FLAC; the FLAC stream is not modified when writing—only the optional ID3 block is added or replaced.

## Implementation summary

- **Module**: `sdk/src/asset_handlers/flac_io.rs`.
- **Handler**: `FlacIO` with `supported_types()` returning `["flac", "audio/flac"]`.
- **Traits**: `CAIReader`, `CAIWriter`, `AssetIO`, `AssetPatch`, `RemoteRefEmbed` (XMP in ID3 PRIV frame, same as MP3).
- **Flow**:
  - **Read**: Detect ID3 vs pure FLAC; if ID3, use the id3 crate to find the GEOB frame and extract the manifest; if no ID3 or no GEOB, return no manifest. After optional ID3, the remainder is validated as FLAC with metaflac.
  - **Write**: Build or replace the ID3 block with a GEOB containing the manifest, then append the FLAC stream (from the start of the file if there was no ID3, or from after the original ID3).
- **Difference from MP3**: After the optional ID3, the remainder must start with `fLaC` and is validated with metaflac; the FLAC stream itself is never rewritten.

## Files touched

- `sdk/Cargo.toml` – added `metaflac` dependency.
- `sdk/src/asset_handlers/flac_io.rs` – new FLAC handler.
- `sdk/src/asset_handlers/mod.rs` – `pub mod flac_io`.
- `sdk/src/error.rs` – `FlacError` and `Error::FlacError`.
- `sdk/src/jumbf_io.rs` – register `FlacIO` in CAI_READERS, CAI_WRITERS, and handler tests.
- `sdk/src/utils/mime.rs` – `"flac"` / `"audio/flac"` in `extension_to_mime` and `format_to_extension`.
- `sdk/tests/fixtures/sample1.flac` – minimal valid FLAC fixture (metadata only, no ID3).

## Testing

- **Fixture**: `sdk/tests/fixtures/sample1.flac` is a minimal valid FLAC (fLaC magic, STREAMINFO block, padding block; no ID3).
- **Tests** (in `flac_io.rs`):
  - `test_read_cai_store_no_id3`: Pure FLAC with no ID3 returns `JumbfNotFound`.
  - `test_write_flac`: Write manifest to FLAC, read back and compare.
  - `test_patch_write_flac`: Patch manifest with same-size data and verify.
  - `test_remove_c2pa_flac`: Remove manifest and assert `JumbfNotFound` on read.
  - `test_get_object_locations_flac`: Write manifest and check `get_object_locations`.
  - `test_remote_ref_flac`: Embed XMP reference in ID3 PRIV and read back.
