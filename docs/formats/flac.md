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

- **Fixture**: `sdk/tests/fixtures/sample1.flac` is a minimal valid FLAC (fLaC magic, STREAMINFO block, padding block; no ID3). Tests also use in-memory streams built with helpers `id3_header()` and `id3_tag_plus_flac()` (ID3 tag bytes + FLAC tail).

All tests live in `sdk/src/asset_handlers/flac_io.rs` under `#[cfg(test)] mod tests`. Run with: `cargo test --package c2pa flac_io::tests::`.

### read_cai / header / validation

| Test | Description |
|------|-------------|
| `test_read_cai_store_no_id3` | Pure FLAC (no ID3) returns `JumbfNotFound`. |
| `test_read_cai_unsupported_type` | First 10 bytes neither ID3 nor fLaC → `UnsupportedType`. |
| `test_read_cai_invalid_id3_version` | ID3 version 1 (invalid for FLAC) → `FlacError::InvalidId3Version`. |
| `test_read_cai_io_error_too_short` | Stream shorter than 10 bytes → `IoError`. |
| `test_read_cai_invalid_flac_after_id3` | Valid ID3 header then non-FLAC bytes → error (e.g. invalid stream). |
| `test_read_cai_too_many_manifest_stores` | Two C2PA GEOB frames in ID3 → `TooManyManifestStores` or single manifest (id3 may merge duplicate frame IDs). |
| `test_read_cai_success_with_manifest` | Save manifest to file, then `read_cai` and assert payload matches. |
| `test_read_cai_store_file_not_found` | `read_cai_store` on nonexistent path → `IoError`. |

### Write / patch / remove

| Test | Description |
|------|-------------|
| `test_write_flac` | Write manifest via `save_cai_store`, read back with `read_cai_store`, compare. |
| `test_patch_write_flac` | Save manifest, patch with same-size data via `patch_cai_store`, read back and compare. |
| `test_patch_cai_store_size_mismatch` | `patch_cai_store` with wrong-length data → `InvalidAsset("patch_cai_store store size mismatch")`. |
| `test_remove_c2pa_flac` | Save manifest, then `remove_cai_store`; read → `JumbfNotFound`. |
| `test_write_cai_empty_store_removes_manifest` | `write_cai` with empty `store_bytes`; read → `JumbfNotFound`. |
| `test_remove_cai_store_from_stream` | `remove_cai_store_from_stream` then `read_cai` on output → `JumbfNotFound`. |

### Object locations

| Test | Description |
|------|-------------|
| `test_get_object_locations_flac` | Save manifest, call `get_object_locations`, assert non-empty. |
| `test_get_object_locations_flac_structure` | After save: 3 entries, lengths sum to file size, one block `Cai`, one `Other` at offset 0. |

### Remote reference (XMP)

| Test | Description |
|------|-------------|
| `test_remote_ref_flac` | No XMP → embed XMP via `embed_reference_to_stream`, read XMP and check provenance. |
| `test_embed_reference_to_stream_unsupported_type` | `embed_reference_to_stream` with `StegoS` → `UnsupportedType`. |
| `test_embed_reference_file_path` | `embed_reference(path, Xmp(url))` then read XMP and assert provenance URL. |

### AssetIO / API

| Test | Description |
|------|-------------|
| `test_supported_types` | `supported_types()` is `["flac", "audio/flac"]` (length 2). |
| `test_get_handler_and_reader` | `get_handler("audio/flac")` and `get_reader()`; read pure FLAC → `JumbfNotFound`. |
