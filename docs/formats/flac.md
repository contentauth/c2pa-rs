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

## Testing

- **Fixture**: `sdk/tests/fixtures/sample1.flac` is a sample FLAC file. In-memory ID3+FLAC streams are constructed in FLAC-specific tests using `test_helpers::id3_header()` from `id3_helper::test_helpers`.
- **Shared test helpers**: Most behavioral tests (write/read roundtrip, patch, remove, remote ref, object locations, etc.) delegate to shared helpers in `id3_helper::test_helpers`, keeping the FLAC test module focused on FLAC-specific edge cases.

All tests live in `sdk/src/asset_handlers/flac_io.rs` under `#[cfg(test)] mod tests`. Run with: `cargo test --package c2pa flac_io::tests::`.

### read_cai / header / validation

| Test | Description |
|------|-------------|
| `test_read_cai_store_no_id3` | Pure FLAC (no ID3) returns `JumbfNotFound`. |
| `test_read_cai_unsupported_type` | First 10 bytes neither ID3 nor fLaC → `UnsupportedType`. (via `test_helpers`) |
| `test_read_cai_invalid_id3_version` | ID3 version 1 (invalid for FLAC) → `FlacError::InvalidId3Version`. |
| `test_read_cai_io_error_too_short` | Stream shorter than 10 bytes → `IoError`. (via `test_helpers`) |
| `test_read_cai_invalid_flac_after_id3` | Valid ID3 header then non-FLAC bytes → error. |
| `test_read_cai_too_many_manifest_stores` | Two C2PA GEOB frames in ID3 → `TooManyManifestStores`. (via `test_helpers`) |
| `test_read_cai_success_with_manifest` | Save manifest to file, then `read_cai` and assert payload matches. (via `test_helpers`) |
| `test_read_cai_store_file_not_found` | `read_cai_store` on nonexistent path → `IoError`. |

### Write / patch / remove

| Test | Description |
|------|-------------|
| `test_write_flac` | Write manifest via `save_cai_store`, read back with `read_cai_store`, compare. (via `test_helpers`) |
| `test_patch_write_flac` | Save manifest, patch with same-size data via `patch_cai_store`, read back and compare. (via `test_helpers`) |
| `test_patch_cai_store_size_mismatch` | `patch_cai_store` with wrong-length data → `InvalidAsset("patch_cai_store store size mismatch")`. (via `test_helpers`) |
| `test_remove_c2pa_flac` | Save manifest, then `remove_cai_store`; read → `JumbfNotFound`. (via `test_helpers`) |
| `test_write_cai_empty_store_removes_manifest` | `write_cai` with empty `store_bytes`; read → `JumbfNotFound`. (via `test_helpers`) |
| `test_remove_cai_store_from_stream` | `remove_cai_store_from_stream` then `read_cai` on output → `JumbfNotFound`. (via `test_helpers`) |

### Object locations

| Test | Description |
|------|-------------|
| `test_get_object_locations_flac_structure` | After save: 3 entries, lengths sum to file size, one block `Cai`, one `Other` at offset 0. (via `test_helpers`) |

### Remote reference (XMP)

| Test | Description |
|------|-------------|
| `test_remote_ref_flac` | No XMP → embed XMP via `embed_reference_to_stream`, read XMP and check provenance. (via `test_helpers`) |
| `test_embed_reference_to_stream_unsupported_type` | `embed_reference_to_stream` with `StegoS` → `UnsupportedType`. (via `test_helpers`) |
| `test_embed_reference_file_path` | `embed_reference(path, Xmp(url))` then read XMP and assert provenance URL. (via `test_helpers`) |

### AssetIO / API

| Test | Description |
|------|-------------|
| `test_supported_types` | `supported_types()` is `["flac", "audio/flac"]` (length 2). (via `test_helpers`) |
| `test_get_handler_and_reader` | `get_handler("audio/flac")` and `get_reader()`; read pure FLAC → `JumbfNotFound`. |
