# Supported file formats

The following table summarizes the supported media (asset) file formats. This information is based on what the Rust library supports; other libraries in the SDK support the same formats unless noted otherwise.

> [!NOTE]
> When reading an asset, the SDK first looks at the file name extension to determine the asset type.  If the file has no extension, then the SDK uses the MIME type specified in the API call (if any).
> When the internal header/MIME disagrees with the extension, the SDK uses the extension, not the internal MIME/metadata.
> If there is no file extension nor MIME type, then the SDK "sniffs the bytes" of the asset using [`infer`](https://docs.rs/infer/latest/infer/) to determine the asset type.

`txt` requires the non-default `unstable_plain_text` feature.

| Extensions      | MIME type                                                                      |
| --------------- | ------------------------------------------------------------------------------- |
| `avi`           | `video/msvideo`, `video/x-msvideo`, `video/avi`, `application/x-troff-msvideo`  |
| `avif`          | `image/avif`                                                                    |
| `c2pa`          | `application/x-c2pa-manifest-store`                                             |
| `dng`           | `image/x-adobe-dng`                                                             |
| `flac`          | `audio/flac`                                                                    |
| `gif`           | `image/gif`                                                                     |
| `heic`          | `image/heic`                                                                    |
| `heif`          | `image/heif`                                                                    |
| `jpg`, `jpeg`   | `image/jpeg`                                                                    |
| `jxl`           | `image/jxl`                                                                     |
| `m4a`           | `audio/mp4`                                                                     |
| `m4s`           | `video/iso.segment`                                                             |
| `mp3`           | `audio/mpeg`                                                                    |
| `mp4`           | `video/mp4`, `application/mp4`                                                  |
| `mov`           | `video/quicktime`                                                               |
| `pdf`           | `application/pdf`                                                               |
| `png`           | `image/png`                                                                     |
| `svg`           | `image/svg+xml`                                                                 |
| `tif`, `tiff`   | `image/tiff`                                                                    |
| `txt`           | `text/plain`                                                                    |
| `wav`           | `audio/wav`                                                                     |
| `webp`          | `image/webp`                                                                    |

Fragmented BMFF (DASH/CMAF) signing is available through Rust's
`Builder::sign_fragmented_files` and the C API's `c2pa_builder_sign_fragmented`,
with the `file_io` feature. Init segments may use any registered BMFF extension,
including `.mp4` and `.m4s`.

Both APIs flatten outputs to `<output>/<init parent directory name>/<file name>`.
The SDK rejects collisions between written rendition-directory and segment-file
names before output writes, including multiple inits in the same directory. Init
names remain native, while fragment names use the writer's lossy UTF-8 conversion.
Empty fragment matches and non-directory output entries are also rejected during
preflight. Existing rendition output directories with matching canonical paths
(including symlink aliases) are rejected, and errors inspecting or resolving
existing output entries are returned before writes. Output rendition directories
that are source directories, and existing output inits that are source files, are
also rejected (by canonical path, and on Unix by file identity to catch hard links).
This is not a full filesystem identity check: aliases with different canonical
paths (e.g. directory hard links, bind mounts, or file hard links on non-Unix
platforms) are not detected. Absent directories are not checked for
case/Unicode aliases; direct Rust
callers still need an exclusive destination ownership policy suitable for their
filesystem. Keep inputs separate from outputs and use fresh output directories;
existing non-source output init files can still be overwritten.
The C API additionally requires absent rendition directories and exclusively
reserves directories and init files, letting the destination filesystem reject
aliases (including case and Unicode normalization aliases). Those reservations
remain compatible with the SDK preflight. Signing is not transactional:
reservation/signing failures may leave empty or partial outputs, including an empty
output root. Neither API supports concurrent changes to inputs or outputs.

## Experimental feature: Text formats

The Rust library supports the following text formats when the `unstable_structured_text` feature is enabled.

| Extensions       | MIME type               |
| ---------------- | ----------------------- |
| `atom`           | `application/atom+xml`  |
| `css`            | `text/css`              |
| `ini`            | (detected by extension) |
| `js`, `mjs`      | `text/javascript`       |
| `md`, `markdown` | `text/markdown`         |
| `py`             | `text/x-python`         |
| `rss`            | `application/rss+xml`   |
| `sql`            | `application/sql`       |
| `tex`            | `application/x-tex`     |
| `toml`           | `application/toml`      |
| `vtt`            | `text/vtt`              |
| `yaml`, `yml`    | `application/yaml`      |
