# Supported file formats

The following table summarizes the supported media (asset) file formats. This information is based on what the Rust library supports; other libraries in the SDK support the same formats unless noted otherwise.

> [!NOTE]
> When reading an asset, the SDK first looks at the file name extension to determine the asset type.  If the file has no extension, then the SDK uses the MIME type specified in the API call (if any).
> When the internal header/MIME disagrees with the extension, the SDK uses the extension, not the internal MIME/metadata.
> If there is no file extension nor MIME type, then the SDK "sniffs the bytes" of the asset using [`infer`](https://docs.rs/infer/latest/infer/) to determine the asset type.

| Extensions      | MIME type                                                                      |
| --------------- | ------------------------------------------------------------------------------- |
| `arw` (read-only) | `image/x-sony-arw`                                                            |
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
| `keras`         | (none registered) <br/>Keras 3 models, which are ZIP archives.                  |
| `m4a`           | `audio/mp4`                                                                     |
| `mp3`           | `audio/mpeg`                                                                    |
| `mp4`           | `video/mp4`, `application/mp4` <br/>Fragmented MP4 (DASH) supported only for file-based operations from the Rust library. |
| `mov`           | `video/quicktime`                                                               |
| `nef` (read-only) | `image/x-nikon-nef`                                                           |
| `pdf`           | `application/pdf`                                                               |
| `png`           | `image/png`                                                                     |
| `svg`           | `image/svg+xml`                                                                 |
| `tif`, `tiff`   | `image/tiff`                                                                    |
| `txt` *         | `text/plain`                                                                    |
| `wav`           | `audio/wav`                                                                     |
| `webp`          | `image/webp`                                                                    |

<sup>*</sup> Requires the non-default `unstable_plain_text` feature.

## Experimental feature: asset_io

The Rust library experimental, non-default `unstable_asset_io` feature routes every container that
[`asset-io`](https://github.com/contentauth/asset-io) 0.5 supports through it: JPEG, PNG, SVG, RIFF (WAV, WebP, AVI),
TIFF/DNG (ARW and NEF read only), MP3, FLAC, GIF, ISO BMFF (MP4, MOV, M4A, HEIC,
HEIF, AVIF), and `.c2pa` sidecars. PDF uses it when the `pdf` feature is also
enabled. JPEG XL, ZIP-based formats and text keep their legacy handlers, as do
all formats without `unstable_asset_io`.

Public handler registration and registry access, differential tests, and their
additional dependencies also require `unstable_asset_io`. Standard Makefile targets do
not enable it; use `make test-local FEATURES=file_io,fetch_remote_manifests,add_thumbnails,unstable_asset_io`
to include the experimental integration.

The ID3 adapter preserves unrelated frames byte-for-byte, including malformed
compressed frames. Its reader can find a manifest after such a frame even when
the legacy ID3 decoder stops before reaching it.

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
