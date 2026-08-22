# Supported file formats

The following table summarizes the supported media (asset) file formats. This information is based on what the Rust library supports; other libraries in the SDK support the same formats unless noted otherwise.

> [!NOTE]
> When reading an asset, the SDK first looks at the file name extension to determine the asset type.  If the file has no extension, then the SDK uses the MIME type specified in the API call (if any).
> When the internal header/MIME disagrees with the extension, the SDK uses the extension, not the internal MIME/metadata.
> If there is no file extension nor MIME type, then the SDK "sniffs the bytes" of the asset using [`infer`](https://docs.rs/infer/latest/infer/) to determine the asset type.

| Extensions    | MIME type                                                                      |
| ------------- | ------------------------------------------------------------------------------ |
| `avi`         | `video/msvideo`, `video/x-msvideo`, `video/avi`, `application/x-troff-msvideo` |
| `avif`        | `image/avif`                                                                   |
| `c2pa`        | `application/x-c2pa-manifest-store`                                            |
| `dng`         | `image/x-adobe-dng`                                                            |
| `flac`        | `audio/flac`                                                                   |
| `gif`         | `image/gif`                                                                    |
| `heic`        | `image/heic`                                                                   |
| `heif`        | `image/heif`                                                                   |
| `jpg`, `jpeg` | `image/jpeg`                                                                   |
| `jxl`         | `image/jxl`                                                                    |
| `m4a`         | `audio/mp4`                                                                    |
| `mp3`         | `audio/mpeg`                                                                   |
| `mp4`         | `video/mp4`, `application/mp4`                                                 |
| `mov`         | `video/quicktime`                                                              |
| `pdf`         | `application/pdf` (**read-only**)                                              |
| `png`         | `image/png`                                                                    |
| `svg`         | `image/svg+xml`                                                                |
| `tif`, `tiff` | `image/tiff`                                                                   |
| `wav`         | `audio/wav`                                                                    |
| `webp`        | `image/webp`                                                                   |

Fragmented MP4 (DASH) is supported only for file-based operations from the Rust library.

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
