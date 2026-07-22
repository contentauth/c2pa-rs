# Supported file formats

The following table summarizes the supported media (asset) file formats.  This information is based on what the Rust library supports; other libraries in the SDK support the same formats unless noted otherwise.

Text formats (`atom`, `css`, `ini`, `js`, `md`, `py`, `rss`, `sql`, `tex`, `toml`, `vtt`, `yaml`) require the non-default `text` feature.


 | Extensions    | MIME type                                                                     |
 | ------------- | ----------------------------------------------------------------------------- |
 | `atom`        | `application/atom+xml`                                                        |
 | `avi`         | `video/msvideo`, `video/x-msvideo`, `video/avi`, `application/x-troff-msvideo`|
 | `avif`        | `image/avif`                                                                  |
 | `c2pa`        | `application/x-c2pa-manifest-store`                                           |
 | `css`         | `text/css`                                                                    |
 | `dng`         | `image/x-adobe-dng`                                                           |
 | `flac`        | `audio/flac`                                                                  |
 | `gif`         | `image/gif`                                                                   |
 | `heic`        | `image/heic`                                                                  |
 | `heif`        | `image/heif`                                                                  |
 | `ini`         | (detected by extension)                                                       |
| `jpg`, `jpeg` | `image/jpeg`                                                                  |
| `js`, `mjs`   | `text/javascript`                                                             |
| `jxl`         | `image/jxl`                                                                   |
| `m4a`         | `audio/mp4`                                                                   |
| `md`, `markdown` | `text/markdown`                                                            |
 | `mp3`         | `audio/mpeg`                                                                  |
 | `mp4`         | `video/mp4`, `application/mp4` <br/>Fragmented MP4 (DASH) supported only for file-based operations from the Rust library.                                   |
 | `mov`         | `video/quicktime`                                                             |
 | `pdf`         | `application/pdf` (**read-only**)                                              |
 | `png`         | `image/png`                                                                   |
 | `py`          | `text/x-python`                                                               |
 | `rss`         | `application/rss+xml`                                                         |
 | `sql`         | `application/sql`                                                             |
 | `svg`         | `image/svg+xml`                                                               |
 | `tex`         | `application/x-tex`                                                           |
 | `tif`,`tiff`  | `image/tiff`                                                                  |
 | `toml`        | `application/toml`                                                            |
 | `vtt`         | `text/vtt`                                                                    |
 | `wav`         | `audio/wav`                                                                   |
 | `webp`        | `image/webp`                                                                  |
 | `yaml`, `yml` | `application/yaml`                                                            |
