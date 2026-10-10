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
| `mp3`           | `audio/mpeg`                                                                    |
| `mp4`           | `video/mp4`, `application/mp4` <br/>Fragmented MP4 (DASH) supported only for file-based operations from the Rust library. |
| `mov`           | `video/quicktime`                                                               |
| `pdf`           | `application/pdf`                                                               |
| `png`           | `image/png`                                                                     |
| `svg`           | `image/svg+xml`                                                                 |
| `tif`, `tiff`   | `image/tiff`                                                                    |
| `txt`           | `text/plain`                                                                    |
| `wav`           | `audio/wav`                                                                     |
| `webp`          | `image/webp`                                                                    |

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

## Experimental feature: GLB

The Rust library supports binary glTF 2.0 (GLB) when the `unstable_glb` feature is enabled. The manifest is carried in a dedicated `C2PA` chunk, following the GLB section of the C2PA specification working draft.

| Extensions | MIME type           |
| ---------- | ------------------- |
| `glb`      | `model/gltf-binary` |

## Experimental feature: Matroska and WebM

The Rust library supports Matroska and WebM when the `unstable_matroska` feature is enabled. The manifest is carried in an `AttachedFile` (`FileMediaType` `application/c2pa`) of an `Attachments` element placed at the end of the `Segment`, following the Matroska section of the C2PA specification working draft. Files with unknown-size elements (for example, unfinalized `MediaRecorder` or live recordings) or with more than one `Segment` are not supported; finalize or remux them first.

| Extensions      | MIME type                                                  |
| --------------- | ---------------------------------------------------------- |
| `mkv`, `mk3d`   | `video/matroska`, `video/x-matroska`, `video/matroska-3d`  |
| `mka`           | `audio/matroska`, `audio/x-matroska`                       |
| `webm`          | `video/webm`, `audio/webm`                                 |
