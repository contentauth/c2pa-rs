# Supported file formats

The following table summarizes the supported media (asset) file formats.  This information is based on what the Rust library supports; other libraries in the SDK support the same formats, unless noted otherwise.


 | Extensions    | MIME type                                                                     |
 | ------------- | ----------------------------------------------------------------------------- |
 | `avi`         | `video/msvideo`, `video/x-msvideo`, `video/avi`, `application/x-troff-msvideo`|
 | `avif`        | `image/avif`                                                                  |
 | `c2pa`        | `application/x-c2pa-manifest-store`                                           |
 | `dng`         | `image/x-adobe-dng`                                                           |
 | `gif`         | `image/gif`                                                                   |
 | `heic`        | `image/heic`                                                                  |
 | `heif`        | `image/heif`                                                                  |
 | `jpg`, `jpeg` | `image/jpeg`                                                                  |
 | `m4a`         | `audio/mp4`                                                                   |
 | `mp3`         | `audio/mpeg`                                                                  |
 | `mp4`         | `video/mp4`, `application/mp4` <sup>*</sup>                                   |
 | `mov`         | `video/quicktime`                                                             |
 | `pdf`         | `application/pdf` <sup>**</sup>                                               |
 | `png`         | `image/png`                                                                   |
 | `svg`         | `image/svg+xml`                                                               |
 | `tif`,`tiff`  | `image/tiff`                                                                  |
 | `wav`         | `audio/wav`                                                                   |
 | `webp`        | `image/webp`                                                                  |

NOTES:
<sup>*</sup> Fragmented MP4 (DASH) is supported only for file-based operations from the Rust library.
<br/>
<sup>**</sup> Read-only

