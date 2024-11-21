# Supported file formats

The following table summarizes the media (asset) file formats that the CAI Rust library supports.
Other libraries in the SDK support the same set of formats, unless noted otherwise.


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
<sup>*</sup> Fragmented MP4 is not yet supported.

<sup>**</sup> Read-only

