// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

// EXPERIMENT (local only, do not commit)
#[cfg(feature = "asset_io")]
pub(crate) mod asset_io_adapter;
pub mod bmff_io;
pub mod c2pa_io;
pub mod flac_io;
pub mod gif_io;
pub(crate) mod id3_helper;
#[cfg(any(not(feature = "asset_io"), test))]
pub mod jpeg_io;
pub mod jpegxl_io;
pub mod mp3_io;
#[cfg(feature = "unstable_plain_text")]
pub mod plain_text_io;
#[cfg(any(not(feature = "asset_io"), test))]
pub mod png_io;
#[cfg(any(not(feature = "asset_io"), test))]
pub mod riff_io;
#[cfg(feature = "unstable_structured_text")]
pub mod structured_text_io;
#[cfg(any(not(feature = "asset_io"), test))]
pub mod svg_io;
#[cfg(feature = "unstable_structured_text")]
pub(crate) mod text_common;
#[cfg(any(not(feature = "asset_io"), test))]
pub mod tiff_io;
pub mod zip_io;

#[cfg(feature = "pdf")]
pub(crate) mod pdf;
#[cfg(all(feature = "pdf", any(not(feature = "asset_io"), test)))]
pub mod pdf_io;
