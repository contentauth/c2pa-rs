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

pub mod bmff_io;
pub mod c2pa_io;
pub mod jpeg_io;
pub mod mp3_io;
pub mod png_io;
pub mod riff_io;
pub mod svg_io;
pub mod tiff_io;

#[cfg(feature = "pdf")]
pub(crate) mod pdf;
#[cfg(feature = "pdf")]
pub mod pdf_io;
