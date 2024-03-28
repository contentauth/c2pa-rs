// Copyright 2024 Adobe. All rights reserved.
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

// mod c2pa;
// pub use c2pa::C2pa;
mod reader;
pub use reader::Reader;
mod builder;
pub use builder::Builder;

// #[cfg(feature = "file_io")]
// pub use crate::{Error, Result};

pub fn format_from_path<P: AsRef<std::path::Path>>(path: P) -> Option<String> {
    path.as_ref()
        .extension()
        .map(|ext| crate::utils::mime::format_to_mime(ext.to_string_lossy().as_ref()))
}
