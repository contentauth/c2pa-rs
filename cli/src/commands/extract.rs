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

use std::fs;

use anyhow::{bail, Result};
use c2pa::ManifestStore;

use crate::{commands::Extract, load_trust_settings};

pub fn extract(config: Extract) -> Result<()> {
    load_trust_settings(&config.trust)?;

    fs::create_dir_all(&config.output)?;

    for entry in glob::glob(&config.path)? {
        let path = entry?;
        if path.is_dir() {
            bail!("Input path cannot be a folder when extracting resources");
        }

        ManifestStore::from_file_with_resources(&path, &config.output)?;
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    // use super::*;

    #[test]
    fn test_sign() {
        // TODO:
    }
}
