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

use twoway::find_bytes;

use crate::error::{Error, Result};

/**
Patch a sequence bytes with a new set of bytes - the search_bytes are erased and replaced with replace_bytes
This function only patches the first occurance
returns the location where splice occurred
*/
pub fn patch_bytes(data: &mut Vec<u8>, search_bytes: &[u8], replace_bytes: &[u8]) -> Result<usize> {
    // patch data bytes in memory

    if let Some(splice_start) = find_bytes(data, search_bytes) {
        data.splice(
            splice_start..splice_start + search_bytes.len(),
            replace_bytes.iter().cloned(),
        );
        Ok(splice_start)
    } else {
        Err(Error::NotFound)
    }
}

/**
Patch new content into a file
path - path to file to be patched
search_bytes - bytes to be replaced
replace_bytes - replacement bytes
returns the location where splice occurred
*/
#[cfg(all(test, feature = "file_io"))]
pub fn patch_file(
    path: &std::path::Path,
    search_bytes: &[u8],
    replace_bytes: &[u8],
) -> Result<usize> {
    let mut buf = std::fs::read(path).map_err(Error::IoError)?;

    let splice_point = patch_bytes(&mut buf, search_bytes, replace_bytes)?;

    std::fs::write(path, &buf).map_err(Error::IoError)?;

    Ok(splice_point)
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_patch() {
        let source = "Hello everyone this is a test".as_bytes();
        let mut source_vec = source.to_vec();
        let search_bytes = "everyone".as_bytes();
        let replace_bytes = "world".as_bytes();
        let replace_bytes2 = "universe".as_bytes();
        let test_bytes = "test".as_bytes();
        let unit_test_bytes = "unit test".as_bytes();

        println!("Original string: {}", String::from_utf8_lossy(&source_vec));

        patch_bytes(&mut source_vec, search_bytes, replace_bytes).unwrap();

        println!(
            "Replaced string: {}\n",
            String::from_utf8_lossy(&source_vec)
        );

        patch_bytes(&mut source_vec, replace_bytes, replace_bytes2).unwrap();

        println!(
            "Re-Replaced string: {}\n",
            String::from_utf8_lossy(&source_vec)
        );

        patch_bytes(&mut source_vec, test_bytes, unit_test_bytes).unwrap();

        println!(
            "Pad end of data string: {}\n",
            String::from_utf8_lossy(&source_vec)
        );
    }
}
