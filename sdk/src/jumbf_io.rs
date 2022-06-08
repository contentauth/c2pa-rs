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

use crate::{
    asset_handlers::{c2pa_io::C2paIO, jpeg_io::JpegIO, png_io::PngIO},
    asset_io::{AssetIO, CAILoader, HashObjectPositions},
    error::{Error, Result},
};

use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
};

static SUPPORTED_TYPES: &[&str; 6] = &[
    "c2pa", // stand-alone manifest file
    "jpg",
    "jpeg",
    "png",
    "image/jpeg",
    "image/png",
];

/// Return jumbf block from in memory asset
pub fn load_jumbf_from_memory(asset_type: &str, data: &[u8]) -> Result<Vec<u8>> {
    let mut buf_reader = Cursor::new(data);

    let cai_block = match get_cailoader_handler(asset_type) {
        Some(asset_handler) => asset_handler.read_cai(&mut buf_reader)?,
        None => return Err(Error::UnsupportedType),
    };
    if cai_block.is_empty() {
        return Err(Error::JumbfNotFound);
    }
    Ok(cai_block)
}

pub fn get_assetio_handler(ext: &str) -> Option<Box<dyn AssetIO>> {
    match ext {
        "c2pa" => Some(Box::new(C2paIO {})),
        "jpg" | "jpeg" => Some(Box::new(JpegIO {})),
        "png" => Some(Box::new(PngIO {})),
        _ => None,
    }
}

pub fn get_cailoader_handler(asset_type: &str) -> Option<Box<dyn CAILoader>> {
    match asset_type {
        "c2pa" | "application/c2pa" => Some(Box::new(C2paIO {})),
        "jpg" | "jpeg" | "image/jpeg" => Some(Box::new(JpegIO {})),
        "png" | "image/png" => Some(Box::new(PngIO {})),
        _ => None,
    }
}

pub fn get_file_extension(path: &Path) -> Option<String> {
    let ext_osstr = path.extension()?;

    let ext = ext_osstr.to_str()?;

    Some(ext.to_lowercase())
}

pub fn get_supported_file_extension(path: &Path) -> Option<String> {
    let ext = get_file_extension(path)?;

    if SUPPORTED_TYPES.contains(&ext.as_ref()) {
        Some(ext)
    } else {
        None
    }
}

/// save_jumbf to a file
/// in_path - path is source file
/// out_path - path to the output file
/// If no output file is given an new file will be created with "-c2pa" appending to file name e.g. "test.jpg" => "test-c2pa.jpg"
/// If input == output then the input file will be overwritten.
pub fn save_jumbf_to_file(data: &[u8], in_path: &Path, out_path: Option<&Path>) -> Result<()> {
    let ext = get_file_extension(in_path).ok_or(Error::UnsupportedType)?;

    // if no output path make a new file based off of source file name
    let img_out_path: PathBuf = match out_path {
        Some(p) => p.to_owned(),
        None => {
            let filename_osstr = in_path.file_stem().ok_or(Error::UnsupportedType)?;
            let filename = filename_osstr.to_str().ok_or(Error::UnsupportedType)?;

            let out_name = format!("{}-c2pa.{}", filename, ext);
            in_path.to_owned().with_file_name(out_name)
        }
    };

    // clone output to be overwritten
    if in_path != img_out_path {
        fs::copy(&in_path, &img_out_path).map_err(Error::IoError)?;
    }

    match get_assetio_handler(&ext) {
        Some(asset_handler) => asset_handler.save_cai_store(&img_out_path, data),
        _ => Err(Error::UnsupportedType),
    }
}

/// Updates jumbf content in a file, this will directly patch the contents no other processing is done.
/// The search for content to replace only occurs over the jumbf content.
/// Note: it is recommended that the replace contents be <= length of the search content so that the length of the
/// file does not change. If it does that could make the new file unreadable. This function is primarily useful for
/// generating test data since depending on how the file is rewritten the hashing mechanism should detect any tampering of the data.
///
/// out_path - path to file to be updated
/// search_bytes - bytes to be replaced
/// replace_bytes - replacement bytes
/// returns the location where splice occurred
#[cfg(test)] // this only used in unit tests
pub fn update_file_jumbf(
    out_path: &Path,
    search_bytes: &[u8],
    replace_bytes: &[u8],
) -> Result<usize> {
    use crate::utils::patch::patch_bytes;

    let mut jumbf = load_jumbf_from_file(out_path)?;

    let splice_point = patch_bytes(&mut jumbf, search_bytes, replace_bytes)?;

    save_jumbf_to_file(&jumbf, out_path, Some(out_path))?;

    Ok(splice_point)
}

/// load the JUMBF block from an asset if available
pub fn load_jumbf_from_file(in_path: &Path) -> Result<Vec<u8>> {
    let ext = get_file_extension(in_path).ok_or(Error::UnsupportedType)?;

    match get_assetio_handler(&ext) {
        Some(asset_handler) => asset_handler.read_cai_store(in_path),
        _ => Err(Error::UnsupportedType),
    }
}

pub fn object_locations(in_path: &Path) -> Result<Vec<HashObjectPositions>> {
    let ext = get_file_extension(in_path).ok_or(Error::UnsupportedType)?;

    match get_assetio_handler(&ext) {
        Some(asset_handler) => asset_handler.get_object_locations(in_path),
        _ => Err(Error::UnsupportedType),
    }
}
