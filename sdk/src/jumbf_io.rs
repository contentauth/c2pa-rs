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

use std::{
    fs::{self, File},
    io::Cursor,
    path::{Path, PathBuf},
};

use crate::{
    asset_handlers::{
        bmff_io::BmffIO, c2pa_io::C2paIO, jpeg_io::JpegIO, png_io::PngIO, tiff_io::TiffIO,
    },
    asset_io::{AssetIO, CAILoader, HashObjectPositions},
    error::{Error, Result},
};

static SUPPORTED_TYPES: [&str; 23] = [
    "avif",
    "c2pa", // stand-alone manifest file
    "heif",
    "heic",
    "jpg",
    "jpeg",
    "mp4",
    "m4a",
    "mov",
    "png",
    "tif",
    "tiff",
    "dng",
    "application/mp4",
    "audio/mp4",
    "image/avif",
    "image/heic",
    "image/heif",
    "image/jpeg",
    "image/png",
    "video/mp4",
    "image/tiff",
    "image/dng",
];

#[cfg(feature = "file_io")]
static BMFF_TYPES: [&str; 12] = [
    "avif",
    "heif",
    "heic",
    "mp4",
    "m4a",
    "mov",
    "application/mp4",
    "audio/mp4",
    "image/avif",
    "image/heic",
    "image/heif",
    "video/mp4",
];

#[cfg(feature = "file_io")]
pub(crate) fn is_bmff_format(asset_type: &str) -> bool {
    BMFF_TYPES.contains(&asset_type)
}

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
    let ext = ext.to_lowercase();
    match ext.as_ref() {
        "c2pa" => Some(Box::new(C2paIO {})),
        "jpg" | "jpeg" => Some(Box::new(JpegIO {})),
        "png" => Some(Box::new(PngIO {})),
        "mp4" | "m4a" | "mov" if cfg!(feature = "bmff") => Some(Box::new(BmffIO::new(&ext))),
        "tif" | "tiff" | "dng" => Some(Box::new(TiffIO {})),
        _ => None,
    }
}

pub fn get_cailoader_handler(asset_type: &str) -> Option<Box<dyn CAILoader>> {
    let asset_type = asset_type.to_lowercase();
    match asset_type.as_ref() {
        "c2pa" | "application/c2pa" | "application/x-c2pa-manifest-store" => {
            Some(Box::new(C2paIO {}))
        }
        "jpg" | "jpeg" | "image/jpeg" => Some(Box::new(JpegIO {})),
        "png" | "image/png" => Some(Box::new(PngIO {})),
        "avif" | "heif" | "heic" | "mp4" | "m4a" | "application/mp4" | "audio/mp4"
        | "image/avif" | "image/heic" | "image/heif" | "video/mp4"
            if cfg!(feature = "bmff") && !cfg!(target_arch = "wasm32") =>
        {
            Some(Box::new(BmffIO::new(&asset_type)))
        }
        "tif" | "tiff" | "dng" => Some(Box::new(TiffIO {})),
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
    let asset_out_path: PathBuf = match out_path {
        Some(p) => p.to_owned(),
        None => {
            let filename_osstr = in_path.file_stem().ok_or(Error::UnsupportedType)?;
            let filename = filename_osstr.to_str().ok_or(Error::UnsupportedType)?;

            let out_name = format!("{}-c2pa.{}", filename, ext);
            in_path.to_owned().with_file_name(out_name)
        }
    };

    // clone output to be overwritten
    if in_path != asset_out_path {
        fs::copy(in_path, &asset_out_path).map_err(Error::IoError)?;
    }

    match get_assetio_handler(&ext) {
        Some(asset_handler) => {
            // patch if possible to save time and resources
            if let Some(patch_handler) = asset_handler.asset_patch_ref() {
                if patch_handler.patch_cai_store(&asset_out_path, data).is_ok() {
                    return Ok(());
                }
            }

            // couldn't patch so just save
            asset_handler.save_cai_store(&asset_out_path, data)
        }
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

    match get_cailoader_handler(&ext) {
        Some(asset_handler) => {
            let mut f = File::open(in_path)?;
            asset_handler.read_cai(&mut f)
        }
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

/// removes the C2PA JUMBF from an asset
/// Note: Use with caution since this deletes C2PA data
/// It is useful when creating remote manifests from embedded manifests
///
/// path - path to file to be updated
/// returns Unsupported type or errors from remove_cai_store
pub fn remove_jumbf_from_file(path: &Path) -> Result<()> {
    let ext = get_file_extension(path).ok_or(Error::UnsupportedType)?;
    match get_assetio_handler(&ext) {
        Some(asset_handler) => asset_handler.remove_cai_store(path),
        _ => Err(Error::UnsupportedType),
    }
}
