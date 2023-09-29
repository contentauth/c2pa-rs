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
    collections::HashMap,
    fs::{self, File},
    io::Cursor,
    path::{Path, PathBuf},
};

use lazy_static::lazy_static;

#[cfg(feature = "pdf")]
use crate::asset_handlers::pdf_io::PdfIO;
use crate::{
    asset_handlers::{
        bmff_io::BmffIO, c2pa_io::C2paIO, jpeg_io::JpegIO, mp3_io::Mp3IO, png_io::PngIO,
        riff_io::RiffIO, svg_io::SvgIO, tiff_io::TiffIO,
    },
    asset_io::{AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashObjectPositions},
    error::{Error, Result},
};

// initialize asset handlers
lazy_static! {
    static ref ASSET_HANDLERS: HashMap<String, Box<dyn AssetIO>> = {
        let handlers: Vec<Box<dyn AssetIO>> = vec![
            #[cfg(feature = "pdf")]
            Box::new(PdfIO::new("")),
            Box::new(BmffIO::new("")),
            Box::new(C2paIO::new("")),
            Box::new(JpegIO::new("")),
            Box::new(PngIO::new("")),
            Box::new(RiffIO::new("")),
            Box::new(SvgIO::new("")),
            Box::new(TiffIO::new("")),
            Box::new(Mp3IO::new("")),
        ];

        let mut handler_map = HashMap::new();

        // build handler map
        for h in handlers {
            // get the supported types add entry for each
            for supported_type in h.supported_types() {
                handler_map.insert(supported_type.to_string(), h.get_handler(supported_type));
            }
        }

        handler_map
    };
}

// initialize streaming write handlers
lazy_static! {
    static ref CAI_WRITERS: HashMap<String, Box<dyn CAIWriter>> = {
        let handlers: Vec<Box<dyn AssetIO>> = vec![
            Box::new(BmffIO::new("")),
            Box::new(C2paIO::new("")),
            Box::new(JpegIO::new("")),
            Box::new(PngIO::new("")),
            Box::new(RiffIO::new("")),
            Box::new(SvgIO::new("")),
            Box::new(TiffIO::new("")),
            Box::new(Mp3IO::new("")),
        ];
        let mut handler_map = HashMap::new();

        // build handler map
        for h in handlers {
            // get the supported types add entry for each
            for supported_type in h.supported_types() {
                if let Some(writer) = h.get_writer(supported_type) { // get streaming writer if supported
                    handler_map.insert(supported_type.to_string(), writer);
                }
            }
        }

        handler_map
    };
}

#[cfg(feature = "file_io")]
pub(crate) fn is_bmff_format(asset_type: &str) -> bool {
    let bmff_io = BmffIO::new("");
    bmff_io.supported_types().contains(&asset_type)
}

/// Return jumbf block from in memory asset
pub fn load_jumbf_from_memory(asset_type: &str, data: &[u8]) -> Result<Vec<u8>> {
    let mut buf_reader = Cursor::new(data);

    load_jumbf_from_stream(asset_type, &mut buf_reader)
}

/// Return jumbf block from stream asset
pub fn load_jumbf_from_stream(asset_type: &str, input_stream: &mut dyn CAIRead) -> Result<Vec<u8>> {
    let cai_block = match get_cailoader_handler(asset_type) {
        Some(asset_handler) => asset_handler.read_cai(input_stream)?,
        None => return Err(Error::UnsupportedType),
    };
    if cai_block.is_empty() {
        return Err(Error::JumbfNotFound);
    }
    Ok(cai_block)
}
/// writes the jumbf data in store_bytes
/// reads an asset of asset_type from reader, adds jumbf data and then writes to writer
pub fn save_jumbf_to_stream(
    asset_type: &str,
    input_stream: &mut dyn CAIRead,
    output_stream: &mut dyn CAIReadWrite,
    store_bytes: &[u8],
) -> Result<()> {
    match get_caiwriter_handler(asset_type) {
        Some(asset_handler) => asset_handler.write_cai(input_stream, output_stream, store_bytes),
        None => Err(Error::UnsupportedType),
    }
}

/// writes the jumbf data in store_bytes into an asset in data and returns the newly created asset
pub fn save_jumbf_to_memory(asset_type: &str, data: &[u8], store_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut input_stream = Cursor::new(data);
    let output_vec: Vec<u8> = Vec::with_capacity(data.len() + store_bytes.len() + 1024);
    let mut output_stream = Cursor::new(output_vec);

    save_jumbf_to_stream(
        asset_type,
        &mut input_stream,
        &mut output_stream,
        store_bytes,
    )?;
    Ok(output_stream.into_inner())
}

pub fn get_assetio_handler_from_path(asset_path: &Path) -> Option<&dyn AssetIO> {
    let ext = get_file_extension(asset_path)?;

    ASSET_HANDLERS.get(&ext).map(|h| h.as_ref())
}

pub fn get_assetio_handler(ext: &str) -> Option<&dyn AssetIO> {
    let ext = ext.to_lowercase();

    ASSET_HANDLERS.get(&ext).map(|h| h.as_ref())
}

pub fn get_cailoader_handler(asset_type: &str) -> Option<&dyn CAIReader> {
    let asset_type = asset_type.to_lowercase();

    ASSET_HANDLERS.get(&asset_type).map(|h| h.get_reader())
}

pub fn get_caiwriter_handler(asset_type: &str) -> Option<&dyn CAIWriter> {
    let asset_type = asset_type.to_lowercase();

    CAI_WRITERS.get(&asset_type).map(|h| h.as_ref())
}

pub fn get_file_extension(path: &Path) -> Option<String> {
    let ext_osstr = path.extension()?;

    let ext = ext_osstr.to_str()?;

    Some(ext.to_lowercase())
}

pub fn get_supported_file_extension(path: &Path) -> Option<String> {
    let ext = get_file_extension(path)?;

    if ASSET_HANDLERS.get(&ext).is_some() {
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

            let out_name = format!("{filename}-c2pa.{ext}");
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

pub fn object_locations_from_stream(
    format: &str,
    stream: &mut dyn CAIRead,
) -> Result<Vec<HashObjectPositions>> {
    match get_caiwriter_handler(format) {
        Some(handler) => handler.get_object_locations_from_stream(stream),
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

/// returns a list of supported file extensions and mime types
pub fn get_supported_types() -> Vec<String> {
    ASSET_HANDLERS.keys().map(|k| k.to_owned()).collect()
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    #[test]
    fn test_get_assetio() {
        let handlers: Vec<Box<dyn AssetIO>> = vec![
            Box::new(C2paIO::new("")),
            Box::new(BmffIO::new("")),
            Box::new(JpegIO::new("")),
            Box::new(PngIO::new("")),
            Box::new(RiffIO::new("")),
            Box::new(TiffIO::new("")),
            Box::new(SvgIO::new("")),
            Box::new(Mp3IO::new("")),
        ];

        // build handler map
        for h in handlers {
            // get the supported types add entry for each
            for supported_type in h.supported_types() {
                assert!(get_assetio_handler(supported_type).is_some());
            }
        }
    }

    #[test]
    fn test_get_reader() {
        let handlers: Vec<Box<dyn AssetIO>> = vec![
            Box::new(C2paIO::new("")),
            Box::new(BmffIO::new("")),
            Box::new(JpegIO::new("")),
            #[cfg(feature = "pdf")]
            Box::new(PdfIO::new("")),
            Box::new(PngIO::new("")),
            Box::new(RiffIO::new("")),
            Box::new(TiffIO::new("")),
            Box::new(SvgIO::new("")),
            Box::new(Mp3IO::new("")),
        ];

        // build handler map
        for h in handlers {
            // get the supported types add entry for each
            for supported_type in h.supported_types() {
                assert!(get_cailoader_handler(supported_type).is_some());
            }
        }
    }

    #[test]
    fn test_get_writer() {
        let handlers: Vec<Box<dyn AssetIO>> = vec![
            Box::new(JpegIO::new("")),
            Box::new(PngIO::new("")),
            Box::new(Mp3IO::new("")),
            Box::new(SvgIO::new("")),
            Box::new(RiffIO::new("")),
        ];

        // build handler map
        for h in handlers {
            // get the supported types add entry for each
            for supported_type in h.supported_types() {
                assert!(get_caiwriter_handler(supported_type).is_some());
            }
        }
    }

    #[test]
    fn test_no_writer() {
        let handlers: Vec<Box<dyn AssetIO>> = vec![
            Box::new(C2paIO::new("")),
            Box::new(BmffIO::new("")),
            Box::new(TiffIO::new("")),
        ];

        // build handler map
        for h in handlers {
            // get the supported types add entry for each
            for supported_type in h.supported_types() {
                assert!(get_caiwriter_handler(supported_type).is_none());
            }
        }
    }

    #[test]
    fn test_get_supported_list() {
        let supported = get_supported_types();

        let pdf_supported = supported.iter().any(|s| s == "pdf");
        assert_eq!(pdf_supported, cfg!(feature = "pdf"));

        assert!(supported.iter().any(|s| s == "jpg"));
        assert!(supported.iter().any(|s| s == "jpeg"));
        assert!(supported.iter().any(|s| s == "png"));
        assert!(supported.iter().any(|s| s == "mov"));
        assert!(supported.iter().any(|s| s == "mp4"));
        assert!(supported.iter().any(|s| s == "m4a"));
        assert!(supported.iter().any(|s| s == "avi"));
        assert!(supported.iter().any(|s| s == "webp"));
        assert!(supported.iter().any(|s| s == "wav"));
        assert!(supported.iter().any(|s| s == "tif"));
        assert!(supported.iter().any(|s| s == "tiff"));
        assert!(supported.iter().any(|s| s == "dng"));
        assert!(supported.iter().any(|s| s == "svg"));
        assert!(supported.iter().any(|s| s == "mp3"));
    }
}
