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

#[cfg(feature = "file_io")]
use std::path::Path;
use std::{collections::HashMap, io::Cursor, sync::Arc};

use lazy_static::lazy_static;

#[cfg(feature = "pdf")]
use crate::asset_handlers::pdf_io::PdfIO;
use crate::{
    asset_handlers::{
        bmff_io::BmffIO, c2pa_io::C2paIO, flac_io::FlacIO, gif_io::GifIO, jpeg_io::JpegIO,
        jpegxl_io::JpegXlIO, mp3_io::Mp3IO, png_io::PngIO, riff_io::RiffIO, svg_io::SvgIO,
        tiff_io::TiffIO,
    },
    asset_io::{AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HandlerRegistry},
    error::{Error, Result},
    utils::mime::normalize_format,
};

// One prototype instance per handler family. All three lookup maps are derived from
// this single list so handlers only need to be enumerated here.
lazy_static! {
    static ref HANDLER_PROTOTYPES: Vec<Box<dyn AssetIO>> = vec![
        #[cfg(feature = "pdf")]
        Box::new(PdfIO::new("")),
        Box::new(BmffIO::new("")),
        Box::new(C2paIO::new("")),
        Box::new(JpegIO::new("")),
        Box::new(JpegXlIO::new("")),
        Box::new(PngIO::new("")),
        Box::new(RiffIO::new("")),
        Box::new(SvgIO::new("")),
        Box::new(TiffIO::new("")),
        Box::new(Mp3IO::new("")),
        Box::new(GifIO::new("")),
        Box::new(FlacIO::new("")),
    ];

    static ref CAI_READERS: HashMap<String, Box<dyn AssetIO>> = {
        let mut map = HashMap::new();
        for h in HANDLER_PROTOTYPES.iter() {
            for t in h.supported_types() {
                map.insert(t.to_string(), h.get_handler(t));
            }
        }
        map
    };

    static ref CAI_WRITERS: HashMap<String, Box<dyn CAIWriter>> = {
        let mut map = HashMap::new();
        for h in HANDLER_PROTOTYPES.iter() {
            for t in h.supported_types() {
                if let Some(writer) = h.get_writer(t) {
                    map.insert(t.to_string(), writer);
                }
            }
        }
        map
    };

    /// The shared default [`HandlerRegistry`], seeded with the same built-in handlers as
    /// `CAI_READERS`/`CAI_WRITERS`. This is what a fresh [`crate::Context`] falls back to
    /// once its own (typically empty) set of custom handlers has been checked.
    static ref DEFAULT_HANDLER_REGISTRY: Arc<HandlerRegistry> = {
        let mut reg = HandlerRegistry::new();
        for h in HANDLER_PROTOTYPES.iter() {
            // One instance stands in for the whole family, matching how a custom handler
            // registered via Context::with_io_handler already works: every get_handler(t)
            // impl just does Box::new(XxxIO::new(t)), so any supported type string produces
            // an equivalent instance for dispatch purposes.
            reg.add_boxed_handler(h.get_handler(h.supported_types()[0]));
        }
        Arc::new(reg)
    };
}

/// Returns the shared default [`HandlerRegistry`], populated with the SDK's built-in asset
/// I/O handlers.
pub(crate) fn default_handler_registry() -> Arc<HandlerRegistry> {
    DEFAULT_HANDLER_REGISTRY.clone()
}

/// Return jumbf block from in memory asset
#[allow(dead_code)]
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

#[cfg(feature = "file_io")]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn get_assetio_handler_from_path(asset_path: &Path) -> Option<&dyn AssetIO> {
    let ext = get_file_extension(asset_path)?;

    CAI_READERS.get(&ext).map(|h| h.as_ref())
}

pub(crate) fn get_assetio_handler(ext: &str) -> Option<&dyn AssetIO> {
    let ext = normalize_format(ext);

    CAI_READERS.get(&ext).map(|h| h.as_ref())
}

pub(crate) fn get_cailoader_handler(asset_type: &str) -> Option<&dyn CAIReader> {
    let asset_type = normalize_format(asset_type);

    CAI_READERS.get(&asset_type).map(|h| h.get_reader())
}

pub(crate) fn get_caiwriter_handler(asset_type: &str) -> Option<&dyn CAIWriter> {
    let asset_type = normalize_format(asset_type);

    CAI_WRITERS.get(&asset_type).map(|h| h.as_ref())
}

#[cfg(feature = "file_io")]
pub(crate) fn get_file_extension(path: &Path) -> Option<String> {
    let ext_osstr = path.extension()?;

    let ext = ext_osstr.to_str()?;

    Some(ext.to_lowercase())
}

#[cfg(feature = "file_io")]
pub(crate) fn get_supported_file_extension(path: &Path) -> Option<String> {
    let ext = get_file_extension(path)?;

    if CAI_READERS.get(&ext).is_some() {
        Some(ext)
    } else {
        None
    }
}

/// Returns a [Vec<String>] of supported mime types for reading manifests.
pub(crate) fn supported_reader_mime_types() -> Vec<String> {
    CAI_READERS.keys().map(String::to_owned).collect()
}

/// Returns a [Vec<String>] of mime types that [c2pa-rs] is able to sign.
pub(crate) fn supported_builder_mime_types() -> Vec<String> {
    CAI_WRITERS.keys().map(String::to_owned).collect()
}

#[cfg(feature = "file_io")]
/// Save JUMBF data to a file.
///
/// Parameters:
/// * save_jumbf to a file
/// * in_path - path is source file
/// * out_path - path to the output file
///
/// If no output file is given an new file will be created with "-c2pa" appending to file name e.g. "test.jpg" => "test-c2pa.jpg"
/// If input == output then the input file will be overwritten.
pub fn save_jumbf_to_file<P1: AsRef<Path>, P2: AsRef<Path>>(
    data: &[u8],
    in_path: P1,
    out_path: Option<P2>,
) -> Result<()> {
    default_handler_registry().write_jumbf_to_file(data, in_path, out_path)
}

#[cfg(feature = "file_io")]
/// load the JUMBF block from an asset if available
pub fn load_jumbf_from_file<P: AsRef<Path>>(in_path: P) -> Result<Vec<u8>> {
    default_handler_registry().read_jumbf_from_file(in_path)
}

/// removes the C2PA JUMBF from an asset
/// Note: Use with caution since this deletes C2PA data
/// It is useful when creating remote manifests from embedded manifests
///
/// path - path to file to be updated
/// returns Unsupported type or errors from remove_cai_store
#[cfg(feature = "file_io")]
pub fn remove_jumbf_from_file<P: AsRef<Path>>(path: P) -> Result<()> {
    let ext = get_file_extension(path.as_ref()).ok_or(Error::UnsupportedType)?;
    match get_assetio_handler(&ext) {
        Some(asset_handler) => asset_handler.remove_cai_store(path.as_ref()),
        _ => Err(Error::UnsupportedType),
    }
}

/// returns a list of supported file extensions and mime types
pub fn get_supported_types() -> Vec<String> {
    CAI_READERS.keys().map(|k| k.to_owned()).collect()
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::Seek;

    use super::*;
    use crate::{
        utils::{test::create_test_store, test_signer::test_signer},
        SigningAlg,
    };

    #[test]
    fn test_get_assetio() {
        let handlers: Vec<Box<dyn AssetIO>> = vec![
            Box::new(C2paIO::new("")),
            Box::new(BmffIO::new("")),
            Box::new(JpegIO::new("")),
            Box::new(JpegXlIO::new("")),
            Box::new(PngIO::new("")),
            Box::new(RiffIO::new("")),
            Box::new(TiffIO::new("")),
            Box::new(SvgIO::new("")),
            Box::new(Mp3IO::new("")),
            Box::new(FlacIO::new("")),
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
            Box::new(JpegXlIO::new("")),
            #[cfg(feature = "pdf")]
            Box::new(PdfIO::new("")),
            Box::new(PngIO::new("")),
            Box::new(RiffIO::new("")),
            Box::new(TiffIO::new("")),
            Box::new(SvgIO::new("")),
            Box::new(Mp3IO::new("")),
            Box::new(FlacIO::new("")),
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
            Box::new(JpegXlIO::new("")),
            Box::new(PngIO::new("")),
            Box::new(Mp3IO::new("")),
            Box::new(FlacIO::new("")),
            Box::new(SvgIO::new("")),
            Box::new(RiffIO::new("")),
            Box::new(GifIO::new("")),
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
    fn test_get_writer_tiff() {
        let h = TiffIO::new("");
        // Writing native formats is beyond the scope of the SDK.
        // Only the following are supported.
        let supported_tiff_types: [&str; 6] = [
            "tif",
            "tiff",
            "image/tiff",
            "dng",
            "image/dng",
            "image/x-adobe-dng",
        ];
        for tiff_type in h.supported_types() {
            if supported_tiff_types.contains(tiff_type) {
                assert!(get_caiwriter_handler(tiff_type).is_some());
            } else {
                assert!(get_caiwriter_handler(tiff_type).is_none());
            }
        }
    }

    /// Padded format strings (e.g. from an FFI boundary) must resolve to the
    /// same handler as the unpadded form for reads and writes.
    #[test]
    fn test_handlers_trim_padded_format() {
        assert!(get_cailoader_handler("  image/jpeg  ").is_some());
        assert!(get_caiwriter_handler("\timage/jpeg\n").is_some());
        assert!(get_assetio_handler("  image/png  ").is_some());
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
        assert!(supported.iter().any(|s| s == "jxl"));
    }

    fn test_jumbf(asset_type: &str, reader: &mut dyn CAIRead) {
        let mut writer = Cursor::new(Vec::new());
        let store = create_test_store().unwrap();
        let signer = test_signer(SigningAlg::Ps256);
        let jumbf = store.to_jumbf_internal(signer.reserve_size()).unwrap();
        save_jumbf_to_stream(asset_type, reader, &mut writer, &jumbf).unwrap();
        writer.set_position(0);
        let jumbf2 = load_jumbf_from_stream(asset_type, &mut writer).unwrap();
        assert_eq!(jumbf, jumbf2);

        // test removing cai store
        writer.set_position(0);
        let handler = get_caiwriter_handler(asset_type).unwrap();
        let mut removed = Cursor::new(Vec::new());
        handler
            .remove_cai_store_from_stream(&mut writer, &mut removed)
            .unwrap();
        removed.set_position(0);
        let result = load_jumbf_from_stream(asset_type, &mut removed);
        if (asset_type != "wav")
            && (asset_type != "avi" && asset_type != "mp3" && asset_type != "webp")
        {
            assert!(matches!(&result.err().unwrap(), Error::JumbfNotFound));
        }
        //assert!(matches!(result.err().unwrap(), Error::JumbfNotFound));
    }

    fn test_remote_ref(asset_type: &str, reader: &mut dyn CAIRead) {
        const REMOTE_URL: &str = "https://example.com/remote_manifest";
        let asset_handler = get_assetio_handler(asset_type).unwrap();
        let remote_ref_writer = asset_handler.remote_manifest_url_ref().unwrap();
        let mut writer = Cursor::new(Vec::new());
        remote_ref_writer
            .write_remote_manifest_url(reader, &mut writer, REMOTE_URL)
            .unwrap();
        writer.set_position(0);
        let xmp = asset_handler.get_reader().read_xmp(&mut writer).unwrap();
        let loaded = crate::utils::xmp_inmemory_utils::extract_provenance(&xmp).unwrap();
        assert_eq!(loaded, REMOTE_URL.to_string());

        writer.set_position(0);
        let loaded = remote_ref_writer.read_manifest_url(&mut writer).unwrap();
        assert_eq!(loaded, REMOTE_URL.to_string());
    }

    #[test]
    fn test_streams_jpeg() {
        let mut reader = std::fs::File::open("tests/fixtures/IMG_0003.jpg").unwrap();
        test_jumbf("jpeg", &mut reader);
        reader.rewind().unwrap();
        test_remote_ref("jpeg", &mut reader);
    }

    #[test]
    fn test_streams_png() {
        let mut reader = std::fs::File::open("tests/fixtures/sample1.png").unwrap();
        test_jumbf("png", &mut reader);
        reader.rewind().unwrap();
        test_remote_ref("png", &mut reader);
    }

    #[test]
    fn test_streams_webp() {
        let mut reader = std::fs::File::open("tests/fixtures/sample1.webp").unwrap();
        test_jumbf("webp", &mut reader);
        reader.rewind().unwrap();
        test_remote_ref("webp", &mut reader);
    }

    #[test]
    fn test_streams_wav() {
        let mut reader = std::fs::File::open("tests/fixtures/sample1.wav").unwrap();
        test_jumbf("wav", &mut reader);
        reader.rewind().unwrap();
        test_remote_ref("wav", &mut reader);
    }

    #[test]
    fn test_streams_avi() {
        let mut reader = std::fs::File::open("tests/fixtures/test.avi").unwrap();
        test_jumbf("avi", &mut reader);
        //reader.rewind().unwrap();
        //test_remote_ref("avi", &mut reader); // not working
    }

    #[test]
    fn test_streams_tiff() {
        let mut reader = std::fs::File::open("tests/fixtures/TUSCANY.TIF").unwrap();
        test_jumbf("tiff", &mut reader);
        reader.rewind().unwrap();
        test_remote_ref("tiff", &mut reader);
    }

    #[test]
    fn test_streams_svg() {
        let mut reader = std::fs::File::open("tests/fixtures/sample1.svg").unwrap();
        test_jumbf("svg", &mut reader);
        //reader.rewind().unwrap();
        //test_remote_ref("svg", &mut reader); // svg doesn't support remote refs
    }

    #[test]
    fn test_streams_mp3() {
        let mut reader = std::fs::File::open("tests/fixtures/sample1.mp3").unwrap();
        test_jumbf("mp3", &mut reader);
        // mp3 doesn't support remote refs
        //reader.rewind().unwrap();
        //test_remote_ref("mp3", &mut reader); // not working
    }

    #[test]
    fn test_streams_avif() {
        let mut reader = std::fs::File::open("tests/fixtures/sample1.avif").unwrap();
        test_jumbf("avif", &mut reader);
        //reader.rewind().unwrap();
        //test_remote_ref("avif", &mut reader);  // not working
    }

    #[test]
    fn test_streams_heic() {
        let mut reader = std::fs::File::open("tests/fixtures/sample1.heic").unwrap();
        test_jumbf("heic", &mut reader);
    }

    #[test]
    fn test_streams_heif() {
        let mut reader = std::fs::File::open("tests/fixtures/sample1.heif").unwrap();
        test_jumbf("heif", &mut reader);
        //reader.rewind().unwrap();
        //test_remote_ref("heif", &mut reader);   // not working
    }

    #[test]
    fn test_streams_mp4() {
        let mut reader = std::fs::File::open("tests/fixtures/video1.mp4").unwrap();
        test_jumbf("mp4", &mut reader);
        reader.rewind().unwrap();
        test_remote_ref("mp4", &mut reader);
    }

    #[test]
    fn test_streams_jxl() {
        // Build a minimal JPEG XL container in memory for testing
        use crate::asset_handlers::jpegxl_io;
        let container = jpegxl_io::tests::build_test_jxl_container();
        let mut reader = Cursor::new(container);
        test_jumbf("jxl", &mut reader);
        reader.rewind().unwrap();
        test_remote_ref("jxl", &mut reader);
    }

    #[test]
    fn test_streams_c2pa() {
        let mut reader = std::fs::File::open("tests/fixtures/cloud_manifest.c2pa").unwrap();
        test_jumbf("c2pa", &mut reader);
    }
}
