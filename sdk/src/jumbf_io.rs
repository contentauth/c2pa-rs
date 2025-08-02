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
    io::{Cursor, Read, Seek},
};
#[cfg(feature = "file_io")]
use std::{
    fs,
    path::{Path, PathBuf},
};

use lazy_static::lazy_static;

#[cfg(feature = "pdf")]
use crate::asset_handlers::pdf_io::PdfIO;
use crate::{
    asset_handlers::{
        bmff_io::BmffIO, c2pa_io::C2paIO, gif_io::GifIO, jpeg_io::JpegIO, mp3_io::Mp3IO,
        png_io::PngIO, riff_io::RiffIO, svg_io::SvgIO, tiff_io::TiffIO, epub_io::EpubIo,
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
            Box::new(GifIO::new("")),
            Box::new(EpubIo::new("")),
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
            Box::new(GifIO::new("")),
            Box::new(EpubIo::new("")),
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

pub(crate) fn is_bmff_format(asset_type: &str) -> bool {
    let bmff_io = BmffIO::new("");
    bmff_io.supported_types().contains(&asset_type)
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
pub(crate) fn get_assetio_handler_from_path(asset_path: &Path) -> Option<&dyn AssetIO> {
    let ext = get_file_extension(asset_path)?;

    ASSET_HANDLERS.get(&ext).map(|h| h.as_ref())
}

pub(crate) fn get_assetio_handler(ext: &str) -> Option<&dyn AssetIO> {
    let ext = ext.to_lowercase();

    ASSET_HANDLERS.get(&ext).map(|h| h.as_ref())
}

pub(crate) fn get_cailoader_handler(asset_type: &str) -> Option<&dyn CAIReader> {
    let asset_type = asset_type.to_lowercase();

    ASSET_HANDLERS.get(&asset_type).map(|h| h.get_reader())
}

pub(crate) fn get_caiwriter_handler(asset_type: &str) -> Option<&dyn CAIWriter> {
    let asset_type = asset_type.to_lowercase();

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

    if ASSET_HANDLERS.get(&ext).is_some() {
        Some(ext)
    } else {
        None
    }
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
    let ext = get_file_extension(in_path.as_ref()).ok_or(Error::UnsupportedType)?;

    // if no output path make a new file based off of source file name
    let asset_out_path: PathBuf = match out_path.as_ref() {
        Some(p) => p.as_ref().to_owned(),
        None => {
            let filename_osstr = in_path.as_ref().file_stem().ok_or(Error::UnsupportedType)?;
            let filename = filename_osstr.to_str().ok_or(Error::UnsupportedType)?;

            let out_name = format!("{filename}-c2pa.{ext}");
            in_path.as_ref().to_owned().with_file_name(out_name)
        }
    };

    // clone output to be overwritten
    if in_path.as_ref() != asset_out_path {
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
#[allow(dead_code)] // this only used in Store unit tests, update this when those tests are updated
#[cfg(feature = "file_io")]
pub(crate) fn update_file_jumbf(
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

#[cfg(feature = "file_io")]
/// load the JUMBF block from an asset if available
pub fn load_jumbf_from_file<P: AsRef<Path>>(in_path: P) -> Result<Vec<u8>> {
    let ext = get_file_extension(in_path.as_ref()).ok_or(Error::UnsupportedType)?;

    match get_assetio_handler(&ext) {
        Some(asset_handler) => asset_handler.read_cai_store(in_path.as_ref()),
        _ => Err(Error::UnsupportedType),
    }
}

#[cfg(all(feature = "v1_api", feature = "file_io"))]
pub(crate) fn object_locations(in_path: &Path) -> Result<Vec<HashObjectPositions>> {
    let ext = get_file_extension(in_path).ok_or(Error::UnsupportedType)?;

    match get_assetio_handler(&ext) {
        Some(asset_handler) => asset_handler.get_object_locations(in_path),
        _ => Err(Error::UnsupportedType),
    }
}

struct CAIReadAdapter<R> {
    pub reader: R,
}

impl<R> Read for CAIReadAdapter<R>
where
    R: Read + Seek,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<R> Seek for CAIReadAdapter<R>
where
    R: Read + Seek,
{
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.reader.seek(pos)
    }
}

pub(crate) fn object_locations_from_stream<R>(
    format: &str,
    stream: &mut R,
) -> Result<Vec<HashObjectPositions>>
where
    R: Read + Seek + Send + ?Sized,
{
    let mut reader = CAIReadAdapter { reader: stream };

    match get_caiwriter_handler(format) {
        Some(handler) => handler.get_object_locations_from_stream(&mut reader),
        _ => Err(Error::UnsupportedType),
    }
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
    ASSET_HANDLERS.keys().map(|k| k.to_owned()).collect()
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::Seek;

    use super::*;
    use crate::{
        asset_io::RemoteRefEmbedType,
        crypto::raw_signature::SigningAlg,
        utils::{test::create_test_store, test_signer::test_signer},
    };

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
            Box::new(EpubIo::new("")),
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
            Box::new(EpubIo::new("")),
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
            Box::new(GifIO::new("")),
            Box::new(EpubIo::new("")),
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

    fn test_jumbf(asset_type: &str, reader: &mut dyn CAIRead) {
        let mut writer = Cursor::new(Vec::new());
        let store = create_test_store().unwrap();
        let signer = test_signer(SigningAlg::Ps256);
        let jumbf = store.to_jumbf(&*signer).unwrap();
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
        let remote_ref_writer = asset_handler.remote_ref_writer_ref().unwrap();
        let mut writer = Cursor::new(Vec::new());
        let embed_ref = RemoteRefEmbedType::Xmp(REMOTE_URL.to_string());
        remote_ref_writer
            .embed_reference_to_stream(reader, &mut writer, embed_ref)
            .unwrap();
        writer.set_position(0);
        let xmp = asset_handler.get_reader().read_xmp(&mut writer).unwrap();
        let loaded = crate::utils::xmp_inmemory_utils::extract_provenance(&xmp).unwrap();
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
    fn test_streams_c2pa() {
        let mut reader = std::fs::File::open("tests/fixtures/cloud_manifest.c2pa").unwrap();
        test_jumbf("c2pa", &mut reader);
    }
}
