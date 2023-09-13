// Copyright 2023 Adobe. All rights reserved.
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
    fs::{File, OpenOptions},
    io::{BufReader, Cursor, Seek, SeekFrom, Write},
    path::Path,
};

use conv::ValueFrom;
use fast_xml::{
    events::{BytesText, Event},
    Reader, Writer,
};
use tempfile::Builder;

use crate::{
    asset_io::{
        AssetIO,
        AssetPatch,
        CAIRead,
        CAIReadWrite,
        CAIReader,
        CAIWriter, //RemoteRefEmbedType,
        HashBlockObjectType,
        //HashBlockObjectType,
        HashObjectPositions,
        RemoteRefEmbed,
    },
    error::{Error, Result},
    utils::base64,
};

static SUPPORTED_TYPES: [&str; 8] = [
    "svg",
    "application/svg+xml",
    "xhtml",
    "xml",
    "application/xhtml+xml",
    "application/xml",
    "image/svg+xml",
    "text/xml",
];

const SVG: &str = "svg";
const METADATA: &str = "metadata";
const MANIFEST: &str = "c2pa:manifest";
const MANIFEST_NS: &str = "xmlns:c2pa";
const MANIFEST_NS_VAL: &str = "http://c2pa.org/manifest";

pub struct SvgIO {}

impl CAIReader for SvgIO {
    fn read_cai(&self, reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let (decoded_manifest_opt, _detected_tag_location, _insertion_point) =
            detect_manifest_location(reader)?;

        match decoded_manifest_opt {
            Some(decoded_manifest) => {
                if !decoded_manifest.is_empty() {
                    Ok(decoded_manifest)
                } else {
                    Err(Error::JumbfNotFound)
                }
            }
            None => Err(Error::JumbfNotFound),
        }
    }

    // Get XMP block
    fn read_xmp(&self, _asset_reader: &mut dyn CAIRead) -> Option<String> {
        None
    }
}

impl AssetIO for SvgIO {
    fn new(_asset_type: &str) -> Self {
        SvgIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(SvgIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(SvgIO::new(asset_type)))
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        let mut input_stream = std::fs::OpenOptions::new()
            .read(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        let mut temp_file = Builder::new()
            .prefix("c2pa_temp")
            .rand_bytes(5)
            .tempfile()?;

        self.write_cai(&mut input_stream, &mut temp_file, store_bytes)?;

        // copy temp file to asset
        std::fs::rename(temp_file.path(), asset_path)
            // if rename fails, try to copy in case we are on different volumes
            .or_else(|_| std::fs::copy(temp_file.path(), asset_path).and(Ok(())))
            .map_err(Error::IoError)
    }

    fn get_object_locations(
        &self,
        asset_path: &std::path::Path,
    ) -> Result<Vec<HashObjectPositions>> {
        let mut input_stream =
            std::fs::File::open(asset_path).map_err(|_err| Error::EmbeddingError)?;

        self.get_object_locations_from_stream(&mut input_stream)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        let mut input_file = File::open(asset_path)?;

        let mut temp_file = Builder::new()
            .prefix("c2pa_temp")
            .rand_bytes(5)
            .tempfile()?;

        self.remove_cai_store_from_stream(&mut input_file, &mut temp_file)?;

        // copy temp file to asset
        std::fs::rename(temp_file.path(), asset_path)
            // if rename fails, try to copy in case we are on different volumes
            .or_else(|_| std::fs::copy(temp_file.path(), asset_path).and(Ok(())))
            .map_err(Error::IoError)
    }

    fn remote_ref_writer_ref(&self) -> Option<&dyn RemoteRefEmbed> {
        None
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

// create manifest entry
fn create_manifest_tag(data: &[u8], with_meta: bool) -> Result<Vec<u8>> {
    let mut output: Vec<u8> = Vec::with_capacity(data.len() + 256);
    let mut writer = Writer::new(Cursor::new(output));

    let encoded = base64::encode(data);

    if with_meta {
        writer
            .create_element(METADATA)
            .write_inner_content(|writer| {
                writer
                    .create_element(MANIFEST)
                    .with_attribute((MANIFEST_NS, MANIFEST_NS_VAL))
                    .write_text_content(BytesText::from_plain_str(&encoded))?;
                Ok(())
            })
            .map_err(|_e| Error::XmlWriteError)?;
    } else {
        writer
            .create_element(MANIFEST)
            .with_attribute((MANIFEST_NS, MANIFEST_NS_VAL))
            .write_text_content(BytesText::from_plain_str(&encoded))
            .map_err(|_e| Error::XmlWriteError)?;
    }

    output = writer.into_inner().into_inner();

    Ok(output)
}

enum DetectedTagsDepth {
    Metadata,
    Manifest,
    Empty,
}

// returns tuple of found manifest, where in the XML hierarchy the manifest needs to go, and the manifest insertion point
fn detect_manifest_location(
    input_stream: &mut dyn CAIRead,
) -> Result<(Option<Vec<u8>>, DetectedTagsDepth, usize)> {
    input_stream.rewind()?;

    let mut buf = Vec::new();

    let buf_reader = BufReader::new(input_stream);

    let mut xml_reader = Reader::from_reader(buf_reader);

    let mut xml_path: Vec<String> = Vec::new();

    let mut detected_level = DetectedTagsDepth::Empty;
    let mut insertion_point = 0;

    let mut output: Option<Vec<u8>> = None;

    loop {
        match xml_reader.read_event(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name()).into_owned();
                xml_path.push(name);

                if xml_path.len() == 2 && xml_path[0] == SVG && xml_path[1] == METADATA {
                    detected_level = DetectedTagsDepth::Metadata;
                    insertion_point = xml_reader.buffer_position();
                }

                if xml_path.len() == 3
                    && xml_path[0] == SVG
                    && xml_path[1] == METADATA
                    && xml_path[2] == MANIFEST
                {
                    detected_level = DetectedTagsDepth::Manifest;
                    insertion_point = xml_reader.buffer_position();

                    let mut temp_buf = Vec::new();
                    let s = xml_reader
                        .read_text(e.name(), &mut temp_buf)
                        .map_err(|_e| {
                            Error::InvalidAsset("XML manifest tag invalid content".to_string())
                        })?;

                    output = Some(base64::decode(&s).map_err(|_e| {
                        dbg!(_e);
                        Error::InvalidAsset("XML bad base64 encoding".to_string())
                    })?);
                }

                if xml_path.len() == 1 && xml_path[0] == SVG {
                    detected_level = DetectedTagsDepth::Empty;
                    insertion_point = xml_reader.buffer_position();
                }
            }
            Ok(Event::End(_)) => {
                let _p = xml_path.pop();
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(Error::InvalidAsset("XML invalid".to_string())),
            _ => (),
        }
    }

    Ok((output, detected_level, insertion_point))
}

fn add_required_segs_to_stream(
    input_stream: &mut dyn CAIRead,
    output_stream: &mut dyn CAIReadWrite,
) -> Result<()> {
    let (encoded_manifest_opt, _detected_tag_location, _insertion_point) =
        detect_manifest_location(input_stream)?;

    let need_manifest = if let Some(encoded_manifest) = encoded_manifest_opt {
        encoded_manifest.is_empty()
    } else {
        true
    };

    if need_manifest {
        // add some data
        let data: &str = "placeholder manifest";

        let svg = SvgIO::new("svg");
        let svg_writer = svg.get_writer("svg").ok_or(Error::UnsupportedType)?;

        svg_writer.write_cai(input_stream, output_stream, data.as_bytes())?;
    } else {
        // just clone
        input_stream.rewind()?;
        output_stream.rewind()?;
        std::io::copy(input_stream, output_stream)?;
    }

    Ok(())
}

impl CAIWriter for SvgIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        input_stream.rewind()?;
        let (_encoded_manifest, detected_tag_location, _insertion_point) =
            detect_manifest_location(input_stream)?;

        input_stream.rewind()?;
        let buf_reader = BufReader::new(input_stream);
        let mut reader = Reader::from_reader(buf_reader);

        output_stream.rewind()?;
        let mut writer = Writer::new(output_stream);

        let mut buf = Vec::new();
        let mut xml_path: Vec<String> = Vec::new();

        match detected_tag_location {
            DetectedTagsDepth::Metadata => {
                // add manifest case
                let manifest_data = create_manifest_tag(store_bytes, false)?;

                loop {
                    match reader.read_event(&mut buf) {
                        Ok(Event::Start(e)) => {
                            let name = String::from_utf8_lossy(e.name()).into_owned();
                            xml_path.push(name);

                            // writes the event to the writer
                            writer
                                .write_event(Event::Start(e))
                                .map_err(|_e| Error::XmlWriteError)?;

                            // add manifest data
                            if xml_path.len() == 2 && xml_path[0] == SVG && xml_path[1] == METADATA
                            {
                                writer
                                    .write(&manifest_data)
                                    .map_err(|_e| Error::XmlWriteError)?;
                            }
                        }
                        Ok(Event::Eof) => break,
                        Ok(Event::End(e)) => {
                            let _p = xml_path.pop();
                            writer
                                .write_event(Event::End(e))
                                .map_err(|_e| Error::XmlWriteError)?;
                        }
                        Ok(e) => writer.write_event(&e).map_err(|_e| Error::XmlWriteError)?,
                        Err(_e) => return Err(Error::InvalidAsset("XML invalid".to_string())),
                    }
                    buf.clear();
                }
            }
            DetectedTagsDepth::Manifest => {
                // replace manifest case
                let encoded = base64::encode(store_bytes);

                loop {
                    match reader.read_event(&mut buf) {
                        Ok(Event::Start(e)) => {
                            let name = String::from_utf8_lossy(e.name()).into_owned();
                            xml_path.push(name);

                            // writes the event to the writer
                            writer
                                .write_event(Event::Start(e))
                                .map_err(|_e| Error::XmlWriteError)?;
                        }
                        Ok(Event::Text(e)) => {
                            // add manifest data
                            if xml_path.len() == 3
                                && xml_path[0] == SVG
                                && xml_path[1] == METADATA
                                && xml_path[2] == MANIFEST
                            {
                                writer
                                    .write(encoded.as_bytes())
                                    .map_err(|_e| Error::XmlWriteError)?;
                            } else {
                                writer
                                    .write_event(Event::Text(e))
                                    .map_err(|_e| Error::XmlWriteError)?; // pass Event through
                            }
                        }
                        Ok(Event::Eof) => break,
                        Ok(Event::End(e)) => {
                            let _p = xml_path.pop();
                            writer
                                .write_event(Event::End(e))
                                .map_err(|_e| Error::XmlWriteError)?;
                        }
                        Ok(e) => writer.write_event(&e).map_err(|_e| Error::XmlWriteError)?,
                        Err(_e) => return Err(Error::InvalidAsset("XML invalid".to_string())),
                    }
                    buf.clear();
                }
            }
            DetectedTagsDepth::Empty => {
                //add metadata & manifest case
                let manifest_data = create_manifest_tag(store_bytes, true)?;

                loop {
                    match reader.read_event(&mut buf) {
                        Ok(Event::Start(e)) => {
                            let name = String::from_utf8_lossy(e.name()).into_owned();
                            xml_path.push(name);

                            // writes the event to the writer
                            writer
                                .write_event(Event::Start(e))
                                .map_err(|_e| Error::XmlWriteError)?;

                            // add manifest data
                            if xml_path.len() == 1 && xml_path[0] == SVG {
                                writer
                                    .write(&manifest_data)
                                    .map_err(|_e| Error::XmlWriteError)?;
                            }
                        }
                        Ok(Event::Eof) => break,
                        Ok(Event::End(e)) => {
                            let _p = xml_path.pop();
                            writer
                                .write_event(Event::End(e))
                                .map_err(|_e| Error::XmlWriteError)?;
                        }
                        Ok(e) => writer.write_event(&e).map_err(|_e| Error::XmlWriteError)?,
                        Err(_e) => return Err(Error::InvalidAsset("XML invalid".to_string())),
                    }
                    buf.clear();
                }
            }
        }

        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let output: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(output);

        add_required_segs_to_stream(input_stream, &mut output_stream)?;

        let mut positions: Vec<HashObjectPositions> = Vec::new();

        let (decoded_manifest_opt, _detected_tag_location, manifest_pos) =
            detect_manifest_location(&mut output_stream)?;

        let decoded_manifest = decoded_manifest_opt.ok_or(Error::JumbfNotFound)?;
        let encoded_manifest_len = base64::encode(&decoded_manifest).len();

        positions.push(HashObjectPositions {
            offset: manifest_pos,
            length: encoded_manifest_len,
            htype: HashBlockObjectType::Cai,
        });

        // add hash of chunks before cai
        positions.push(HashObjectPositions {
            offset: 0,
            length: manifest_pos,
            htype: HashBlockObjectType::Other,
        });

        // add position from cai to end
        let end = manifest_pos + encoded_manifest_len;
        let length = usize::value_from(input_stream.seek(SeekFrom::End(0))?)
            .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?
            - end;
        positions.push(HashObjectPositions {
            offset: end,
            length,
            htype: HashBlockObjectType::Other,
        });

        Ok(positions)
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        let buf_reader = BufReader::new(input_stream);
        let mut reader = Reader::from_reader(buf_reader);

        output_stream.rewind()?;
        let mut writer = Writer::new(output_stream);

        let mut buf = Vec::new();
        let mut xml_path: Vec<String> = Vec::new();

        loop {
            match reader.read_event(&mut buf) {
                Ok(Event::Start(e)) => {
                    let name = String::from_utf8_lossy(e.name()).into_owned();
                    xml_path.push(name);

                    if xml_path.len() == 3
                        && xml_path[0] == SVG
                        && xml_path[1] == METADATA
                        && xml_path[2] == MANIFEST
                    {
                        // skip the manifest
                        continue;
                    } else {
                        writer
                            .write_event(Event::Start(e))
                            .map_err(|_e| Error::XmlWriteError)?; // pass Event through
                    }
                }
                Ok(Event::Text(e)) => {
                    if xml_path.len() == 3
                        && xml_path[0] == SVG
                        && xml_path[1] == METADATA
                        && xml_path[2] == MANIFEST
                    {
                        // skip the manifest
                        continue;
                    } else {
                        writer
                            .write_event(Event::Text(e))
                            .map_err(|_e| Error::XmlWriteError)?; // pass Event through
                    }
                }
                Ok(Event::Eof) => break,
                Ok(Event::End(e)) => {
                    if xml_path.len() == 3
                        && xml_path[0] == SVG
                        && xml_path[1] == METADATA
                        && xml_path[2] == MANIFEST
                    {
                        // skip the manifest
                        let _p = xml_path.pop();
                        continue;
                    } else {
                        let _p = xml_path.pop();
                        writer
                            .write_event(Event::End(e))
                            .map_err(|_e| Error::XmlWriteError)?; // pass Event through
                    }
                }
                Ok(e) => writer.write_event(&e).map_err(|_e| Error::XmlWriteError)?,
                Err(_e) => return Err(Error::InvalidAsset("XML invalid".to_string())),
            }
            buf.clear();
        }

        Ok(())
    }
}

impl AssetPatch for SvgIO {
    fn patch_cai_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        let mut input_file = OpenOptions::new()
            .write(true)
            .read(true)
            .create(false)
            .open(asset_path)?;

        let (asset_manifest_opt, _detected_tag_location, insertion_point) =
            detect_manifest_location(&mut input_file)?;
        let encoded_store_bytes = base64::encode(store_bytes);

        if let Some(manifest_bytes) = asset_manifest_opt {
            // base 64 encode
            let encoded_manifest_bytes = base64::encode(&manifest_bytes);
            // can patch if encoded lengths are ==
            if encoded_store_bytes.len() == encoded_manifest_bytes.len() {
                input_file.seek(SeekFrom::Start(insertion_point as u64))?;
                input_file.write_all(encoded_store_bytes.as_bytes())?;
                Ok(())
            } else {
                Err(Error::InvalidAsset(
                    "patch_cai_store store size mismatch.".to_string(),
                ))
            }
        } else {
            Err(Error::InvalidAsset(
                "patch_cai_store store size mismatch.".to_string(),
            ))
        }
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::Read;

    use tempfile::tempdir;

    use super::*;
    use crate::utils::{
        hash_utils::vec_compare,
        test::{fixture_path, temp_dir_path},
    };

    #[test]
    fn test_write_svg_no_meta() {
        let more_data = "some more test data".as_bytes();
        let source = fixture_path("sample1.svg");

        let mut success = false;
        if let Ok(temp_dir) = tempdir() {
            let output = temp_dir_path(&temp_dir, "sample1.svg");

            if let Ok(_size) = std::fs::copy(source, &output) {
                let svg_io = SvgIO::new("svg");

                if let Ok(()) = svg_io.save_cai_store(&output, more_data) {
                    if let Ok(read_test_data) = svg_io.read_cai_store(&output) {
                        assert!(vec_compare(more_data, &read_test_data));
                        success = true;
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_write_svg_with_meta() {
        let more_data = "some more test data".as_bytes();
        let source = fixture_path("sample2.svg");

        let mut success = false;
        if let Ok(temp_dir) = tempdir() {
            let output = temp_dir_path(&temp_dir, "sample2.svg");

            if let Ok(_size) = std::fs::copy(source, &output) {
                let svg_io = SvgIO::new("svg");

                if let Ok(()) = svg_io.save_cai_store(&output, more_data) {
                    if let Ok(read_test_data) = svg_io.read_cai_store(&output) {
                        assert!(vec_compare(more_data, &read_test_data));
                        success = true;
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_write_svg_with_manifest() {
        let more_data = "some more test data into existing manifest".as_bytes();
        let source = fixture_path("sample3.svg");

        let mut success = false;
        if let Ok(temp_dir) = tempdir() {
            let output = temp_dir_path(&temp_dir, "sample3.svg");

            if let Ok(_size) = std::fs::copy(source, &output) {
                let svg_io = SvgIO::new("svg");

                if let Ok(()) = svg_io.save_cai_store(&output, more_data) {
                    if let Ok(read_test_data) = svg_io.read_cai_store(&output) {
                        assert!(vec_compare(more_data, &read_test_data));
                        success = true;
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_patch_write_svg() {
        let test_data = "some test data".as_bytes();
        let source = fixture_path("sample1.svg");

        let mut success = false;
        if let Ok(temp_dir) = tempdir() {
            let output = temp_dir_path(&temp_dir, "sample1.svg");

            if let Ok(_size) = std::fs::copy(source, &output) {
                let svg_io = SvgIO::new("svg");

                if let Ok(()) = svg_io.save_cai_store(&output, test_data) {
                    if let Ok(source_data) = svg_io.read_cai_store(&output) {
                        // create replacement data of same size
                        let mut new_data = vec![0u8; source_data.len()];
                        new_data[..test_data.len()].copy_from_slice(test_data);
                        svg_io.patch_cai_store(&output, &new_data).unwrap();

                        let replaced = svg_io.read_cai_store(&output).unwrap();

                        assert_eq!(new_data, replaced);

                        success = true;
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_remove_c2pa() {
        let source = fixture_path("sample4.svg");

        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "sample4.svg");

        std::fs::copy(source, &output).unwrap();
        let svg_io = SvgIO::new("svg");

        svg_io.remove_cai_store(&output).unwrap();

        // read back in asset, JumbfNotFound is expected since it was removed
        match svg_io.read_cai_store(&output) {
            Err(Error::JumbfNotFound) => (),
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_get_object_location() {
        let more_data = "some more test data into existing manifest".as_bytes();
        let source = fixture_path("sample1.svg");

        let mut success = false;
        if let Ok(temp_dir) = tempdir() {
            let output = temp_dir_path(&temp_dir, "sample1.svg");

            if let Ok(_size) = std::fs::copy(source, &output) {
                let svg_io = SvgIO::new("svg");

                if let Ok(()) = svg_io.save_cai_store(&output, more_data) {
                    if let Ok(locations) = svg_io.get_object_locations(&output) {
                        for op in locations {
                            if op.htype == HashBlockObjectType::Cai {
                                let mut of = File::open(&output).unwrap();

                                let mut manifests_buf: Vec<u8> = vec![0u8; op.length];
                                of.seek(SeekFrom::Start(op.offset as u64)).unwrap();
                                of.read_exact(manifests_buf.as_mut_slice()).unwrap();
                                let buf_str = std::str::from_utf8(&manifests_buf).unwrap();
                                let decoded_data = base64::decode(buf_str).unwrap();
                                if vec_compare(more_data, &decoded_data) {
                                    success = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(success)
    }
}
