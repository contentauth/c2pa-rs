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

use std::io::{BufReader, Cursor, Read, Seek, SeekFrom, Write};

use fast_xml::{
    events::{BytesText, Event},
    Reader, Writer,
};

use crate::{
    ByteSpan, C2paSpan, CodecError, Decode, DefaultSpan, Embed, Embeddable, Encode, EncodeInPlace,
    Span, Support,
};

const SVG: &str = "svg";
const METADATA: &str = "metadata";
const MANIFEST: &str = "c2pa:manifest";
const MANIFEST_NS: &str = "xmlns:c2pa";
const MANIFEST_NS_VAL: &str = "http://c2pa.org/manifest";

#[derive(Debug)]
pub struct SvgCodec<R> {
    src: R,
}

impl<R> SvgCodec<R> {
    pub fn new(src: R) -> Self {
        Self { src }
    }
}

impl Support for SvgCodec<()> {
    const MAX_SIGNATURE_LEN: usize = 0;

    // TODO: does this impl cover all cases? it should also run last due to the computation
    //       we can probably also add a short circuit type of method, where if the first few bytes
    //       aren't xml it isn't an svg
    // TODO: we also need to reset the stream to the first x bytes when this returns
    fn supports_stream(src: impl Read + Seek) -> Result<bool, CodecError> {
        let mut src = BufReader::new(src);
        let mut reader = Reader::from_reader(&mut src);

        let mut event = Vec::new();
        loop {
            match reader.read_event(&mut event) {
                Ok(Event::Start(ref e)) => {
                    if e.name() == SVG.as_bytes() {
                        return Ok(true);
                    }
                }
                Ok(Event::Eof) | Err(_) => break,
                _ => {}
            }

            event.clear();
        }

        Ok(false)
    }

    fn supports_extension(extension: &str) -> bool {
        matches!(extension, "svg" | "xhtml" | "xml")
    }

    fn supports_mime(mime: &str) -> bool {
        matches!(
            mime,
            "application/svg+xml"
                | "application/xhtml+xml"
                | "application/xml"
                | "image/svg+xml"
                | "text/xml"
        )
    }
}

impl<R: Read + Seek> Embed for SvgCodec<R> {
    fn embeddable(bytes: &[u8]) -> Result<Embeddable, CodecError> {
        todo!()
    }

    fn embed(&mut self, embeddable: Embeddable, dst: impl Write) -> Result<(), CodecError> {
        todo!()
    }
}

impl<R: Read + Seek> Decode for SvgCodec<R> {
    fn read_c2pa(&mut self) -> Result<Option<Vec<u8>>, CodecError> {
        let (decoded_manifest_opt, _detected_tag_location, _insertion_point) =
            detect_manifest_location(&mut self.src)?;

        match decoded_manifest_opt {
            Some(decoded_manifest) => {
                if !decoded_manifest.is_empty() {
                    Ok(Some(decoded_manifest))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }
}

// create manifest entry
fn create_manifest_tag(data: &[u8], with_meta: bool) -> Result<Vec<u8>, CodecError> {
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
            .map_err(|err| CodecError::InvalidAsset {
                src: Some(err.to_string()),
                context: "failed to create manifest tag with metadata".to_owned(),
            })?;
    } else {
        writer
            .create_element(MANIFEST)
            .with_attribute((MANIFEST_NS, MANIFEST_NS_VAL))
            .write_text_content(BytesText::from_plain_str(&encoded))
            .map_err(|err| CodecError::InvalidAsset {
                src: Some(err.to_string()),
                context: "failed to create manifest tag".to_string(),
            })?;
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
    mut src: impl Read + Seek,
) -> Result<(Option<Vec<u8>>, DetectedTagsDepth, usize), CodecError> {
    src.rewind()?;

    let mut buf = Vec::new();

    let buf_reader = BufReader::new(&mut src);

    // TODO: quickxml doesn't require an internal bufreader
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
                        .map_err(|err| CodecError::InvalidAsset {
                            src: Some(err.to_string()),
                            context: "XML manifest tag invalid content".to_string(),
                        })?;

                    output = Some(base64::decode(&s).map_err(|err| CodecError::InvalidAsset {
                        src: Some(err.to_string()),
                        context: "XML bad base64 encoding".to_string(),
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
            Err(err) => {
                return Err(CodecError::InvalidAsset {
                    src: Some(err.to_string()),
                    context: "XML invalid".to_string(),
                })
            }
            _ => (),
        }
    }

    Ok((output, detected_level, insertion_point))
}

fn add_required_segs_to_stream(
    mut src: impl Read + Seek,
    mut dst: impl Write + Seek,
) -> Result<(), CodecError> {
    let (encoded_manifest_opt, _detected_tag_location, _insertion_point) =
        detect_manifest_location(&mut src)?;

    let need_manifest = if let Some(encoded_manifest) = encoded_manifest_opt {
        encoded_manifest.is_empty()
    } else {
        true
    };

    if need_manifest {
        // add some data
        let data: &str = "placeholder manifest";

        let mut codec = SvgCodec::new(&mut src);
        codec.write_c2pa(dst, data.as_bytes())?;
    } else {
        // just clone
        src.rewind()?;
        dst.rewind()?;
        std::io::copy(&mut src, &mut dst)?;
    }

    Ok(())
}

impl<R: Read + Seek> Encode for SvgCodec<R> {
    fn write_c2pa(&mut self, dst: impl Write, c2pa: &[u8]) -> Result<(), CodecError> {
        self.src.rewind()?;
        let (_encoded_manifest, detected_tag_location, _insertion_point) =
            detect_manifest_location(&mut self.src)?;

        self.src.rewind()?;
        let buf_reader = BufReader::new(&mut self.src);
        let mut reader = Reader::from_reader(buf_reader);

        let mut writer = Writer::new(dst);

        let mut buf = Vec::new();
        let mut xml_path: Vec<String> = Vec::new();

        match detected_tag_location {
            DetectedTagsDepth::Metadata => {
                // add manifest case
                let manifest_data = create_manifest_tag(c2pa, false)?;

                loop {
                    match reader.read_event(&mut buf) {
                        Ok(Event::Start(e)) => {
                            let name = String::from_utf8_lossy(e.name()).into_owned();
                            xml_path.push(name);

                            // writes the event to the writer
                            writer.write_event(Event::Start(e)).map_err(|err| {
                                CodecError::InvalidAsset {
                                    src: Some(err.to_string()),
                                    context: "TODO".to_string(),
                                }
                            })?;

                            // add manifest data
                            if xml_path.len() == 2 && xml_path[0] == SVG && xml_path[1] == METADATA
                            {
                                writer.write(&manifest_data).map_err(|err| {
                                    CodecError::InvalidAsset {
                                        src: Some(err.to_string()),
                                        context: "TODO".to_string(),
                                    }
                                })?;
                            }
                        }
                        Ok(Event::Eof) => break,
                        Ok(Event::End(e)) => {
                            let _p = xml_path.pop();
                            writer.write_event(Event::End(e)).map_err(|err| {
                                CodecError::InvalidAsset {
                                    src: Some(err.to_string()),
                                    context: "TODO".to_string(),
                                }
                            })?;
                        }
                        Ok(e) => {
                            writer
                                .write_event(&e)
                                .map_err(|err| CodecError::InvalidAsset {
                                    src: Some(err.to_string()),
                                    context: "TODO".to_string(),
                                })?
                        }
                        Err(err) => {
                            return Err(CodecError::InvalidAsset {
                                src: Some(err.to_string()),
                                context: "XML invalid".to_string(),
                            })
                        }
                    }
                    buf.clear();
                }
            }
            DetectedTagsDepth::Manifest => {
                // replace manifest case
                let encoded = base64::encode(c2pa);

                loop {
                    match reader.read_event(&mut buf) {
                        Ok(Event::Start(e)) => {
                            let name = String::from_utf8_lossy(e.name()).into_owned();
                            xml_path.push(name);

                            // writes the event to the writer
                            writer.write_event(Event::Start(e)).map_err(|err| {
                                CodecError::InvalidAsset {
                                    src: Some(err.to_string()),
                                    context: "TODO".to_string(),
                                }
                            })?;
                        }
                        Ok(Event::Text(e)) => {
                            // add manifest data
                            if xml_path.len() == 3
                                && xml_path[0] == SVG
                                && xml_path[1] == METADATA
                                && xml_path[2] == MANIFEST
                            {
                                writer.write(encoded.as_bytes()).map_err(|err| {
                                    CodecError::InvalidAsset {
                                        src: Some(err.to_string()),
                                        context: "TODO".to_string(),
                                    }
                                })?;
                            } else {
                                writer.write_event(Event::Text(e)).map_err(|err| {
                                    CodecError::InvalidAsset {
                                        src: Some(err.to_string()),
                                        context: "TODO".to_string(),
                                    }
                                })?; // pass Event through
                            }
                        }
                        Ok(Event::Eof) => break,
                        Ok(Event::End(e)) => {
                            let _p = xml_path.pop();
                            writer.write_event(Event::End(e)).map_err(|err| {
                                CodecError::InvalidAsset {
                                    src: Some(err.to_string()),
                                    context: "TODO".to_string(),
                                }
                            })?;
                        }
                        Ok(e) => {
                            writer
                                .write_event(&e)
                                .map_err(|err| CodecError::InvalidAsset {
                                    src: Some(err.to_string()),
                                    context: "TODO".to_string(),
                                })?
                        }
                        Err(err) => {
                            return Err(CodecError::InvalidAsset {
                                src: Some(err.to_string()),
                                context: "XML invalid".to_string(),
                            })
                        }
                    }
                    buf.clear();
                }
            }
            DetectedTagsDepth::Empty => {
                //add metadata & manifest case
                let manifest_data = create_manifest_tag(c2pa, true)?;

                loop {
                    match reader.read_event(&mut buf) {
                        Ok(Event::Start(e)) => {
                            let name = String::from_utf8_lossy(e.name()).into_owned();
                            xml_path.push(name);

                            // writes the event to the writer
                            writer.write_event(Event::Start(e)).map_err(|err| {
                                CodecError::InvalidAsset {
                                    src: Some(err.to_string()),
                                    context: "TODO".to_string(),
                                }
                            })?;

                            // add manifest data
                            if xml_path.len() == 1 && xml_path[0] == SVG {
                                writer.write(&manifest_data).map_err(|err| {
                                    CodecError::InvalidAsset {
                                        src: Some(err.to_string()),
                                        context: "TODO".to_string(),
                                    }
                                })?;
                            }
                        }
                        Ok(Event::Eof) => break,
                        Ok(Event::End(e)) => {
                            let _p = xml_path.pop();
                            writer.write_event(Event::End(e)).map_err(|err| {
                                CodecError::InvalidAsset {
                                    src: Some(err.to_string()),
                                    context: "TODO".to_string(),
                                }
                            })?;
                        }
                        Ok(e) => {
                            writer
                                .write_event(&e)
                                .map_err(|err| CodecError::InvalidAsset {
                                    src: Some(err.to_string()),
                                    context: "TODO".to_string(),
                                })?
                        }
                        Err(err) => {
                            return Err(CodecError::InvalidAsset {
                                src: Some(err.to_string()),
                                context: "XML invalid".to_string(),
                            })
                        }
                    }
                    buf.clear();
                }
            }
        }

        Ok(())
    }

    fn remove_c2pa(&mut self, dst: impl Write) -> Result<bool, CodecError> {
        self.src.rewind()?;

        let buf_reader = BufReader::new(&mut self.src);
        let mut reader = Reader::from_reader(buf_reader);

        let mut writer = Writer::new(dst);

        let mut buf = Vec::new();
        let mut xml_path: Vec<String> = Vec::new();

        let mut removed = false;

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
                        removed = true;
                        // skip the manifest
                        continue;
                    } else {
                        writer.write_event(Event::Start(e)).map_err(|err| {
                            CodecError::InvalidAsset {
                                src: Some(err.to_string()),
                                context: "TODO".to_string(),
                            }
                        })?; // pass Event through
                    }
                }
                Ok(Event::Text(e)) => {
                    if xml_path.len() == 3
                        && xml_path[0] == SVG
                        && xml_path[1] == METADATA
                        && xml_path[2] == MANIFEST
                    {
                        removed = true;
                        // skip the manifest
                        continue;
                    } else {
                        writer.write_event(Event::Text(e)).map_err(|err| {
                            CodecError::InvalidAsset {
                                src: Some(err.to_string()),
                                context: "TODO".to_string(),
                            }
                        })?; // pass Event through
                    }
                }
                Ok(Event::Eof) => break,
                Ok(Event::End(e)) => {
                    if xml_path.len() == 3
                        && xml_path[0] == SVG
                        && xml_path[1] == METADATA
                        && xml_path[2] == MANIFEST
                    {
                        removed = true;
                        // skip the manifest
                        let _p = xml_path.pop();
                        continue;
                    } else {
                        let _p = xml_path.pop();
                        writer.write_event(Event::End(e)).map_err(|err| {
                            CodecError::InvalidAsset {
                                src: Some(err.to_string()),
                                context: "TODO".to_string(),
                            }
                        })?; // pass Event through
                    }
                }
                Ok(e) => writer
                    .write_event(&e)
                    .map_err(|err| CodecError::InvalidAsset {
                        src: Some(err.to_string()),
                        context: "TODO".to_string(),
                    })?,
                Err(err) => {
                    return Err(CodecError::InvalidAsset {
                        src: Some(err.to_string()),
                        context: "XML invalid".to_string(),
                    })
                }
            }
            buf.clear();
        }

        Ok(removed)
    }
}

impl<R: Read + Write + Seek> EncodeInPlace for SvgCodec<R> {
    fn patch_c2pa(&mut self, c2pa: &[u8]) -> Result<(), CodecError> {
        let (asset_manifest_opt, _detected_tag_location, insertion_point) =
            detect_manifest_location(&mut self.src)?;
        let encoded_store_bytes = base64::encode(c2pa);

        if let Some(manifest_bytes) = asset_manifest_opt {
            // base 64 encode
            let encoded_manifest_bytes = base64::encode(&manifest_bytes);
            // can patch if encoded lengths are ==
            if encoded_store_bytes.len() == encoded_manifest_bytes.len() {
                self.src.seek(SeekFrom::Start(insertion_point as u64))?;
                self.src.write_all(encoded_store_bytes.as_bytes())?;
                Ok(())
            } else {
                Err(CodecError::InvalidPatchSize {
                    expected: encoded_manifest_bytes.len() as u64,
                    actual: encoded_store_bytes.len() as u64,
                })
            }
        } else {
            Err(CodecError::NothingToPatch)
        }
    }
}

impl<R: Read + Seek> Span for SvgCodec<R> {
    fn span(&mut self) -> Result<DefaultSpan, CodecError> {
        Ok(DefaultSpan::Data(self.c2pa_span()?))
    }

    fn c2pa_span(&mut self) -> Result<C2paSpan, CodecError> {
        let output: Vec<u8> = Vec::new();
        let mut dst = Cursor::new(output);

        add_required_segs_to_stream(&mut self.src, &mut dst)?;

        let mut positions = Vec::new();

        let (decoded_manifest_opt, _detected_tag_location, manifest_pos) =
            detect_manifest_location(&mut dst)?;

        // TODO: if decoded_manifest_opt is None, we need to generate a placeholder
        //       remove unwrap!!!
        let decoded_manifest = decoded_manifest_opt.unwrap();
        let encoded_manifest_len = base64::encode(&decoded_manifest).len();

        positions.push(ByteSpan {
            start: manifest_pos as u64,
            len: encoded_manifest_len as u64,
        });

        Ok(C2paSpan { spans: positions })
    }
}

#[cfg(test)]
pub mod tests {
    //     #![allow(clippy::expect_used)]
    //     #![allow(clippy::panic)]
    //     #![allow(clippy::unwrap_used)]

    //     use std::io::Read;

    //     use tempfile::tempdir;

    //     use super::*;
    //     use crate::utils::{
    //         hash_utils::vec_compare,
    //         test::{fixture_path, temp_dir_path},
    //     };

    //     #[test]
    //     fn test_write_svg_no_meta() {
    //         let more_data = "some more test data".as_bytes();
    //         let source = fixture_path("sample1.svg");

    //         let mut success = false;
    //         if let Ok(temp_dir) = tempdir() {
    //             let output = temp_dir_path(&temp_dir, "sample1.svg");

    //             if let Ok(_size) = std::fs::copy(source, &output) {
    //                 let svg_io = SvgCodec::new("svg");

    //                 if let Ok(()) = svg_io.save_cai_store(&output, more_data) {
    //                     if let Ok(read_test_data) = svg_io.read_cai_store(&output) {
    //                         assert!(vec_compare(more_data, &read_test_data));
    //                         success = true;
    //                     }
    //                 }
    //             }
    //         }
    //         assert!(success)
    //     }

    //     #[test]
    //     fn test_write_svg_with_meta() {
    //         let more_data = "some more test data".as_bytes();
    //         let source = fixture_path("sample2.svg");

    //         let mut success = false;
    //         if let Ok(temp_dir) = tempdir() {
    //             let output = temp_dir_path(&temp_dir, "sample2.svg");

    //             if let Ok(_size) = std::fs::copy(source, &output) {
    //                 let svg_io = SvgCodec::new("svg");

    //                 if let Ok(()) = svg_io.save_cai_store(&output, more_data) {
    //                     if let Ok(read_test_data) = svg_io.read_cai_store(&output) {
    //                         assert!(vec_compare(more_data, &read_test_data));
    //                         success = true;
    //                     }
    //                 }
    //             }
    //         }
    //         assert!(success)
    //     }

    //     #[test]
    //     fn test_write_svg_with_manifest() {
    //         let more_data = "some more test data into existing manifest".as_bytes();
    //         let source = fixture_path("sample3.svg");

    //         let mut success = false;
    //         if let Ok(temp_dir) = tempdir() {
    //             let output = temp_dir_path(&temp_dir, "sample3.svg");

    //             if let Ok(_size) = std::fs::copy(source, &output) {
    //                 let svg_io = SvgCodec::new("svg");

    //                 if let Ok(()) = svg_io.save_cai_store(&output, more_data) {
    //                     if let Ok(read_test_data) = svg_io.read_cai_store(&output) {
    //                         assert!(vec_compare(more_data, &read_test_data));
    //                         success = true;
    //                     }
    //                 }
    //             }
    //         }
    //         assert!(success)
    //     }

    //     #[test]
    //     fn test_patch_write_svg() {
    //         let test_data = "some test data".as_bytes();
    //         let source = fixture_path("sample1.svg");

    //         let mut success = false;
    //         if let Ok(temp_dir) = tempdir() {
    //             let output = temp_dir_path(&temp_dir, "sample1.svg");

    //             if let Ok(_size) = std::fs::copy(source, &output) {
    //                 let svg_io = SvgCodec::new("svg");

    //                 if let Ok(()) = svg_io.save_cai_store(&output, test_data) {
    //                     if let Ok(source_data) = svg_io.read_cai_store(&output) {
    //                         // create replacement data of same size
    //                         let mut new_data = vec![0u8; source_data.len()];
    //                         new_data[..test_data.len()].copy_from_slice(test_data);
    //                         svg_io.patch_cai_store(&output, &new_data).unwrap();

    //                         let replaced = svg_io.read_cai_store(&output).unwrap();

    //                         assert_eq!(new_data, replaced);

    //                         success = true;
    //                     }
    //                 }
    //             }
    //         }
    //         assert!(success)
    //     }

    //     #[test]
    //     fn test_remove_c2pa() {
    //         let source = fixture_path("sample4.svg");

    //         let temp_dir = tempdir().unwrap();
    //         let output = temp_dir_path(&temp_dir, "sample4.svg");

    //         std::fs::copy(source, &output).unwrap();
    //         let svg_io = SvgCodec::new("svg");

    //         svg_io.remove_cai_store(&output).unwrap();

    //         // read back in asset, JumbfNotFound is expected since it was removed
    //         match svg_io.read_cai_store(&output) {
    //             Err(Error::JumbfNotFound) => (),
    //             _ => unreachable!(),
    //         }
    //     }

    //     #[test]
    //     fn test_get_object_location() {
    //         let more_data = "some more test data into existing manifest".as_bytes();
    //         let source = fixture_path("sample1.svg");

    //         let mut success = false;
    //         if let Ok(temp_dir) = tempdir() {
    //             let output = temp_dir_path(&temp_dir, "sample1.svg");

    //             if let Ok(_size) = std::fs::copy(source, &output) {
    //                 let svg_io = SvgCodec::new("svg");

    //                 if let Ok(()) = svg_io.save_cai_store(&output, more_data) {
    //                     if let Ok(locations) = svg_io.get_object_locations(&output) {
    //                         for op in locations {
    //                             if op.htype == HashBlockObjectType::Cai {
    //                                 let mut of = File::open(&output).unwrap();

    //                                 let mut manifests_buf: Vec<u8> = vec![0u8; op.length];
    //                                 of.seek(SeekFrom::Start(op.offset as u64)).unwrap();
    //                                 of.read_exact(manifests_buf.as_mut_slice()).unwrap();
    //                                 let buf_str = std::str::from_utf8(&manifests_buf).unwrap();
    //                                 let decoded_data = base64::decode(buf_str).unwrap();
    //                                 if vec_compare(more_data, &decoded_data) {
    //                                     success = true;
    //                                 }
    //                             }
    //                         }
    //                     }
    //                 }
    //             }
    //         }
    //         assert!(success)
    //     }
}
