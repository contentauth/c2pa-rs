// Copyright 2024 Encypher Corporation. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

//! C2PA Text asset handler.
//!
//! Embeds and extracts C2PA JUMBF manifests in plain text using the c2pa-text
//! crate, which encodes binary data as invisible Unicode Variation Selectors
//! per the C2PA Text Embedding specification.

use std::{fs::File, path::Path};

use c2pa_text::{embed_manifest, extract_manifest};

use crate::{
    asset_io::{
        rename_or_move, AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter,
        HashBlockObjectType, HashObjectPositions,
    },
    error::{Error, Result},
    utils::io_utils::tempfile_builder,
};

static SUPPORTED_TYPES: [&str; 2] = ["txt", "text/plain"];

pub struct TextIO {}

/// Read the entire stream as a UTF-8 string.
fn stream_to_string(reader: &mut dyn CAIRead) -> Result<String> {
    reader.rewind()?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    String::from_utf8(buf)
        .map_err(|_| Error::InvalidAsset("text asset is not valid UTF-8".to_string()))
}

impl CAIReader for TextIO {
    fn read_cai(&self, reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let text = stream_to_string(reader)?;

        let result = extract_manifest(&text)
            .map_err(|e| Error::InvalidAsset(format!("text manifest extraction failed: {e}")))?;

        match result.manifest {
            Some(manifest) => Ok(manifest),
            None => Err(Error::JumbfNotFound),
        }
    }

    fn read_xmp(&self, _reader: &mut dyn CAIRead) -> Option<String> {
        // Text files do not carry XMP.
        None
    }
}

impl CAIWriter for TextIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        let text = stream_to_string(input_stream)?;

        // Strip any existing wrapper to get clean text.
        let clean = match extract_manifest(&text) {
            Ok(r) => r.clean_text,
            Err(_) => text,
        };

        let signed = embed_manifest(&clean, store_bytes);

        output_stream.rewind()?;
        output_stream.write_all(signed.as_bytes())?;
        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let text = stream_to_string(input_stream)?;

        let result = extract_manifest(&text)
            .map_err(|e| Error::InvalidAsset(format!("text manifest extraction failed: {e}")))?;

        let (offset, length) = match (result.offset, result.length) {
            (Some(o), Some(l)) => (o, l),
            _ => return Err(Error::JumbfNotFound),
        };

        let total = text.len();

        let mut positions = Vec::new();

        // Pre-wrapper content
        positions.push(HashObjectPositions {
            offset: 0,
            length: offset,
            htype: HashBlockObjectType::Other,
        });

        // C2PA wrapper (the variation-selector encoded block)
        positions.push(HashObjectPositions {
            offset,
            length,
            htype: HashBlockObjectType::Cai,
        });

        // Post-wrapper content (if any)
        let end = offset + length;
        if end < total {
            positions.push(HashObjectPositions {
                offset: end,
                length: total - end,
                htype: HashBlockObjectType::Other,
            });
        }

        Ok(positions)
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        let text = stream_to_string(input_stream)?;

        let clean = match extract_manifest(&text) {
            Ok(r) => r.clean_text,
            Err(_) => text,
        };

        output_stream.rewind()?;
        output_stream.write_all(clean.as_bytes())?;
        Ok(())
    }
}

impl AssetIO for TextIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        TextIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(TextIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(TextIO::new(asset_type)))
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut input_stream = File::open(asset_path).map_err(Error::IoError)?;

        let mut temp_file = tempfile_builder("c2pa_temp")?;

        self.write_cai(&mut input_stream, &mut temp_file, store_bytes)?;

        rename_or_move(temp_file, asset_path)
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        let mut input_stream = File::open(asset_path).map_err(|_| Error::EmbeddingError)?;
        self.get_object_locations_from_stream(&mut input_stream)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        let mut input_file = File::open(asset_path)?;

        let mut temp_file = tempfile_builder("c2pa_temp")?;

        self.remove_cai_store_from_stream(&mut input_file, &mut temp_file)?;

        rename_or_move(temp_file, asset_path)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

#[cfg(test)]
#[cfg(feature = "file_io")]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;

    /// Round-trip: write manifest into text, then read it back.
    #[test]
    fn text_io_stream_roundtrip() {
        let plain = "Hello, C2PA world!";
        let jumbf: Vec<u8> = vec![0, 0, 0, 8, b'j', b'u', b'm', b'b'];

        // Build a signed text string via c2pa-text directly.
        let signed = embed_manifest(plain, &jumbf);

        // Read back through the handler.
        let text_io = TextIO::new("txt");
        let mut reader = Cursor::new(signed.clone().into_bytes());
        let extracted = text_io.read_cai(&mut reader).expect("read_cai");
        assert_eq!(extracted, jumbf);

        // Write through the handler (replaces old manifest).
        let new_jumbf: Vec<u8> = vec![0, 0, 0, 8, b'j', b'u', b'm', b'b', 0xAA];
        let mut input = Cursor::new(signed.into_bytes());
        let mut output = Cursor::new(Vec::new());
        text_io
            .write_cai(&mut input, &mut output, &new_jumbf)
            .expect("write_cai");

        // Read new manifest.
        output.set_position(0);
        let extracted2 = text_io.read_cai(&mut output).expect("read_cai after write");
        assert_eq!(extracted2, new_jumbf);
    }

    /// Removing the CAI store produces clean text.
    #[test]
    fn text_io_remove_store() {
        let plain = "Article body text.";
        let jumbf: Vec<u8> = vec![0, 0, 0, 8, b'j', b'u', b'm', b'b'];
        let signed = embed_manifest(plain, &jumbf);

        let text_io = TextIO::new("txt");
        let mut input = Cursor::new(signed.into_bytes());
        let mut output = Cursor::new(Vec::new());
        text_io
            .remove_cai_store_from_stream(&mut input, &mut output)
            .expect("remove_cai_store_from_stream");

        let clean = String::from_utf8(output.into_inner()).unwrap();
        assert_eq!(clean, plain);
    }

    /// Object locations correctly partition the byte stream.
    #[test]
    fn text_io_object_locations() {
        let plain = "Test text.";
        let jumbf: Vec<u8> = vec![0, 0, 0, 8, b'j', b'u', b'm', b'b'];
        let signed = embed_manifest(plain, &jumbf);
        let total_bytes = signed.len();

        let text_io = TextIO::new("txt");
        let mut reader = Cursor::new(signed.into_bytes());
        let positions = text_io
            .get_object_locations_from_stream(&mut reader)
            .expect("get_object_locations_from_stream");

        // Should have pre + cai + (possibly post)
        assert!(positions.len() >= 2);

        let cai_pos = positions
            .iter()
            .find(|p| p.htype == HashBlockObjectType::Cai)
            .expect("CAI block");
        assert!(cai_pos.length > 0);

        // All positions should cover the total byte range without overlap.
        let covered: usize = positions.iter().map(|p| p.length).sum();
        assert_eq!(covered, total_bytes);
    }

    /// Plain text with no wrapper returns JumbfNotFound.
    #[test]
    fn text_io_no_manifest() {
        let text_io = TextIO::new("txt");
        let mut reader = Cursor::new("Just plain text.".as_bytes().to_vec());
        let result = text_io.read_cai(&mut reader);
        assert!(matches!(result.unwrap_err(), Error::JumbfNotFound));
    }
}
