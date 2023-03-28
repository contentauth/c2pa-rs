// Copyright 2022 Monotype. All rights reserved.
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
use std::{fs::File, path::*};

use base64::decode as base64_decode;
use base64::encode as base64_encode;
use fonttools::{tables, types::*};
use std::convert::TryFrom;

use crate::{
    asset_io::{
        AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter,
        HashBlockObjectType, HashObjectPositions},
    error::{Error, Result},
};
use fonttools::font::Font;
use fonttools::tables::name::NameRecord;

/// Supported extension and mime-types
static SUPPORTED_TYPES: [&str; 7] = [
    "application/font-snft",
    "font/otf",
    "font/sfnt",
    "font/otf",
    "otf",
    "sfnt",
    "ttf",
    ];

// Special record fields signally a C2PA manifest name table record.
const C2PA_PLATFORM_ID: u16 = 0;
const C2PA_ENCODING_ID: u16 = 3;
const C2PA_LANGUAGE_ID: u16 = 1024;
const C2PA_NAME_ID: u16 = 1024;
/// Tag for the 'name' table in a font.
const NAME_TABLE_TAG: Tag = tables::name::TAG;

/// Various valid version tags seen in a OTF/TTF file.
pub enum FontVersion {
    /// TrueType (ttf) version for Windows and/or Adobe
    TrueType = 0x00010000,
    /// OpenType (otf) version
    OpenType = 0x4F54544F,
    /// Old style PostScript font housed in a sfnt wrapper
    Typ1 = 0x74797031,
    /// 'true' font, a TrueType font for OS X and iOS only
    AppleTrue = 0x74727565,
}

/// Used to try and convert from a u32 value to FontVersion
impl TryFrom<u32> for FontVersion {
    type Error = ();
    /// Tries to convert from u32 to a valid font version.
    fn try_from(v: u32) -> core::result::Result<Self, Self::Error> {
        match v {
            x if x == FontVersion::TrueType as u32 => Ok(FontVersion::TrueType),
            x if x == FontVersion::OpenType as u32 => Ok(FontVersion::OpenType),
            x if x == FontVersion::Typ1 as u32 => Ok(FontVersion::Typ1),
            x if x == FontVersion::AppleTrue as u32 => Ok(FontVersion::AppleTrue),
            _ => Err(()),
        }
    }
}

/// Tries to convert a &[u8] to a u32 value using big endian byte ordering
/// as specified in the font spec.
fn read_u32(x: &[u8]) -> Result<u32> {
    let var = <&[u8] as std::convert::TryInto<&[u8; 4]>>::try_into(x)
        .map_err(|_err| Error::BadParam("x".to_string()))?;
    Ok(u32::from_be_bytes(*var))
}

/// Tries to convert a &[u8] to a u16 value using big endian byte ordering
/// as specified by the font spec.
fn read_u16(x: &[u8]) -> Result<u16> {
    let bytes: &[u8; 2] = <&[u8] as std::convert::TryInto<&[u8; 2]>>::try_into(x)
        .map_err(|_err| Error::BadParam("x".to_string()))?;
    Ok(u16::from_be_bytes(*bytes))
}

/// Tries to convert a &[u8] to fixed &[u8; 4] array.
fn read_u8_4(x: &[u8]) -> Result<&[u8; 4]> {
    <&[u8] as std::convert::TryInto<&[u8; 4]>>::try_into(x)
        .map_err(|_err| Error::BadParam("x".to_string()))
}

/// Main OTF IO feature.
pub struct OtfIO {}

/// OTF implementation of the CAILoader trait.
impl CAIReader for OtfIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let font_file: Font =
            Font::from_reader(asset_reader).map_err(|_err| Error::FontLoadError)?;
        // Grab the name table.
        let name_table = font_file
            .tables
            .name()
            .map_err(|_err| Error::DeserializationError)?
            .ok_or(Error::NotFound)?;
        // Look for our special manifest record in the name table, returning
        // manifest if we found it.
        for name_table_entry in name_table.records.iter() {
            if name_table_entry.encodingID == C2PA_ENCODING_ID
                && name_table_entry.languageID == C2PA_LANGUAGE_ID
                && name_table_entry.nameID == C2PA_NAME_ID
                && name_table_entry.platformID == C2PA_PLATFORM_ID
            {
                let data = base64_decode(name_table_entry.string.clone())
                    .map_err(|_err| Error::ClaimDecoding)?;
                return Ok(data);
            }
        }
        Err(Error::NotFound)
    }

    #[allow(unused_variables)]
    fn read_xmp(&self, asset_reader: &mut dyn CAIRead) -> Option<String> {
        // Fonts have no XMP data.
        None
    }
}

/// OTF/TTF implementations for the CAIWriter trait.
impl CAIWriter for OtfIO {
    fn write_cai(
        &self,
        _input_stream: &mut dyn CAIRead,
        _output_stream: &mut dyn CAIReadWrite,
        _store_bytes: &[u8],
    ) -> Result<()> {
        todo!("Implement write_cai for streaming");
    }

    fn get_object_locations_from_stream(
        &self,
        _input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        todo!("Implement for streaming")
    }

    fn remove_cai_store_from_stream(
        &self,
        _input_stream: &mut dyn CAIRead,
        _output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        todo!("Implement for streaming")
    }

}

/// OTF/TTF implementations for the AssetIO trait.
impl AssetIO for OtfIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        OtfIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(OtfIO::new(asset_type))
    }
    fn get_reader(&self) -> &dyn CAIReader {
        self
    }
    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(OtfIO::new(asset_type)))
    }
    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f: File = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut font_file: Font = Font::load(asset_path).map_err(|_err| Error::FontLoadError)?;
        // Get our name table.
        let mut name_table = font_file
            .tables
            .name()
            .map_err(|_err| Error::DeserializationError)?
            .ok_or(Error::NotFound)?;
        // Remove any of our special manifest records.
        name_table.records.retain(|x: &NameRecord| {
            x.encodingID != C2PA_ENCODING_ID
                && x.languageID != C2PA_LANGUAGE_ID
                && x.nameID != C2PA_NAME_ID
                && x.platformID != C2PA_PLATFORM_ID
        });
        // Create a new manifest record with our manifest data.
        let c2pa_name = NameRecord {
            encodingID: C2PA_ENCODING_ID,
            languageID: C2PA_LANGUAGE_ID,
            nameID: C2PA_NAME_ID,
            platformID: C2PA_PLATFORM_ID,
            string: base64_encode(store_bytes),
        };
        // Add new record to the name table.  This will cause a copy to occur
        // as the CowPtr creates a clone to occur as the push signals that a
        // write is going to occur.
        name_table.records.push(c2pa_name);
        // Re-insert the modified name table.
        font_file.tables.insert(name_table);
        // Save back to the original file.
        font_file
            .save(asset_path)
            .map_err(|_err| Error::FontSaveError)?;

        Ok(())
    }

    #[allow(unused_variables)]
    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        let mut positions: Vec<HashObjectPositions> = Vec::new();
        let table_header_sz: usize = 12;
        let table_entry_sz: usize = 16;
        // We need to get the offset to the 'name' table and exclude the length of it and its data.
        let data: Vec<u8> = std::fs::read(asset_path)?;
        // Verify the font has a valid version in it before assuming the rest is
        // valid (NOTE: we don't actually do anything with it, just as a safety check).
        let sfnt_u32: u32 = read_u32(&data[0..4])?;
        let sfnt_version: FontVersion =
            <u32 as std::convert::TryInto<FontVersion>>::try_into(sfnt_u32)
                .map_err(|_err| Error::UnsupportedFontError)?;
        let num_tables: u16 = read_u16(&data[4..6])?;
        // Get the slice of the table array
        let tables: &[u8] = &data[12..];
        // Using a counter to calculate the offset to the name table
        let mut table_counter: usize = 0;

        // Then enumerate over all of the table entries looking for a name table
        for table_slice in tables.chunks_exact(table_entry_sz) {
            // Check for the name table from the tag entry
            if NAME_TABLE_TAG.as_bytes() == read_u8_4(&table_slice[0..4])? {
                // We will need to add a position for the 'name' entry since the
                // checksum changes.
                positions.push(HashObjectPositions {
                    offset: table_header_sz + (table_entry_sz * table_counter),
                    length: table_entry_sz,
                    htype: HashBlockObjectType::Cai,
                });

                // Then grab the offset and length of the actual name table to
                // create the other exclusion zone.
                let offset = read_u32(&table_slice[8..12])?;
                let length = read_u32(&table_slice[12..16])?;
                positions.push(HashObjectPositions {
                    offset: offset as usize,
                    length: length as usize,
                    htype: HashBlockObjectType::Cai,
                });

                // Finally return our collection of positions to ignore/exclude.
                return Ok(positions);
            }
            table_counter += 1;

            // If we have iterated over all of our tables, bail
            if table_counter >= num_tables as usize {
                break;
            }
        }
        Err(Error::NotFound)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        let mut font_file: Font = Font::load(asset_path).map_err(|_err| Error::FontLoadError)?;

        // Grab our name table.
        let mut name_table = font_file
            .tables
            .name()
            .map_err(|_err| Error::DeserializationError)?
            .ok_or(Error::NotFound)?;
        // Remove any of our manifest name records.
        name_table.records.retain(|x: &NameRecord| {
            x.encodingID != C2PA_ENCODING_ID
                && x.languageID != C2PA_LANGUAGE_ID
                && x.nameID != C2PA_NAME_ID
                && x.platformID != C2PA_PLATFORM_ID
        });
        // Write out modified font.
        font_file
            .save(asset_path)
            .map_err(|_err| Error::FontSaveError)?;

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {

    /* Rudimentary integration test, left here to allow for quick verification until
       property unit/integration testing has been implemented.

    use super::*;

        #[test]
        fn add_cai() {
            let font_path = Path::new("<path to font>/CultStd.otf");
            let manifest: [u8; 12] = [0u8; 12];
            let otf_io = OtfIO {};
            otf_io.save_cai_store(&font_path, &manifest).ok();
            let parsed_manifest = otf_io.read_cai_store(&font_path).unwrap();
            let parsed_manifest_slice = parsed_manifest.as_slice();
            assert_eq!(manifest, parsed_manifest_slice);
        }
    */
}
