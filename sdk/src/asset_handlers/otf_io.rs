// Copyright 2022,2023 Monotype. All rights reserved.
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
    convert::TryFrom,
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::*,
};

use byteorder::{BigEndian, ReadBytesExt};
use fonttools::{font::Font, table_store::CowPtr, tables, tables::C2PA::C2PA, types::*};
use log::debug;
use tempfile::TempDir;
use uuid::Uuid;

use crate::{
    asset_io::{
        AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashBlockObjectType,
        HashObjectPositions, RemoteRefEmbed, RemoteRefEmbedType,
    },
    error::{Error, Result},
};

/// This module is a temporary implementation of a very basic support for XMP in
/// fonts. Ideally the reading/writing of the following should be independent of
/// XMP support:
///
/// - `InstanceID` - Unique identifier of the instance
/// - `DocumentID` - Unique identifier of the document
/// - `Provenance` - Url/Uri of the provenance
///
/// But as the authoring of this module the Rust SDK still assumes the remote
/// manifest reference comes from the XMP when building the `Ingredient` (as
/// seen in the ingredient module). The instance/document ID also are read from
/// the XMP when building the ingredient, so until this type of logic has been
/// abstracted this is meant as a temporary hack to provide a working
/// implementation for remote manifests.
///
/// ### Remarks
///
/// This module depends on the `feature = "xmp_write"` to be enabled.
#[cfg(feature = "xmp_write")]
mod font_xmp_support {
    use xmp_toolkit::{FromStrOptions, XmpError, XmpErrorType, XmpMeta};

    use super::*;

    /// Creates a default `XmpMeta` object for fonts
    ///
    /// ### Arguments
    ///
    /// - `document_id` - optional unique identifier for the document
    /// - `instance_id` - optional unique identifier for the instance
    ///
    /// ### Remarks
    ///
    /// Default/random values will be used for the document/instance IDs as
    /// needed.
    fn default_font_xmp_meta(
        document_id: Option<String>,
        instance_id: Option<String>,
    ) -> Result<XmpMeta> {
        // But we could build up a default document/instance ID for a font and
        // use it to seed the data. Doing this would only make sense if creating
        // and writing the data to the font
        let xmp_mm_namespace = "http://ns.adobe.com/xap/1.0/mm/";
        // If there was no reference in the stream, then we build up
        // a default XMP data
        let mut xmp_meta = XmpMeta::new().map_err(xmp_write_err)?;

        // Add a document ID
        xmp_meta
            .set_property(
                xmp_mm_namespace,
                "DocumentID",
                // Use the supplied document ID or default to one if needed
                &document_id.unwrap_or(OtfIO::default_document_id()).into(),
            )
            .map_err(xmp_write_err)?;

        // Add an instance ID
        xmp_meta
            .set_property(
                xmp_mm_namespace,
                "InstanceID",
                // Use the supplied instance ID or default to one if needed
                &instance_id.unwrap_or(OtfIO::default_instance_id()).into(),
            )
            .map_err(xmp_write_err)?;

        Ok(xmp_meta)
    }

    /// Builds a `XmpMeta` element from the data within the source stream
    ///
    /// ### Parameters
    ///
    /// - `source` - Source stream to read data from to build the `XmpMeta` object
    ///
    /// ### Returns
    ///
    /// A new `XmpMeta` object, either based on information that already exists in
    /// the stream or using defaults
    ///
    /// ### Remarks
    /// The use of this function really shouldn't be needed, but currently the SDK
    /// is tightly coupled to the use of XMP with assets.
    pub fn build_xmp_from_stream<TSource>(source: &mut TSource) -> Result<XmpMeta>
    where
        TSource: Read + Seek + ?Sized,
    {
        match read_reference_to_stream(source)? {
            // For now we pretend the reference read from the stream is really XMP
            // data
            Some(xmp) => {
                // If we did have reference data in the stream, we assume it is
                // really XMP data, and will read as such
                XmpMeta::from_str_with_options(xmp.as_str(), FromStrOptions::default())
                    .map_err(xmp_write_err)
            }
            // Mention there is no data representing XMP found
            None => Err(Error::NotFound),
        }
    }

    /// Maps the errors from the xmp_toolkit crate
    ///
    /// ### Parameters
    ///
    /// - `err` - The `XmpError` to map to an internal error type
    ///
    /// ### Remarks
    /// This is nearly a copy/paste from `embedded_xmp` crate, we should clean this
    /// up at some point
    fn xmp_write_err(err: XmpError) -> crate::Error {
        match err.error_type {
            // convert to OS permission error code so we can detect it correctly upstream
            XmpErrorType::FilePermission => Error::IoError(std::io::Error::from_raw_os_error(13)),
            XmpErrorType::NoFile => Error::NotFound,
            XmpErrorType::NoFileHandler => Error::UnsupportedType,
            _ => Error::XmpWriteError,
        }
    }

    /// Adds a C2PA manifest reference as XMP data to a font file
    ///
    /// ### Parameters
    /// - `font_path` - Path to the font file to add the reference to
    /// - `manifest_uri` - A C2PA manifest URI (JUMBF or URL based)
    ///
    /// ### Remarks
    /// This method is considered a stop-gap for now until the official SDK
    /// offers a more generic method to indicate a document ID, instance ID,
    /// and a reference to the a remote manifest.
    pub fn add_reference_as_xmp_to_font(font_path: &Path, manifest_uri: &str) -> Result<()> {
        process_file_with_streams(font_path, move |input_stream, temp_file| {
            // Write the manifest URI to the stream
            add_reference_as_xmp_to_stream(input_stream, temp_file.get_mut_file(), manifest_uri)
        })
    }

    /// Adds a C2PA manifest reference as XMP data to the stream
    ///
    /// ### Parameters
    /// - `source` - Source stream to read from
    /// - `destination` - Destination stream to write the reference to
    /// - `reference` - A C2PA manifest URI (JUMBF or URL based)
    ///
    /// ### Remarks
    /// This method is considered a stop-gap for now until the official SDK
    /// offers a more generic method to indicate a document ID, instance ID,
    /// and a reference to the a remote manifest.
    #[allow(dead_code)]
    pub fn add_reference_as_xmp_to_stream<TSource, TDest>(
        source: &mut TSource,
        destination: &mut TDest,
        manifest_uri: &str,
    ) -> Result<()>
    where
        TSource: Read + Seek + ?Sized,
        TDest: Write + ?Sized,
    {
        // We must register the namespace for dcterms, to be able to set the
        // provenance
        XmpMeta::register_namespace("http://purl.org/dc/terms/", "dcterms")
            .map_err(xmp_write_err)?;
        // Build a simple XMP meta element from the current source stream
        let mut xmp_meta = match build_xmp_from_stream(source) {
            // Use the data already available
            Ok(meta) => meta,
            // If data was not found for building out the XMP, we will default
            // to some good starting points
            Err(Error::NotFound) => default_font_xmp_meta(None, None)?,
            // At this point, the font is considered to be invalid possibly
            Err(error) => return Err(error),
        };
        // Reset the source stream to the beginning
        source.seek(SeekFrom::Start(0))?;
        // We don't really care if there was a provenance before, since we are
        // writing a new one we will either be adding or overwriting what
        // was there.
        xmp_meta
            .set_property(
                "http://purl.org/dc/terms/",
                "provenance",
                &manifest_uri.into(),
            )
            .map_err(xmp_write_err)?;
        // Finally write the XMP data as a string to the stream
        add_reference_to_stream(source, destination, &xmp_meta.to_string())?;

        Ok(())
    }
}

struct TempFile {
    // The temp_dir must be referenced during the duration of the use of the
    // temporary file, as soon as it is dropped the temporary directory and the
    // contents thereof are deleted
    #[allow(dead_code)]
    temp_dir: TempDir,
    path: Box<Path>,
    file: File,
}

impl TempFile {
    /// Creates a new temporary file within the `env::temp_dir()` directory,
    /// which should be deleted once the object is dropped.
    ///
    /// ## Arguments
    ///
    /// * `base_name` - Base name to use for the temporary file name
    pub fn new(base_name: &Path) -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let temp_dir_path = temp_dir.path();
        let path = temp_dir_path.join(
            base_name
                .file_name()
                .ok_or_else(|| Error::BadParam("Invalid file name".to_string()))?,
        );
        let file = File::create(&path)?;
        Ok(Self {
            temp_dir,
            path: path.into(),
            file,
        })
    }

    /// Get the path of the temporary file
    pub fn get_path(&self) -> &Path {
        self.path.as_ref()
    }

    /// Get a mutable reference to the temporary file
    pub fn get_mut_file(&mut self) -> &mut File {
        &mut self.file
    }
}

/// Supported extension and mime-types
static SUPPORTED_TYPES: [&str; 10] = [
    "application/font-sfnt",
    "application/x-font-opentype",
    "application/x-font-ttf",
    "application/x-font-truetype",
    "font/otf",
    "font/sfnt",
    "font/ttf",
    "otf",
    "sfnt",
    "ttf",
];

/// Tag for the 'C2PA' table in a font.
const C2PA_TABLE_TAG: Tag = tables::C2PA::TAG;
/// Tag for the 'head' table in a font.
const HEAD_TABLE_TAG: Tag = tables::head::TAG;

/// Various valid version tags seen in a OTF/TTF file.
pub enum FontVersion {
    /// TrueType (ttf) version for Windows and/or Adobe
    TrueType = 0x00010000,
    /// OpenType (otf) version
    OpenType = 0x4f54544f,
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

/// Adds C2PA manifest store data to a font file
///
/// ## Arguments
///
/// * `font_path` - Path to a font file
/// * `manifest_store_data` - C2PA manifest store data to add to the font file
fn add_c2pa_to_font(font_path: &Path, manifest_store_data: &[u8]) -> Result<()> {
    process_file_with_streams(font_path, move |input_stream, temp_file| {
        // Add the C2PA data to the temp file
        add_c2pa_to_stream(input_stream, temp_file.get_mut_file(), manifest_store_data)
    })
}

/// Adds C2PA manifest store data to a font stream
///
/// ## Arguments
///
/// * `source` - Source stream to read initial data from
/// * `destination` - Destination stream to write C2PA manifest store data
/// * `manifest_store_data` - C2PA manifest store data to add to the font stream
fn add_c2pa_to_stream<TSource, TDest>(
    source: &mut TSource,
    destination: &mut TDest,
    manifest_store_data: &[u8],
) -> Result<()>
where
    TSource: Read + Seek + ?Sized,
    TDest: Write + ?Sized,
{
    let mut font_file: Font = Font::from_reader(source).map_err(|_| Error::FontLoadError)?;
    match font_file.tables.C2PA() {
        Ok(Some(c2pa_table)) => {
            font_file.tables.insert(C2PA::new(
                c2pa_table.activeManifestUri.clone(),
                Some(manifest_store_data.to_vec()),
            ));
        }
        Ok(None) => font_file
            .tables
            .insert(C2PA::new(None, Some(manifest_store_data.to_vec()))),
        Err(_) => return Err(Error::DeserializationError),
    };
    // Write to the destination stream
    font_file
        .write(destination)
        .map_err(|_| Error::FontSaveError)?;
    Ok(())
}

/// Adds the manifest URI reference to the font at the given path.
///
/// ## Arguments
///
/// * `font_path` - Path to a font file
/// * `manifest_uri` - Reference URI to a manifest store
#[allow(dead_code)]
fn add_reference_to_font(font_path: &Path, manifest_uri: &str) -> Result<()> {
    process_file_with_streams(font_path, move |input_stream, temp_file| {
        // Write the manifest URI to the stream
        add_reference_to_stream(input_stream, temp_file.get_mut_file(), manifest_uri)
    })
}

/// Adds the specified reference to the font.
///
/// ## Arguments
///
/// * `source` - Source stream to read initial data from
/// * `destination` - Destination stream to write data with new reference
/// * `manifest_uri` - Reference URI to a manifest store
fn add_reference_to_stream<TSource, TDest>(
    source: &mut TSource,
    destination: &mut TDest,
    manifest_uri: &str,
) -> Result<()>
where
    TSource: Read + Seek + ?Sized,
    TDest: Write + ?Sized,
{
    let mut font = Font::from_reader(source).map_err(|_| Error::FontLoadError)?;
    match font.tables.C2PA() {
        Ok(Some(c2pa_table)) => {
            font.tables.insert(C2PA::new(
                Some(manifest_uri.to_string()),
                c2pa_table.get_manifest_store().map(|x| x.to_vec()),
            ));
        }
        Ok(None) => font
            .tables
            .insert(C2PA::new(Some(manifest_uri.to_string()), None)),
        Err(_) => return Err(Error::DeserializationError),
    };
    font.write(destination).map_err(|_| Error::FontSaveError)?;
    Ok(())
}

/// Opens a BufReader for the given file path
///
/// ## Arguments
///
/// * `file_path` - Valid path to a file to open in a buffer reader
///
/// ## Returns
///
/// A BufReader<File> object
fn open_bufreader_for_file(file_path: &Path) -> Result<BufReader<File>> {
    let file = File::open(file_path)?;
    Ok(BufReader::new(file))
}

/// Processes a font file using a streams to process.
///
/// ## Arguments
///
/// * `font_path` - Path to the font file to process
/// * `callback` - Method to process the stream
fn process_file_with_streams(
    font_path: &Path,
    callback: impl Fn(&mut BufReader<File>, &mut TempFile) -> Result<()>,
) -> Result<()> {
    // Open the font source for a buffer read
    let mut font_buffer = open_bufreader_for_file(font_path)?;
    // Open a temporary file, which will be deleted after destroyed
    let mut temp_file = TempFile::new(font_path)?;
    callback(&mut font_buffer, &mut temp_file)?;
    // Finally copy the temporary file, replacing the original file
    std::fs::copy(temp_file.get_path(), font_path)?;
    Ok(())
}

/// Reads the C2PA manifest store reference from the font file.
///
/// ## Arguments
///
/// * `font_path` - File path to the font file to read reference from.
///
/// ## Returns
/// If a reference is available, it will be returned.
#[allow(dead_code)]
fn read_reference_from_font(font_path: &Path) -> Result<Option<String>> {
    // open the font source
    let mut font_stream = open_bufreader_for_file(font_path)?;
    read_reference_to_stream(&mut font_stream)
}

/// Reads the C2PA manifest store reference from the stream.
///
/// ## Arguments
///
/// * `source` - Source font stream to read reference from.
///
/// ## Returns
/// If a reference is available, it will be returned.
#[allow(dead_code)]
fn read_reference_to_stream<TSource>(source: &mut TSource) -> Result<Option<String>>
where
    TSource: Read + Seek + ?Sized,
{
    match read_c2pa_from_stream(source) {
        Ok(c2pa_data) => Ok(c2pa_data.activeManifestUri.to_owned()),
        Err(Error::JumbfNotFound) => Ok(None),
        Err(_) => Err(Error::DeserializationError),
    }
}

/// Remove the `C2PA` font table from the font file.
///
/// ## Arguments
///
/// * `font_path` - path to the font file to remove C2PA from
fn remove_c2pa_from_font(font_path: &Path) -> Result<()> {
    process_file_with_streams(font_path, move |input_stream, temp_file| {
        // Remove the C2PA manifest store from the stream
        remove_c2pa_from_stream(input_stream, temp_file.get_mut_file())
    })
}

/// Remove the `C2PA` font table from the font data stream, writing to the
/// destination.
///
/// ## Arguments
///
/// * `source` - Source data stream containing font data
/// * `destination` - Destination data stream to write new font data with the
///                   C2PA table removed
fn remove_c2pa_from_stream<TSource, TDest>(
    source: &mut TSource,
    destination: &mut TDest,
) -> Result<()>
where
    TSource: Read + Seek + ?Sized,
    TDest: Write + ?Sized,
{
    // Load the font from the stream
    let mut font = Font::from_reader(source).map_err(|_| Error::FontLoadError)?;
    // Remove the table from the collection
    font.tables.remove(C2PA_TABLE_TAG);
    // And write it to the destination stream
    font.write(destination).map_err(|_| Error::FontSaveError)?;

    Ok(())
}

/// Removes the reference to the active manifest from the source stream, writing
/// to the destination.
///
/// ## Arguments
///
/// * `source` - Source data stream containing font data
/// * `destination` - Destination data stream to write new font data with the
///                   active manifest reference removed
///
/// ## Returns
///
/// The active manifest URI reference that was removed, if there was one
#[allow(dead_code)]
fn remove_reference_from_stream<TSource, TDest>(
    source: &mut TSource,
    destination: &mut TDest,
) -> Result<Option<String>>
where
    TSource: Read + Seek + ?Sized,
    TDest: Write + ?Sized,
{
    let mut font = Font::from_reader(source).map_err(|_| Error::FontLoadError)?;
    let manifest_uri = match font.tables.C2PA() {
        Ok(Some(c2pa_table)) => {
            let manifest_uri = c2pa_table.activeManifestUri.clone();
            font.tables.insert(C2PA::new(
                None,
                c2pa_table.get_manifest_store().map(|x| x.to_vec()),
            ));
            manifest_uri
        }
        Ok(None) => None,
        Err(_) => return Err(Error::DeserializationError),
    };
    font.write(destination).map_err(|_| Error::FontSaveError)?;
    Ok(manifest_uri)
}

/// Gets a collection of positions of hash objects, which are to be excluded from the hashing.
///
/// ## Arguments
///
/// * `reader` - Reader object used to read object locations from
///
/// ## Returns
///
/// A collection of positions/offsets and length to omit from hashing.
fn get_object_locations_from_stream<T>(reader: &mut T) -> Result<Vec<HashObjectPositions>>
where
    T: Read + Seek + ?Sized,
{
    let mut positions: Vec<HashObjectPositions> = Vec::new();
    let table_header_sz: usize = 12;
    let table_entry_sz: usize = 16;
    // Create a 16-byte buffer to hold each table entry as we read through the file
    let mut table_entry_buf: [u8; 16] = [0; 16];
    // We need to get the offset to the 'name' table and exclude the length of it and its data.
    // Verify the font has a valid version in it before assuming the rest is
    // valid (NOTE: we don't actually do anything with it, just as a safety check).
    let sfnt_u32: u32 = reader.read_u32::<BigEndian>()?;
    let _sfnt_version: FontVersion =
        <u32 as std::convert::TryInto<FontVersion>>::try_into(sfnt_u32)
            .map_err(|_err| Error::UnsupportedFontError)?;

    // Using a counter to calculate the offset to the name table
    let mut table_counter: usize = 0;
    // Get the number of tables available from the next 2 bytes
    let num_tables: u16 = reader.read_u16::<BigEndian>()?;
    // Advance to the start of the table entries
    reader.seek(SeekFrom::Start(12))?;

    while reader.read_exact(&mut table_entry_buf).is_ok() {
        let table_tag = &table_entry_buf[0..4];
        // Add the contents of the C2PA table to the exclusion
        if C2PA_TABLE_TAG.as_bytes() == table_tag {
            // We will need to add a position for the 'C2PA' entry since the
            // checksum changes.
            positions.push(HashObjectPositions {
                offset: table_header_sz + (table_entry_sz * table_counter),
                length: table_entry_sz,
                htype: HashBlockObjectType::Cai,
            });

            // Then grab the offset and length of the actual name table to
            // create the other exclusion zone.
            let offset = (&table_entry_buf[8..12]).read_u32::<BigEndian>()?;
            let length = (&table_entry_buf[12..16]).read_u32::<BigEndian>()?;
            positions.push(HashObjectPositions {
                offset: offset as usize,
                length: length as usize,
                htype: HashBlockObjectType::Cai,
            });
        }
        // Add the `head[checksumAdjustment]` value as it will change after
        // adding C2PA
        else if HEAD_TABLE_TAG.as_bytes() == table_tag {
            let offset = (&table_entry_buf[8..12]).read_u32::<BigEndian>()?;
            // Add in the `head`[checksumAdjustment] to the exclusions
            positions.push(HashObjectPositions {
                offset: offset as usize + 8,
                length: 4,
                htype: HashBlockObjectType::Cai,
            });
        }
        table_counter += 1;

        // If we have iterated over all of our tables, bail
        if table_counter >= num_tables as usize {
            break;
        }
    }
    // Add the table directory headers
    positions.push(HashObjectPositions {
        offset: table_header_sz,
        length: table_entry_sz * num_tables as usize,
        htype: HashBlockObjectType::Cai,
    });
    for position in positions.iter().as_ref() {
        debug!("Position for C2PA in font: {:?}", &position);
    }
    Ok(positions)
}

/// Reads the `C2PA` font table from the data stream
///
/// ## Arguments
///
/// * `reader` - data stream reader to read font data from
///
/// ## Returns
///
/// A result containing the `C2PA` font table data
fn read_c2pa_from_stream<T: Read + Seek + ?Sized>(reader: &mut T) -> Result<CowPtr<C2PA>> {
    let font: Font = Font::from_reader(reader).map_err(|_| Error::FontLoadError)?;
    // Grab the C2PA table.
    font.tables
        .C2PA()
        .map_err(|_err| Error::DeserializationError)?
        .ok_or(Error::JumbfNotFound)
}

/// Main OTF IO feature.
pub struct OtfIO {}

impl OtfIO {
    #[allow(dead_code)]
    pub fn default_document_id() -> String {
        format!("fontsoftware:did:{}", Uuid::new_v4())
    }

    #[allow(dead_code)]
    pub fn default_instance_id() -> String {
        format!("fontsoftware:iid:{}", Uuid::new_v4())
    }
}

/// OTF implementation of the CAILoader trait.
impl CAIReader for OtfIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let c2pa_table = read_c2pa_from_stream(asset_reader)?;
        match c2pa_table.get_manifest_store() {
            Some(manifest_store) => Ok(manifest_store.to_vec()),
            _ => Err(Error::JumbfNotFound),
        }
    }

    fn read_xmp(&self, asset_reader: &mut dyn CAIRead) -> Option<String> {
        // Fonts have no XMP data.
        // BUT, for now we will pretend it does and read from the reference
        match read_reference_to_stream(asset_reader) {
            Ok(reference) => reference,
            Err(_) => None,
        }
    }
}

/// OTF/TTF implementations for the CAIWriter trait.
impl CAIWriter for OtfIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        add_c2pa_to_stream(input_stream, output_stream, store_bytes)
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        get_object_locations_from_stream(input_stream)
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        remove_c2pa_from_stream(input_stream, output_stream)
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

    fn remote_ref_writer_ref(&self) -> Option<&dyn RemoteRefEmbed> {
        Some(self)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f: File = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        add_c2pa_to_font(asset_path, store_bytes)
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        let mut buf_reader = open_bufreader_for_file(asset_path)?;
        get_object_locations_from_stream(&mut buf_reader)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        remove_c2pa_from_font(asset_path)
    }
}

impl RemoteRefEmbed for OtfIO {
    #[allow(unused_variables)]
    fn embed_reference(
        &self,
        asset_path: &Path,
        embed_ref: crate::asset_io::RemoteRefEmbedType,
    ) -> Result<()> {
        match embed_ref {
            crate::asset_io::RemoteRefEmbedType::Xmp(manifest_uri) => {
                #[cfg(feature = "xmp_write")]
                {
                    font_xmp_support::add_reference_as_xmp_to_font(asset_path, &manifest_uri)
                }
                #[cfg(not(feature = "xmp_write"))]
                {
                    add_reference_to_font(asset_path, &manifest_uri)
                }
            }
            crate::asset_io::RemoteRefEmbedType::StegoS(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::StegoB(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::Watermark(_) => Err(Error::UnsupportedType),
        }
    }

    fn embed_reference_to_stream(
        &self,
        source_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        embed_ref: RemoteRefEmbedType,
    ) -> Result<()> {
        match embed_ref {
            crate::asset_io::RemoteRefEmbedType::Xmp(manifest_uri) => {
                #[cfg(feature = "xmp_write")]
                {
                    font_xmp_support::add_reference_as_xmp_to_stream(
                        source_stream,
                        output_stream,
                        &manifest_uri,
                    )
                }
                #[cfg(not(feature = "xmp_write"))]
                {
                    add_reference_to_stream(source_stream, output_stream, &manifest_uri)
                }
            }
            crate::asset_io::RemoteRefEmbedType::StegoS(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::StegoB(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::Watermark(_) => Err(Error::UnsupportedType),
        }
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]
    use std::io::Cursor;

    use tempfile::tempdir;

    use super::*;
    use crate::utils::test::temp_dir_path;

    #[test]
    #[cfg(not(feature = "xmp_write"))]
    /// Verifies the adding of a remote C2PA manifest reference works as
    /// expected.
    fn add_c2pa_ref() {
        let c2pa_data = "test data";

        // Load the basic OTF test fixture
        let source = crate::utils::test::fixture_path("font.otf");

        // Create a temporary output for the file
        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "test.otf");

        // Copy the source to the output
        std::fs::copy(source, &output).unwrap();

        // Create our OtfIO asset handler for testing
        let otf_io = OtfIO {};

        let expected_manifest_uri = "https://test/ref";

        otf_io
            .embed_reference(
                &output,
                crate::asset_io::RemoteRefEmbedType::Xmp(expected_manifest_uri.to_owned()),
            )
            .unwrap();
        // Save the C2PA manifest store to the file
        otf_io
            .save_cai_store(&output, c2pa_data.as_bytes())
            .unwrap();
        // Loading it back from the same output file
        let loaded_c2pa = otf_io.read_cai_store(&output).unwrap();
        // Which should work out to be the same in the end
        assert_eq!(&loaded_c2pa, c2pa_data.as_bytes());

        match read_reference_from_font(&output) {
            Ok(Some(manifest_uri)) => assert_eq!(expected_manifest_uri, manifest_uri),
            _ => panic!("Expected to read a reference from the font file"),
        };
    }

    #[test]
    #[cfg(feature = "xmp_write")]
    /// Verifies the adding of a remote C2PA manifest reference as XMP works as
    /// expected.
    fn add_c2pa_ref() {
        use std::str::FromStr;

        use xmp_toolkit::XmpMeta;

        let c2pa_data = "test data";

        // Load the basic OTF test fixture
        let source = crate::utils::test::fixture_path("font.otf");

        // Create a temporary output for the file
        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "test.otf");

        // Copy the source to the output
        std::fs::copy(source, &output).unwrap();

        // Create our OtfIO asset handler for testing
        let otf_io = OtfIO {};

        let expected_manifest_uri = "https://test/ref";

        otf_io
            .embed_reference(
                &output,
                crate::asset_io::RemoteRefEmbedType::Xmp(expected_manifest_uri.to_owned()),
            )
            .unwrap();
        // Save the C2PA manifest store to the file
        otf_io
            .save_cai_store(&output, c2pa_data.as_bytes())
            .unwrap();
        // Loading it back from the same output file
        let loaded_c2pa = otf_io.read_cai_store(&output).unwrap();
        // Which should work out to be the same in the end
        assert_eq!(&loaded_c2pa, c2pa_data.as_bytes());

        match read_reference_from_font(&output) {
            Ok(Some(manifest_uri)) => {
                let xmp_meta = XmpMeta::from_str(manifest_uri.as_str()).unwrap();
                let provenance = xmp_meta
                    .property("http://purl.org/dc/terms/", "provenance")
                    .unwrap();
                assert_eq!(expected_manifest_uri, provenance.value.as_str());
            }
            _ => panic!("Expected to read a reference from the font file"),
        };
    }

    /// Verify when reading the object locations for hashing, we get zero
    /// positions when the font contains zero tables
    #[test]
    fn get_object_locations_without_any_tables() {
        let font_data = vec![
            0x4f, 0x54, 0x54, 0x4f, // OTTO
            0x00, 0x00, // 0 tables
        ];
        let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
        let positions = get_object_locations_from_stream(&mut font_stream).unwrap();
        // Should have one position reported for the entire "file"
        assert_eq!(1, positions.len());
        assert_eq!(12, positions.get(0).unwrap().offset);
        assert_eq!(0, positions.get(0).unwrap().length);
    }

    /// Verify when reading the object locations for hashing, we get zero
    /// positions when the font does not contain a C2PA font table
    #[test]
    fn get_object_locations_without_c2pa_table() {
        let font_data = vec![
            0x4f, 0x54, 0x54, 0x4f, // OTTO
            0x00, 0x01, // 1 tables
            0x00, 0x00, // search range
            0x00, 0x00, // entry selector
            0x00, 0x00, // range shift
            0x43, 0x32, 0x50, 0x42, // C2PB table tag
            0x00, 0x00, 0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x1c, // offset to table data
            0x00, 0x00, 0x00, 0x01, // length of table data
            0x00, // C2PB data
        ];
        let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
        let positions = get_object_locations_from_stream(&mut font_stream).unwrap();
        // Should have one position reported for the table directory
        assert_eq!(1, positions.len());
        assert_eq!(12, positions.get(0).unwrap().offset);
        assert_eq!(16, positions.get(0).unwrap().length);
    }

    /// Verifies the correct object positions are returned when a font contains
    /// C2PA data
    #[test]
    fn get_object_locations_with_table() {
        let font_data = vec![
            0x4f, 0x54, 0x54, 0x4f, // OTTO - OpenType tag
            0x00, 0x01, // 1 tables
            0x00, 0x00, // search range
            0x00, 0x00, // entry selector
            0x00, 0x00, // range shift
            0x43, 0x32, 0x50, 0x41, // C2PA table tag
            0x00, 0x00, 0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x1c, // offset to table data
            0x00, 0x00, 0x00, 0x1a, // length of table data
            0x00, 0x00, // Major version
            0x00, 0x01, // Minor version
            0x00, 0x00, 0x00, 0x12, // Active manifest URI offset
            0x00, 0x08, // Active manifest URI length
            0x00, 0x00, 0x00, 0x00, // C2PA manifest store offset
            0x00, 0x00, 0x00, 0x00, // C2PA manifest store length
            0x66, 0x69, 0x6c, 0x65, 0x3a, 0x2f, 0x2f, 0x61, // active manifest uri data
        ];
        let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
        let positions = get_object_locations_from_stream(&mut font_stream).unwrap();
        // Should have 3 positions reported
        assert_eq!(3, positions.len());
        // The first one is the position to the table header entry which describes where
        // the C2PA table is
        assert_eq!(16, positions.get(0).unwrap().length);
        assert_eq!(12, positions.get(0).unwrap().offset);
        // The second one is the position of the actual C2PA table
        assert_eq!(26, positions.get(1).unwrap().length);
        assert_eq!(28, positions.get(1).unwrap().offset);
        // And the third is the position of the actual directory table
        assert_eq!(16, positions.get(2).unwrap().length);
        assert_eq!(12, positions.get(2).unwrap().offset);
    }

    /// Verifies the correct object positions are returned when a font contains
    /// C2PA data
    #[test]
    fn get_object_locations_with_head_and_c2pa_tables() {
        let font_data = vec![
            0x4f, 0x54, 0x54, 0x4f, // OTTO - OpenType tag
            0x00, 0x02, // 2 tables
            0x00, 0x00, // search range
            0x00, 0x00, // entry selector
            0x00, 0x00, // range shift
            0x43, 0x32, 0x50, 0x41, // C2PA table tag
            0x00, 0x00, 0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x32, // offset to table data
            0x00, 0x00, 0x00, 0x1a, // length of table data
            0x68, 0x65, 0x61, 0x64, // head table tag
            0x00, 0x00, 0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x4c, // offset to table data
            0x00, 0x00, 0x00, 0x0d, // length of table data
            0x00, 0x00, // Major version
            0x00, 0x01, // Minor version
            0x00, 0x00, 0x00, 0x12, // Active manifest URI offset
            0x00, 0x08, // Active manifest URI length
            0x00, 0x00, 0x00, 0x00, // C2PA manifest store offset
            0x00, 0x00, 0x00, 0x00, // C2PA manifest store length
            0x66, 0x69, 0x6c, 0x65, 0x3a, 0x2f, 0x2f, 0x61, // active manifest uri data
            0x00, 0x00, // Major version
            0x00, 0x01, // Minor version
            0x00, 0x00, 0x00, 0x00, // fontRevision
            0x00, 0x00, 0x00, 0x00, // checksumAdjustment
        ];
        let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
        let positions = get_object_locations_from_stream(&mut font_stream).unwrap();
        // Should have 4 positions reported
        assert_eq!(4, positions.len());
        // The first one is the position to the table header entry which describes where
        // the C2PA table is
        assert_eq!(16, positions.get(0).unwrap().length);
        assert_eq!(12, positions.get(0).unwrap().offset);
        // The second one is the position of the actual C2PA table
        assert_eq!(26, positions.get(1).unwrap().length);
        assert_eq!(50, positions.get(1).unwrap().offset);
        // The third is the position of the `head[checksumAdjustment]` table entry
        assert_eq!(4, positions.get(2).unwrap().length);
        assert_eq!(84, positions.get(2).unwrap().offset);
        // The fourth is the position of the actual directory table
        assert_eq!(32, positions.get(3).unwrap().length);
        assert_eq!(12, positions.get(3).unwrap().offset);
    }

    /// Verify the C2PA table data can be read from a font stream
    #[test]
    fn reads_c2pa_table_from_stream() {
        let font_data = vec![
            0x4f, 0x54, 0x54, 0x4f, // OTTO - OpenType tag
            0x00, 0x01, // 1 table
            0x00, 0x00, // search range
            0x00, 0x00, // entry selector
            0x00, 0x00, // range shift
            0x43, 0x32, 0x50, 0x41, // C2PA table tag
            0x00, 0x00, 0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x1c, // offset to table data
            0x00, 0x00, 0x00, 0x23, // length of table data
            0x00, 0x00, // Major version
            0x00, 0x01, // Minor version
            0x00, 0x00, 0x00, 0x12, // Active manifest URI offset
            0x00, 0x08, // Active manifest URI length
            0x00, 0x00, 0x00, 0x1a, // C2PA manifest store offset
            0x00, 0x00, 0x00, 0x09, // C2PA manifest store length
            0x66, 0x69, 0x6c, 0x65, 0x3a, 0x2f, 0x2f,
            0x61, // active manifest uri data (e.g., file://a)
            0x74, 0x65, 0x73, 0x74, 0x2d, 0x64, 0x61, 0x74, 0x61, // C2PA manifest store data
        ];
        let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
        let c2pa_data = read_c2pa_from_stream(&mut font_stream).unwrap();
        // Verify the active manifest uri
        assert_eq!(Some("file://a".to_string()), c2pa_data.activeManifestUri);
        // Verify the embedded C2PA data as well
        assert_eq!(
            Some(vec![0x74, 0x65, 0x73, 0x74, 0x2d, 0x64, 0x61, 0x74, 0x61].as_ref()),
            c2pa_data.get_manifest_store()
        );
    }

    /// Verifies the ability to write/read C2PA manifest store data to/from an
    /// OpenType font
    #[test]
    fn remove_c2pa_manifest_store() {
        let c2pa_data = "test data";

        // Load the basic OTF test fixture
        let source = crate::utils::test::fixture_path("font.otf");

        // Create a temporary output for the file
        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "test.otf");

        // Copy the source to the output
        std::fs::copy(source, &output).unwrap();

        // Create our OtfIO asset handler for testing
        let otf_io = OtfIO {};

        // Save the C2PA manifest store to the file
        otf_io
            .save_cai_store(&output, c2pa_data.as_bytes())
            .unwrap();
        // Loading it back from the same output file
        let loaded_c2pa = otf_io.read_cai_store(&output).unwrap();
        // Which should work out to be the same in the end
        assert_eq!(&loaded_c2pa, c2pa_data.as_bytes());

        otf_io.remove_cai_store(&output).unwrap();
        match otf_io.read_cai_store(&output) {
            Err(Error::JumbfNotFound) => (),
            _ => panic!("Should not contain any C2PA data"),
        };
    }

    /// Verifies the ability to write/read C2PA manifest store data to/from an
    /// OpenType font
    #[test]
    fn write_read_c2pa_from_font() {
        let c2pa_data = "test data";

        // Load the basic OTF test fixture
        let source = crate::utils::test::fixture_path("font.otf");

        // Create a temporary output for the file
        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "test.otf");

        // Copy the source to the output
        std::fs::copy(source, &output).unwrap();

        // Create our OtfIO asset handler for testing
        let otf_io = OtfIO {};

        // Save the C2PA manifest store to the file
        otf_io
            .save_cai_store(&output, c2pa_data.as_bytes())
            .unwrap();
        // Loading it back from the same output file
        let loaded_c2pa = otf_io.read_cai_store(&output).unwrap();
        // Which should work out to be the same in the end
        assert_eq!(&loaded_c2pa, c2pa_data.as_bytes());
    }

    #[cfg(feature = "xmp_write")]
    #[cfg(test)]
    pub mod font_xmp_support_tests {
        use std::{fs::File, io::Cursor, str::FromStr};

        use tempfile::tempdir;
        use xmp_toolkit::XmpMeta;

        use crate::{
            asset_handlers::otf_io::{font_xmp_support, OtfIO},
            asset_io::CAIReader,
            utils::test::temp_dir_path,
            Error,
        };

        /// Verifies the `font_xmp_support::add_reference_as_xmp_to_stream` is
        /// able to add a reference to as XMP when there is already data in the
        /// reference field.
        #[test]
        fn add_reference_as_xmp_to_stream_with_data() {
            // Load the basic OTF test fixture
            let source = crate::utils::test::fixture_path("font.otf");

            // Create a temporary output for the file
            let temp_dir = tempdir().unwrap();
            let output = temp_dir_path(&temp_dir, "test.otf");

            // Copy the source to the output
            std::fs::copy(source, &output).unwrap();

            // Add a reference to the font
            match font_xmp_support::add_reference_as_xmp_to_font(&output, "test data") {
                Ok(_) => {}
                Err(_) => panic!("Unexpected error when building XMP data"),
            }

            // Add again, with a new value
            match font_xmp_support::add_reference_as_xmp_to_font(&output, "new test data") {
                Ok(_) => {}
                Err(_) => panic!("Unexpected error when building XMP data"),
            }

            let otf_handler = OtfIO {};
            let mut f: File = File::open(output).unwrap();
            match otf_handler.read_xmp(&mut f) {
                Some(xmp_data_str) => {
                    let xmp_data = XmpMeta::from_str(&xmp_data_str).unwrap();
                    match xmp_data.property("http://purl.org/dc/terms/", "provenance") {
                        Some(xmp_value) => assert_eq!("new test data", xmp_value.value),
                        None => panic!("Expected a value for provenance"),
                    }
                }
                None => panic!("Expected to read XMP from the resource."),
            }
        }

        /// Verifies the `font_xmp_support::build_xmp_from_stream` method
        /// correctly returns error for NotFound when there is no data in the
        /// stream to return.
        #[test]
        fn build_xmp_from_stream_without_reference() {
            let font_data = vec![
                0x4f, 0x54, 0x54, 0x4f, // OTTO
                0x00, 0x01, // 1 tables
                0x00, 0x00, // search range
                0x00, 0x00, // entry selector
                0x00, 0x00, // range shift
                0x43, 0x32, 0x50, 0x42, // C2PB table tag
                0x00, 0x00, 0x00, 0x00, // Checksum
                0x00, 0x00, 0x00, 0x1c, // offset to table data
                0x00, 0x00, 0x00, 0x01, // length of table data
                0x00, // C2PB data
            ];
            let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
            match font_xmp_support::build_xmp_from_stream(&mut font_stream) {
                Ok(_) => panic!("Did not expect an OK result, as data is missing"),
                Err(Error::NotFound) => {}
                Err(_) => panic!("Unexpected error when building XMP data"),
            }
        }

        /// Verifies the `font_xmp_support::build_xmp_from_stream` method
        /// correctly returns error for NotFound when there is no data in the
        /// stream to return.
        #[test]
        fn build_xmp_from_stream_with_reference_not_xmp() {
            let font_data = vec![
                0x4f, 0x54, 0x54, 0x4f, // OTTO - OpenType tag
                0x00, 0x01, // 1 tables
                0x00, 0x00, // search range
                0x00, 0x00, // entry selector
                0x00, 0x00, // range shift
                0x43, 0x32, 0x50, 0x41, // C2PA table tag
                0x00, 0x00, 0x00, 0x00, // Checksum
                0x00, 0x00, 0x00, 0x1c, // offset to table data
                0x00, 0x00, 0x00, 0x1a, // length of table data
                0x00, 0x00, // Major version
                0x00, 0x01, // Minor version
                0x00, 0x00, 0x00, 0x12, // Active manifest URI offset
                0x00, 0x08, // Active manifest URI length
                0x00, 0x00, 0x00, 0x00, // C2PA manifest store offset
                0x00, 0x00, 0x00, 0x00, // C2PA manifest store length
                0x66, 0x69, 0x6c, 0x65, 0x3a, 0x2f, 0x2f, 0x61, // active manifest uri data
            ];
            let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
            match font_xmp_support::build_xmp_from_stream(&mut font_stream) {
                Ok(_xmp_data) => {}
                Err(_) => panic!("Unexpected error when building XMP data"),
            }
        }
    }
}
