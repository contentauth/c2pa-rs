// Copyright 2023 Monotype. All rights reserved.
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
use core::mem::size_of;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, Cursor, Read, Seek, SeekFrom, Write},
    path::*,
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use log::trace;
use serde_bytes::ByteBuf;
use tempfile::TempDir;
use uuid::Uuid;

use crate::{
    assertions::BoxMap,
    asset_handlers::font_io::*,
    asset_io::{
        AssetBoxHash, AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashBlockObjectType,
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
/// # Remarks
/// This module depends on the `feature = "xmp_write"` to be enabled.
#[cfg(feature = "xmp_write")]
mod font_xmp_support {
    use xmp_toolkit::{FromStrOptions, XmpError, XmpErrorType, XmpMeta};

    use super::*;

    /// Creates a default `XmpMeta` object for fonts, using the supplied
    /// document and instance identifiers.
    ///
    /// # Remarks
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
                &document_id.unwrap_or(WoffIO::default_document_id()).into(),
            )
            .map_err(xmp_write_err)?;

        // Add an instance ID
        xmp_meta
            .set_property(
                xmp_mm_namespace,
                "InstanceID",
                // Use the supplied instance ID or default to one if needed
                &instance_id.unwrap_or(WoffIO::default_instance_id()).into(),
            )
            .map_err(xmp_write_err)?;

        Ok(xmp_meta)
    }

    /// Builds a `XmpMeta` element from the data within the source stream, based
    /// on either the information already in the stream or default values.
    ///
    /// # Remarks
    /// The use of this function really shouldn't be needed, but currently the SDK
    /// is tightly coupled to the use of XMP with assets.
    pub(crate) fn build_xmp_from_stream<TSource>(source: &mut TSource) -> Result<XmpMeta>
    where
        TSource: Read + Seek + ?Sized,
    {
        match read_reference_from_stream(source)? {
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
    /// # Remarks
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

    /// Adds a C2PA manifest reference (specified by URI, JUMBF or URL based) as
    /// XMP data to a font file (specified by path).
    ///
    /// # Remarks
    /// This method is considered a stop-gap for now until the official SDK
    /// offers a more generic method to indicate a document ID, instance ID,
    /// and a reference to the a remote manifest.
    pub(crate) fn add_reference_as_xmp_to_font(font_path: &Path, manifest_uri: &str) -> Result<()> {
        process_file_with_streams(font_path, move |input_stream, temp_file| {
            // Write the manifest URI to the stream
            add_reference_as_xmp_to_stream(input_stream, temp_file.get_mut_file(), manifest_uri)
        })
    }

    /// Adds a C2PA manifest reference (specified as a URI, JUMBF or URL based)
    /// as XMP data to the stream, writing the result to the destination stream.
    ///
    /// # Remarks
    /// This method is considered a stop-gap for now until the official SDK
    /// offers a more generic method to indicate a document ID, instance ID,
    /// and a reference to the a remote manifest.
    #[allow(dead_code)]
    pub(crate) fn add_reference_as_xmp_to_stream<TSource, TDest>(
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
    /// which should be deleted once the object is dropped.  Uses the specified
    /// base name for the temporary file.
    pub(crate) fn new(base_name: &Path) -> Result<Self> {
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
    pub(crate) fn get_path(&self) -> &Path {
        self.path.as_ref()
    }

    /// Get a mutable reference to the temporary file
    pub(crate) fn get_mut_file(&mut self) -> &mut File {
        &mut self.file
    }
}

/// WOFF 1.0 WOFFHeader
const WOFF_HEADER_CHUNK_NAME: SfntTag = SfntTag {
    data: *b"\x00\x00\x00w",
};
// Then SFNT header could be *b"\x00\x00\x00w", and all the "header" chunks
// will automatically BTreeMap to start-of-file.

/// Pseudo-tag for the table directory.
const WOFF_DIRECTORY_CHUNK_NAME: SfntTag = SfntTag {
    data: *b"\x00\x00\x01D",
}; // Sorts to just-after HEADER tag.

/// WOFF 1.0 / 2.0 trailing XML metadata
const WOFF_METADATA_CHUNK_NAME: SfntTag = SfntTag {
    data: *b"\x7F\x7F\x7FM",
}; // Sorts to the penultimate position.

/// WOFF 1.0 / 2.0 trailing private data
const WOFF_PRIVATE_CHUNK_NAME: SfntTag = SfntTag {
    data: *b"\x7F\x7F\x7FP",
}; // Sorts to the very end.

/// Implementation of a WOFF 1.0 font
struct WoffFont {
    header: WoffHeader,
    directory: WoffDirectory,
    /// All the Tables in this font, keyed by SfntTag.
    // TBD - WOFF2 - For this format, the Table Directory entries are not
    // sorted by tag; rather, their order determines the physical order of the
    // tables themselves. Therefore, a BTreeMap keyed by tag is not appropriate;
    // we need to generalize the concept of table order across font container
    // types. Design considerations include:
    // - Any motivation to _not_ ensure that SFNTs/WOFF1s are sorted correctly;
    //   if our goal is simply to describe the provenance _of an already-existing asset_,
    //   then perhaps we need to permit incorrectly-ordered SFNTs/WOFF1s? In that
    //   case, then perhaps the selection of BTreeMap versus Vec is done at
    //   construction time, ensuring the desired behavior?
    // - Otherwise, we could just use BTreeMap for SFNT/WOFF1 and Vec for WOFF2
    // - Other matters?
    tables: BTreeMap<SfntTag, NamedTable>,
    meta: Option<TableUnspecified>,
    private: Option<TableUnspecified>,
}

impl WoffFont {
    /// Reads in a WOFF 1 font file from the given stream.
    fn from_reader<T: Read + Seek + ?Sized>(
        reader: &mut T,
    ) -> core::result::Result<WoffFont, Error> {
        // Read in the WOFFHeader
        let woff_hdr = WoffHeader::from_reader(reader)?;

        // After the header should be the directory.
        let woff_dir = WoffDirectory::from_reader(reader, woff_hdr.numTables as usize)?;

        // With that, we can construct the tables
        let mut woff_tables = BTreeMap::new();

        for entry in woff_dir.entries.iter() {
            // Try to parse the next dir entry
            let offset: u64 = entry.offset as u64;
            let size: usize = entry.compLength as usize;
            // Create a table instance for it.
            let table = NamedTable::from_reader(&entry.tag, reader, offset, size)?;
            // Tell it to get in the van
            woff_tables.insert(entry.tag, table);
        }

        // Get the XML metadata if present
        let woff_meta = if woff_hdr.metaLength > 0 {
            Some(TableUnspecified::from_reader(
                reader,
                woff_hdr.metaOffset as u64,
                woff_hdr.metaOrigLength as usize,
            )?)
        } else {
            None
        };

        // Get the private data if present
        let woff_private = if woff_hdr.privLength > 0 {
            Some(TableUnspecified::from_reader(
                reader,
                woff_hdr.privOffset as u64,
                woff_hdr.privLength as usize,
            )?)
        } else {
            None
        };

        // Assemble the five lions as shown to construct your robot.
        Ok(WoffFont {
            header: woff_hdr,
            directory: woff_dir,
            tables: woff_tables,
            meta: woff_meta,
            private: woff_private,
        })
    }

    /// Writes out this font file.
    fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        // First the header.
        self.header.write(destination)?;
        // Then the directory.
        self.directory.write(destination)?;
        // Then the tables, in physical order.
        for entry in self.directory.physical_order().iter() {
            // TBD - current-offset sanity-checking:
            //  1. Did we go backwards (despite the request for physical_order)?
            //  2. Did we go more than 3 bytes forward (file has excess padding)?
            // destination.seek(SeekFrom::Start(entry.offset as u64))?;
            // Note that dest stream is not seekable.
            // Write out the (real and fake) tables.
            self.tables[&entry.tag].write(destination)?;
        }
        // Then the XML meta, if present.
        match &self.meta {
            Some(woff_meta) => {
                woff_meta.write(destination)?;
            }
            None => (),
        };
        // Then the private data, if present.
        match &self.private {
            Some(woff_private) => {
                woff_private.write(destination)?;
            }
            None => (),
        };
        // If we made it here, it all worked.
        Ok(())
    }

    /// Add an empty C2PA table in this font, at the end, so we don't have to
    /// re-position any existing tables.
    fn append_empty_c2pa_table(&mut self) -> Result<()> {
        // Create the empty table
        let c2pa_table = TableC2PA::new(None, None);
        // Size of the empty table in the font file
        let empty_table_size = size_of::<TableC2PARaw>() as u32;
        // Offset just past the last valid byte of font table data. This should
        // point to pad bytes, XML data, or private data, but nothing else.
        let existing_table_data_limit = match self.directory.physical_order().last() {
            Some(last_phys_entry) => last_phys_entry.offset + last_phys_entry.compLength,
            None => (size_of::<WoffHeader>() + size_of::<WoffTableDirEntry>()) as u32,
        };
        // Padding needed before the new table.
        let pre_padding = (4 - (existing_table_data_limit & 3)) & 3;
        // Padded needed after.
        let post_padding =
            (4 - ((existing_table_data_limit + pre_padding + empty_table_size) & 3)) & 3;
        // And a directory entry for it. The easiest approach is to add the table
        // to the end of the font; for one thing, resizing it is much simpler,
        // since we'll just need to change some size fields (and not re-flow
        // other tables.
        let c2pa_entry = WoffTableDirEntry {
            tag: C2PA_TABLE_TAG,
            offset: existing_table_data_limit + pre_padding,
            compLength: empty_table_size,
            origLength: empty_table_size,
            origChecksum: c2pa_table.checksum().0,
        };
        // Store the new directory entry & table.
        self.directory.entries.push(c2pa_entry);
        self.tables
            .insert(C2PA_TABLE_TAG, NamedTable::C2PA(c2pa_table));
        // Count the table, grow the total size, grow, the "SFNT size"
        self.header.numTables += 1;
        // (TBD compression - conflating comp/uncomp sizes here.)
        // (TBD philosophy - better to just re-compute these from scratch, yeah?)
        self.header.length =
            existing_table_data_limit + pre_padding + c2pa_entry.compLength + post_padding;
        // Bump the XML meta block ahead, if present.
        if self.header.metaOffset > 0 {
            self.header.metaOffset += c2pa_entry.compLength + post_padding;
        }
        // Bump the private block ahead, if present.
        if self.header.privOffset > 0 {
            self.header.privOffset += c2pa_entry.compLength + post_padding;
        }
        // Re-reckon the size of this font as an SFNT:
        //   First, the header, then the directory, and finally the tables
        self.header.totalSfntSize = size_of::<SfntHeader>() as u32;
        self.header.totalSfntSize +=
            (size_of::<SfntDirectoryEntry>() * self.header.numTables as usize) as u32;
        self.header.totalSfntSize += self
            .directory
            .entries
            .iter()
            .map(|e| (e.origLength + 3) & !3)
            .sum::<u32>();
        // Success at last
        Ok(())
    }

    fn _resize_c2pa_table(&mut self, _desired_new_size: u32) -> Result<()> {
        // 1. If no table present -- create one?
        // 2. With a table in hand:
        //    a. Resize the table
        //    b. Change the compSize/origSize in the directory
        //    c. Update self.header.length and .totalSfntSize
        todo!("When the content changes, we'll need to be invoked.")
    }
}

/// WOFF 1.0 file header, from the WOFF spec.
///
/// TBD: Should this be treated as a "Table", perhaps with a magic tag value that
/// always sorts first, for operational reasons?
#[derive(Copy, Clone, Debug)]
#[repr(C, packed(1))] // As defined by the WOFF spec. (though we don't as yet directly support exotics like FIXED)
#[allow(non_snake_case)] // As named by the WOFF spec.
struct WoffHeader {
    signature: u32,
    flavor: u32,
    length: u32,
    numTables: u16,
    reserved: u16,
    totalSfntSize: u32,
    majorVersion: u16,
    minorVersion: u16,
    metaOffset: u32,
    metaLength: u32,
    metaOrigLength: u32,
    privOffset: u32,
    privLength: u32,
}

impl WoffHeader {
    /// Reads a new instance from the given source.
    pub(crate) fn from_reader<T: Read + Seek + ?Sized>(reader: &mut T) -> Result<Self> {
        Ok(Self {
            signature: reader.read_u32::<BigEndian>()?,
            flavor: reader.read_u32::<BigEndian>()?,
            length: reader.read_u32::<BigEndian>()?,
            numTables: reader.read_u16::<BigEndian>()?,
            reserved: reader.read_u16::<BigEndian>()?,
            totalSfntSize: reader.read_u32::<BigEndian>()?,
            majorVersion: reader.read_u16::<BigEndian>()?,
            minorVersion: reader.read_u16::<BigEndian>()?,
            metaOffset: reader.read_u32::<BigEndian>()?,
            metaLength: reader.read_u32::<BigEndian>()?,
            metaOrigLength: reader.read_u32::<BigEndian>()?,
            privOffset: reader.read_u32::<BigEndian>()?,
            privLength: reader.read_u32::<BigEndian>()?,
        })
    }

    /// Serializes this instance to the given writer.
    fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        destination.write_u32::<BigEndian>(self.signature)?;
        destination.write_u32::<BigEndian>(self.flavor)?;
        destination.write_u32::<BigEndian>(self.length)?;
        destination.write_u16::<BigEndian>(self.numTables)?;
        destination.write_u16::<BigEndian>(self.reserved)?;
        destination.write_u32::<BigEndian>(self.totalSfntSize)?;
        destination.write_u16::<BigEndian>(self.majorVersion)?;
        destination.write_u16::<BigEndian>(self.minorVersion)?;
        destination.write_u32::<BigEndian>(self.metaOffset)?;
        destination.write_u32::<BigEndian>(self.metaLength)?;
        destination.write_u32::<BigEndian>(self.metaOrigLength)?;
        destination.write_u32::<BigEndian>(self.privOffset)?;
        destination.write_u32::<BigEndian>(self.privLength)?;
        Ok(())
    }
}

impl Default for WoffHeader {
    fn default() -> Self {
        Self {
            signature: Magic::Woff as u32,
            flavor: 0,
            length: 0,
            numTables: 0,
            reserved: 0,
            totalSfntSize: 44,
            majorVersion: 1,
            minorVersion: 0,
            metaOffset: 0,
            metaLength: 0,
            metaOrigLength: 0,
            privOffset: 0,
            privLength: 0,
        }
    }
}

/// WOFF 1.0 Table Directory Entry, from the WOFF spec.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed(1))] // As defined by the WOFF spec. (though we don't as yet directly support exotics like FIXED)
#[allow(non_snake_case)] // As named by the WOFF spec.
struct WoffTableDirEntry {
    tag: SfntTag,
    offset: u32,
    compLength: u32,
    origLength: u32,
    origChecksum: u32,
}
impl WoffTableDirEntry {
    /// Reads a new instance from the given source.
    pub(crate) fn from_reader<T: Read + Seek + ?Sized>(reader: &mut T) -> Result<Self> {
        Ok(Self {
            tag: SfntTag::from_reader(reader)?,
            offset: reader.read_u32::<BigEndian>()?,
            compLength: reader.read_u32::<BigEndian>()?,
            origLength: reader.read_u32::<BigEndian>()?,
            origChecksum: reader.read_u32::<BigEndian>()?,
        })
    }

    /// Serialize this directory entry to the given writer.
    fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        self.tag.write(destination)?;
        destination.write_u32::<BigEndian>(self.offset)?;
        destination.write_u32::<BigEndian>(self.compLength)?;
        destination.write_u32::<BigEndian>(self.origLength)?;
        destination.write_u32::<BigEndian>(self.origChecksum)?;
        Ok(())
    }
}

/// WOFF 1.0 Directory is just an array of entries. Undoubtedly there exists a
/// more-oxidized way of just using Vec directly for this...
#[derive(Debug)]
struct WoffDirectory {
    entries: Vec<WoffTableDirEntry>,
}
impl WoffDirectory {
    /// Creates a new, empty, instance.
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            entries: Vec::new(),
        })
    }

    /// Reads a new instance from the given source, reading the specified
    /// number of entries.
    pub(crate) fn from_reader<T: Read + Seek + ?Sized>(
        reader: &mut T,
        entry_count: usize,
    ) -> Result<Self> {
        let mut the_directory = WoffDirectory::new()?;
        for _entry in 0..entry_count {
            the_directory
                .entries
                .push(WoffTableDirEntry::from_reader(reader)?);
        }
        Ok(the_directory)
    }

    /// Serialize this directory entry to the given writer.
    fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        for entry in self.entries.iter() {
            entry.write(destination)?;
        }
        Ok(())
    }

    /// Returns an array which contains the indices of this directory's entries,
    /// arranged in their physical (offset+size) order.
    fn physical_order(&self) -> Vec<WoffTableDirEntry> {
        let mut physically_ordered_entries = self.entries.clone();
        physically_ordered_entries.sort_by_key(|e| e.offset);
        physically_ordered_entries
    }
}

/// Identifies types of regions within a font file. Chunks with lesser enum
/// values precede those with greater enum values; order within a given group
/// of chunks (such as a series of `Table` chunks) must be preserved by some
/// other mechanism.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ChunkType {
    /// Whole-container header.
    Header,
    /// Table directory entry or entries.
    Directory,
    /// Table data
    Table,
    /// WOFF metadata
    WoffMeta,
    /// WOFF private data
    WoffPrivate,
}

/// Represents regions within a font file that may be of interest when it
/// comes to hashing data for C2PA.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ChunkPosition {
    /// Offset to the start of the chunk
    pub offset: u64,
    /// Length of the chunk
    pub length: u32,
    /// Tag of the chunk
    pub name: [u8; 4],
    /// Type of chunk
    pub chunk_type: ChunkType,
}

//impl PartialEq for ChunkPosition {
//    fn eq(&self, other: &Self) -> bool {
//        self.offset == other.offset
//            && self.length == other.length
//            && self.name == other.name
//            && self.chunk_type == other.chunk_type
//    }
//}

/// Custom trait for reading chunks of data from a scalable font (SFNT).
pub(crate) trait ChunkReader {
    type Error;
    /// Gets a collection of positions of chunks within the font, used to
    /// omit from hashing.
    fn get_chunk_positions<T: Read + Seek + ?Sized>(
        &self,
        reader: &mut T,
    ) -> core::result::Result<Vec<ChunkPosition>, Self::Error>;
}

/// Reads in chunks for a WOFF 1.0 file
impl ChunkReader for WoffIO {
    type Error = crate::error::Error;

    fn get_chunk_positions<T: Read + Seek + ?Sized>(
        &self,
        reader: &mut T,
    ) -> core::result::Result<Vec<ChunkPosition>, Self::Error> {
        reader.rewind()?;
        // WOFFHeader
        let woff_hdr = WoffHeader::from_reader(reader)?;
        // Verify the font has a valid version in it before assuming the rest is
        // valid (NOTE: we don't actually do anything with it, just as a safety
        // check).
        //
        // TBD - Push this into WoffHeader::from_reader
        let _font_magic: Magic =
            <u32 as std::convert::TryInto<Magic>>::try_into(woff_hdr.signature)
                .map_err(|_err| Error::UnsupportedFontError)?;
        // Add the position of the header.
        let mut positions: Vec<ChunkPosition> = Vec::new();
        positions.push(ChunkPosition {
            offset: 0,
            length: size_of::<WoffHeader>() as u32,
            name: WOFF_HEADER_CHUNK_NAME.data,
            chunk_type: ChunkType::Header,
        });

        // Advance to the start of the table entries
        reader.seek(SeekFrom::Start(size_of::<WoffHeader>() as u64))?;

        // Read in the directory, and add its chunk
        let woff_dir = WoffDirectory::from_reader(reader, woff_hdr.numTables as usize)?;
        positions.push(ChunkPosition {
            offset: size_of::<WoffHeader>() as u64,
            length: woff_hdr.numTables as u32 * size_of::<WoffTableDirEntry>() as u32,
            name: WOFF_DIRECTORY_CHUNK_NAME.data,
            chunk_type: ChunkType::Directory,
        });

        // Add a chunk for each table, in directory order
        for entry in woff_dir.physical_order().iter() {
            positions.push(ChunkPosition {
                offset: entry.offset as u64,
                length: entry.origLength, // TBD compression support
                name: entry.tag.data,
                chunk_type: ChunkType::Table,
            });
        }

        // Check for XML metadata trailer
        if woff_hdr.metaLength > 0 {
            positions.push(ChunkPosition {
                offset: woff_hdr.metaOffset as u64,
                length: woff_hdr.metaLength,
                name: WOFF_METADATA_CHUNK_NAME.data,
                chunk_type: ChunkType::WoffMeta,
            });
        }

        // Check for private data trailer
        if woff_hdr.privLength > 0 {
            positions.push(ChunkPosition {
                offset: woff_hdr.privOffset as u64,
                length: woff_hdr.privLength,
                name: WOFF_PRIVATE_CHUNK_NAME.data,
                chunk_type: ChunkType::WoffPrivate,
            });
        }

        // Do not iterate if the log level is not set to at least trace
        if log::max_level().cmp(&log::LevelFilter::Trace).is_ge() {
            for position in positions.iter().as_ref() {
                trace!("Position for C2PA in font: {:?}", &position);
            }
        }

        Ok(positions)
    }
}

/// Adds C2PA manifest store data to a font file (specified by path).
fn add_c2pa_to_font(font_path: &Path, manifest_store_data: &[u8]) -> Result<()> {
    process_file_with_streams(font_path, move |input_stream, temp_file| {
        // Add the C2PA data to the temp file
        add_c2pa_to_stream(input_stream, temp_file.get_mut_file(), manifest_store_data)
    })
}

/// Adds C2PA manifest store data to a font stream, writing the result to the
/// destination stream.
fn add_c2pa_to_stream<TSource, TDest>(
    source: &mut TSource,
    destination: &mut TDest,
    manifest_store_data: &[u8],
) -> Result<()>
where
    TSource: Read + Seek + ?Sized,
    TDest: Write + ?Sized,
{
    source.rewind()?;
    let mut font = WoffFont::from_reader(source).map_err(|_| Error::FontLoadError)?;
    // Install the provide active_manifest_uri in this font's C2PA table, adding
    // that table if needed.
    match font.tables.get_mut(&C2PA_TABLE_TAG) {
        // If there isn't one, create it.
        None => {
            font.tables.insert(
                C2PA_TABLE_TAG,
                NamedTable::C2PA(TableC2PA::new(None, Some(manifest_store_data.to_vec()))),
            );
        }
        Some(NamedTable::C2PA(c2pa)) => c2pa.manifest_store = Some(manifest_store_data.to_vec()),
        // Yikes! Non-C2PA table with C2PA tag!
        Some(_) => {
            return Err(Error::FontLoadError);
        }
    };
    font.write(destination).map_err(|_| Error::FontSaveError)?;
    Ok(())
}

/// Adds the manifest URI reference to the font at the given path.
#[allow(dead_code)]
fn add_reference_to_font(font_path: &Path, manifest_uri: &str) -> Result<()> {
    process_file_with_streams(font_path, move |input_stream, temp_file| {
        // Write the manifest URI to the stream
        add_reference_to_stream(input_stream, temp_file.get_mut_file(), manifest_uri)
    })
}

/// Adds the specified reference URI to the source data, writing the result to
/// the destination stream.
fn add_reference_to_stream<TSource, TDest>(
    source: &mut TSource,
    destination: &mut TDest,
    manifest_uri: &str,
) -> Result<()>
where
    TSource: Read + Seek + ?Sized,
    TDest: Write + ?Sized,
{
    source.rewind()?;
    let mut font = WoffFont::from_reader(source).map_err(|_| Error::FontLoadError)?;
    // Install the provide active_manifest_uri in this font's C2PA table, adding
    // that table if needed.
    match font.tables.get_mut(&C2PA_TABLE_TAG) {
        // If there isn't one, create it.
        None => {
            font.tables.insert(
                C2PA_TABLE_TAG,
                NamedTable::C2PA(TableC2PA::new(Some(manifest_uri.to_string()), None)),
            );
        }
        // If there is, replace its `active_manifest_uri` value with the
        // provided one.
        Some(NamedTable::C2PA(c2pa)) => c2pa.active_manifest_uri = Some(manifest_uri.to_string()),
        // Yikes! Non-C2PA table with C2PA tag!
        Some(_) => {
            return Err(Error::FontLoadError);
        }
    };
    font.write(destination).map_err(|_| Error::FontSaveError)?;
    Ok(())
}

/// Adds the required chunks to the source stream for supporting C2PA, if the
/// chunks are already present nothing is done.  Writes the resulting data to
/// the destination stream.
///
/// # Remarks
/// Neither streams are rewound before and/or after the operation, so it is up
/// to the caller.
fn add_required_chunks_to_stream<TReader, TWriter>(
    input_stream: &mut TReader,
    output_stream: &mut TWriter,
) -> Result<()>
where
    TReader: Read + Seek + ?Sized,
    TWriter: Read + Seek + ?Sized + Write,
{
    // Read the font from the input stream
    let mut font = WoffFont::from_reader(input_stream).map_err(|_| Error::FontLoadError)?;
    // If the C2PA table does not exist...
    if font.tables.get(&C2PA_TABLE_TAG).is_none() {
        // ...install an empty one.
        font.append_empty_c2pa_table()?;
    }
    // Write the font to the output stream
    font.write(output_stream)
        .map_err(|_| Error::FontSaveError)?;
    Ok(())
}

/// Opens a BufReader for the given file path
fn open_bufreader_for_file(file_path: &Path) -> Result<BufReader<File>> {
    let file = File::open(file_path)?;
    Ok(BufReader::new(file))
}

/// Processes a font file (specified by path) by stream with the given callback.
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

/// Reads the C2PA manifest store reference from the font file (specified by
/// path).
#[allow(dead_code)]
fn read_reference_from_font(font_path: &Path) -> Result<Option<String>> {
    // open the font source
    let mut font_stream = open_bufreader_for_file(font_path)?;
    read_reference_from_stream(&mut font_stream)
}

/// Reads the C2PA manifest store reference from the stream.
#[allow(dead_code)]
fn read_reference_from_stream<TSource>(source: &mut TSource) -> Result<Option<String>>
where
    TSource: Read + Seek + ?Sized,
{
    match read_c2pa_from_stream(source) {
        Ok(c2pa_data) => Ok(c2pa_data.active_manifest_uri),
        Err(Error::JumbfNotFound) => Ok(None),
        Err(_) => Err(Error::DeserializationError),
    }
}

/// Remove the `C2PA` font table from the font file (specified by path).
fn remove_c2pa_from_font(font_path: &Path) -> Result<()> {
    process_file_with_streams(font_path, move |input_stream, temp_file| {
        // Remove the C2PA manifest store from the stream
        remove_c2pa_from_stream(input_stream, temp_file.get_mut_file())
    })
}

/// Remove the `C2PA` font table from the font data stream, writing to the
/// destination.
fn remove_c2pa_from_stream<TSource, TDest>(
    source: &mut TSource,
    destination: &mut TDest,
) -> Result<()>
where
    TSource: Read + Seek + ?Sized,
    TDest: Write + ?Sized,
{
    source.rewind()?;
    // Load the font from the stream
    let mut font = WoffFont::from_reader(source).map_err(|_| Error::FontLoadError)?;
    // Remove the table from the collection
    font.tables.remove(&C2PA_TABLE_TAG);
    // And write it to the destination stream
    font.write(destination).map_err(|_| Error::FontSaveError)?;

    Ok(())
}

/// Removes the reference to the active manifest from the source stream, writing
/// to the destination.  Returns an optional active manifest URI reference, if
/// there was one.
#[allow(dead_code)]
fn remove_reference_from_stream<TSource, TDest>(
    source: &mut TSource,
    destination: &mut TDest,
) -> Result<Option<String>>
where
    TSource: Read + Seek + ?Sized,
    TDest: Write + ?Sized,
{
    source.rewind()?;
    let mut font = WoffFont::from_reader(source).map_err(|_| Error::FontLoadError)?;
    let old_manifest_uri_maybe = match font.tables.get_mut(&C2PA_TABLE_TAG) {
        // If there isn't one, how pleasant, there will be so much less to do.
        None => None,
        // If there is, and it has Some `active_manifest_uri`, then mutate that
        // to None, and return the former value.
        Some(NamedTable::C2PA(c2pa)) => {
            if c2pa.active_manifest_uri.is_none() {
                None
            } else {
                // TBD this cannot really be the idiomatic way, can it?
                let old_manifest_uri = c2pa.active_manifest_uri.clone();
                c2pa.active_manifest_uri = None;
                old_manifest_uri
            }
        }
        // Yikes! Non-C2PA table with C2PA tag!
        Some(_) => {
            return Err(Error::FontLoadError);
        }
    };
    font.write(destination).map_err(|_| Error::FontSaveError)?;
    Ok(old_manifest_uri_maybe)
}

/// Gets a collection of positions of hash objects from the reader which are to
/// be excluded from the hashing, used to omit from hashing.
fn get_object_locations_from_stream<T>(
    woff_io: &WoffIO,
    reader: &mut T,
) -> Result<Vec<HashObjectPositions>>
where
    T: Read + Seek + ?Sized,
{
    // The SDK doesn't necessarily promise the input stream is rewound, so do so
    // now to make sure we can parse the font.
    reader.rewind()?;
    // We must take into account a font that may not have a C2PA table in it at
    // this point, adding any required chunks needed for C2PA to work correctly.
    let output_vec: Vec<u8> = Vec::new();
    let mut output_stream = Cursor::new(output_vec);
    add_required_chunks_to_stream(reader, &mut output_stream)?;
    output_stream.rewind()?;

    // Build up the positions we will hand back to the caller
    let mut positions: Vec<HashObjectPositions> = Vec::new();

    // Which will be built up from the different chunks from the file
    let chunk_positions = woff_io.get_chunk_positions(&mut output_stream)?;
    for chunk_position in chunk_positions {
        let mut position_objs = match chunk_position.chunk_type {
            // The table directory, other than the table records array will be
            // added as "other"
            ChunkType::Header => vec![HashObjectPositions {
                offset: chunk_position.offset as usize,
                length: chunk_position.length as usize,
                htype: HashBlockObjectType::Other,
            }],
            // For the table record entries, we will specialize the C2PA table
            // record and all others will be added as is
            ChunkType::Directory => {
                if chunk_position.name == C2PA_TABLE_TAG.data {
                    vec![HashObjectPositions {
                        offset: chunk_position.offset as usize,
                        length: chunk_position.length as usize,
                        htype: HashBlockObjectType::Cai,
                    }]
                } else {
                    vec![HashObjectPositions {
                        offset: chunk_position.offset as usize,
                        length: chunk_position.length as usize,
                        htype: HashBlockObjectType::Other,
                    }]
                }
            }
            // Similarly for the actual table data, we need to specialize C2PA
            // and in this case the `head` table as well, to ignore the checksum
            // adjustment.
            //
            // ("Other" data gets treated the same as an uninteresting table.)
            ChunkType::Table | ChunkType::WoffMeta | ChunkType::WoffPrivate => {
                let mut table_positions = Vec::<HashObjectPositions>::new();
                // We must split out the head table to ignore the checksum
                // adjustment, because it changes after the C2PA table is
                // written to the font
                if chunk_position.name == HEAD_TABLE_TAG.data {
                    let head_offset = &chunk_position.offset;
                    let head_length = &chunk_position.length;
                    // Include the major/minor/revision version numbers
                    table_positions.push(HashObjectPositions {
                        offset: *head_offset as usize,
                        length: 8,
                        htype: HashBlockObjectType::Other,
                    });
                    // Indicate the checksumAdjustment value as CAI
                    table_positions.push(HashObjectPositions {
                        offset: (head_offset + 8) as usize,
                        length: 4,
                        htype: HashBlockObjectType::Cai,
                    });
                    // And the remainder of the table as other
                    table_positions.push(HashObjectPositions {
                        offset: (head_offset + 12) as usize,
                        length: (head_length - 12) as usize,
                        htype: HashBlockObjectType::Other,
                    });
                } else if chunk_position.name == C2PA_TABLE_TAG.data {
                    table_positions.push(HashObjectPositions {
                        offset: chunk_position.offset as usize,
                        length: chunk_position.length as usize,
                        htype: HashBlockObjectType::Cai,
                    });
                } else {
                    table_positions.push(HashObjectPositions {
                        offset: chunk_position.offset as usize,
                        length: chunk_position.length as usize,
                        htype: HashBlockObjectType::Other,
                    });
                }
                table_positions
            }
        };
        positions.append(&mut position_objs);
    }
    Ok(positions)
}

/// Reads the `C2PA` font table from the data stream, returning the `C2PA` font
/// table data
fn read_c2pa_from_stream<T: Read + Seek + ?Sized>(reader: &mut T) -> Result<TableC2PA> {
    let woff = WoffFont::from_reader(reader).map_err(|_| Error::FontLoadError)?;
    let c2pa_table: Option<TableC2PA> = match woff.tables.get(&C2PA_TABLE_TAG) {
        None => None,
        // If there is, replace its `manifest_store` value with the
        // provided one.
        Some(NamedTable::C2PA(c2pa)) => Some(c2pa.clone()),
        // Yikes! Non-C2PA table with C2PA tag!
        Some(_) => {
            return Err(Error::FontLoadError);
        }
    };
    c2pa_table.ok_or(Error::JumbfNotFound)
}

/// Main WOFF IO feature.
pub(crate) struct WoffIO {}

impl WoffIO {
    #[allow(dead_code)]
    pub(crate) fn default_document_id() -> String {
        format!("fontsoftware:did:{}", Uuid::new_v4())
    }

    #[allow(dead_code)]
    pub(crate) fn default_instance_id() -> String {
        format!("fontsoftware:iid:{}", Uuid::new_v4())
    }
}

/// WOFF implementation of the CAILoader trait.
impl CAIReader for WoffIO {
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
        match read_reference_from_stream(asset_reader) {
            Ok(reference) => reference,
            Err(_) => None,
        }
    }
}

/// WOFF/TTF implementations for the CAIWriter trait.
impl CAIWriter for WoffIO {
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
        get_object_locations_from_stream(self, input_stream)
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        remove_c2pa_from_stream(input_stream, output_stream)
    }
}

/// WOFF/TTF implementations for the AssetIO trait.
impl AssetIO for WoffIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        WoffIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(WoffIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(WoffIO::new(asset_type)))
    }

    fn remote_ref_writer_ref(&self) -> Option<&dyn RemoteRefEmbed> {
        Some(self)
    }

    fn supported_types(&self) -> &[&str] {
        // Supported extension and mime-types
        &[
            "application/font-woff",
            "application/x-font-woff",
            "font/woff",
            "woff",
        ]
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
        get_object_locations_from_stream(self, &mut buf_reader)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        remove_c2pa_from_font(asset_path)
    }

    fn asset_box_hash_ref(&self) -> Option<&dyn AssetBoxHash> {
        Some(self)
    }
}

// Implementation for the asset box hash trait for general box hash support
impl AssetBoxHash for WoffIO {
    fn get_box_map(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<BoxMap>> {
        // Get the chunk positions
        let positions = self.get_chunk_positions(input_stream)?;
        // Create a box map vector to map the chunk positions to
        let mut box_maps = Vec::<BoxMap>::new();
        for position in positions {
            let box_map = BoxMap {
                names: vec![format!("{:?}", position.chunk_type)],
                alg: None,
                hash: ByteBuf::from(Vec::new()),
                pad: ByteBuf::from(Vec::new()),
                range_start: position.offset as usize,
                range_len: position.length as usize,
            };
            box_maps.push(box_map);
        }
        Ok(box_maps)
    }
}

impl RemoteRefEmbed for WoffIO {
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
        reader: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        embed_ref: RemoteRefEmbedType,
    ) -> Result<()> {
        match embed_ref {
            crate::asset_io::RemoteRefEmbedType::Xmp(manifest_uri) => {
                #[cfg(feature = "xmp_write")]
                {
                    font_xmp_support::add_reference_as_xmp_to_stream(
                        reader,
                        output_stream,
                        &manifest_uri,
                    )
                }
                #[cfg(not(feature = "xmp_write"))]
                {
                    add_reference_to_stream(reader, output_stream, &manifest_uri)
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

    use claims::*;
    use tempfile::tempdir;

    use super::*;
    use crate::utils::test::{fixture_path, temp_dir_path};

    #[ignore] // Need WOFF 1 test fixture
    #[test]
    #[cfg(not(feature = "xmp_write"))]
    // Key to cryptic test comments.
    //
    //   IIP - Invalid/Ignored/Passthrough
    //         This field's value is bogus, possibly illegal, but it is expected
    //         that this code will neither detect nor modify it. Examples are
    //         "reserved" bytes in font tables which are supposed to be zero,
    //         major and/or minor version fields that look pretty in the spec
    //         but never have any practical effect in the real world, etc.
    /// Verifies the adding of a remote C2PA manifest reference works as
    /// expected.
    fn add_c2pa_ref() {
        let c2pa_data = "test data";

        // Need WOFF 1 test fixture
        let source = fixture_path("font.woff");

        // Create a temporary output for the file
        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "test.woff");

        // Copy the source to the output
        std::fs::copy(source, &output).unwrap();

        // Create our WoffIO asset handler for testing
        let woff_io = WoffIO {};

        let expected_manifest_uri = "https://test/ref";

        woff_io
            .embed_reference(
                &output,
                crate::asset_io::RemoteRefEmbedType::Xmp(expected_manifest_uri.to_owned()),
            )
            .unwrap();
        // Save the C2PA manifest store to the file
        woff_io
            .save_cai_store(&output, c2pa_data.as_bytes())
            .unwrap();
        // Loading it back from the same output file
        let loaded_c2pa = woff_io.read_cai_store(&output).unwrap();
        // Which should work out to be the same in the end
        assert_eq!(&loaded_c2pa, c2pa_data.as_bytes());

        match read_reference_from_font(&output) {
            Ok(Some(manifest_uri)) => assert_eq!(expected_manifest_uri, manifest_uri),
            _ => panic!("Expected to read a reference from the font file"),
        };
    }

    /// Verifies the adding of a remote C2PA manifest reference as XMP works as
    /// expected.
    #[ignore] // Need WOFF 1 test fixture
    #[test]
    #[cfg(feature = "xmp_write")]
    fn add_c2pa_ref() {
        use std::str::FromStr;

        use xmp_toolkit::XmpMeta;

        let c2pa_data = "test data";

        // Load the basic WOFF 1 test fixture
        let source = fixture_path("font.woff");

        // Create a temporary output for the file
        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "test.woff");

        // Copy the source to the output
        std::fs::copy(source, &output).unwrap();

        // Create our WoffIO asset handler for testing
        let woff_io = WoffIO {};

        let expected_manifest_uri = "https://test/ref";

        woff_io
            .embed_reference(
                &output,
                crate::asset_io::RemoteRefEmbedType::Xmp(expected_manifest_uri.to_owned()),
            )
            .unwrap();
        // Save the C2PA manifest store to the file
        woff_io
            .save_cai_store(&output, c2pa_data.as_bytes())
            .unwrap();
        // Loading it back from the same output file
        let loaded_c2pa = woff_io.read_cai_store(&output).unwrap();
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

    #[test]
    /// Verify when reading the object locations for hashing, we get zero
    /// positions when the font contains zero tables
    fn get_chunk_positions_without_any_tables() {
        let font_data = vec![
            0x77, 0x4f, 0x46, 0x46, // wOFF
            0x72, 0x73, 0x74, 0x75, // flavor (IIP)
            0x00, 0x00, 0x00, 0x2c, // length (44)
            0x00, 0x00, 0x00, 0x00, // numTables (0) / reserved (0)
            0x00, 0x00, 0x00, 0x0c, // totalSfntSize (12 for header only)
            0x82, 0x83, 0x84, 0x85, // majorVersion / minorVersion (IIP)
            0x00, 0x00, 0x00, 0x00, // metaOffset (0)
            0x00, 0x00, 0x00, 0x00, // metaLength (0)
            0x00, 0x00, 0x00, 0x00, // metaOrigLength (0)
            0x00, 0x00, 0x00, 0x00, // privOffset (0)
            0x00, 0x00, 0x00, 0x00, // privLength (0)
        ];
        let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
        let woff_io = WoffIO {};
        let positions = woff_io.get_chunk_positions(&mut font_stream).unwrap();
        // Should have one position reported for the table directory itself
        assert_eq!(2, positions.len());
        assert_eq!(0, positions.first().unwrap().offset);
        assert_eq!(
            size_of::<WoffHeader>(),
            positions.first().unwrap().length as usize
        );
        assert_eq!(ChunkType::Header, positions.first().unwrap().chunk_type);
        assert_eq!(
            size_of::<WoffHeader>(),
            positions.get(1).unwrap().offset as usize
        );
        assert_eq!(0, positions.get(1).unwrap().length as usize);
        assert_eq!(ChunkType::Directory, positions.get(1).unwrap().chunk_type);
    }

    #[test]
    /// Verify when reading the object locations for hashing, we get zero
    /// positions when the font does not contain a C2PA font table
    fn get_chunk_positions_without_c2pa_table() {
        let font_data = vec![
            // WOFFHeader
            0x77, 0x4f, 0x46, 0x46, // wOFF
            0x72, 0x73, 0x74, 0x75, // flavor (IIP)
            0x00, 0x00, 0x00, 0x54, // length (84)
            0x00, 0x01, 0x00, 0x00, // numTables (1) / reserved (0)
            0x00, 0x00, 0x00, 0x30, // totalSfntSize (48 = 12 + 16 + 20)
            0x82, 0x83, 0x84, 0x85, // majorVersion / minorVersion (IIP)
            0x00, 0x00, 0x00, 0x00, // metaOffset (0)
            0x00, 0x00, 0x00, 0x00, // metaLength (0)
            0x00, 0x00, 0x00, 0x00, // metaOrigLength (0)
            0x00, 0x00, 0x00, 0x00, // privOffset (0)
            0x00, 0x00, 0x00, 0x00, // privLength (0)
            // WOFFTableDirectory
            0x67, 0x61, 0x71, 0x66, // garf
            0x00, 0x00, 0x00, 0x40, //   offset (64)
            0x00, 0x00, 0x00, 0x07, //   compLength (7)
            0x00, 0x00, 0x00, 0x07, //   origLength (7)
            0x12, 0x34, 0x56, 0x78, //   origChecksum (0x12345678)
            // garf Table
            0x6c, 0x61, 0x73, 0x61, // Major / Minor versions
            0x67, 0x6e, 0x61,
        ];
        let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
        let woff_io = WoffIO {};
        let positions = woff_io.get_chunk_positions(&mut font_stream).unwrap();

        // Should have 3 positions reported for the header, directory, and table.
        // record, and the table data
        assert_eq!(3, positions.len());

        let hdr_chunk = positions.first().unwrap();
        assert_eq!(ChunkType::Header, hdr_chunk.chunk_type);
        assert_eq!(0, hdr_chunk.offset);
        assert_eq!(size_of::<WoffHeader>(), hdr_chunk.length as usize);

        let dir_chunk = positions.get(1).unwrap();
        assert_eq!(ChunkType::Directory, dir_chunk.chunk_type);
        assert_eq!(size_of::<WoffHeader>(), dir_chunk.offset as usize);
        assert_eq!(size_of::<WoffTableDirEntry>(), dir_chunk.length as usize);

        let tbl_chunk = positions.get(2).unwrap();
        assert_eq!(ChunkType::Table, tbl_chunk.chunk_type);
        assert_eq!(
            size_of::<WoffHeader>() + size_of::<WoffTableDirEntry>(),
            tbl_chunk.offset as usize
        );
        assert_eq!(7, tbl_chunk.length);
    }

    #[ignore] // Need WOFF 1 test fixture
    #[test]
    fn get_object_locations() {
        // Load the basic WOFF 1 test fixture - C2PA-XYZ - Select WOFF 1 test fixture
        let source = fixture_path("font.woff");

        // Create a temporary output for the file
        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "test.woff");

        // Copy the source to the output
        std::fs::copy(source, &output).unwrap();

        // Create our WoffIO asset handler for testing
        let woff_io = WoffIO {};
        // The font has 11 records, 11 tables, 1 table directory
        // but the head table will expand from 1 to 3 positions bringing it to 25
        // And then the required C2PA chunks will be added, bringing it to 27
        let object_positions = woff_io.get_object_locations(&output).unwrap();
        assert_eq!(27, object_positions.len());
    }

    #[test]
    /// Verify the C2PA table data can be read from a font stream
    fn reads_c2pa_table_from_stream() {
        let font_data = vec![
            // WOFFHeader
            0x77, 0x4f, 0x46, 0x46, // wOFF
            0x72, 0x73, 0x74, 0x75, // flavor (IIP)
            0x00, 0x00, 0x00, 0x54, // length (84)
            0x00, 0x01, 0x00, 0x00, // numTables (1) / reserved (0)
            0x00, 0x00, 0x00, 0x30, // totalSfntSize (48 = 12 + 16 + 20)
            0x82, 0x83, 0x84, 0x85, // majorVersion / minorVersion (IIP)
            0x00, 0x00, 0x00, 0x00, // metaOffset (0)
            0x00, 0x00, 0x00, 0x00, // metaLength (0)
            0x00, 0x00, 0x00, 0x00, // metaOrigLength (0)
            0x00, 0x00, 0x00, 0x00, // privOffset (0)
            0x00, 0x00, 0x00, 0x00, // privLength (0)
            // WOFFTableDirectory
            0x43, 0x32, 0x50, 0x41, // C2PA
            0x00, 0x00, 0x00, 0x40, //   offset (64)
            0x00, 0x00, 0x00, 0x25, //   compLength (37)
            0x00, 0x00, 0x00, 0x25, //   origLength (37)
            0x12, 0x34, 0x56, 0x78, //   origChecksum (0x12345678)
            // C2PA Table
            0x00, 0x01, 0x00, 0x04, // Major / Minor versions
            0x00, 0x00, 0x00, 0x14, // Manifest URI offset (0)
            0x00, 0x08, 0x00, 0x00, // Manifest URI length (0) / reserved (0)
            0x00, 0x00, 0x00, 0x1c, // C2PA manifest store offset (0)
            0x00, 0x00, 0x00, 0x09, // C2PA manifest store length (0)
            0x66, 0x69, 0x6c, 0x65, // active manifest uri data
            0x3a, 0x2f, 0x2f, 0x61, // active manifest uri data cont'd
            // Rust Question - Is there some way of breaking up this array
            // definition into chunks? For example, in C, the syntax
            //    "some" "more" "string"
            // gets consolidated by the compiler into the single string literal
            // "somemorestring" - if we could could do that, we could D.R.Y. up
            // the definition of this content-fragment and the literal in the
            // assert down below that checks. (And maybe the chunk lengths could
            // be compile-time-knowable, too, for checking size/offset stuff?)
            0x74, 0x65, 0x73, 0x74, // manifest store data
            0x2d, 0x64, 0x61, 0x74, // manifest store data, cont'd
            0x61, // manifest store data, cont'd
        ];
        let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
        let c2pa_data = read_c2pa_from_stream(&mut font_stream).unwrap();
        // Verify the active manifest uri
        assert_eq!(Some("file://a".to_string()), c2pa_data.active_manifest_uri);
        // Verify the embedded C2PA data as well
        assert_eq!(
            Some(vec![0x74, 0x65, 0x73, 0x74, 0x2d, 0x64, 0x61, 0x74, 0x61].as_ref()),
            c2pa_data.get_manifest_store()
        );
    }

    #[ignore] // Need WOFF 1 test fixture
    #[test]
    /// Verifies the ability to write/read C2PA manifest store data to/from an
    /// OpenType font
    fn remove_c2pa_manifest_store() {
        let c2pa_data = "test data";

        // Load the basic WOFF 1 test fixture - C2PA-XYZ - Select WOFF 1 test fixture
        let source = fixture_path("font.woff");

        // Create a temporary output for the file
        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "test.woff");

        // Copy the source to the output
        std::fs::copy(source, &output).unwrap();

        // Create our WoffIO asset handler for testing
        let woff_io = WoffIO {};

        // Save the C2PA manifest store to the file
        woff_io
            .save_cai_store(&output, c2pa_data.as_bytes())
            .unwrap();
        // Loading it back from the same output file
        let loaded_c2pa = woff_io.read_cai_store(&output).unwrap();
        // Which should work out to be the same in the end
        assert_eq!(&loaded_c2pa, c2pa_data.as_bytes());

        woff_io.remove_cai_store(&output).unwrap();
        match woff_io.read_cai_store(&output) {
            Err(Error::JumbfNotFound) => (),
            _ => panic!("Should not contain any C2PA data"),
        };
    }

    #[ignore] // Need WOFF 1 test fixture
    #[test]
    /// Verifies the ability to write/read C2PA manifest store data to/from an
    /// OpenType font
    fn write_read_c2pa_from_font() {
        let c2pa_data = "test data";

        // Load the basic WOFF 1 test fixture - C2PA-XYZ - Select WOFF 1 test fixture
        let source = fixture_path("font.woff");

        // Create a temporary output for the file
        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "test.woff");

        // Copy the source to the output
        std::fs::copy(source, &output).unwrap();

        // Create our WoffIO asset handler for testing
        let woff_io = WoffIO {};

        // Save the C2PA manifest store to the file
        woff_io
            .save_cai_store(&output, c2pa_data.as_bytes())
            .unwrap();
        // Loading it back from the same output file
        let loaded_c2pa = woff_io.read_cai_store(&output).unwrap();
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
            asset_handlers::woff_io::{font_xmp_support, WoffIO},
            asset_io::CAIReader,
            utils::test::temp_dir_path,
            Error,
        };

        #[ignore] // Need WOFF 1 test fixture
        #[test]
        /// Verifies the `font_xmp_support::add_reference_as_xmp_to_stream` is
        /// able to add a reference to as XMP when there is already data in the
        /// reference field.
        fn add_reference_as_xmp_to_stream_with_data() {
            // Load the basic WOFF 1 test fixture - C2PA-XYZ - Select WOFF 1 test fixture
            let source = crate::utils::test::fixture_path("font.woff");

            // Create a temporary output for the file
            let temp_dir = tempdir().unwrap();
            let output = temp_dir_path(&temp_dir, "test.woff");

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

            let woff_handler = WoffIO {};
            let mut f: File = File::open(output).unwrap();
            match woff_handler.read_xmp(&mut f) {
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

        #[test]
        /// Verifies the `font_xmp_support::build_xmp_from_stream` method
        /// correctly returns error for NotFound when there is no data in the
        /// stream to return.
        fn build_xmp_from_stream_without_reference() {
            let font_data = vec![
                // WOFFHeader
                0x77, 0x4f, 0x46, 0x46, // wOFF
                0x72, 0x73, 0x74, 0x75, // flavor (IIP)
                0x00, 0x00, 0x00, 0x54, // length (84)
                0x00, 0x01, 0x00, 0x00, // numTables (1) / reserved (0)
                0x00, 0x00, 0x00, 0x30, // totalSfntSize (48 = 12 + 16 + 20)
                0x82, 0x83, 0x84, 0x85, // majorVersion / minorVersion (IIP)
                0x00, 0x00, 0x00, 0x00, // metaOffset (0)
                0x00, 0x00, 0x00, 0x00, // metaLength (0)
                0x00, 0x00, 0x00, 0x00, // metaOrigLength (0)
                0x00, 0x00, 0x00, 0x00, // privOffset (0)
                0x00, 0x00, 0x00, 0x00, // privLength (0)
                // WOFFTableDirectory
                0x67, 0x61, 0x71, 0x66, // garf
                0x00, 0x00, 0x00, 0x40, //   offset (64)
                0x00, 0x00, 0x00, 0x07, //   compLength (7)
                0x00, 0x00, 0x00, 0x07, //   origLength (7)
                0x12, 0x34, 0x56, 0x78, //   origChecksum (0x12345678)
                // garf Table
                0x6c, 0x61, 0x73, 0x61, // Major / Minor versions
                0x67, 0x6e, 0x61,
            ];
            let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
            match font_xmp_support::build_xmp_from_stream(&mut font_stream) {
                Ok(_) => panic!("Did not expect an OK result, as data is missing"),
                Err(Error::NotFound) => {}
                Err(_) => panic!("Unexpected error when building XMP data"),
            }
        }

        #[test]
        /// Verifies the `font_xmp_support::build_xmp_from_stream` method
        /// correctly returns error for NotFound when there is no data in the
        /// stream to return.
        fn build_xmp_from_stream_with_reference_not_xmp() {
            let font_data = vec![
                // WOFFHeader
                0x77, 0x4f, 0x46, 0x46, // wOFF
                0x72, 0x73, 0x74, 0x75, // flavor (IIP)
                0x00, 0x00, 0x00, 0x54, // length (84)
                0x00, 0x01, 0x00, 0x00, // numTables (1) / reserved (0)
                0x00, 0x00, 0x00, 0x30, // totalSfntSize (48 = 12 + 16 + 20)
                0x82, 0x83, 0x84, 0x85, // majorVersion / minorVersion (IIP)
                0x00, 0x00, 0x00, 0x00, // metaOffset (0)
                0x00, 0x00, 0x00, 0x00, // metaLength (0)
                0x00, 0x00, 0x00, 0x00, // metaOrigLength (0)
                0x00, 0x00, 0x00, 0x00, // privOffset (0)
                0x00, 0x00, 0x00, 0x00, // privLength (0)
                // WOFFTableDirectory
                0x43, 0x32, 0x50, 0x41, // C2PA
                0x00, 0x00, 0x00, 0x40, //   offset (64)
                0x00, 0x00, 0x00, 0x25, //   compLength (37)
                0x00, 0x00, 0x00, 0x25, //   origLength (37)
                0x12, 0x34, 0x56, 0x78, //   origChecksum (0x12345678)
                // C2PA Table
                0x00, 0x01, 0x00, 0x04, // Major / Minor versions
                0x00, 0x00, 0x00, 0x14, // Manifest URI offset (0)
                0x00, 0x08, 0x00, 0x00, // Manifest URI length (0) / reserved (0)
                0x00, 0x00, 0x00, 0x1c, // C2PA manifest store offset (0)
                0x00, 0x00, 0x00, 0x09, // C2PA manifest store length (0)
                0x66, 0x69, 0x6c, 0x65, // active manifest uri data
                0x3a, 0x2f, 0x2f, 0x61, // active manifest uri data cont'd
                // Rust Question - Is there some way of breaking up this array
                // definition into chunks? For example, in C, the syntax
                //    "some" "more" "string"
                // gets consolidated by the compiler into the single string literal
                // "somemorestring" - if we could could do that, we could D.R.Y. up
                // the definition of this content-fragment and the literal in the
                // assert down below that checks. (And maybe the chunk lengths could
                // be compile-time-knowable, too, for checking size/offset stuff?)
                0x74, 0x65, 0x73, 0x74, // manifest store data
                0x2d, 0x64, 0x61, 0x74, // manifest store data, cont'd
                0x61, // manifest store data, cont'd
            ];
            let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
            match font_xmp_support::build_xmp_from_stream(&mut font_stream) {
                Ok(_xmp_data) => {}
                Err(_) => panic!("Unexpected error when building XMP data"),
            }
        }
    }

    #[test]
    fn add_required_chunks_to_stream_minimal() {
        let min_font_data = vec![
            0x77, 0x4f, 0x46, 0x46, // wOFF
            0x72, 0x73, 0x74, 0x75, // flavor (IIP)
            0x00, 0x00, 0x00, 0x2c, // length (44)
            0x00, 0x00, 0x00, 0x00, // numTables (0) / reserved (0)
            0x00, 0x00, 0x00, 0x0c, // totalSfntSize (12 for header only)
            0x82, 0x83, 0x84, 0x85, // majorVersion / minorVersion (IIP)
            0x00, 0x00, 0x00, 0x00, // metaOffset (0)
            0x00, 0x00, 0x00, 0x00, // metaLength (0)
            0x00, 0x00, 0x00, 0x00, // metaOrigLength (0)
            0x00, 0x00, 0x00, 0x00, // privOffset (0)
            0x00, 0x00, 0x00, 0x00, // privLength (0)
        ];
        let expected_min_font_data_min_c2pa = vec![
            // WOFFHeader
            0x77, 0x4f, 0x46, 0x46, // wOFF
            0x72, 0x73, 0x74, 0x75, // flavor (IIP)
            0x00, 0x00, 0x00, 0x54, // length (84)
            0x00, 0x01, 0x00, 0x00, // numTables (1) / reserved (0)
            0x00, 0x00, 0x00, 0x30, // totalSfntSize (48 = 12 + 16 + 20)
            0x82, 0x83, 0x84, 0x85, // majorVersion / minorVersion (IIP)
            0x00, 0x00, 0x00, 0x00, // metaOffset (0)
            0x00, 0x00, 0x00, 0x00, // metaLength (0)
            0x00, 0x00, 0x00, 0x00, // metaOrigLength (0)
            0x00, 0x00, 0x00, 0x00, // privOffset (0)
            0x00, 0x00, 0x00, 0x00, // privLength (0)
            // WOFFTableDirectory
            0x43, 0x32, 0x50, 0x41, // C2PA
            0x00, 0x00, 0x00, 0x40, //   offset (64)
            0x00, 0x00, 0x00, 0x14, //   compLength (20)
            0x00, 0x00, 0x00, 0x14, //   origLength (20)
            0x00, 0x00, 0x00, 0x01, //   origChecksum (0x00000001)
            // C2PA Table
            0x00, 0x00, 0x00, 0x01, // Major / Minor versions
            0x00, 0x00, 0x00, 0x00, // Manifest URI offset (0)
            0x00, 0x00, 0x00, 0x00, // Manifest URI length (0) / reserved (0)
            0x00, 0x00, 0x00, 0x00, // C2PA manifest store offset (0)
            0x00, 0x00, 0x00, 0x00, // C2PA manifest store length (0)
        ];
        let mut the_reader: Cursor<&[u8]> = Cursor::<&[u8]>::new(&min_font_data);
        let mut the_writer = Cursor::new(Vec::new());

        assert_ok!(add_required_chunks_to_stream(
            &mut the_reader,
            &mut the_writer
        ));

        // Write into the "file" and seek to the beginning
        assert_eq!(
            expected_min_font_data_min_c2pa,
            the_writer.get_ref().as_slice()
        );
    }

    #[test]
    fn get_chunk_positions_minimal() {
        let font_data = vec![
            // WOFFHeader
            0x77, 0x4f, 0x46, 0x46, // wOFF
            0x72, 0x73, 0x74, 0x75, // flavor (IIP)
            0x00, 0x00, 0x00, 0x2c, // length (44)
            0x00, 0x00, 0x00, 0x00, // numTables (0) / reserved (0)
            0x00, 0x00, 0x00, 0x0c, // totalSfntSize (12 for header only)
            0x00, 0x00, 0x00, 0x00, // majorVersion / minorVersion
            0x00, 0x00, 0x00, 0x00, // metaOffset (0)
            0x00, 0x00, 0x00, 0x00, // metaLength (0)
            0x00, 0x00, 0x00, 0x00, // metaOrigLength (0)
            0x00, 0x00, 0x00, 0x00, // privOffset (0)
            0x00, 0x00, 0x00, 0x00, // privLength (0)
        ];
        let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
        let woff_io = WoffIO {};
        let positions = woff_io.get_chunk_positions(&mut font_stream).unwrap();
        // Should have one position reported for the table directory itself
        assert_eq!(2, positions.len());
        let header_posn = positions.first().unwrap();
        assert_eq!(
            *header_posn,
            ChunkPosition {
                offset: 0,
                length: 44,
                name: WOFF_HEADER_CHUNK_NAME.data,
                chunk_type: ChunkType::Header,
            }
        );
        let directory_posn = positions.get(1).unwrap();
        assert_eq!(
            *directory_posn,
            ChunkPosition {
                offset: 44,
                length: 0,
                name: WOFF_DIRECTORY_CHUNK_NAME.data,
                chunk_type: ChunkType::Directory,
            }
        );
    }
}
