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
use core::{cmp::Ordering, fmt, mem::size_of, num::Wrapping};
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

    /// Creates a default `XmpMeta` object for fonts, using the specified
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
                &document_id.unwrap_or(SfntIO::default_document_id()).into(),
            )
            .map_err(xmp_write_err)?;

        // Add an instance ID
        xmp_meta
            .set_property(
                xmp_mm_namespace,
                "InstanceID",
                // Use the supplied instance ID or default to one if needed
                &instance_id.unwrap_or(SfntIO::default_instance_id()).into(),
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

/// Pseudo-tag for the SFNT file header
const SFNT_HEADER_CHUNK_NAME: SfntTag = SfntTag { data: *b" HDR" };

/// Pseudo-tag for the table directory.
const _SFNT_DIRECTORY_CHUNK_NAME: SfntTag = SfntTag { data: *b" DIR" }; // Sorts to just-after HEADER tag.

/// Implementation of ye olde SFNT
struct SfntFont {
    header: SfntHeader,
    directory: SfntDirectory,
    /// All the Tables in this font, keyed by SfntTag.
    tables: BTreeMap<SfntTag, NamedTable>,
}

impl SfntFont {
    /// Reads a new instance from the given source.
    fn from_reader<T: Read + Seek + ?Sized>(
        reader: &mut T,
    ) -> core::result::Result<SfntFont, Error> {
        // Read in the SfntHeader
        let sfnt_hdr = SfntHeader::from_reader(reader)?;

        // After the header should be the directory.
        let sfnt_dir = SfntDirectory::from_reader(reader, sfnt_hdr.numTables as usize)?;

        // With that, we can construct the tables
        let mut sfnt_tables = BTreeMap::new();

        for entry in sfnt_dir.entries.iter() {
            // Try to parse the next dir entry
            let offset: u64 = entry.offset as u64;
            let size: usize = entry.length as usize;
            // Create a table instance for it.
            let table = NamedTable::from_reader(&entry.tag, reader, offset, size)?;
            // Tell it to get in the van
            sfnt_tables.insert(entry.tag, table);
        }

        // Assemble the five lions as shown to construct your robot.
        Ok(SfntFont {
            header: sfnt_hdr,
            directory: sfnt_dir,
            tables: sfnt_tables,
        })
    }

    /// Serializes this instance to the given writer.
    fn write<TDest: Write + ?Sized>(&mut self, destination: &mut TDest) -> Result<()> {
        let mut neo_header = SfntHeader::default();
        let mut neo_directory = SfntDirectory::new()?;
        // Re-synthesize the file header based on the actual table count
        neo_header.sfntVersion = self.header.sfntVersion;
        neo_header.numTables = self.tables.len() as u16;
        neo_header.entrySelector = if neo_header.numTables > 0 {
            neo_header.numTables.ilog2() as u16
        } else {
            0_u16
        };
        neo_header.searchRange = 2_u16.pow(neo_header.entrySelector as u32) * 16;
        neo_header.rangeShift = neo_header.numTables * 16 - neo_header.searchRange;
        // At the moment, font editing services are limited. We make the
        // assumption that the *only* permissible font mutation is one of the
        // following:
        //
        // - An existing C2PA table has been altered: table count unchanged
        // - An existing C2PA table has been removed: num_tables -= 1
        // - A new C2PA table has been added: num_tables += 1

        // If our actual table count has increased by one since the file was
        // read, it's because we've added a C2PA table; we'll need to add a
        // directory entry for it; shoving all the data in the file down a bit
        // to make room...
        let orig_table_count = self.header.numTables as usize;
        let td_derived_offset_bias: i64 = match self.tables.len().cmp(&orig_table_count) {
            Ordering::Greater => {
                if (self.tables.len() as u16) - self.header.numTables == 1 {
                    // We added exactly one table
                    size_of::<SfntDirectoryEntry>() as i64
                } else {
                    // We added some other number of tables
                    return Err(wrap_font_err(FontError::SaveError));
                }
            }
            Ordering::Equal => 0,
            Ordering::Less => {
                if self.header.numTables - (self.tables.len() as u16) == 1 {
                    // Therefore, the actual table list should not contain
                    // the C2PA table - that's the only one we should ever
                    // be removing.
                    if self.tables.contains_key(&C2PA_TABLE_TAG) {
                        return Err(wrap_font_err(FontError::SaveError));
                    }
                    // We removed exactly one table
                    -(size_of::<SfntDirectoryEntry>() as i64)
                } else {
                    // We added some other number of tables. Weird, right?
                    return Err(wrap_font_err(FontError::SaveError));
                }
            }
        };

        // Figure out the size of the tables we know about already; any new
        // tables will have to follow.
        let new_data_offset = match self.directory.physical_order().last() {
            Some(&entry) => align_to_four(
                (entry.offset as i64 + entry.length as i64 + td_derived_offset_bias) as usize,
            ),
            None => 0_usize,
        };

        // Enumerate the Tables and ensure each one has a Directory Entry.
        for (tag, table) in &self.tables {
            // 😕 There is logical entanglement between this `match` and the
            // code above which figures out whether we added or removed (or
            // neither) a C2PA table, and figures out the table data bias.
            //
            // As example, see the explicit error returns when td_derived_offset_bias is the "wrong" sign.
            match self
                .directory
                .entries
                .iter()
                .find(|&entry| entry.tag == *tag)
            {
                Some(entry) => {
                    // Check - if this is the C2PA table, then this *must not*
                    // be the case where we're removing the C2PA table; the
                    // bias *must not* be negative.
                    if entry.tag == C2PA_TABLE_TAG && td_derived_offset_bias < 0 {
                        return Err(wrap_font_err(FontError::SaveError));
                    }
                    let neo_entry = SfntDirectoryEntry {
                        tag: entry.tag,
                        offset: ((entry.offset as i64) + td_derived_offset_bias) as u32,
                        checksum: match *tag {
                            C2PA_TABLE_TAG => table.checksum().0,
                            _ => entry.checksum,
                        },
                        length: match tag {
                            &C2PA_TABLE_TAG => table.len() as u32,
                            _ => entry.length,
                        },
                    };
                    neo_directory.entries.push(neo_entry);
                }
                None => match *tag {
                    C2PA_TABLE_TAG => {
                        // Check - this *must* be the case where we're adding
                        // a C2PA table - therefore the bias should be positive.
                        if td_derived_offset_bias <= 0 {
                            return Err(wrap_font_err(FontError::SaveError));
                        }
                        let neo_entry = SfntDirectoryEntry {
                            tag: *tag,
                            offset: align_to_four(new_data_offset) as u32,
                            checksum: table.checksum().0,
                            length: table.len() as u32,
                        };
                        neo_directory.entries.push(neo_entry);
                        // Note - new_data_offset is never actually used after
                        // this point, but _if it were_, it would need to be
                        // mutable, and we would move it ahead like so:
                        // new_data_offset =
                        //    align_to_four(entry.offset as usize + entry.length as usize);
                    }
                    _ => {
                        return Err(wrap_font_err(FontError::SaveError));
                    }
                },
            }
        }

        // Figure the checksum for the whole font - the header, the directory,
        // and then all the tables; we can just use the per-table checksums,
        // since the only one we alter is C2PA, and we just refreshed it...
        let font_cksum = neo_header.checksum()
            + neo_directory.checksum()
            + neo_directory
                .entries
                .iter()
                .fold(Wrapping(0_u32), |tables_cksum, entry| {
                    tables_cksum + Wrapping(entry.checksum)
                });

        // Rewrite the head table's checksumAdjustment. (This act does *not*
        // invalidate the checksum in the TDE for the 'head' table, which is        // always treated as zero during check summing).
        if let Some(NamedTable::Head(head)) = self.tables.get_mut(&HEAD_TABLE_TAG) {
            head.checksumAdjustment =
                (Wrapping(SFNT_EXPECTED_CHECKSUM) - font_cksum - Wrapping(0)).0;
        }

        // Replace our header & directory with updated editions.
        self.header = neo_header;
        self.directory = neo_directory;
        // Write everything out.
        self.header.write(destination)?;
        self.directory.write(destination)?;
        for entry in self.directory.physical_order().iter() {
            self.tables[&entry.tag].write(destination)?;
        }
        Ok(())
    }

    /// Add an empty C2PA table in this font, at the end, so we don't have to
    /// re-position any existing tables.
    fn append_empty_c2pa_table(&mut self) -> Result<()> {
        // Just add an empty table...
        self.tables
            .insert(C2PA_TABLE_TAG, NamedTable::C2PA(TableC2PA::default()));
        // ...and then later, when the .write() function is invoked, it will
        // notice that self.tables.len() no longer matches
        // self.header.numTables, and regenerate the header & directory.
        //
        // Success at last
        Ok(())
    }
}

/// Definitions for the SFNT file header and Table Directory structures are in
/// the font_io module, because WOFF support needs to use them as well.
impl SfntHeader {
    /// Reads a new instance from the given source.
    pub(crate) fn from_reader<T: Read + Seek + ?Sized>(reader: &mut T) -> Result<Self> {
        Ok(Self {
            sfntVersion: reader.read_u32::<BigEndian>()?,
            numTables: reader.read_u16::<BigEndian>()?,
            searchRange: reader.read_u16::<BigEndian>()?,
            entrySelector: reader.read_u16::<BigEndian>()?,
            rangeShift: reader.read_u16::<BigEndian>()?,
        })
    }

    /// Serializes this instance to the given writer.
    fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        destination.write_u32::<BigEndian>(self.sfntVersion)?;
        destination.write_u16::<BigEndian>(self.numTables)?;
        destination.write_u16::<BigEndian>(self.searchRange)?;
        destination.write_u16::<BigEndian>(self.entrySelector)?;
        destination.write_u16::<BigEndian>(self.rangeShift)?;
        Ok(())
    }

    /// Computes the checksum for this font.
    pub(crate) fn checksum(&self) -> Wrapping<u32> {
        // 0x00
        Wrapping(self.sfntVersion)
            // 0x04
            + u32_from_u16_pair(self.numTables, self.searchRange)
            // 0x08
            + u32_from_u16_pair(self.entrySelector, self.rangeShift)
    }
}

impl Default for SfntHeader {
    fn default() -> Self {
        Self {
            sfntVersion: Magic::TrueType as u32,
            numTables: 0,
            searchRange: 0,
            entrySelector: 0,
            rangeShift: 0,
        }
    }
}

impl SfntDirectoryEntry {
    /// Reads a new instance from the given source.
    pub(crate) fn from_reader<T: Read + Seek + ?Sized>(reader: &mut T) -> Result<Self> {
        Ok(Self {
            tag: SfntTag::from_reader(reader)?,
            checksum: reader.read_u32::<BigEndian>()?,
            offset: reader.read_u32::<BigEndian>()?,
            length: reader.read_u32::<BigEndian>()?,
        })
    }

    /// Serializes this instance to the given writer.
    pub(crate) fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        self.tag.write(destination)?;
        destination.write_u32::<BigEndian>(self.checksum)?;
        destination.write_u32::<BigEndian>(self.offset)?;
        destination.write_u32::<BigEndian>(self.length)?;
        Ok(())
    }

    /// Computes the checksum for this entry.
    pub(crate) fn checksum(&self) -> Wrapping<u32> {
        Wrapping(u32::from_be_bytes(self.tag.data))
            + Wrapping(self.checksum)
            + Wrapping(self.offset)
            + Wrapping(self.length)
    }
}

impl Default for SfntDirectoryEntry {
    fn default() -> Self {
        Self {
            tag: SfntTag::new(*b"\0\0\0\0"),
            checksum: 0,
            offset: 0,
            length: 0,
        }
    }
}

/// SFNT Directory is just an array of entries. Undoubtedly there exists a
/// more-oxidized way of just using Vec directly for this... but maybe we
/// don't want to? Note the choice of Vec over BTreeMap here, which lets us
/// keep non-compliant fonts as-is...
#[derive(Debug)]
struct SfntDirectory {
    entries: Vec<SfntDirectoryEntry>,
}

impl SfntDirectory {
    /// Constructs a new, empty, instance.
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
        let mut the_directory = SfntDirectory::new()?;
        for _entry in 0..entry_count {
            the_directory
                .entries
                .push(SfntDirectoryEntry::from_reader(reader)?);
        }
        Ok(the_directory)
    }

    /// Serializes this instance to the given writer.
    fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        for entry in self.entries.iter() {
            entry.write(destination)?;
        }
        Ok(())
    }

    /// Returns an array which contains the indices of this directory's entries,
    /// arranged in increasing order of `offset` field.
    fn physical_order(&self) -> Vec<SfntDirectoryEntry> {
        let mut physically_ordered_entries = self.entries.clone();
        physically_ordered_entries.sort_by_key(|e| e.offset);
        physically_ordered_entries
    }

    /// Computes the checksum for this directory.
    pub(crate) fn checksum(&self) -> Wrapping<u32> {
        match self.entries.is_empty() {
            true => Wrapping(0_u32),
            false => self
                .entries
                .iter()
                .fold(Wrapping(0_u32), |cksum, entry| cksum + entry.checksum()),
        }
    }
}

/// Identifies types of regions within a font file. Chunks with lesser enum
/// values precede those with greater enum values; order within a given group
/// of chunks (such as a series of `Table` chunks) must be preserved by some
/// other mechanism.
#[derive(Eq, PartialEq)]
pub(crate) enum ChunkType {
    /// Whole-container header.
    Header,
    /// Table directory entry or entries.
    _Directory,
    /// Table data included in C2PA hash.
    TableDataIncluded,
    /// Table data excluded from C2PA hash.
    TableDataExcluded,
}

impl std::fmt::Display for ChunkType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ChunkType::Header => write!(f, "Header"),
            ChunkType::_Directory => write!(f, "Directory"),
            ChunkType::TableDataIncluded => write!(f, "TableDataIncluded"),
            ChunkType::TableDataExcluded => write!(f, "TableDataExcluded"),
        }
    }
}

impl std::fmt::Debug for ChunkType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ChunkType::Header => write!(f, "Header"),
            ChunkType::_Directory => write!(f, "Directory"),
            ChunkType::TableDataIncluded => write!(f, "TableDataIncluded"),
            ChunkType::TableDataExcluded => write!(f, "TableDataExcluded"),
        }
    }
}

/// Represents regions within a font file that may be of interest when it
/// comes to hashing data for C2PA.
#[derive(Eq, PartialEq)]
pub(crate) struct ChunkPosition {
    /// Offset to the start of the chunk
    pub offset: usize,
    /// Length of the chunk
    pub length: usize,
    /// Tag of the chunk
    pub name: [u8; 4],
    /// Type of chunk
    pub chunk_type: ChunkType,
}

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

impl std::fmt::Display for ChunkPosition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}, {}, {}, {}",
            String::from_utf8_lossy(&self.name),
            self.offset,
            self.length,
            self.chunk_type
        )
    }
}

impl std::fmt::Debug for ChunkPosition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}, {}, {}, {}",
            String::from_utf8_lossy(&self.name),
            self.offset,
            self.length,
            self.chunk_type
        )
    }
}

/// Reads in chunks for an SFNT file
impl ChunkReader for SfntIO {
    type Error = crate::error::Error;

    /// Get a map of all the chunks in the given source stream.
    fn get_chunk_positions<T: Read + Seek + ?Sized>(
        &self,
        reader: &mut T,
    ) -> core::result::Result<Vec<ChunkPosition>, Self::Error> {
        // Rewind to start and read the SFNT header and directory - that's
        // really all we need in order to map the chunks.
        reader.rewind()?;
        let header = SfntHeader::from_reader(reader)?;
        let directory = SfntDirectory::from_reader(reader, header.numTables as usize)?;

        // TBD - Streamlined approach:
        // 1 - Header + directory
        // 2 - Data from start to head::checksumAdjustment
        // 3 - head::checksumAdjustment
        // 4 - Data from head::checksumAdjustment through penultimate table
        // 5 - The C2PA table

        // The first chunk excludes the header & directory from hashing
        let mut positions: Vec<ChunkPosition> = Vec::new();
        positions.push(ChunkPosition {
            offset: 0,
            length: size_of::<SfntHeader>()
                + header.numTables as usize * size_of::<SfntDirectoryEntry>(),
            name: SFNT_HEADER_CHUNK_NAME.data,
            chunk_type: ChunkType::Header,
        });

        // The subsequent chunks represent the tables. All table data is hashed,
        // with two exceptions:
        // - The C2PA table itself.
        // - The head table's `checksumAdjustment` field.
        for entry in directory.physical_order() {
            match entry.tag {
                C2PA_TABLE_TAG => {
                    positions.push(ChunkPosition {
                        offset: entry.offset as usize,
                        length: entry.length as usize,
                        name: entry.tag.data,
                        chunk_type: ChunkType::TableDataExcluded,
                    });
                }
                HEAD_TABLE_TAG => {
                    // TBD - These hard-coded magic numbers could be mopped up
                    // if only we could use offset_of, see https://github.com/rust-lang/rust/issues/106655
                    positions.push(ChunkPosition {
                        offset: entry.offset as usize,
                        length: 8_usize,
                        name: *b"hea0",
                        chunk_type: ChunkType::TableDataIncluded,
                    });
                    positions.push(ChunkPosition {
                        offset: entry.offset as usize + 8_usize,
                        length: 4_usize,
                        name: *b"hea1",
                        chunk_type: ChunkType::TableDataExcluded,
                    });
                    positions.push(ChunkPosition {
                        offset: entry.offset as usize + 12_usize,
                        length: 42_usize,
                        name: *b"hea2",
                        chunk_type: ChunkType::TableDataIncluded,
                    });
                }
                _ => {
                    positions.push(ChunkPosition {
                        offset: entry.offset as usize,
                        length: entry.length as usize,
                        name: entry.tag.data,
                        chunk_type: ChunkType::TableDataIncluded,
                    });
                }
            }
        }

        // Do not iterate if the log level is not set to at least trace
        if log::max_level().cmp(&log::LevelFilter::Trace).is_ge() {
            for (i, dirent) in directory.entries.iter().enumerate() {
                trace!("get_chunk_positions/table[{:02}]: {:?}", i, &dirent);
            }
            for (i, chunk) in positions.iter().enumerate() {
                trace!("get_chunk_positions/chunk[{:02}]: {:?}", i, &chunk);
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
    let mut font = SfntFont::from_reader(source).map_err(|_| FontError::LoadError)?;
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
        // If there is, replace its `manifest_store` value with the
        // provided one.
        Some(NamedTable::C2PA(c2pa)) => c2pa.manifest_store = Some(manifest_store_data.to_vec()),
        // Yikes! Non-C2PA table with C2PA tag!
        Some(_) => {
            return Err(wrap_font_err(FontError::LoadError));
        }
    };
    font.write(destination).map_err(|_| FontError::SaveError)?;
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
    let mut font = SfntFont::from_reader(source).map_err(|_| FontError::LoadError)?;
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
            return Err(wrap_font_err(FontError::LoadError));
        }
    };
    font.write(destination).map_err(|_| FontError::SaveError)?;
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
    let mut font = SfntFont::from_reader(input_stream).map_err(|_| FontError::LoadError)?;
    // If the C2PA table does not exist...
    if font.tables.get(&C2PA_TABLE_TAG).is_none() {
        // ...install an empty one.
        font.append_empty_c2pa_table()?;
    }
    // Write the font to the output stream
    font.write(output_stream)
        .map_err(|_| FontError::SaveError)?;
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
        Err(_) => Err(wrap_font_err(FontError::DeserializationError)),
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
    let mut font = SfntFont::from_reader(source).map_err(|_| FontError::LoadError)?;
    // Remove the table from the collection
    font.tables.remove(&C2PA_TABLE_TAG);
    // And write it to the destination stream
    font.write(destination).map_err(|_| FontError::SaveError)?;
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
    let mut font = SfntFont::from_reader(source).map_err(|_| FontError::LoadError)?;
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
            return Err(wrap_font_err(FontError::LoadError));
        }
    };
    font.write(destination).map_err(|_| FontError::SaveError)?;
    Ok(old_manifest_uri_maybe)
}

/// Gets a collection of positions of hash objects from the reader which are to
/// be excluded from the hashing, used to omit from hashing.
fn get_object_locations_from_stream<T>(
    sfnt_io: &SfntIO,
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

    // NOTE - This call is pointless when we already have a C2PA table, and
    // a bit silly-seeming when we don't?
    add_required_chunks_to_stream(reader, &mut output_stream)?;
    output_stream.rewind()?;

    // Build up the positions we will hand back to the caller
    let mut locations: Vec<HashObjectPositions> = Vec::new();

    // Which will be built up from the different chunks from the file
    for chunk in sfnt_io.get_chunk_positions(&mut output_stream)? {
        match chunk.chunk_type {
            // The table directory, other than the table records array will be
            // added as "Cai" -- metadata to be excluded from hashing.
            ChunkType::Header | ChunkType::_Directory | ChunkType::TableDataExcluded => {
                locations.push(HashObjectPositions {
                    offset: chunk.offset,
                    length: chunk.length,
                    htype: HashBlockObjectType::Cai,
                });
            }
            // All else is treated as "Other" -- content to be hashed.
            ChunkType::TableDataIncluded => {
                locations.push(HashObjectPositions {
                    offset: chunk.offset,
                    length: chunk.length,
                    htype: HashBlockObjectType::Other,
                });
            }
        }
    }
    // Do not iterate if the log level is not set to at least trace
    if log::max_level().cmp(&log::LevelFilter::Trace).is_ge() {
        for (i, location) in locations.iter().enumerate() {
            trace!(
                "get_object_locations_from_stream/loc[{:02}]: {:?}",
                i,
                &location
            );
        }
    }
    Ok(locations)
}

/// Reads the `C2PA` font table from the data stream, returning the `C2PA` font
/// table data
fn read_c2pa_from_stream<T: Read + Seek + ?Sized>(reader: &mut T) -> Result<TableC2PA> {
    let sfnt = SfntFont::from_reader(reader).map_err(|_| FontError::LoadError)?;
    match sfnt.tables.get(&C2PA_TABLE_TAG) {
        None => Err(Error::JumbfNotFound),
        // If there is, replace its `manifest_store` value with the
        // provided one.
        Some(NamedTable::C2PA(c2pa)) => Ok(c2pa.clone()),
        // Yikes! Non-C2PA table with C2PA tag!
        Some(_) => Err(wrap_font_err(FontError::LoadError)),
    }
}

/// Main SFNT IO feature.
pub(crate) struct SfntIO {}

impl SfntIO {
    #[allow(dead_code)]
    pub(crate) fn default_document_id() -> String {
        format!("fontsoftware:did:{}", Uuid::new_v4())
    }

    #[allow(dead_code)]
    pub(crate) fn default_instance_id() -> String {
        format!("fontsoftware:iid:{}", Uuid::new_v4())
    }
}

/// SFNT implementation of the CAILoader trait.
impl CAIReader for SfntIO {
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

/// SFNT implementations for the CAIWriter trait.
impl CAIWriter for SfntIO {
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

/// SFNT implementations for the AssetIO trait.
impl AssetIO for SfntIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        SfntIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(SfntIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(SfntIO::new(asset_type)))
    }

    fn remote_ref_writer_ref(&self) -> Option<&dyn RemoteRefEmbed> {
        Some(self)
    }

    fn supported_types(&self) -> &[&str] {
        // Supported extension and mime-types
        &[
            "application/font-sfnt",
            "application/x-font-ttf",
            "application/x-font-opentype",
            "application/x-font-truetype",
            "font/otf",
            "font/sfnt",
            "font/ttf",
            "otf",
            "sfnt",
            "ttf",
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
impl AssetBoxHash for SfntIO {
    fn get_box_map(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<BoxMap>> {
        // Get the chunk positions
        let chunks = self.get_chunk_positions(input_stream)?;
        // Create a box map vector to map the chunk positions to
        let mut box_maps = Vec::<BoxMap>::new();
        for chunk in chunks {
            let box_map = BoxMap {
                names: vec![format!("{:?}", chunk.name)],
                alg: None,
                hash: ByteBuf::from(Vec::new()),
                pad: ByteBuf::from(Vec::new()),
                range_start: chunk.offset,
                range_len: chunk.length,
            };
            box_maps.push(box_map);
        }
        // Do not iterate if the log level is not set to at least trace
        if log::max_level().cmp(&log::LevelFilter::Trace).is_ge() {
            for (i, box_map) in box_maps.iter().enumerate() {
                trace!("get_box_map/boxes[{:02}]: {:?}", i, &box_map);
            }
        }
        Ok(box_maps)
    }
}

impl RemoteRefEmbed for SfntIO {
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

    #[test]
    #[cfg(not(feature = "xmp_write"))]
    /// Verifies the adding of a remote C2PA manifest reference works as
    /// expected.
    fn add_c2pa_ref() {
        let c2pa_data = "test data";

        // Load the basic OTF test fixture
        let source = fixture_path("font.otf");

        // Create a temporary output for the file
        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "test.otf");

        // Copy the source to the output
        std::fs::copy(source, &output).unwrap();

        // Create our SfntIO asset handler for testing
        let sfnt_io = SfntIO {};

        let expected_manifest_uri = "https://test/ref";

        sfnt_io
            .embed_reference(
                &output,
                crate::asset_io::RemoteRefEmbedType::Xmp(expected_manifest_uri.to_owned()),
            )
            .unwrap();
        // Save the C2PA manifest store to the file
        sfnt_io
            .save_cai_store(&output, c2pa_data.as_bytes())
            .unwrap();
        // Loading it back from the same output file
        let loaded_c2pa = sfnt_io.read_cai_store(&output).unwrap();
        // Which should work out to be the same in the end
        assert_eq!(&loaded_c2pa, c2pa_data.as_bytes());

        match read_reference_from_font(&output) {
            Ok(Some(manifest_uri)) => assert_eq!(expected_manifest_uri, manifest_uri),
            _ => panic!("Expected to read a reference from the font file"),
        };

        let output_data = std::fs::read(&output).unwrap();
        assert_eq!(checksum(&output_data).0, SFNT_EXPECTED_CHECKSUM);
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
        let source = fixture_path("font.otf");

        // Create a temporary output for the file
        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "test.otf");

        // Copy the source to the output
        std::fs::copy(source, &output).unwrap();

        // Create our SfntIO asset handler for testing
        let sfnt_io = SfntIO {};

        let expected_manifest_uri = "https://test/ref";

        sfnt_io
            .embed_reference(
                &output,
                crate::asset_io::RemoteRefEmbedType::Xmp(expected_manifest_uri.to_owned()),
            )
            .unwrap();
        // Save the C2PA manifest store to the file
        sfnt_io
            .save_cai_store(&output, c2pa_data.as_bytes())
            .unwrap();
        // Loading it back from the same output file
        let loaded_c2pa = sfnt_io.read_cai_store(&output).unwrap();
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

        let output_data = std::fs::read(&output).unwrap();
        assert_eq!(checksum(&output_data).0, SFNT_EXPECTED_CHECKSUM);
    }

    #[test]
    /// Verify read/write idempotency
    fn read_write_idempotent_no_c2pa() {
        // Load the basic OTF test fixture
        let mut font_stream = File::open(fixture_path("font.otf")).unwrap();
        // Read & build
        let mut sfnt = SfntFont::from_reader(&mut font_stream).unwrap();
        // Then serialize back out
        let mut test_data = Vec::new();
        sfnt.write(&mut test_data).unwrap();
        // and read _that_ back in...
        let mut font_data = Vec::new();
        font_stream.rewind().unwrap();
        font_stream.read_to_end(&mut font_data).unwrap();
        // data should match & checksum should be right
        assert_eq!(font_data, test_data);
        let naive_test_cksum = checksum(&test_data).0;
        assert_eq!(naive_test_cksum, SFNT_EXPECTED_CHECKSUM);
    }

    #[test]
    /// Verify read/write idempotency
    fn read_write_idempotent_yes_c2pa() {
        // Load the basic OTF test fixture
        let mut font_stream = File::open(fixture_path("font_c2pa.otf")).unwrap();
        // Read & build
        let mut sfnt = SfntFont::from_reader(&mut font_stream).unwrap();
        // Then serialize back out
        let mut test_data = Vec::new();
        sfnt.write(&mut test_data).unwrap();
        // and read _that_ back in...
        let mut font_data = Vec::new();
        font_stream.rewind().unwrap();
        font_stream.read_to_end(&mut font_data).unwrap();
        // data should match & checksum should be right
        assert_eq!(font_data, test_data);
        let naive_test_cksum = checksum(&test_data).0;
        assert_eq!(naive_test_cksum, SFNT_EXPECTED_CHECKSUM);
    }

    #[test]
    /// Verify that short file fails to chunk-parse at all
    fn get_chunk_positions_without_any_font() {
        let font_data = vec![
            0x4f, 0x54, 0x54, 0x4f, // OTTO
            0x00, // ...and then one more byte, and that's it.
        ];
        let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
        let sfnt_io = SfntIO {};
        assert_err!(sfnt_io.get_chunk_positions(&mut font_stream));
    }

    #[test]
    /// Verify chunk-parsing behavior for empty font with just the header
    fn get_chunk_positions_without_any_tables() {
        let font_data = vec![
            0x4f, 0x54, 0x54, 0x4f, // OTTO
            0x00, 0x00, 0x00, 0x00, // 0 tables / 0
            0x00, 0x00, 0x00, 0x00, // 0 / 0
        ];
        let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
        let sfnt_io = SfntIO {};
        let positions = sfnt_io.get_chunk_positions(&mut font_stream).unwrap();
        // Should have one positions reported, for a header and no dir entries
        assert_eq!(1, positions.len());
        assert_eq!(
            positions.first().unwrap(),
            &ChunkPosition {
                offset: 0_usize,
                length: 12_usize,
                name: SFNT_HEADER_CHUNK_NAME.data,
                chunk_type: ChunkType::Header,
            }
        );
    }

    #[test]
    /// Verify when reading the object locations for hashing, we get zero
    /// positions when the font does not contain a C2PA font table
    fn get_chunk_positions_without_c2pa_table() {
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
        let sfnt_io = SfntIO {};
        let positions = sfnt_io.get_chunk_positions(&mut font_stream).unwrap();
        // Should have 2 positions reported for the header and the table data
        assert_eq!(2, positions.len());
        // First is the header
        assert_eq!(
            positions.first().unwrap(),
            &ChunkPosition {
                offset: 0_usize,
                length: 28_usize,
                name: SFNT_HEADER_CHUNK_NAME.data,
                chunk_type: ChunkType::Header,
            }
        );
        // Second is the C2PB table
        assert_eq!(
            positions.get(1).unwrap(),
            &ChunkPosition {
                offset: 28_usize,
                length: 1,
                name: *b"C2PB",
                chunk_type: ChunkType::TableDataIncluded,
            }
        );
    }

    #[test]
    fn get_object_locations() {
        // Load the basic OTF test fixture
        let source = fixture_path("font.otf");

        // Create a temporary output for the file
        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "test.otf");

        // Copy the source to the output
        std::fs::copy(source, &output).unwrap();

        // Create our SfntIO asset handler for testing
        let sfnt_io = SfntIO {};

        // The font has 11 records, 11 tables, 1 table directory
        // but the head table will expand from 1 to 3 positions bringing it to 25
        // And then the required C2PA chunks will be added, bringing it to 27
        let positions = sfnt_io.get_object_locations(&output).unwrap();
        assert_eq!(15, positions.len());
    }

    #[test]
    /// Verify the C2PA table data can be read from a font stream
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
            0x00, 0x00, 0x00, 0x25, // length of table data
            0x00, 0x00, // Major version
            0x00, 0x01, // Minor version
            0x00, 0x00, 0x00, 0x14, // Active manifest URI offset
            0x00, 0x08, // Active manifest URI length
            0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x1c, // C2PA manifest store offset
            0x00, 0x00, 0x00, 0x09, // C2PA manifest store length
            0x66, 0x69, 0x6c, 0x65, 0x3a, 0x2f, 0x2f,
            0x61, // active manifest uri data (e.g., file://a)
            0x74, 0x65, 0x73, 0x74, 0x2d, 0x64, 0x61, 0x74, 0x61, // C2PA manifest store data
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

    #[test]
    /// Verifies the ability to write/read C2PA manifest store data to/from an
    /// OpenType font
    fn remove_c2pa_manifest_store() {
        let c2pa_data = "test data";

        // Load the basic OTF test fixture
        let source = fixture_path("font.otf");

        // Create a temporary output for the file
        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "test.otf");

        // Copy the source to the output
        std::fs::copy(source, &output).unwrap();

        // Create our SfntIO asset handler for testing
        let sfnt_io = SfntIO {};

        // Save the C2PA manifest store to the file
        sfnt_io
            .save_cai_store(&output, c2pa_data.as_bytes())
            .unwrap();
        // Loading it back from the same output file
        let loaded_c2pa = sfnt_io.read_cai_store(&output).unwrap();
        // Which should work out to be the same in the end
        assert_eq!(&loaded_c2pa, c2pa_data.as_bytes());

        sfnt_io.remove_cai_store(&output).unwrap();
        match sfnt_io.read_cai_store(&output) {
            Err(Error::JumbfNotFound) => (),
            _ => panic!("Should not contain any C2PA data"),
        };
    }

    #[test]
    /// Verifies the ability to write/read C2PA manifest store data to/from an
    /// OpenType font
    fn write_read_c2pa_from_font() {
        let c2pa_data = "test data";

        // Load the basic OTF test fixture
        let source = fixture_path("font.otf");

        // Create a temporary output for the file
        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "test.otf");

        // Copy the source to the output
        std::fs::copy(source, &output).unwrap();

        // Create our SfntIO asset handler for testing
        let sfnt_io = SfntIO {};

        // Save the C2PA manifest store to the file
        sfnt_io
            .save_cai_store(&output, c2pa_data.as_bytes())
            .unwrap();
        // Loading it back from the same output file
        let loaded_c2pa = sfnt_io.read_cai_store(&output).unwrap();
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
            asset_handlers::sfnt_io::{font_xmp_support, SfntIO},
            asset_io::CAIReader,
            utils::test::temp_dir_path,
            Error,
        };

        #[test]
        /// Verifies the `font_xmp_support::add_reference_as_xmp_to_stream` is
        /// able to add a reference to as XMP when there is already data in the
        /// reference field.
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

            let otf_handler = SfntIO {};
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

        #[test]
        /// Verifies the `font_xmp_support::build_xmp_from_stream` method
        /// correctly returns error for NotFound when there is no data in the
        /// stream to return.
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

        #[test]
        /// Verifies the `font_xmp_support::build_xmp_from_stream` method
        /// correctly returns error for NotFound when there is no data in the
        /// stream to return.
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
                0x00, 0x00, 0x00, 0x1c, // length of table data
                0x00, 0x00, // Major version
                0x00, 0x01, // Minor version
                0x00, 0x00, 0x00, 0x14, // Active manifest URI offset
                0x00, 0x08, // Active manifest URI length
                0x00, 0x00, // reserved
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
