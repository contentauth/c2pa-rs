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
    cmp::Ordering,
    collections::BTreeMap,
    fs::File,
    io::{BufReader, Cursor, Read, Seek, SeekFrom, Write},
    mem::size_of,
    num::Wrapping, // TBD - should we be using core::num?
    path::*,
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
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
/// ### Remarks
/// This module depends on the `feature = "xmp_write"` to be enabled.
#[cfg(feature = "xmp_write")]
mod font_xmp_support {
    use xmp_toolkit::{FromStrOptions, XmpError, XmpErrorType, XmpMeta};

    use super::*;

    /// Creates a default `XmpMeta` object for fonts
    ///
    /// ### Parameters
    /// - `document_id` - optional unique identifier for the document
    /// - `instance_id` - optional unique identifier for the instance
    ///
    /// ### Remarks
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

    /// Builds a `XmpMeta` element from the data within the source stream
    ///
    /// ### Parameters
    /// - `source` - Source stream to read data from to build the `XmpMeta` object
    ///
    /// ### Returns
    /// A new `XmpMeta` object, either based on information that already exists in
    /// the stream or using defaults
    ///
    /// ### Remarks
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
    /// ### Parameters
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
    pub(crate) fn add_reference_as_xmp_to_font(font_path: &Path, manifest_uri: &str) -> Result<()> {
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
    /// which should be deleted once the object is dropped.
    ///
    /// ### Parameters
    /// - `base_name` - Base name to use for the temporary file name
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
const SFNT_DIRECTORY_CHUNK_NAME: SfntTag = SfntTag { data: *b" DIR" }; // Sorts to just-after HEADER tag.

/// Implementation of ye olde SFNT
struct SfntFont {
    header: SfntHeader,
    directory: SfntDirectory,
    /// All the Tables in this font, keyed by SfntTag.
    tables: BTreeMap<SfntTag, Table>,
}

impl SfntFont {
    /// Reads a new instance from the given source.
    ///
    /// ### Parameters
    /// - `reader` - Input stream
    ///
    /// ### Returns
    /// Result containing an instance.
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
            let table: Table = {
                match entry.tag {
                    C2PA_TABLE_TAG => Table::C2PA(TableC2PA::from_reader(reader, offset, size)?),
                    HEAD_TABLE_TAG => Table::Head(TableHead::from_reader(reader, offset, size)?),
                    _ => Table::Unspecified(TableUnspecified::from_reader(reader, offset, size)?),
                }
            };
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
    ///
    /// ### Parameters
    /// - `destination` - Output stream
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
                    size_of::<SfntTableDirEntry>() as i64
                } else {
                    // We added some other number of tables
                    return Err(Error::FontSaveError);
                }
            }
            Ordering::Equal => 0,
            Ordering::Less => {
                if self.header.numTables - (self.tables.len() as u16) == 1 {
                    // Therefore, the actual table list should not contain
                    // the C2PA table - that's the only one we should ever
                    // be removing.
                    if self.tables.contains_key(&C2PA_TABLE_TAG) {
                        return Err(Error::FontSaveError);
                    }
                    // We removed exactly one table
                    -(size_of::<SfntTableDirEntry>() as i64)
                } else {
                    // We added some other number of tables. Weird, right?
                    return Err(Error::FontSaveError);
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
                        return Err(Error::FontSaveError);
                    }
                    let neo_entry = SfntTableDirEntry {
                        tag: entry.tag,
                        offset: ((entry.offset as i64) + td_derived_offset_bias) as u32,
                        checksum: match *tag {
                            C2PA_TABLE_TAG => table.checksum().0,
                            HEAD_TABLE_TAG => table.checksum().0,
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
                            return Err(Error::FontSaveError);
                        }
                        let neo_entry = SfntTableDirEntry {
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
                        return Err(Error::FontSaveError);
                    }
                },
            }
        }
        // If a 'C2PA' table is present, re-compute its directory-entry's
        // checksum...
        if let Some(c2pa_entry) = neo_directory
            .entries
            .iter_mut()
            .find(|entry| entry.tag == C2PA_TABLE_TAG)
        {
            if let Some(c2pa) = self.tables.get(&C2PA_TABLE_TAG) {
                c2pa_entry.checksum = c2pa.checksum().0;
            } else {
                // Code smell - keeping the directory and the tables separated.
                return Err(Error::FontSaveError);
            }
        }
        // ...allowing us to re-compute the whole-font checksum, if a 'head'
        // table is present...
        //
        // TBD - This ostensible_table two-step is just the pits:
        // "Hey, get me the barrel from the fridge marked PICKLES,
        //  okay thanks, now let me open it and seANCHOVIES WHY ARE THERE
        //  ANCHOVIES WHY MUST I ALWAYS DOUBLE-CHECK THE DATATYPE OF THE THINGS
        //  YOU ARE GIVING ME" so what we need instead of (or in addition to)
        // BTreeMap is a kind of hash-map where each key, if present, can have
        // a value of one specific unique data type (i.e, one of our Table
        // enums.)
        if let Some(ostensible_head) = self.tables.get(&HEAD_TABLE_TAG) {
            match ostensible_head {
                Table::Head(head) => {
                    if let Some(head_entry) = neo_directory
                        .entries
                        .iter_mut()
                        .find(|entry| entry.tag == HEAD_TABLE_TAG)
                    {
                        head_entry.checksum = head.checksum().0;
                    }
                }
                _ => {
                    // Tables and directory are out-of-sync
                    return Err(Error::FontSaveError);
                }
            };
        };

        // Get the checksum for the whole font, starting with the front matter...
        // TBD note this is wasted work, if there's no head table in which to
        // store the result.
        let font_cksum = self.header.checksum()
            + self.directory.checksum()
            + self
                .directory
                .physical_order()
                .iter()
                .fold(Wrapping(0_u32), |tables_cksum, entry| {
                    tables_cksum + Wrapping(entry.checksum)
                });

        // Rewrite the head table's checksumAdjustment. (This act does *not*
        // invalidate the checksum in the TDE for the 'head' table, which is
        // always treated as zero during check summing.
        if let Some(ostensible_head) = self.tables.get_mut(&HEAD_TABLE_TAG) {
            match ostensible_head {
                Table::Head(head) => {
                    head.checksumAdjustment = (Wrapping(SFNT_EXPECTED_CHECKSUM) - font_cksum).0;
                }
                _ => {
                    // Tables and directory are out-of-sync
                    return Err(Error::FontSaveError);
                }
            };
        };

        // TBD - Debug check - does a naive checksum of the font data yield
        // HEAD_MAGIC_NUMBER, as it should if everything is assembled as
        // expected?
        //
        // That's probably a really good idea with this early implementation,
        // since our current test matrix is rather sparse.

        // ...and now, with everything in sync, we can start writing; first,
        // the header.
        neo_header.write(destination)?;
        // Then the directory.
        neo_directory.write(destination)?;
        // The above items are fixed sizes which are even multiples of four;
        // therefore we can presume our current write offset.
        for entry in neo_directory.physical_order().iter() {
            // TBD - current-offset consistency-checking:
            //  1. Did we go backwards (despite the request for physical_order)?
            //  2. Did we go more than 3 bytes forward (file has excess padding)?
            // destination.seek(SeekFrom::Start(entry.offset as u64))?;
            // Note that dest stream is not seekable.
            // Write out the (real and fake) tables.
            match &self.tables[&entry.tag] {
                Table::C2PA(c2pa) => c2pa.write(destination)?,
                Table::Head(head) => head.write(destination)?,
                Table::Unspecified(un) => un.write(destination)?,
            }
        }
        // If we made it here, it all worked.
        Ok(())
    }

    /// Add an empty C2PA table in this font, at the end, so we don't have to
    /// re-position any existing tables.
    ///
    /// ### Parameters
    /// - `self` - Instance
    fn append_empty_c2pa_table(&mut self) -> Result<()> {
        // Create the empty table
        let c2pa_table = TableC2PA::default();
        // Size of the empty table in the font file
        let empty_table_size = size_of::<TableC2PARaw>() as u32;
        // Offset just past the last valid byte of font table data. This should
        // point to pad bytes, XML data, or private data, but nothing else.
        let existing_table_data_limit = match self.directory.physical_order().last() {
            Some(last_phys_entry) => last_phys_entry.offset + last_phys_entry.length,
            None => (size_of::<SfntHeader>() + size_of::<SfntTableDirEntry>()) as u32,
        };
        // Padding needed before the new table.
        let pre_padding = (4 - (existing_table_data_limit & 3)) & 3;
        // And a directory entry for it. The easiest approach is to add the table
        // to the end of the font; for one thing, resizing it is much simpler,
        // since we'll just need to change some size fields (and not re-flow
        // other tables.
        let c2pa_entry = SfntTableDirEntry {
            tag: C2PA_TABLE_TAG,
            offset: existing_table_data_limit + pre_padding,
            length: empty_table_size,
            checksum: c2pa_table.checksum().0,
        };
        // Store the new directory entry & table.
        self.directory.entries.push(c2pa_entry);
        self.tables.insert(C2PA_TABLE_TAG, Table::C2PA(c2pa_table));
        // Count the table, grow the total size, grow, the "SFNT size"
        self.header.numTables += 1;
        // (TBD compression - conflating comp/uncomp sizes here.)
        // (TBD philosophy - better to just re-compute these from scratch, yeah?)
        self.header.searchRange = 0; // TBD fix these
        self.header.rangeShift = 0;
        self.header.entrySelector = 0;
        // Success at last
        Ok(())
    }
}

/// Definitions for the SFNT file header and Table Directory structures are in
/// the font_io module, because WOFF support needs to use them as well.
impl SfntHeader {
    /// Reads a new instance from the given source.
    ///
    /// ### Parameters
    /// - `reader` - Input stream
    ///
    /// ### Returns
    /// Result containing an instance.
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
    ///
    /// ### Parameters
    /// - `destination` - Output stream
    fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        destination.write_u32::<BigEndian>(self.sfntVersion)?;
        destination.write_u16::<BigEndian>(self.numTables)?;
        destination.write_u16::<BigEndian>(self.searchRange)?;
        destination.write_u16::<BigEndian>(self.entrySelector)?;
        destination.write_u16::<BigEndian>(self.rangeShift)?;
        Ok(())
    }

    /// Computes the checksum for this font.
    ///
    /// ### Parameters
    /// - `self` - Instance
    ///
    /// ### Returns
    /// Wrapping<u32> with the checksum.
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

impl SfntTableDirEntry {
    /// Reads a new instance from the given source.
    ///
    /// ### Parameters
    /// - `reader` - Input stream
    ///
    /// ### Returns
    /// Result containing an instance.
    pub(crate) fn from_reader<T: Read + Seek + ?Sized>(reader: &mut T) -> Result<Self> {
        Ok(Self {
            tag: SfntTag::from_reader(reader)?,
            checksum: reader.read_u32::<BigEndian>()?,
            offset: reader.read_u32::<BigEndian>()?,
            length: reader.read_u32::<BigEndian>()?,
        })
    }

    /// Serializes this instance to the given writer.
    ///
    /// ### Parameters
    /// - `self` - Instance
    /// - `destination` - Output stream
    pub(crate) fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        self.tag.write(destination)?;
        destination.write_u32::<BigEndian>(self.checksum)?;
        destination.write_u32::<BigEndian>(self.offset)?;
        destination.write_u32::<BigEndian>(self.length)?;
        Ok(())
    }

    /// Computes the checksum for this entry.
    ///
    /// ### Parameters
    /// - `self` - Instance
    ///
    /// ### Returns
    /// Wrapping<u32> with the checksum.
    pub(crate) fn checksum(&self) -> Wrapping<u32> {
        Wrapping(u32::from_be_bytes(self.tag.data))
            + Wrapping(self.checksum)
            + Wrapping(self.offset)
            + Wrapping(self.length)
    }
}

impl Default for SfntTableDirEntry {
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
///
/// TBD - SfntTableDir or Directory, in keeping with SfntTableDirEntry?
#[derive(Debug)]
struct SfntDirectory {
    entries: Vec<SfntTableDirEntry>,
}

impl SfntDirectory {
    /// Constructs a new, empty, instance.
    ///
    /// ### Returns
    /// A new instance.
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            entries: Vec::new(),
        })
    }

    /// Reads a new instance from the given source.
    ///
    /// ### Parameters
    /// - `reader` - Input stream
    /// - `offset` - Position in stream where the table begins
    /// - `size`   - Size of the table in bytes.
    ///
    /// ### Returns
    /// Result containing an instance.
    pub(crate) fn from_reader<T: Read + Seek + ?Sized>(
        reader: &mut T,
        entry_count: usize,
    ) -> Result<Self> {
        let mut the_directory = SfntDirectory::new()?;
        for _entry in 0..entry_count {
            the_directory
                .entries
                .push(SfntTableDirEntry::from_reader(reader)?);
        }
        Ok(the_directory)
    }

    /// Serializes this instance to the given writer.
    ///
    /// ### Parameters
    /// - `self` - Instance
    /// - `destination` - Output stream
    fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        for entry in self.entries.iter() {
            entry.write(destination)?;
        }
        Ok(())
    }

    /// Returns an array which contains the indices of this directory's entries,
    /// arranged in increasing order of `offset` field.
    ///
    /// ### Parameters
    /// - `self` - Instance
    ///
    /// ### Returns
    /// Vector of copies of our entries, in increasing 'offset' order.
    fn physical_order(&self) -> Vec<SfntTableDirEntry> {
        let mut physically_ordered_entries = self.entries.clone();
        physically_ordered_entries.sort_by_key(|e| e.offset);
        physically_ordered_entries
    }

    /// Computes the checksum for this directory.
    ///
    /// ### Parameters
    /// - `self` - Instance
    ///
    /// ### Returns
    /// Wrapping<u32> with the checksum.
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
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ChunkType {
    /// Whole-container header.
    Header,
    /// Table directory entry or entries.
    Directory,
    /// Table data included in C2PA hash.
    TableDataIncluded,
    /// Table data excluded from C2PA hash.
    TableDataExcluded,
}

/// Represents regions within a font file that may be of interest when it
/// comes to hashing data for C2PA.
#[derive(Debug, Eq, PartialEq)]
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
    /// Gets a collection of positions of chunks within the font.
    ///
    /// ### Parameters
    /// - `reader` - Source stream to read data from
    ///
    /// ### Returns
    /// A collection of positions/offsets and length to omit from hashing.
    fn get_chunk_positions<T: Read + Seek + ?Sized>(
        &self,
        reader: &mut T,
    ) -> core::result::Result<Vec<ChunkPosition>, Self::Error>;
}

/// Reads in chunks for an SFNT file
impl ChunkReader for SfntIO {
    type Error = crate::error::Error;

    /// Get a map of all the chunks in this file.
    ///
    /// ### Parameters
    /// - `self` - Instance
    /// - `reader` - Stream to interpret.
    ///
    /// ### Returns
    /// Result with vector of chunks
    fn get_chunk_positions<T: Read + Seek + ?Sized>(
        &self,
        reader: &mut T,
    ) -> core::result::Result<Vec<ChunkPosition>, Self::Error> {
        // Rewind to start and read the SFNT header and directory - that's
        // really all we need in order to map the chunks.
        reader.rewind()?;
        let header = SfntHeader::from_reader(reader)?;
        let directory = SfntDirectory::from_reader(reader, header.numTables as usize)?;

        // The first chunk excludes the header from hashing
        let mut positions: Vec<ChunkPosition> = Vec::new();
        positions.push(ChunkPosition {
            offset: 0,
            length: size_of::<SfntHeader>(),
            name: SFNT_HEADER_CHUNK_NAME.data,
            chunk_type: ChunkType::Header,
        });

        // The second chunk excludes the directory
        positions.push(ChunkPosition {
            offset: size_of::<SfntHeader>(),
            length: header.numTables as usize * size_of::<SfntTableDirEntry>(),
            name: SFNT_DIRECTORY_CHUNK_NAME.data,
            chunk_type: ChunkType::Directory,
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
                        name: entry.tag.data,
                        chunk_type: ChunkType::TableDataIncluded,
                    });
                    positions.push(ChunkPosition {
                        offset: entry.offset as usize + 8_usize,
                        length: 4_usize,
                        name: entry.tag.data,
                        chunk_type: ChunkType::TableDataExcluded,
                    });
                    positions.push(ChunkPosition {
                        offset: entry.offset as usize + 12_usize,
                        length: 42_usize,
                        name: entry.tag.data,
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
        Ok(positions)
    }
}

/// Adds C2PA manifest store data to a font file
///
/// ### Parameters
/// - `font_path` - Path to a font file
/// - `manifest_store_data` - C2PA manifest store data to add to the font file
fn add_c2pa_to_font(font_path: &Path, manifest_store_data: &[u8]) -> Result<()> {
    process_file_with_streams(font_path, move |input_stream, temp_file| {
        // Add the C2PA data to the temp file
        add_c2pa_to_stream(input_stream, temp_file.get_mut_file(), manifest_store_data)
    })
}

/// Adds C2PA manifest store data to a font stream
///
/// ### Parameters
/// - `source` - Source stream to read initial data from
/// - `destination` - Destination stream to write C2PA manifest store data
/// - `manifest_store_data` - C2PA manifest store data to add to the font stream
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
    let mut font = SfntFont::from_reader(source).map_err(|_| Error::FontLoadError)?;
    // Install the provide active_manifest_uri in this font's C2PA table, adding
    // that table if needed.
    match font.tables.get_mut(&C2PA_TABLE_TAG) {
        // If there isn't one, create it.
        None => {
            font.tables.insert(
                C2PA_TABLE_TAG,
                Table::C2PA(TableC2PA::new(None, Some(manifest_store_data.to_vec()))),
            );
        }
        // If there is, replace its `active_manifest_uri` value with the
        // provided one.
        Some(ostensible_c2pa_table) => {
            match ostensible_c2pa_table {
                Table::C2PA(c2pa_table) => {
                    c2pa_table.manifest_store = Some(manifest_store_data.to_vec());
                }
                _ => {
                    // Non-C2PA table with C2PA tag
                    return Err(Error::FontLoadError);
                }
            };
        }
    };
    font.write(destination).map_err(|_| Error::FontSaveError)?;
    Ok(())
}

/// Adds the manifest URI reference to the font at the given path.
///
/// ### Parameters
/// - `font_path` - Path to a font file
/// - `manifest_uri` - Reference URI to a manifest store
#[allow(dead_code)]
fn add_reference_to_font(font_path: &Path, manifest_uri: &str) -> Result<()> {
    process_file_with_streams(font_path, move |input_stream, temp_file| {
        // Write the manifest URI to the stream
        add_reference_to_stream(input_stream, temp_file.get_mut_file(), manifest_uri)
    })
}

/// Adds the specified reference to the font.
///
/// ### Parameters
/// - `source` - Source stream to read initial data from
/// - `destination` - Destination stream to write data with new reference
/// - `manifest_uri` - Reference URI to a manifest store
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
    let mut font = SfntFont::from_reader(source).map_err(|_| Error::FontLoadError)?;
    // Install the provide active_manifest_uri in this font's C2PA table, adding
    // that table if needed.
    match font.tables.get_mut(&C2PA_TABLE_TAG) {
        // If there isn't one, create it.
        None => {
            font.tables.insert(
                C2PA_TABLE_TAG,
                Table::C2PA(TableC2PA::new(Some(manifest_uri.to_string()), None)),
            );
        }
        // If there is, replace its `active_manifest_uri` value with the
        // provided one.
        Some(ostensible_c2pa_table) => {
            match ostensible_c2pa_table {
                Table::C2PA(c2pa_table) => {
                    c2pa_table.active_manifest_uri = Some(manifest_uri.to_string());
                }
                _ => {
                    // Non-C2PA table with C2PA tag
                    return Err(Error::FontLoadError);
                }
            };
        }
    };
    font.write(destination).map_err(|_| Error::FontSaveError)?;
    Ok(())
}

/// Adds the required chunks to the stream for supporting C2PA, if the chunks are
/// already present nothing is done.
///
/// ### Parameters
/// - `input_stream` - Source stream to read initial data from
/// - `output_stream` - Destination stream to write data with the added required
///                     chunks
///
/// ### Remarks
/// Neither streams are rewound before and/or after the operation, so it is up
/// to the caller.
///
/// ### Returns
/// A Result indicating success or failure
fn add_required_chunks_to_stream<TReader, TWriter>(
    input_stream: &mut TReader,
    output_stream: &mut TWriter,
) -> Result<()>
where
    TReader: Read + Seek + ?Sized,
    TWriter: Read + Seek + ?Sized + Write,
{
    // Read the font from the input stream
    let mut font = SfntFont::from_reader(input_stream).map_err(|_| Error::FontLoadError)?;
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
///
/// ### Parameters
/// - `file_path` - Valid path to a file to open in a buffer reader
///
/// ### Returns
/// A BufReader<File> object
fn open_bufreader_for_file(file_path: &Path) -> Result<BufReader<File>> {
    let file = File::open(file_path)?;
    Ok(BufReader::new(file))
}

/// Processes a font file using a streams to process.
///
/// ### Parameters
/// - `font_path` - Path to the font file to process
/// - `callback` - Method to process the stream
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
/// ### Parameters
/// - `font_path` - File path to the font file to read reference from.
///
/// ### Returns
/// If a reference is available, it will be returned.
#[allow(dead_code)]
fn read_reference_from_font(font_path: &Path) -> Result<Option<String>> {
    // open the font source
    let mut font_stream = open_bufreader_for_file(font_path)?;
    read_reference_from_stream(&mut font_stream)
}

/// Reads the C2PA manifest store reference from the stream.
///
/// ### Parameters
/// - `source` - Source font stream to read reference from.
///
/// ### Returns
/// If a reference is available, it will be returned.
#[allow(dead_code)]
fn read_reference_from_stream<TSource>(source: &mut TSource) -> Result<Option<String>>
where
    TSource: Read + Seek + ?Sized,
{
    match read_c2pa_from_stream(source) {
        Ok(c2pa_data) => Ok(c2pa_data.active_manifest_uri.to_owned()),
        Err(Error::JumbfNotFound) => Ok(None),
        Err(_) => Err(Error::DeserializationError),
    }
}

/// Remove the `C2PA` font table from the font file.
///
/// ### Parameters
/// - `font_path` - path to the font file to remove C2PA from
fn remove_c2pa_from_font(font_path: &Path) -> Result<()> {
    process_file_with_streams(font_path, move |input_stream, temp_file| {
        // Remove the C2PA manifest store from the stream
        remove_c2pa_from_stream(input_stream, temp_file.get_mut_file())
    })
}

/// Remove the `C2PA` font table from the font data stream, writing to the
/// destination.
///
/// ### Parameters
/// - `source` - Source data stream containing font data
/// - `destination` - Destination data stream to write new font data with the
///                   C2PA table removed
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
    let mut font = SfntFont::from_reader(source).map_err(|_| Error::FontLoadError)?;
    // Remove the table from the collection
    font.tables.remove(&C2PA_TABLE_TAG);
    // And write it to the destination stream
    font.write(destination).map_err(|_| Error::FontSaveError)?;
    Ok(())
}

/// Removes the reference to the active manifest from the source stream, writing
/// to the destination.
///
/// ### Parameters
/// - `source` - Source data stream containing font data
/// - `destination` - Destination data stream to write new font data with the
///                   active manifest reference removed
///
/// ### Returns
/// Optional active manifest URI reference
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
    let mut font = SfntFont::from_reader(source).map_err(|_| Error::FontLoadError)?;
    let old_manifest_uri_maybe = match font.tables.get_mut(&C2PA_TABLE_TAG) {
        // If there isn't one, how pleasant, there will be so much less to do.
        None => None,
        // If there is, and it has Some `active_manifest_uri`, then mutate that
        // to None, and return the former value.
        Some(ostensible_c2pa_table) => {
            match ostensible_c2pa_table {
                Table::C2PA(c2pa_table) => {
                    if c2pa_table.active_manifest_uri.is_none() {
                        None
                    } else {
                        // TBD this cannot really be the idiomatic way, can it?
                        let old_manifest_uri = c2pa_table.active_manifest_uri.clone();
                        c2pa_table.active_manifest_uri = None;
                        old_manifest_uri
                    }
                }
                _ => {
                    // Non-C2PA table with C2PA tag
                    return Err(Error::FontLoadError);
                }
            }
        }
    };
    font.write(destination).map_err(|_| Error::FontSaveError)?;
    Ok(old_manifest_uri_maybe)
}

/// Gets a collection of positions of hash objects, which are to be excluded from the hashing.
///
/// ### Parameters
/// - `reader` - Reader object used to read object locations from
///
/// ### Returns
/// A collection of positions/offsets and length to omit from hashing.
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
            // added as "other"
            ChunkType::Header | ChunkType::Directory | ChunkType::TableDataExcluded => {
                locations.push(HashObjectPositions {
                    offset: chunk.offset,
                    length: chunk.length,
                    htype: HashBlockObjectType::Other,
                });
            }
            ChunkType::TableDataIncluded => {
                locations.push(HashObjectPositions {
                    offset: chunk.offset,
                    length: chunk.length,
                    htype: HashBlockObjectType::Cai,
                });
            }
        }
    }
    Ok(locations)
}

/// Reads the `C2PA` font table from the data stream
///
/// ### Parameters
/// - `reader` - data stream reader to read font data from
///
/// ### Returns
/// A result containing the `C2PA` font table data
fn read_c2pa_from_stream<T: Read + Seek + ?Sized>(reader: &mut T) -> Result<TableC2PA> {
    let sfnt = SfntFont::from_reader(reader).map_err(|_| Error::FontLoadError)?;
    let c2pa_table: Option<TableC2PA> = match sfnt.tables.get(&C2PA_TABLE_TAG) {
        None => None,
        Some(ostensible_c2pa_table) => match ostensible_c2pa_table {
            Table::C2PA(bonafied_c2pa_table) => Some(bonafied_c2pa_table.clone()),
            _ => {
                // Non-C2PA table with C2PA tag
                return Err(Error::FontLoadError);
            }
        },
    };
    c2pa_table.ok_or(Error::JumbfNotFound)
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
    }

    /// Verify that short file fails to chunk-parse at all
    #[test]
    fn get_chunk_positions_without_any_font() {
        let font_data = vec![
            0x4f, 0x54, 0x54, 0x4f, // OTTO
            0x00, // ...and then one more byte, and that's it.
        ];
        let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
        let sfnt_io = SfntIO {};
        assert_err!(sfnt_io.get_chunk_positions(&mut font_stream));
    }

    /// Verify chunk-parsing behavior for empty font with just the header
    #[test]
    fn get_chunk_positions_without_any_tables() {
        let font_data = vec![
            0x4f, 0x54, 0x54, 0x4f, // OTTO
            0x00, 0x00, 0x00, 0x00, // 0 tables / 0
            0x00, 0x00, 0x00, 0x00, // 0 / 0
        ];
        let mut font_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&font_data);
        let sfnt_io = SfntIO {};
        let positions = sfnt_io.get_chunk_positions(&mut font_stream).unwrap();
        // Should have two positions reported:
        assert_eq!(2, positions.len());
        // First is the header
        assert_eq!(
            positions.first().unwrap(),
            &ChunkPosition {
                offset: 0_usize,
                length: 12_usize,
                name: SFNT_HEADER_CHUNK_NAME.data,
                chunk_type: ChunkType::Header,
            }
        );
        // Second is an empty table directory
        assert_eq!(
            positions.get(1).unwrap(),
            &ChunkPosition {
                offset: 12_usize,
                length: 0_usize,
                name: SFNT_DIRECTORY_CHUNK_NAME.data,
                chunk_type: ChunkType::Directory,
            }
        );
    }

    /// Verify when reading the object locations for hashing, we get zero
    /// positions when the font does not contain a C2PA font table
    #[test]
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
        // Should have 3 positions reported for the table directory, table
        // record, and the table data
        assert_eq!(3, positions.len());
        // First is the header
        assert_eq!(
            positions.first().unwrap(),
            &ChunkPosition {
                offset: 0_usize,
                length: 12_usize,
                name: SFNT_HEADER_CHUNK_NAME.data,
                chunk_type: ChunkType::Header,
            }
        );
        // Second is a single-entry table directory
        assert_eq!(
            positions.get(1).unwrap(),
            &ChunkPosition {
                offset: 12_usize,
                length: 16_usize,
                name: SFNT_DIRECTORY_CHUNK_NAME.data,
                chunk_type: ChunkType::Directory,
            }
        );
        // Third is the C2PB table
        assert_eq!(
            positions.get(2).unwrap(),
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
        assert_eq!(16, positions.len());
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

    /// Verifies the ability to write/read C2PA manifest store data to/from an
    /// OpenType font
    #[test]
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

    /// Verifies the ability to write/read C2PA manifest store data to/from an
    /// OpenType font
    #[test]
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
