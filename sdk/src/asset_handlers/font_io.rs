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

use core::{convert::TryFrom, mem::size_of, num::Wrapping, str::from_utf8};
use std::io::{Read, Seek, SeekFrom, Write};

use asn1_rs::nom::AsBytes;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};

use crate::error::{Error, Result};

// Types for supporting fonts in any container.

/// Errors that can occur when working with fonts.
#[derive(Debug, thiserror::Error)]
pub enum FontError {
    /// Failed to parse or de-serialize font data
    #[error("Failed to de-serialize data")]
    DeserializationError,

    /// Failed to load a font.
    #[error("Failed to load font")]
    LoadError,

    /// Failed to load the font's 'C2PA' table, either because it was missing or
    /// because it was truncated/bad.
    #[error("C2PA table bad or missing")]
    LoadC2PATableBadMissing,

    /// The font's 'C2PA' table contains invalid UTF-8 data.
    #[error("C2PA table manifest data is not valid UTF-8")]
    LoadC2PATableInvalidUtf8,

    /// The font's 'C2PA' table is truncated.
    #[error("C2PA table claimed sizes exceed actual")]
    LoadC2PATableTruncated,

    /// The font's 'head' table is bad or missing.
    #[error("head table bad or missing")]
    LoadHeadTableBadMissing,

    /// The font's SFNT header is bad or missing.
    #[error("SFNT header bad or missing")]
    LoadSfntHeaderBadMissing,

    /// Failed to save the font.
    #[error("Failed to save font")]
    SaveError,

    /// The font is missing a valid 'magic' number, therefore an unknown font type.
    #[error("Unknown font format, the 'magic' number is not recognized.")]
    UnknownMagic,

    /// Invalid or unsupported font format
    #[error("Invalid or unsupported font format")]
    Unsupported,
}

/// Helper method for wrapping a FontError into a crate level error.
pub(crate) fn wrap_font_err(e: FontError) -> Error {
    Error::FontError(e)
}

/// Four-character tag which names a font table.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct SfntTag {
    pub data: [u8; 4],
}

#[allow(dead_code)] // TBD - Is creating some UTs sufficient to quicken/animate this code?
impl SfntTag {
    /// Constructs a new instance with a specified tag.
    pub(crate) fn new(source_data: [u8; 4]) -> Self {
        Self { data: source_data }
    }

    /// Creates a new instance, reading data from the provided source.
    pub(crate) fn from_reader<T: Read + Seek + ?Sized>(reader: &mut T) -> Result<Self> {
        Ok(Self::new([
            reader.read_u8()?,
            reader.read_u8()?,
            reader.read_u8()?,
            reader.read_u8()?,
        ]))
    }

    /// Serializes this instance to the given writer.
    pub(crate) fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        destination.write_all(&self.data)?;
        Ok(())
    }
}

impl std::fmt::Display for SfntTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.data))
    }
}

impl std::fmt::Debug for SfntTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.data))
    }
}

/// Round the given value up to the next multiple of four (4).
///
/// # Examples
/// ```ignore
/// // Cannot work as written because font_io is private.
/// use c2pa::asset_handlers::font_io::align_to_four;
/// let forties = (align_to_four(36), align_to_four(37));
/// assert_eq!(forties.0, 36);
/// assert_eq!(forties.1, 40);
/// ```
pub(crate) fn align_to_four(size: usize) -> usize {
    (size + 3) & (!3)
}

/// 32-bit font-format identification magic number.
///
/// Note that Embedded OpenType and MicroType Express formats cannot be detected
/// with a simple magic-number sniff. Conceivably, EOT could be dealt with as a
/// variation on SFNT, but MTX will needs more exotic handling.
pub(crate) enum Magic {
    /// 'OTTO' - OpenType
    OpenType = 0x4f54544f,
    /// FIXED 1.0 - TrueType (or possibly v1.0 Embedded OpenType)
    TrueType = 0x00010000,
    /// 'typ1' - PostScript Type 1
    PostScriptType1 = 0x74797031,
    /// 'true' - TrueType fonts for OS X / iOS
    AppleTrue = 0x74727565,
    /// 'wOFF' - WOFF 1.0
    Woff = 0x774f4646,
    /// 'wOF2' - WOFF 2.0
    Woff2 = 0x774f4632,
}

/// Tags for the font tables we care about.

/// Tag for the 'C2PA' table.
#[allow(dead_code)]
pub(crate) const C2PA_TABLE_TAG: SfntTag = SfntTag { data: *b"C2PA" };

/// Tag for the 'head' table in a font.
#[allow(dead_code)]
pub(crate) const HEAD_TABLE_TAG: SfntTag = SfntTag { data: *b"head" };

/// Spec-mandated value for 'head'::magicNumber
pub(crate) const HEAD_TABLE_MAGICNUMBER: u32 = 0x5f0f3cf5;

/// The 'head' table's checksumAdjustment value should be such that the whole-
/// font checksum comes out to this value.
#[allow(dead_code)]
pub(crate) const SFNT_EXPECTED_CHECKSUM: u32 = 0xb1b0afba;

/// Used to attempt conversion from u32 to a Magic value.
impl TryFrom<u32> for Magic {
    type Error = FontError;

    /// Try to match the given u32 value to a known font-format magic number.
    fn try_from(v: u32) -> core::result::Result<Self, Self::Error> {
        match v {
            ot if ot == Magic::OpenType as u32 => Ok(Magic::OpenType),
            tt if tt == Magic::TrueType as u32 => Ok(Magic::TrueType),
            t1 if t1 == Magic::PostScriptType1 as u32 => Ok(Magic::PostScriptType1),
            at if at == Magic::AppleTrue as u32 => Ok(Magic::AppleTrue),
            w1 if w1 == Magic::Woff as u32 => Ok(Magic::Woff),
            w2 if w2 == Magic::Woff2 as u32 => Ok(Magic::Woff2),
            _unknown => Err(FontError::UnknownMagic),
        }
    }
}

/// Computes a 32-bit big-endian OpenType-style checksum on the given byte
/// array, which is presumed to start on a 4-byte boundary.
///
/// # Remarks
/// Note that trailing pad bytes do not affect this checksum - it's not a real
/// CRC.
///
/// # Panics
/// Panics if the the `bytes` array is not aligned on a 4-byte boundary.
#[allow(dead_code)]
pub(crate) fn checksum(bytes: &[u8]) -> Wrapping<u32> {
    // Cut your pie into 1x4cm pieces to serve
    let words = bytes.chunks_exact(size_of::<u32>());
    // ...and then any remainder...
    let frag_cksum: Wrapping<u32> = Wrapping(
        // (away, mayhap, with issue #32463)
        words
            .remainder()
            .iter()
            .fold(Wrapping(0_u32), |acc, byte| {
                // At some point, it should be possible to:
                // - Remove the `Wrapping(...)` surrounding the outer expression
                // - Get rid of `.0` and just access plain `acc`
                // - Get rid of `.0` down there getting applied to the end of
                //   this .fold(), as well as
                // - Get rid of the `Wrapping(...)` in this next expression
                // but unfortunately as of this writing, attempting to call
                // `.rotate_left` on a `Wrapping<u32>` fails:
                //   use of unstable library feature 'wrapping_int_impl', see issue
                //     #32463 <https://github.com/rust-lang/rust/issues/32463>
                Wrapping(acc.0.rotate_left(u8::BITS) + *byte as u32)
            })
            .0 // (goes away, mayhap, when issue #32463 is done)
            .rotate_left(u8::BITS * (size_of::<u32>() - words.remainder().len()) as u32),
    );
    // Sum all the exact chunks...
    let chunks_cksum: Wrapping<u32> = words.fold(Wrapping(0_u32), |running_cksum, exact_chunk| {
        running_cksum + Wrapping(BigEndian::read_u32(exact_chunk))
    });
    // Combine ingredients & serve.
    chunks_cksum + frag_cksum
}

/// Computes a 32-bit big-endian OpenType-style checksum on the given byte
/// array, which is presumed to start on a 4-byte boundary.  The `bias`
/// parameter specifies the starting byte offset.
///
/// # Remarks
/// Note that trailing pad bytes do not affect this checksum - it's not a real
/// CRC.
#[allow(dead_code)]
pub(crate) fn checksum_biased(bytes: &[u8], bias: u32) -> Wrapping<u32> {
    match bias & 3 {
        0 => checksum(bytes),
        1 => Wrapping(BigEndian::read_u24(bytes)) + checksum(&(bytes[3..bytes.len()])),
        2 => Wrapping(BigEndian::read_u16(bytes) as u32) + checksum(&(bytes[2..bytes.len()])),
        3 => Wrapping(bytes[0] as u32) + checksum(&(bytes[1..bytes.len()])),
        4_u32..=u32::MAX => todo!(),
    }
}

/// Assembles two u16 values (with `hi` being the more-significant u16 halfword,
/// and `lo` being the less-significant u16 halfword) into a u32, returning a
/// u32 fullword composed of the given halfwords, with `hi` in the
/// more-significant position.
///
/// # Examples
/// ```ignore
/// // Cannot work as written because font_io is private.
/// use c2pa::asset_handlers::font_io::u32_from_u16_pair;
/// let full_word = u32_from_u16_pair(0x1234, 0x5678);
/// assert_eq!(full_word, 0x12345678);
/// ```
#[allow(dead_code)]
pub(crate) fn u32_from_u16_pair(hi: u16, lo: u16) -> Wrapping<u32> {
    // TBD - Supposedly the bytemuck crate, already in this project, can help us
    // with stuff like this.
    Wrapping((hi as u32 * 65536) + lo as u32)
}

/// Gets the high-order u32 from the given u64 (extracted from the
/// more-significant 32 bits of the given value).
///
/// # Examples
/// ```ignore
/// // Cannot work as written because font_io is private.
/// use c2pa::asset_handlers::font_io::u32_from_u64_hi;
/// let hi_word = u32_from_u64_hi(0x123456789abcdef0);
/// assert_eq!(hi_word, 0x12345678);
/// ```
#[allow(dead_code)]
pub(crate) fn u32_from_u64_hi(big: u64) -> Wrapping<u32> {
    Wrapping(((big & 0xffffffff00000000) >> 32) as u32)
}

/// Gets the low-order u32 from the given u64 (extracted from the
/// less-significant 32 bits of the given value).
///
/// # Examples
/// ```ignore
/// // Cannot work as written because font_io is private.
/// use c2pa::asset_handlers::font_io::u32_from_u64_lo;
/// let lo_word = u32_from_u64_lo(0x123456789abcdef0);
/// assert_eq!(lo_word, 0x9abcdef0);
/// ```
#[allow(dead_code)]
pub(crate) fn u32_from_u64_lo(big: u64) -> Wrapping<u32> {
    Wrapping((big & 0x00000000ffffffff) as u32)
}

pub(crate) trait Table {
    /// Computes the checksum for this table.
    fn checksum(&self) -> Wrapping<u32>;

    /// Returns the total length in bytes of this table.
    fn len(&self) -> usize;

    /// Serializes this instance to the given writer.
    fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()>;
}

/// 'C2PA' font table as it appears in storage
#[derive(Debug, Default)]
#[repr(C, packed(1))] // As defined by the C2PA spec.
#[allow(non_snake_case)] // As named by the C2PA spec.
pub(crate) struct TableC2PARaw {
    /// Specifies the major version of the C2PA font table.
    pub majorVersion: u16,
    /// Specifies the minor version of the C2PA font table.
    pub minorVersion: u16,
    /// Offset from the beginning of the C2PA font table to the section
    /// containing a URI to the active manifest. If a URI is not provided a
    /// NULL offset = 0x0000 should be used.
    pub activeManifestUriOffset: u32,
    /// Length of URI in bytes.
    pub activeManifestUriLength: u16,
    /// Reserved for future use.
    pub reserved: u16,
    /// Offset from the beginning of the C2PA font table to the section
    /// containing a C2PA Manifest Store. If a Manifest Store is not provided a
    /// NULL offset = 0x0000 should be used.
    pub manifestStoreOffset: u32,
    /// Length of the C2PA Manifest Store data in bytes.
    pub manifestStoreLength: u32,
}

impl TableC2PARaw {
    /// Creates a new instance, reading data from the provided source.
    pub(crate) fn from_reader<T: Read + Seek + ?Sized>(reader: &mut T) -> Result<Self> {
        Ok(Self {
            majorVersion: reader.read_u16::<BigEndian>()?,
            minorVersion: reader.read_u16::<BigEndian>()?,
            activeManifestUriOffset: reader.read_u32::<BigEndian>()?,
            activeManifestUriLength: reader.read_u16::<BigEndian>()?,
            reserved: reader.read_u16::<BigEndian>()?,
            manifestStoreOffset: reader.read_u32::<BigEndian>()?,
            manifestStoreLength: reader.read_u32::<BigEndian>()?,
        })
    }

    pub(crate) fn from_table(c2pa: &TableC2PA) -> Self {
        Self {
            majorVersion: c2pa.major_version,
            minorVersion: c2pa.minor_version,
            activeManifestUriOffset: if let Some(_uri) = &c2pa.active_manifest_uri {
                size_of::<TableC2PARaw>() as u32
            } else {
                0_u32
            },
            activeManifestUriLength: if let Some(uri) = &c2pa.active_manifest_uri {
                uri.len() as u16
            } else {
                0_u16
            },
            reserved: 0,
            manifestStoreOffset: if let Some(_manifest_store) = &c2pa.manifest_store {
                size_of::<TableC2PARaw>() as u32
                    + if let Some(uri) = &c2pa.active_manifest_uri {
                        uri.len() as u32
                    } else {
                        0_u32
                    }
            } else {
                0
            },
            manifestStoreLength: if let Some(manifest_store) = &c2pa.manifest_store {
                manifest_store.len() as u32
            } else {
                0
            },
        }
    }

    /// Serializes this instance to the given writer.
    pub(crate) fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        destination.write_u16::<BigEndian>(self.majorVersion)?;
        destination.write_u16::<BigEndian>(self.minorVersion)?;
        destination.write_u32::<BigEndian>(self.activeManifestUriOffset)?;
        destination.write_u16::<BigEndian>(self.activeManifestUriLength)?;
        destination.write_u16::<BigEndian>(self.reserved)?;
        destination.write_u32::<BigEndian>(self.manifestStoreOffset)?;
        destination.write_u32::<BigEndian>(self.manifestStoreLength)?;
        Ok(())
    }

    /// Computes the checksum for this instance.
    pub(crate) fn checksum(&self) -> Wrapping<u32> {
        // Start with the fixed part
        let mut cksum = u32_from_u16_pair(self.majorVersion, self.minorVersion);
        cksum += self.activeManifestUriOffset;
        cksum += u32_from_u16_pair(self.activeManifestUriLength, self.reserved);
        cksum += self.manifestStoreOffset + self.manifestStoreLength;
        cksum
    }
}

/// 'C2PA' font table, fully loaded.
#[derive(Clone, Debug)]
pub(crate) struct TableC2PA {
    /// Major version of the C2PA table record
    pub major_version: u16,
    /// Minor version of the C2PA table record
    pub minor_version: u16,
    /// Optional URI to an active manifest
    pub active_manifest_uri: Option<String>,
    /// Optional embedded manifest store
    pub manifest_store: Option<Vec<u8>>,
}

impl TableC2PA {
    /// Constructs a new, empty, instance.
    pub(crate) fn new(
        active_manifest_uri: Option<String>,
        manifest_store: Option<Vec<u8>>,
    ) -> Self {
        Self {
            active_manifest_uri,
            manifest_store,
            ..TableC2PA::default()
        }
    }

    /// Creates a new instance, reading data from the provided source at a
    /// specific offset.
    pub(crate) fn from_reader<T: Read + Seek + ?Sized>(
        reader: &mut T,
        offset: u64,
        size: usize,
    ) -> Result<TableC2PA> {
        if size < size_of::<TableC2PARaw>() {
            Err(wrap_font_err(FontError::LoadC2PATableTruncated))
        } else {
            let mut active_manifest_uri: Option<String> = None;
            let mut manifest_store: Option<Vec<u8>> = None;
            // Read the initial fixed-sized portion of the table
            reader.seek(SeekFrom::Start(offset))?;
            let raw_table = TableC2PARaw::from_reader(reader)?;
            // Check parameters
            if size
                < size_of::<TableC2PARaw>()
                    + raw_table.activeManifestUriLength as usize
                    + raw_table.manifestStoreLength as usize
            {
                return Err(wrap_font_err(FontError::LoadC2PATableTruncated));
            }
            // If a remote manifest URI is present, unpack it from the remaining
            // data in the table.
            if raw_table.activeManifestUriLength > 0 {
                let mut uri_bytes: Vec<u8> = vec![0; raw_table.activeManifestUriLength as usize];
                reader.seek(SeekFrom::Start(
                    offset + raw_table.activeManifestUriOffset as u64,
                ))?;
                reader.read_exact(&mut uri_bytes)?;
                active_manifest_uri = Some(
                    from_utf8(&uri_bytes)
                        .map_err(|_e| FontError::LoadC2PATableInvalidUtf8)?
                        .to_string(),
                );
            }
            if raw_table.manifestStoreLength > 0 {
                let mut manifest_bytes: Vec<u8> = vec![0; raw_table.manifestStoreLength as usize];
                reader.seek(SeekFrom::Start(
                    offset + raw_table.manifestStoreOffset as u64,
                ))?;
                reader.read_exact(&mut manifest_bytes)?;
                manifest_store = Some(manifest_bytes);
            }
            // Return our record
            Ok(TableC2PA {
                major_version: raw_table.majorVersion,
                minor_version: raw_table.minorVersion,
                active_manifest_uri,
                manifest_store,
            })
        }
    }

    /// Get the manifest store data if available
    pub(crate) fn get_manifest_store(&self) -> Option<&[u8]> {
        self.manifest_store.as_deref()
    }
}

impl Table for TableC2PA {
    fn checksum(&self) -> Wrapping<u32> {
        // Set up the structured data
        let raw_table = TableC2PARaw::from_table(self);
        let header_cksum = raw_table.checksum();
        // Add remote-manifest URI if present.
        let uri_cksum = if let Some(uri_string) = self.active_manifest_uri.as_ref() {
            checksum(uri_string.as_bytes())
        } else {
            Wrapping(0_u32)
        };
        let manifest_cksum = if let Some(manifest_store) = self.manifest_store.as_ref() {
            checksum_biased(
                manifest_store.as_bytes(),
                raw_table.activeManifestUriLength as u32,
            )
        } else {
            Wrapping(0_u32)
        };
        header_cksum + uri_cksum + manifest_cksum
    }

    fn len(&self) -> usize {
        size_of::<TableC2PARaw>()
            + match &self.active_manifest_uri {
                Some(uri) => uri.len(),
                None => 0,
            }
            + match &self.manifest_store {
                Some(store) => store.len(),
                None => 0,
            }
    }

    fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        // Set up the structured data
        let raw_table = TableC2PARaw::from_table(self);
        // Write the table data
        raw_table.write(destination)?;
        // Write the remote manifest URI, if present.
        if let Some(uri_string) = self.active_manifest_uri.as_ref() {
            destination.write_all(uri_string.as_bytes())?;
        }
        // Write out the local manifest store, if present.
        if let Some(manifest_store) = self.manifest_store.as_ref() {
            destination.write_all(manifest_store)?;
        }
        // Done
        Ok(())
    }
}

impl Default for TableC2PA {
    fn default() -> Self {
        Self {
            major_version: 0,
            minor_version: 1,
            active_manifest_uri: Default::default(),
            manifest_store: Default::default(),
        }
    }
}

/// 'head' font table. For now, there is no need for a 'raw' variant, since only
/// byte-swapping is needed.
#[derive(Debug, Default)]
#[repr(C, packed(1))]
// As defined by Open Font Format / OpenType (though we don't as yet directly
// support exotics like FIXED).
#[allow(non_snake_case)] // As named by Open Font Format / OpenType.
pub(crate) struct TableHead {
    pub majorVersion: u16,       // Note - Since we only modify checksumAdjustment,
    pub minorVersion: u16,       // we might just as well define this struct as
    pub fontRevision: u32,       //    version_stuff: u8[8],
    pub checksumAdjustment: u32, //    checksumAdjustment: u32,
    pub magicNumber: u32,        //    rest_of_stuff: u8[42],
    pub flags: u16,
    pub unitsPerEm: u16,
    pub created: i64,
    pub modified: i64,
    pub xMin: i16,
    pub yMin: i16,
    pub xMax: i16,
    pub yMax: i16,
    pub macStyle: u16,
    pub lowestRecPPEM: u16,
    pub fontDirectionHint: i16,
    pub indexToLocFormat: i16,
    pub glyphDataFormat: i16,
}

impl TableHead {
    /// Creates a new instance, using data from the provided source at a
    /// specific offset.
    pub(crate) fn from_reader<T: Read + Seek + ?Sized>(
        reader: &mut T,
        offset: u64,
        size: usize,
    ) -> core::result::Result<TableHead, Error> {
        reader.seek(SeekFrom::Start(offset))?;
        let actual_size = size_of::<TableHead>();
        if size != actual_size {
            Err(wrap_font_err(FontError::LoadHeadTableBadMissing))
        } else {
            let head = Self {
                // 0x00
                majorVersion: reader.read_u16::<BigEndian>()?,
                minorVersion: reader.read_u16::<BigEndian>()?,
                // 0x04
                fontRevision: reader.read_u32::<BigEndian>()?,
                // 0x08
                checksumAdjustment: reader.read_u32::<BigEndian>()?,
                // 0x0c
                magicNumber: reader.read_u32::<BigEndian>()?,
                // 0x10
                flags: reader.read_u16::<BigEndian>()?,
                unitsPerEm: reader.read_u16::<BigEndian>()?,
                // 0x14
                created: reader.read_i64::<BigEndian>()?,
                // 0x1c
                modified: reader.read_i64::<BigEndian>()?,
                // 0x24
                xMin: reader.read_i16::<BigEndian>()?,
                yMin: reader.read_i16::<BigEndian>()?,
                // 0x28
                xMax: reader.read_i16::<BigEndian>()?,
                yMax: reader.read_i16::<BigEndian>()?,
                // 0x2c
                macStyle: reader.read_u16::<BigEndian>()?,
                lowestRecPPEM: reader.read_u16::<BigEndian>()?,
                // 0x30
                fontDirectionHint: reader.read_i16::<BigEndian>()?,
                indexToLocFormat: reader.read_i16::<BigEndian>()?,
                // 0x34
                glyphDataFormat: reader.read_i16::<BigEndian>()?,
                // 0x36 - 54 bytes
                // TBD - Two bytes of padding to get to 56/0x38. Should we
                // seek/discard two more bytes, just to leave the stream in a
                // known state? Be nice if we didn't have to.
                //   1. On the one hand, whoever's invoking us could more-
                //      efficiently mess around with the offsets and padding.
                //   B. On the other, for the .write() code, we definitely push
                //      the "pad *yourself* up to four, impl!" approach
                //   III. Likewise the .checksum() code (although, because this
                //        is a simple checksum, the matter is moot; it doesn't
                //        matter whether we add '0_u16' to the total.
                //   IIII. (On clocks, IIII is a permissible Roman numeral) But
                //      what about that "simple" '.len()' call? Should it
                //      include the two pad bytes?
                // For now, the surrounding code doesn't care how the read
                // stream is left, so we don't do anything, since that is simplest.
            };
            if head.magicNumber != HEAD_TABLE_MAGICNUMBER {
                return Err(wrap_font_err(FontError::LoadHeadTableBadMissing));
            }
            Ok(head)
        }
    }
}

impl Table for TableHead {
    fn checksum(&self) -> Wrapping<u32> {
        // 0x00
        u32_from_u16_pair(self.majorVersion, self.minorVersion)
          // 0x04
          + Wrapping(self.fontRevision)
          // 0x08
          // (Note: checksumAdjustment is treated as containing all-
          //  zeros during this operation.)
          // 0x0c
          + Wrapping(self.magicNumber)
          // 0x10
          + u32_from_u16_pair(self.flags, self.unitsPerEm)
          // 0x14
          + u32_from_u64_hi(self.created as u64)
          + u32_from_u64_lo(self.created as u64)
          // 0x1c
          + u32_from_u64_hi(self.modified as u64)
          + u32_from_u64_lo(self.modified as u64)
          // 0x24
          + u32_from_u16_pair(self.xMin as u16, self.yMin as u16)
          // 0x28
          + u32_from_u16_pair(self.xMax as u16, self.yMax as u16)
          // 0x2c
          + u32_from_u16_pair(self.macStyle, self.lowestRecPPEM)
          // 0x30
          + u32_from_u16_pair(self.fontDirectionHint as u16, self.indexToLocFormat as u16)
          // 0x34
          + u32_from_u16_pair(self.glyphDataFormat as u16, 0_u16/*padpad*/)
        // 0x38
    }

    fn len(&self) -> usize {
        // TBD - Is this called?
        size_of::<Self>()
    }

    fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        // 0x00
        destination.write_u16::<BigEndian>(self.majorVersion)?;
        destination.write_u16::<BigEndian>(self.minorVersion)?;
        // 0x04
        destination.write_u32::<BigEndian>(self.fontRevision)?;
        // 0x08
        destination.write_u32::<BigEndian>(self.checksumAdjustment)?;
        destination.write_u32::<BigEndian>(self.magicNumber)?;
        // 0x10
        destination.write_u16::<BigEndian>(self.flags)?;
        destination.write_u16::<BigEndian>(self.unitsPerEm)?;
        // 0x14
        destination.write_i64::<BigEndian>(self.created)?;
        // 0x1c
        destination.write_i64::<BigEndian>(self.modified)?;
        // 0x24
        destination.write_i16::<BigEndian>(self.xMin)?;
        destination.write_i16::<BigEndian>(self.yMin)?;
        // 0x28
        destination.write_i16::<BigEndian>(self.xMax)?;
        destination.write_i16::<BigEndian>(self.yMax)?;
        // 0x2c
        destination.write_u16::<BigEndian>(self.macStyle)?;
        destination.write_u16::<BigEndian>(self.lowestRecPPEM)?;
        // 0x30
        destination.write_i16::<BigEndian>(self.fontDirectionHint)?;
        destination.write_i16::<BigEndian>(self.indexToLocFormat)?;
        // 0x34
        destination.write_i16::<BigEndian>(self.glyphDataFormat)?;
        // 0x36
        destination.write_u16::<BigEndian>(0_u16)?;
        // 0x38 - two bytes to get 54-byte 'head' up to nice round 56 bytes
        Ok(())
    }
}

/// Generic font table with unknown contents.
#[derive(Debug)]
pub(crate) struct TableUnspecified {
    pub data: Vec<u8>,
}

/// Any font table.
impl TableUnspecified {
    /// Creates a new instance, reading data from the provided source at a
    /// specific offset.
    pub(crate) fn from_reader<T: Read + Seek + ?Sized>(
        reader: &mut T,
        offset: u64,
        size: usize,
    ) -> Result<TableUnspecified> {
        let mut raw_table_data: Vec<u8> = vec![0; size];
        reader.seek(SeekFrom::Start(offset))?;
        reader.read_exact(&mut raw_table_data)?;
        Ok(Self {
            data: raw_table_data,
        })
    }
}

impl Table for TableUnspecified {
    fn checksum(&self) -> Wrapping<u32> {
        checksum(&self.data)
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        destination
            .write_all(&self.data[..])
            .map_err(|_e| FontError::SaveError)?;
        let limit = self.data.len() % 4;
        if limit > 0 {
            let pad: [u8; 3] = [0, 0, 0];
            destination
                .write_all(&pad[0..(4 - limit)])
                .map_err(|_e| FontError::SaveError)?;
        }
        Ok(())
    }
}

/// Possible tables
#[derive(Debug)]
pub(crate) enum NamedTable {
    /// 'C2PA' table
    C2PA(TableC2PA),
    /// 'head' table
    Head(TableHead),
    /// any other table
    Unspecified(TableUnspecified),
}

impl NamedTable {
    /// Creates a new instance, reading from the provided source at a specific
    /// offset and created the type specific to the given tag.
    pub(crate) fn from_reader<T: Read + Seek + ?Sized>(
        tag: &SfntTag,
        reader: &mut T,
        offset: u64,
        length: usize,
    ) -> Result<Self> {
        match *tag {
            C2PA_TABLE_TAG => Ok(NamedTable::C2PA(TableC2PA::from_reader(
                reader, offset, length,
            )?)),
            HEAD_TABLE_TAG => Ok(NamedTable::Head(TableHead::from_reader(
                reader, offset, length,
            )?)),
            _ => Ok(NamedTable::Unspecified(TableUnspecified::from_reader(
                reader, offset, length,
            )?)),
        }
    }
}

// TBD - This looks sort of like the CRTP from C++; do we want a Trait here
// that *both* table *and* its value-types implement?
impl Table for NamedTable {
    fn checksum(&self) -> Wrapping<u32> {
        match self {
            NamedTable::C2PA(c2pa) => c2pa.checksum(),
            NamedTable::Head(head) => head.checksum(),
            NamedTable::Unspecified(un) => un.checksum(),
        }
    }

    fn len(&self) -> usize {
        match self {
            NamedTable::C2PA(c2pa) => c2pa.len(),
            NamedTable::Head(head) => head.len(),
            NamedTable::Unspecified(un) => un.len(),
        }
    }

    fn write<TDest: Write + ?Sized>(&self, destination: &mut TDest) -> Result<()> {
        match self {
            NamedTable::C2PA(c2pa) => c2pa.write(destination),
            NamedTable::Head(head) => head.write(destination),
            NamedTable::Unspecified(un) => un.write(destination),
        }
    }
}

/// All the serialization structures so far have been defined using native
/// Rust types; should we go all-out in the other direction, and establish a
/// layer of "font" types (FWORD, FIXED, etc.)?

/// SFNT header, from the OpenType spec.
///
/// This SFNT type is also referenced by WOFF formats, so it is defined here for
/// common use.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed(1))] // As defined by the OpenType spec.
#[allow(dead_code, non_snake_case)] // As defined by the OpenType spec.
pub(crate) struct SfntHeader {
    pub sfntVersion: u32,
    pub numTables: u16,
    pub searchRange: u16,
    pub entrySelector: u16,
    pub rangeShift: u16,
}

/// SFNT Table Directory Entry, from the OpenType spec.
///
/// This SFNT type is also referenced by WOFF formats, so it is defined here for
/// common use.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed(1))] // As defined by the OpenType spec.
#[allow(dead_code, non_snake_case)] // As defined by the OpenType spec.
pub(crate) struct SfntDirectoryEntry {
    pub tag: SfntTag,
    pub checksum: u32,
    pub offset: u32,
    pub length: u32,
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use claims::*;

    use super::*;

    // TBD - add'l c2pa table tests:
    //  - Short table
    //  - Offset of an element is nonzero when size is zero
    //  - URI offset >, <, =, manifest offset
    //  - Invalid UTF8 in the URI
    //  - Bad offset/size to from_reader
    #[test]
    /// Verifies the head table's .checksum() method.
    fn c2pa_raw_checksum() {
        let c2pa_raw_data = vec![
            0x00, 0x07, 0x00, 0x11, // Major: 7, Minor: 17
            0x00, 0x00, 0x00, 0x00, // Manifest URI offset (0)
            0x00, 0x1a, 0x00, 0x01, // Manifest URI length (26) / reserved (1)
            0x00, 0x00, 0x00, 0x2e, // C2PA manifest store offset (46)
            0x00, 0x00, 0x00, 0x12, // C2PA manifest store length (18)
        ];
        let mut c2pa_raw_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&c2pa_raw_data);
        assert_eq!(size_of::<TableC2PARaw>(), c2pa_raw_data.len());
        let c2pa_raw = TableC2PARaw::from_reader(&mut c2pa_raw_stream).unwrap();
        let naive_cksum = checksum(&c2pa_raw_data).0;
        let table_cksum = c2pa_raw.checksum().0;
        assert_eq!(2162770, naive_cksum);
        assert_eq!(2162770, table_cksum);
    }

    #[test]
    /// Verifies the head table's .checksum() method.
    fn c2pa_checksum() {
        let c2pa_data = vec![
            0x00, 0x07, 0x00, 0x11, // Major: 7, Minor: 17
            0x00, 0x00, 0x00, 0x14, // Manifest URI offset (20)
            0x00, 0x1a, 0x00, 0x00, // Manifest URI length (26) / reserved (0)
            0x00, 0x00, 0x00, 0x2e, // C2PA manifest store offset (46)
            0x00, 0x00, 0x00, 0x12, // C2PA manifest store length (18)
            0x68, 0x74, 0x74, 0x70, // http
            0x3a, 0x2f, 0x2f, 0x65, // ://e
            0x78, 0x61, 0x6d, 0x70, // xamp
            0x6c, 0x65, 0x2e, 0x63, // le.c
            0x6f, 0x6d, 0x2f, 0x6e, // om/n
            0x6f, 0x74, 0x68, 0x69, // othi
            0x6e, 0x67, 0x3c, 0x45, // ng<E
            0x78, 0x61, 0x6d, 0x70, // xamp
            0x6c, 0x65, 0x4d, 0x61, // leMa
            0x6e, 0x69, 0x66, 0x65, // nife
            0x73, 0x74, 0x2f, 0x3e, // st/>
        ];
        let mut c2pa_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&c2pa_data);
        assert_eq!(size_of::<TableC2PARaw>() + 26 + 18, c2pa_data.len());
        let c2pa = TableC2PA::from_reader(&mut c2pa_stream, 0, c2pa_data.len()).unwrap();
        let naive_cksum = checksum(&c2pa_data).0;
        let table_cksum = c2pa.checksum().0;
        assert_eq!(2608358557, naive_cksum);
        assert_eq!(2608358557, table_cksum);
    }

    #[test]
    /// Verify read/write idempotency with neither a URI nor a manifest
    fn c2pa_read_write_idempotent_empty() {
        let c2pa_input_data = vec![
            0x00, 0x09, 0x00, 0x13, // Major: 9, Minor: 19
            0x00, 0x00, 0x00, 0x00, // Manifest URI offset (0)
            0x00, 0x00, 0x00, 0x00, // Manifest URI length (0) / reserved (0)
            0x00, 0x00, 0x00, 0x00, // C2PA manifest store offset (0)
            0x00, 0x00, 0x00, 0x00, // C2PA manifest store length (0)
        ];
        let mut c2pa_input_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&c2pa_input_data);
        let mut c2pa_output_stream = Cursor::new(Vec::new());
        let c2pa =
            TableC2PA::from_reader(&mut c2pa_input_stream, 0, c2pa_input_data.len()).unwrap();
        assert_ok!(c2pa.write(&mut c2pa_output_stream));
        assert_eq!(c2pa_input_data, c2pa_output_stream.get_ref().as_slice());
    }

    #[test]
    /// Verify read/write idempotency with a URI, but no manifest
    fn c2pa_read_write_idempotent_uri() {
        let c2pa_input_data = vec![
            0x00, 0x08, 0x00, 0x12, // Major: 8, Minor: 18
            0x00, 0x00, 0x00, 0x14, // Manifest URI offset (20)
            0x00, 0x1a, 0x00, 0x00, // Manifest URI length (26) / reserved (0)
            0x00, 0x00, 0x00, 0x00, // C2PA manifest store offset (0)
            0x00, 0x00, 0x00, 0x00, // C2PA manifest store length (0)
            0x68, 0x74, 0x74, 0x70, // http
            0x3a, 0x2f, 0x2f, 0x65, // ://e
            0x78, 0x61, 0x6d, 0x70, // xamp
            0x6c, 0x65, 0x2e, 0x63, // le.c
            0x6f, 0x6d, 0x2f, 0x6e, // om/n
            0x6f, 0x74, 0x68, 0x69, // othi
            0x6e, 0x67, // ng
        ];
        let mut c2pa_input_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&c2pa_input_data);
        let mut c2pa_output_stream = Cursor::new(Vec::new());
        let c2pa =
            TableC2PA::from_reader(&mut c2pa_input_stream, 0, c2pa_input_data.len()).unwrap();
        assert_ok!(c2pa.write(&mut c2pa_output_stream));
        assert_eq!(c2pa_input_data, c2pa_output_stream.get_ref().as_slice());
    }

    #[test]
    /// Verify read/write idempotency with no URI, but a manifest
    fn c2pa_read_write_idempotent_manifest() {
        let c2pa_input_data = vec![
            0x00, 0x07, 0x00, 0x11, // Major: 7, Minor: 17
            0x00, 0x00, 0x00, 0x00, // Manifest URI offset (20)
            0x00, 0x00, 0x00, 0x00, // Manifest URI length (26) / reserved (0)
            0x00, 0x00, 0x00, 0x14, // C2PA manifest store offset (20)
            0x00, 0x00, 0x00, 0x12, // C2PA manifest store length (18)
            0x3c, 0x45, 0x78, 0x61, // <Exa
            0x6d, 0x70, 0x6c, 0x65, // mple
            0x4d, 0x61, 0x6e, 0x69, // Mani
            0x66, 0x65, 0x73, 0x74, // fest
            0x2f, 0x3e, // />
        ];
        let mut c2pa_input_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&c2pa_input_data);
        let mut c2pa_output_stream = Cursor::new(Vec::new());
        let c2pa =
            TableC2PA::from_reader(&mut c2pa_input_stream, 0, c2pa_input_data.len()).unwrap();
        assert_ok!(c2pa.write(&mut c2pa_output_stream));
        assert_eq!(c2pa_input_data, c2pa_output_stream.get_ref().as_slice());
    }

    #[test]
    /// Verify read/write idempotency with both a URI and a manifest
    fn c2pa_read_write_idempotent_both() {
        let c2pa_input_data = vec![
            0x00, 0x07, 0x00, 0x11, // Major: 7, Minor: 17
            0x00, 0x00, 0x00, 0x14, // Manifest URI offset (20)
            0x00, 0x1a, 0x00, 0x00, // Manifest URI length (26) / reserved (0)
            0x00, 0x00, 0x00, 0x2e, // C2PA manifest store offset (46)
            0x00, 0x00, 0x00, 0x12, // C2PA manifest store length (18)
            0x68, 0x74, 0x74, 0x70, // http
            0x3a, 0x2f, 0x2f, 0x65, // ://e
            0x78, 0x61, 0x6d, 0x70, // xamp
            0x6c, 0x65, 0x2e, 0x63, // le.c
            0x6f, 0x6d, 0x2f, 0x6e, // om/n
            0x6f, 0x74, 0x68, 0x69, // othi
            0x6e, 0x67, 0x3c, 0x45, // ng<E
            0x78, 0x61, 0x6d, 0x70, // xamp
            0x6c, 0x65, 0x4d, 0x61, // leMa
            0x6e, 0x69, 0x66, 0x65, // nife
            0x73, 0x74, 0x2f, 0x3e, // st/>
        ];
        let mut c2pa_input_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&c2pa_input_data);
        let mut c2pa_output_stream = Cursor::new(Vec::new());
        let c2pa =
            TableC2PA::from_reader(&mut c2pa_input_stream, 0, c2pa_input_data.len()).unwrap();
        assert_ok!(c2pa.write(&mut c2pa_output_stream));
        assert_eq!(c2pa_input_data, c2pa_output_stream.get_ref().as_slice());
    }

    // TBD - add'l head table tests:
    //  - Bad offset/size to from_reader

    #[test]
    /// Verifies that data with bad magic fails to produce a head table.
    fn head_bad_magic() {
        let head_data = vec![
            0x00, 0x07, 0x00, 0x07, // majorVersion: 7, minorVersion: 7
            0x12, 0x34, 0x56, 0x78, // fontRevision: 305419896
            0x81, 0x29, 0x36, 0x0f, // checksumAdjustment: 2166961679
            0x5f, 0x0f, 0x3c, 0xf6, // magicNumber: 1594834166
            0xc3, 0x5a, 0x04, 0x22, // flags: 0xc35a, unitsPerEm: 0x0422
            0x90, 0x00, 0x00, 0x00, // created (hi) 0x90000000
            0x81, 0x4e, 0xaf, 0x80, // created (lo) 0x814eaf80
            0xa0, 0x00, 0x00, 0x00, // modified (hi) 0xa0000000
            0x83, 0x39, 0x1d, 0x80, // modified (lo) 0x83391d80
            0xff, 0xb7, 0xff, 0xb6, // xMin: -73, yMin: -72
            0x00, 0x48, 0x00, 0x49, // xMax:  72, yMax:  73
            0xa5, 0x3c, 0x04, 0x05, // macStyle: 0xa53c, lowestRecPPEM: 1029
            0xff, 0xfd, 0x11, 0x11, // fontDirectionHint: -3, indexToLocFormat: 0x1111
            0x22, 0x22, // glyphDataFormat: 0x2222
        ];
        let mut head_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&head_data);
        assert_eq!(size_of::<TableHead>(), head_data.len());
        let head = TableHead::from_reader(&mut head_stream, 0, head_data.len());
        assert_matches!(
            head,
            Err(Error::FontError(FontError::LoadHeadTableBadMissing))
        );
    }

    #[test]
    /// Verifies that short data fails to produce a head table.
    fn head_short() {
        let head_data = vec![
            0x00, 0x07, 0x00, 0x07, // majorVersion: 7, minorVersion: 7
            0x12, 0x34, 0x56, 0x78, // fontRevision: 305419896
            0x81, 0x29, 0x36, 0x0f, // checksumAdjustment: 2166961679
            0x5f, 0x0f, 0x3c, 0xf5, // magicNumber: 1594834165
            0xc3, 0x5a, 0x04, 0x22, // flags: 0xc35a, unitsPerEm: 0x0422
            0x90, 0x00, 0x00, 0x00, // created (hi) 0x90000000
            0x81, 0x4e, 0xaf, 0x80, // created (lo) 0x814eaf80
            0xa0, 0x00, 0x00, 0x00, // modified (hi) 0xa0000000
            0x83, 0x39, 0x1d, 0x80, // modified (lo) 0x83391d80
            0xff, 0xb7, 0xff, 0xb6, // xMin: -73, yMin: -72
            0x00, 0x48, 0x00, 0x49, // xMax:  72, yMax:  73
            0xa5, 0x3c, 0x04, 0x05, // macStyle: 0xa53c, lowestRecPPEM: 1029
            0xff, 0xfd, 0x11, 0x11, // fontDirectionHint: -3, indexToLocFormat: 0x1111
            0x22, // glyphDataFormat: 0x22...yikes!
        ];
        let mut head_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&head_data);
        assert_eq!(size_of::<TableHead>(), head_data.len() + 1);
        let head = TableHead::from_reader(&mut head_stream, 0, head_data.len());
        assert_matches!(
            head,
            Err(Error::FontError(FontError::LoadHeadTableBadMissing))
        );
    }

    #[test]
    /// Verifies the head table's .checksum() method.
    fn head_checksum() {
        let head_data = vec![
            0x00, 0x07, 0x00, 0x07, // majorVersion: 7, minorVersion: 7
            0x12, 0x34, 0x56, 0x78, // fontRevision: 305419896
            0x81, 0x29, 0x36, 0x0f, // checksumAdjustment: 2166961679
            0x5f, 0x0f, 0x3c, 0xf5, // magicNumber: 1594834165
            0xc3, 0x5a, 0x04, 0x22, // flags: 0xc35a, unitsPerEm: 0x0422
            0x90, 0x00, 0x00, 0x00, // created (hi) 0x90000000
            0x81, 0x4e, 0xaf, 0x80, // created (lo) 0x814eaf80
            0xa0, 0x00, 0x00, 0x00, // modified (hi) 0xa0000000
            0x83, 0x39, 0x1d, 0x80, // modified (lo) 0x83391d80
            0xff, 0xb7, 0xff, 0xb6, // xMin: -73, yMin: -72
            0x00, 0x48, 0x00, 0x49, // xMax:  72, yMax:  73
            0xa5, 0x3c, 0x04, 0x05, // macStyle: 0xa53c, lowestRecPPEM: 1029
            0xff, 0xfd, 0x11, 0x11, // fontDirectionHint: -3, indexToLocFormat: 0x1111
            0x22, 0x22, // glyphDataFormat: 0x2222
        ];
        let mut head_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&head_data);
        assert_eq!(size_of::<TableHead>(), head_data.len());
        let head = TableHead::from_reader(&mut head_stream, 0, head_data.len()).unwrap();
        let naive_cksum = checksum(&head_data).0;
        let table_cksum = head.checksum().0;
        // Verify that a naive word-wise checksum produces the well-known
        // expected value of a valid SFNT.
        assert_eq!(SFNT_EXPECTED_CHECKSUM, naive_cksum);
        // Verify that head.checksum() excluded the checksumAdjustment field.
        assert_eq!(814184875, table_cksum);
    }

    #[test]
    /// Verifies the adding of a remote C2PA manifest reference works as
    /// expected.
    fn un_checksums() {
        let un_data = vec![
            0x0f, 0x0f, 0x0f, 0x0f, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x01, 0x00,
        ];
        let un_expecteds: [u32; 17] = [
            0x00000000_u32,
            0x0f000000_u32,
            0x0f0f0000_u32,
            0x0f0f0f00_u32,
            0x0f0f0f0f_u32,
            0x130f0f0f_u32,
            0x13120f0f_u32,
            0x1312110f_u32,
            0x13121110_u32,
            0x13121110_u32,
            0x13121110_u32,
            0x13121110_u32,
            0x13121110_u32,
            0x13121110_u32,
            0x13131110_u32,
            0x13131210_u32,
            0x13131210_u32,
        ];
        let mut un_stream: Cursor<&[u8]> = Cursor::<&[u8]>::new(&un_data);
        for (n, un_expected) in un_expecteds.iter().enumerate() {
            // Make an unspecified table from the first n bytes
            let un = TableUnspecified::from_reader(&mut un_stream, 0, n).unwrap();
            let un_cksum = un.checksum();
            assert_eq!(un_expected, &(un_cksum.0));
        }
    }
}
