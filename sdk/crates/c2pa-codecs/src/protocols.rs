use std::io::{Read, Seek, Write};

use crate::ParseError;

pub const MAX_SIGNATURE_LEN: usize = 8;

// TODO: composed manifest is used to precompute the size of a block for a data hash. That info should now be included in Hash::data_hash

// NOTE: the reason encoders/decoders take &mut self and no src is because they take them on construction.
//       in a normal signing flow, we hash, write, hash, then write again. That's only for a normal data hash gif flow
//       There's a lot of information we can cache.
// TODO: document stream position behavior, it should assume it starts where requested and there is no guarantee on where it ends, the caller can handle that
pub trait Encoder {
    fn write_c2pa(&mut self, dst: impl Write, c2pa: &[u8]) -> Result<(), ParseError>;

    /// Removes the C2PA block from the stream or returns false if a C2PA block was not found.
    fn remove_c2pa(&mut self, dst: impl Write) -> Result<bool, ParseError>;

    /// Replaces the C2PA block with the specified manifest ONLY if the given manifest is the same exact
    /// size as the existing C2PA block.
    ///
    /// If no C2PA block was found, then errors with [`ParseError::NothingToPatch`].
    /// If the size of the found C2PA block differs, then errors with [`ParseError::InvalidPatchSize`].
    fn patch_c2pa(&self, dst: impl Read + Write + Seek, c2pa: &[u8]) -> Result<(), ParseError> {
        Err(ParseError::Unsupported)
    }

    fn write_xmp(&mut self, dst: impl Write, xmp: &str) -> Result<(), ParseError> {
        Err(ParseError::Unsupported)
    }
}

pub trait Decoder {
    fn read_c2pa(&mut self) -> Result<Option<Vec<u8>>, ParseError>;

    fn read_xmp(&mut self) -> Result<Option<String>, ParseError> {
        Err(ParseError::Unsupported)
    }
}

pub trait Hasher {
    fn hash(&mut self) -> Result<Hash, ParseError>;

    fn data_hash(&mut self) -> Result<DataHash, ParseError> {
        Err(ParseError::Unsupported)
    }

    fn box_hash(&mut self) -> Result<BoxHash, ParseError> {
        Err(ParseError::Unsupported)
    }

    fn bmff_hash(&mut self) -> Result<BmffHash, ParseError> {
        Err(ParseError::Unsupported)
    }

    fn collection_hash(&mut self) -> Result<CollectionHash, ParseError> {
        Err(ParseError::Unsupported)
    }
}

pub trait Supporter {
    fn supports_signature(signature: &[u8]) -> bool;

    fn supports_extension(extension: &str) -> bool;

    fn supports_mime(mime: &str) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteSpan {
    pub start: u64,
    pub len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NamedByteSpan {
    pub names: Vec<String>,
    pub span: ByteSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DataHash {
    /// Span of bytes that encompass the manifest with specifical consideration
    /// for some formats defined in the spec.
    pub spans: Vec<ByteSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BoxHash {
    /// Span of bytes for each block, corresponding to their box name as defined
    /// in the spec.
    pub spans: Vec<NamedByteSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BmffHash {
    // TODO
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CollectionHash {
    pub zip_central_directory_span: Option<ByteSpan>,
    pub uri_spans: Vec<ByteSpan>,
}

#[derive(Debug)]
pub enum Hash {
    Data(DataHash),
    Box(BoxHash),
    Bmff(BmffHash),
    Collection(CollectionHash),
}
