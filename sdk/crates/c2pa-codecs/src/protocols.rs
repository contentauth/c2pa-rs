use std::io::{BufReader, Read, Seek, Write};

use crate::{xmp, CodecError};

// NOTE: the reason encoders/decoders take &mut self and no src is because they take them on construction.
//       in a normal gif signing flow, we read, write, read, then write again There's a lot of info we can cache.
// TODO: document stream position behavior, it should assume it starts where requested and there is no guarantee on where it ends, the caller can handle restoration
pub trait Encode {
    // TODO: should we require this function to search for existing c2pa manfiests?
    /// Writes the C2PA block with the specified manifest or replaces it if it already exists.
    fn write_c2pa(&mut self, dst: impl Write, c2pa: &[u8]) -> Result<(), CodecError>;

    /// Removes the C2PA block from the stream or returns false if a C2PA block was not found.
    fn remove_c2pa(&mut self, dst: impl Write) -> Result<bool, CodecError>;

    fn write_xmp(&mut self, dst: impl Write, xmp: &str) -> Result<(), CodecError> {
        let _ = dst;
        let _ = xmp;
        Err(CodecError::Unimplemented)
    }

    fn write_xmp_provenance(&mut self, dst: impl Write, provenance: &str) -> Result<(), CodecError>
    where
        Self: Decode,
    {
        let existing_xmp = self
            .read_xmp()?
            .unwrap_or_else(|| format!("http://ns.adobe.com/xap/1.0/\0 {}", xmp::MIN_XMP));
        self.write_xmp(dst, &xmp::add_provenance(&existing_xmp, provenance)?)
    }

    fn remove_xmp(&mut self, dst: impl Write, xmp: &str) -> Result<(), CodecError> {
        let _ = dst;
        let _ = xmp;
        Err(CodecError::Unimplemented)
    }

    fn remove_xmp_provenance(&mut self, dst: impl Write) -> Result<(), CodecError>
    where
        Self: Decode,
    {
        todo!()
    }
}

pub trait EncodeInPlace {
    /// Replaces the C2PA block with the specified manifest ONLY if the given manifest is the same exact
    /// size as the existing C2PA block.
    ///
    /// If no C2PA block was found, then errors with [`ParseError::NothingToPatch`].
    /// If the size of the found C2PA block differs, then errors with [`ParseError::InvalidPatchSize`].
    fn patch_c2pa(&mut self, c2pa: &[u8]) -> Result<(), CodecError>;
}

pub trait Decode {
    fn read_c2pa(&mut self) -> Result<Option<Vec<u8>>, CodecError>;

    fn read_xmp(&mut self) -> Result<Option<String>, CodecError> {
        Err(CodecError::Unimplemented)
    }

    fn read_xmp_provenance(&mut self) -> Result<Option<String>, CodecError> {
        todo!()
    }
}

pub trait Embed {
    fn embeddable(bytes: &[u8]) -> Result<Embeddable, CodecError>;

    // fn read_embeddable(&mut self) -> Embeddable;

    fn embed(&mut self, embeddable: Embeddable, dst: impl Write) -> Result<(), CodecError>;
}

pub trait Span {
    fn span(&mut self) -> Result<DefaultSpan, CodecError>;

    // TODO: document that if there is no c2pa manifest it should return where it should be
    // TODO: what happens if a data hash has multiple placeholder locations? how does the code know where to hash?
    fn c2pa_span(&mut self) -> Result<C2paSpan, CodecError> {
        Err(CodecError::Unimplemented)
    }

    // TODO: read above
    fn box_span(&mut self) -> Result<BoxSpan, CodecError> {
        Err(CodecError::Unimplemented)
    }

    fn bmff_span(&mut self) -> Result<BmffSpan, CodecError> {
        Err(CodecError::Unimplemented)
    }

    fn collection_span(&mut self) -> Result<CollectionSpan, CodecError> {
        Err(CodecError::Unimplemented)
    }
}

pub trait Support {
    const MAX_SIGNATURE_LEN: usize;

    fn supports_signature(signature: &[u8]) -> bool {
        let _ = signature;
        false
    }

    // Not all file types support a signature (e.g. SVG), but some can be inferred based
    // on their structure. That operation is likely expensive, which is why we separate it
    // into a supports_stream method.
    fn supports_stream(src: impl Read + Seek) -> Result<bool, CodecError> {
        let _ = src;
        Err(CodecError::Unimplemented)
    }

    // fn supports_signature_from_stream(mut src: impl Read) -> Result<bool, CodecError> {
    //     let mut signature = Vec::with_capacity(Self::MAX_SIGNATURE_LEN);
    //     src.read_exact(&mut signature)?;
    //     Self::supports_signature(&signature)
    // }

    fn supports_extension(extension: &str) -> bool;

    fn supports_mime(mime: &str) -> bool;
}

#[derive(Debug)]
pub struct Embeddable {
    pub bytes: Vec<u8>,
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
pub struct C2paSpan {
    /// Span of bytes that encompass the manifest with specifical consideration
    /// for some formats defined in the spec.
    pub spans: Vec<ByteSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BoxSpan {
    /// Span of bytes for each block, corresponding to their box name as defined
    /// in the spec.
    pub spans: Vec<NamedByteSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BmffSpan {
    // TODO
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CollectionSpan {
    pub zip_central_directory_span: Option<ByteSpan>,
    pub uri_spans: Vec<ByteSpan>,
}

#[derive(Debug)]
pub enum DefaultSpan {
    Data(C2paSpan),
    Box(BoxSpan),
    Bmff(BmffSpan),
    Collection(CollectionSpan),
}

impl Encode for () {
    fn write_c2pa(&mut self, dst: impl Write, c2pa: &[u8]) -> Result<(), CodecError> {
        Err(CodecError::Unsupported)
    }

    fn remove_c2pa(&mut self, dst: impl Write) -> Result<bool, CodecError> {
        Err(CodecError::Unsupported)
    }
}

impl EncodeInPlace for () {
    fn patch_c2pa(&mut self, c2pa: &[u8]) -> Result<(), CodecError> {
        Err(CodecError::Unsupported)
    }
}

impl Decode for () {
    fn read_c2pa(&mut self) -> Result<Option<Vec<u8>>, CodecError> {
        Err(CodecError::Unsupported)
    }
}

impl Embed for () {
    fn embeddable(bytes: &[u8]) -> Result<Embeddable, CodecError> {
        Err(CodecError::Unsupported)
    }

    fn embed(&mut self, embeddable: Embeddable, dst: impl Write) -> Result<(), CodecError> {
        Err(CodecError::Unsupported)
    }
}

impl Span for () {
    fn span(&mut self) -> Result<DefaultSpan, CodecError> {
        Err(CodecError::Unsupported)
    }
}

impl Support for () {
    const MAX_SIGNATURE_LEN: usize = 0;

    fn supports_stream(src: impl Read + Seek) -> Result<bool, CodecError> {
        Ok(false)
    }

    fn supports_extension(extension: &str) -> bool {
        false
    }

    fn supports_mime(mime: &str) -> bool {
        false
    }
}
