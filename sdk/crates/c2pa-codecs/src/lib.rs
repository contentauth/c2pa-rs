// Copyright 2022 Adobe. All rights reserved.
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
    io::{self, Read, Seek, Write},
    num,
};

use codecs::{c2pa_io::C2paCodec, gif::GifCodec};
pub use protocols::*; // TODO: for now
use thiserror::Error;

pub mod codecs;
mod protocols;
mod xmp;

// TODO: WRITE MACROS!!!
// TODO: add other codecs

pub enum Codec<R, E = ()> {
    C2pa(C2paCodec<R>),
    Gif(GifCodec<R>),
    External(E),
}

impl<R: Read + Seek> Codec<R> {
    pub fn from_stream(mut src: R) -> Result<Self, ParseError> {
        let mut signature = [0; MAX_SIGNATURE_LEN];
        src.read_exact(&mut signature)?;
        if C2paCodec::supports_signature(&signature) {
            Ok(Self::C2pa(C2paCodec::new(src)))
        } else if GifCodec::supports_signature(&signature) {
            Ok(Self::Gif(GifCodec::new(src)))
        } else {
            Err(ParseError::UnknownFormat)
        }
    }

    pub fn from_extension(extension: &str, src: R) -> Result<Self, ParseError> {
        if C2paCodec::supports_extension(extension) {
            Ok(Self::C2pa(C2paCodec::new(src)))
        } else if GifCodec::supports_extension(extension) {
            Ok(Self::Gif(GifCodec::new(src)))
        } else {
            Err(ParseError::UnknownFormat)
        }
    }

    pub fn from_mime(mime: &str, src: R) -> Result<Self, ParseError> {
        if C2paCodec::supports_mime(mime) {
            Ok(Self::C2pa(C2paCodec::new(src)))
        } else if GifCodec::supports_mime(mime) {
            Ok(Self::Gif(GifCodec::new(src)))
        } else {
            Err(ParseError::UnknownFormat)
        }
    }
}

impl<R, E> Codec<R, E> {
    pub fn from_external(external: E) -> Self {
        Self::External(external)
    }
}

impl<R: Read + Seek, E: Encoder> Encoder for Codec<R, E> {
    fn write_c2pa(&mut self, dst: impl Write, c2pa: &[u8]) -> Result<(), ParseError> {
        match self {
            Codec::Gif(codec) => codec.write_c2pa(dst, c2pa),
            Codec::C2pa(codec) => codec.write_c2pa(dst, c2pa),
            Codec::External(codec) => codec.write_c2pa(dst, c2pa),
        }
    }

    fn remove_c2pa(&mut self, dst: impl Write) -> Result<bool, ParseError> {
        match self {
            Codec::Gif(codec) => codec.remove_c2pa(dst),
            Codec::C2pa(codec) => codec.remove_c2pa(dst),
            Codec::External(codec) => codec.remove_c2pa(dst),
        }
    }

    fn write_xmp(&mut self, dst: impl Write, xmp: &str) -> Result<(), ParseError> {
        match self {
            Codec::Gif(codec) => codec.write_xmp(dst, xmp),
            Codec::C2pa(codec) => codec.write_xmp(dst, xmp),
            Codec::External(codec) => codec.write_xmp(dst, xmp),
        }
    }

    fn patch_c2pa(&self, dst: impl Read + Write + Seek, c2pa: &[u8]) -> Result<(), ParseError> {
        match self {
            Codec::Gif(codec) => codec.patch_c2pa(dst, c2pa),
            Codec::C2pa(codec) => codec.patch_c2pa(dst, c2pa),
            Codec::External(codec) => codec.patch_c2pa(dst, c2pa),
        }
    }
}

impl<R: Read + Seek> Encoder for Codec<R, ()> {
    fn write_c2pa(&mut self, dst: impl Write, c2pa: &[u8]) -> Result<(), ParseError> {
        match self {
            Codec::Gif(codec) => codec.write_c2pa(dst, c2pa),
            Codec::C2pa(codec) => codec.write_c2pa(dst, c2pa),
            Codec::External(_) => Err(ParseError::Unsupported),
        }
    }

    fn remove_c2pa(&mut self, dst: impl Write) -> Result<bool, ParseError> {
        match self {
            Codec::Gif(codec) => codec.remove_c2pa(dst),
            Codec::C2pa(codec) => codec.remove_c2pa(dst),
            Codec::External(_) => Err(ParseError::Unsupported),
        }
    }

    fn write_xmp(&mut self, dst: impl Write, xmp: &str) -> Result<(), ParseError> {
        match self {
            Codec::Gif(codec) => codec.write_xmp(dst, xmp),
            Codec::C2pa(codec) => codec.write_xmp(dst, xmp),
            Codec::External(_) => Err(ParseError::Unsupported),
        }
    }

    fn patch_c2pa(&self, dst: impl Read + Write + Seek, c2pa: &[u8]) -> Result<(), ParseError> {
        match self {
            Codec::Gif(codec) => codec.patch_c2pa(dst, c2pa),
            Codec::C2pa(codec) => codec.patch_c2pa(dst, c2pa),
            Codec::External(_) => Err(ParseError::Unsupported),
        }
    }
}

impl<R: Read + Seek, E: Decoder> Decoder for Codec<R, E> {
    fn read_c2pa(&mut self) -> Result<Option<Vec<u8>>, ParseError> {
        match self {
            Codec::Gif(codec) => codec.read_c2pa(),
            Codec::C2pa(codec) => codec.read_c2pa(),
            Codec::External(codec) => codec.read_c2pa(),
        }
    }

    fn read_xmp(&mut self) -> Result<Option<String>, ParseError> {
        match self {
            Codec::Gif(codec) => codec.read_xmp(),
            Codec::C2pa(codec) => codec.read_xmp(),
            Codec::External(codec) => codec.read_xmp(),
        }
    }
}

impl<R: Read + Seek> Decoder for Codec<R, ()> {
    fn read_c2pa(&mut self) -> Result<Option<Vec<u8>>, ParseError> {
        match self {
            Codec::Gif(codec) => codec.read_c2pa(),
            Codec::C2pa(codec) => codec.read_c2pa(),
            Codec::External(_) => Err(ParseError::Unsupported),
        }
    }

    fn read_xmp(&mut self) -> Result<Option<String>, ParseError> {
        match self {
            Codec::Gif(codec) => codec.read_xmp(),
            Codec::C2pa(codec) => codec.read_xmp(),
            Codec::External(_) => Err(ParseError::Unsupported),
        }
    }
}

impl<R: Read + Seek, E: Hasher> Hasher for Codec<R, E> {
    fn hash(&mut self) -> Result<Hash, ParseError> {
        match self {
            Codec::Gif(codec) => codec.hash(),
            Codec::C2pa(codec) => codec.hash(),
            Codec::External(codec) => codec.hash(),
        }
    }

    fn data_hash(&mut self) -> Result<DataHash, ParseError> {
        match self {
            Codec::Gif(codec) => codec.data_hash(),
            Codec::C2pa(codec) => codec.data_hash(),
            Codec::External(codec) => codec.data_hash(),
        }
    }

    fn box_hash(&mut self) -> Result<BoxHash, ParseError> {
        match self {
            Codec::Gif(codec) => codec.box_hash(),
            Codec::C2pa(codec) => codec.box_hash(),
            Codec::External(codec) => codec.box_hash(),
        }
    }

    fn bmff_hash(&mut self) -> Result<BmffHash, ParseError> {
        match self {
            Codec::Gif(codec) => codec.bmff_hash(),
            Codec::C2pa(codec) => codec.bmff_hash(),
            Codec::External(codec) => codec.bmff_hash(),
        }
    }

    fn collection_hash(&mut self) -> Result<CollectionHash, ParseError> {
        match self {
            Codec::Gif(codec) => codec.collection_hash(),
            Codec::C2pa(codec) => codec.collection_hash(),
            Codec::External(codec) => codec.collection_hash(),
        }
    }
}

impl<R: Read + Seek> Hasher for Codec<R, ()> {
    fn hash(&mut self) -> Result<Hash, ParseError> {
        match self {
            Codec::Gif(codec) => codec.hash(),
            Codec::C2pa(codec) => codec.hash(),
            Codec::External(_) => Err(ParseError::Unsupported),
        }
    }

    fn data_hash(&mut self) -> Result<DataHash, ParseError> {
        match self {
            Codec::Gif(codec) => codec.data_hash(),
            Codec::C2pa(codec) => codec.data_hash(),
            Codec::External(_) => Err(ParseError::Unsupported),
        }
    }

    fn box_hash(&mut self) -> Result<BoxHash, ParseError> {
        match self {
            Codec::Gif(codec) => codec.box_hash(),
            Codec::C2pa(codec) => codec.box_hash(),
            Codec::External(_) => Err(ParseError::Unsupported),
        }
    }

    fn bmff_hash(&mut self) -> Result<BmffHash, ParseError> {
        match self {
            Codec::Gif(codec) => codec.bmff_hash(),
            Codec::C2pa(codec) => codec.bmff_hash(),
            Codec::External(_) => Err(ParseError::Unsupported),
        }
    }

    fn collection_hash(&mut self) -> Result<CollectionHash, ParseError> {
        match self {
            Codec::Gif(codec) => codec.collection_hash(),
            Codec::C2pa(codec) => codec.collection_hash(),
            Codec::External(_) => Err(ParseError::Unsupported),
        }
    }
}

impl Supporter for Codec<()> {
    const MAX_SIGNATURE_LEN: usize = MAX_SIGNATURE_LEN;

    fn supports_signature(signature: &[u8]) -> bool {
        GifCodec::supports_signature(signature)
    }

    fn supports_extension(extension: &str) -> bool {
        GifCodec::supports_extension(extension)
    }

    fn supports_mime(mime: &str) -> bool {
        GifCodec::supports_mime(mime)
    }
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("TODO")]
    Unsupported,

    #[error("TODO")]
    UnknownFormat,

    #[error("TODO")]
    NothingToPatch,

    #[error("TODO")]
    InvalidPatchSize { expected: u64, actually: u64 },

    // This case occurs, for instance, when the magic trailer at the end of an XMP block in a GIF
    // does not conform to spec or the string is not valid UTF-8.
    #[error("XMP was found, but failed to validate")]
    InvalidXmpBlock,

    #[error("TODO")]
    InvalidAsset { reason: String },

    #[error("TODO")]
    SeekOutOfBounds(num::TryFromIntError),

    // TODO: use quick_xml
    // This occurs when we fail to parse the XML in the XMP string.
    #[error("TODO")]
    XmpParseError(fast_xml::Error),

    #[error("TODO")]
    IoError(#[from] io::Error),
}
