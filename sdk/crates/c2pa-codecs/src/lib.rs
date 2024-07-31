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

use codecs::gif::GifCodec;
pub use protocols::*; // TODO: for now
use thiserror::Error;

pub mod codecs;
mod protocols;
mod xmp;

// TODO: https://github.com/contentauth/c2pa-rs/issues/363
// TODO: https://github.com/contentauth/c2pa-rs/issues/398
// TODO: https://github.com/contentauth/c2pa-rs/issues/381
// TODO: write macro for everything below (so we don't have to use trait objects)
// TODO: add other codecs
#[derive(Debug)]
pub enum Codec<R> {
    Gif(GifCodec<R>),
    // External(Box<dyn Encoder + Decoder>),
}

impl<R: Read + Seek> Codec<R> {
    pub fn from_stream(mut src: R) -> Result<Self, ParseError> {
        let mut signature = [0; MAX_SIGNATURE_LEN];
        src.read_exact(&mut signature)?;

        if GifCodec::supports_signature(&signature) {
            Ok(Self::Gif(GifCodec::new(src)))
        } else {
            Err(ParseError::UnknownFormat)
        }
    }

    pub fn from_extension(extension: &str, src: R) -> Result<Self, ParseError> {
        if GifCodec::supports_extension(extension) {
            Ok(Self::Gif(GifCodec::new(src)))
        } else {
            Err(ParseError::UnknownFormat)
        }
    }

    pub fn from_mime(mime: &str, src: R) -> Result<Self, ParseError> {
        if GifCodec::supports_mime(mime) {
            Ok(Self::Gif(GifCodec::new(src)))
        } else {
            Err(ParseError::UnknownFormat)
        }
    }
}

impl<R: Read + Seek> Encoder for Codec<R> {
    fn write_c2pa(&mut self, dst: impl Write, c2pa: &[u8]) -> Result<(), ParseError> {
        match self {
            Codec::Gif(codec) => codec.write_c2pa(dst, c2pa),
        }
    }

    fn remove_c2pa(&mut self, dst: impl Write) -> Result<bool, ParseError> {
        match self {
            Codec::Gif(codec) => codec.remove_c2pa(dst),
        }
    }

    fn write_xmp(&mut self, dst: impl Write, xmp: &str) -> Result<(), ParseError> {
        match self {
            Codec::Gif(codec) => codec.write_xmp(dst, xmp),
        }
    }

    fn patch_c2pa(&self, dst: impl Read + Write + Seek, c2pa: &[u8]) -> Result<(), ParseError> {
        match self {
            Codec::Gif(codec) => codec.patch_c2pa(dst, c2pa),
        }
    }
}

impl<R: Read + Seek> Decoder for Codec<R> {
    fn read_c2pa(&mut self) -> Result<Option<Vec<u8>>, ParseError> {
        match self {
            Codec::Gif(codec) => codec.read_c2pa(),
        }
    }

    fn read_xmp(&mut self) -> Result<Option<String>, ParseError> {
        match self {
            Codec::Gif(codec) => codec.read_xmp(),
        }
    }
}

impl<R: Read + Seek> Hasher for Codec<R> {
    fn hash(&mut self) -> Result<Hash, ParseError> {
        match self {
            Codec::Gif(codec) => codec.hash(),
        }
    }

    fn data_hash(&mut self) -> Result<DataHash, ParseError> {
        match self {
            Codec::Gif(codec) => codec.data_hash(),
        }
    }

    fn box_hash(&mut self) -> Result<BoxHash, ParseError> {
        match self {
            Codec::Gif(codec) => codec.box_hash(),
        }
    }

    fn bmff_hash(&mut self) -> Result<BmffHash, ParseError> {
        match self {
            Codec::Gif(codec) => codec.bmff_hash(),
        }
    }

    fn collection_hash(&mut self) -> Result<CollectionHash, ParseError> {
        match self {
            Codec::Gif(codec) => codec.collection_hash(),
        }
    }
}

impl Supporter for Codec<()> {
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
