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

use codecs::{c2pa::C2paCodec, gif::GifCodec, svg::SvgCodec};
pub use protocols::*; // TODO: for now
use thiserror::Error;

pub mod codecs;
mod protocols;
mod xmp;

// TODO: WRITE MACROS!!!
// TODO: add other codecs
// TODO: users should wrap it in their own BufReader, don't include in impl (like svg)

pub enum Codec<R, E = ()> {
    C2pa(C2paCodec<R>),
    Gif(GifCodec<R>),
    Svg(SvgCodec<R>),
    External(E),
}

impl<R: Read + Seek> Codec<R> {
    pub fn from_stream(mut src: R) -> Result<Self, CodecError> {
        let mut signature = [0; MAX_SIGNATURE_LEN];
        src.read_exact(&mut signature)?;
        if C2paCodec::supports_signature(&signature) {
            Ok(Self::C2pa(C2paCodec::new(src)))
        } else if GifCodec::supports_signature(&signature) {
            Ok(Self::Gif(GifCodec::new(src)))
        } else if SvgCodec::supports_signature(&signature) {
            Ok(Self::Svg(SvgCodec::new(src)))
        } else {
            Err(CodecError::UnknownFormat)
        }
    }

    pub fn from_extension(extension: &str, src: R) -> Result<Self, CodecError> {
        if C2paCodec::supports_extension(extension) {
            Ok(Self::C2pa(C2paCodec::new(src)))
        } else if GifCodec::supports_extension(extension) {
            Ok(Self::Gif(GifCodec::new(src)))
        } else if SvgCodec::supports_extension(extension) {
            Ok(Self::Svg(SvgCodec::new(src)))
        } else {
            Err(CodecError::UnknownFormat)
        }
    }

    pub fn from_mime(mime: &str, src: R) -> Result<Self, CodecError> {
        if C2paCodec::supports_mime(mime) {
            Ok(Self::C2pa(C2paCodec::new(src)))
        } else if GifCodec::supports_mime(mime) {
            Ok(Self::Gif(GifCodec::new(src)))
        } else if SvgCodec::supports_mime(mime) {
            Ok(Self::Svg(SvgCodec::new(src)))
        } else {
            Err(CodecError::UnknownFormat)
        }
    }
}

impl<R, E> Codec<R, E> {
    pub fn from_external(external: E) -> Self {
        Self::External(external)
    }
}

impl<R: Read + Seek, E: Encode> Encode for Codec<R, E> {
    fn write_c2pa(&mut self, dst: impl Write, c2pa: &[u8]) -> Result<(), CodecError> {
        match self {
            Codec::Gif(codec) => codec.write_c2pa(dst, c2pa),
            Codec::C2pa(codec) => codec.write_c2pa(dst, c2pa),
            Codec::Svg(codec) => codec.write_c2pa(dst, c2pa),
            Codec::External(codec) => codec.write_c2pa(dst, c2pa),
        }
    }

    fn remove_c2pa(&mut self, dst: impl Write) -> Result<bool, CodecError> {
        match self {
            Codec::Gif(codec) => codec.remove_c2pa(dst),
            Codec::C2pa(codec) => codec.remove_c2pa(dst),
            Codec::Svg(codec) => codec.remove_c2pa(dst),
            Codec::External(codec) => codec.remove_c2pa(dst),
        }
    }

    fn write_xmp(&mut self, dst: impl Write, xmp: &str) -> Result<(), CodecError> {
        match self {
            Codec::Gif(codec) => codec.write_xmp(dst, xmp),
            Codec::C2pa(codec) => codec.write_xmp(dst, xmp),
            Codec::Svg(codec) => codec.write_xmp(dst, xmp),
            Codec::External(codec) => codec.write_xmp(dst, xmp),
        }
    }

    fn patch_c2pa(&self, dst: impl Read + Write + Seek, c2pa: &[u8]) -> Result<(), CodecError> {
        match self {
            Codec::Gif(codec) => codec.patch_c2pa(dst, c2pa),
            Codec::C2pa(codec) => codec.patch_c2pa(dst, c2pa),
            Codec::Svg(codec) => codec.patch_c2pa(dst, c2pa),
            Codec::External(codec) => codec.patch_c2pa(dst, c2pa),
        }
    }
}

impl<R: Read + Seek> Encode for Codec<R, ()> {
    fn write_c2pa(&mut self, dst: impl Write, c2pa: &[u8]) -> Result<(), CodecError> {
        match self {
            Codec::Gif(codec) => codec.write_c2pa(dst, c2pa),
            Codec::C2pa(codec) => codec.write_c2pa(dst, c2pa),
            Codec::Svg(codec) => codec.write_c2pa(dst, c2pa),
            Codec::External(_) => Err(CodecError::Unsupported),
        }
    }

    fn remove_c2pa(&mut self, dst: impl Write) -> Result<bool, CodecError> {
        match self {
            Codec::Gif(codec) => codec.remove_c2pa(dst),
            Codec::C2pa(codec) => codec.remove_c2pa(dst),
            Codec::Svg(codec) => codec.remove_c2pa(dst),
            Codec::External(_) => Err(CodecError::Unsupported),
        }
    }

    fn write_xmp(&mut self, dst: impl Write, xmp: &str) -> Result<(), CodecError> {
        match self {
            Codec::Gif(codec) => codec.write_xmp(dst, xmp),
            Codec::C2pa(codec) => codec.write_xmp(dst, xmp),
            Codec::Svg(codec) => codec.write_xmp(dst, xmp),
            Codec::External(_) => Err(CodecError::Unsupported),
        }
    }

    fn patch_c2pa(&self, dst: impl Read + Write + Seek, c2pa: &[u8]) -> Result<(), CodecError> {
        match self {
            Codec::Gif(codec) => codec.patch_c2pa(dst, c2pa),
            Codec::C2pa(codec) => codec.patch_c2pa(dst, c2pa),
            Codec::Svg(codec) => codec.patch_c2pa(dst, c2pa),
            Codec::External(_) => Err(CodecError::Unsupported),
        }
    }
}

impl<R: Read + Seek, E: Decode> Decode for Codec<R, E> {
    fn read_c2pa(&mut self) -> Result<Option<Vec<u8>>, CodecError> {
        match self {
            Codec::Gif(codec) => codec.read_c2pa(),
            Codec::C2pa(codec) => codec.read_c2pa(),
            Codec::Svg(codec) => codec.read_c2pa(),
            Codec::External(codec) => codec.read_c2pa(),
        }
    }

    fn read_xmp(&mut self) -> Result<Option<String>, CodecError> {
        match self {
            Codec::Gif(codec) => codec.read_xmp(),
            Codec::C2pa(codec) => codec.read_xmp(),
            Codec::Svg(codec) => codec.read_xmp(),
            Codec::External(codec) => codec.read_xmp(),
        }
    }
}

impl<R: Read + Seek> Decode for Codec<R, ()> {
    fn read_c2pa(&mut self) -> Result<Option<Vec<u8>>, CodecError> {
        match self {
            Codec::Gif(codec) => codec.read_c2pa(),
            Codec::C2pa(codec) => codec.read_c2pa(),
            Codec::Svg(codec) => codec.read_c2pa(),
            Codec::External(_) => Err(CodecError::Unsupported),
        }
    }

    fn read_xmp(&mut self) -> Result<Option<String>, CodecError> {
        match self {
            Codec::Gif(codec) => codec.read_xmp(),
            Codec::C2pa(codec) => codec.read_xmp(),
            Codec::Svg(codec) => codec.read_xmp(),
            Codec::External(_) => Err(CodecError::Unsupported),
        }
    }
}

impl<R: Read + Seek, E: Embed> Embed for Codec<R, E> {
    fn embeddable(&self, bytes: &[u8]) -> Embeddable {
        match self {
            Codec::Gif(codec) => codec.embeddable(bytes),
            Codec::C2pa(codec) => todo!(),
            Codec::Svg(codec) => codec.embeddable(bytes),
            Codec::External(codec) => codec.embeddable(bytes),
        }
    }

    fn read_embeddable(&mut self) -> Embeddable {
        match self {
            Codec::Gif(codec) => codec.read_embeddable(),
            Codec::C2pa(codec) => todo!(),
            Codec::Svg(codec) => codec.read_embeddable(),
            // TODO: same here
            Codec::External(codec) => codec.read_embeddable(),
        }
    }

    fn write_embeddable(
        &mut self,
        embeddable: Embeddable,
        dst: impl Write,
    ) -> Result<(), CodecError> {
        match self {
            Codec::Gif(codec) => codec.write_embeddable(embeddable, dst),
            Codec::C2pa(codec) => todo!(),
            Codec::Svg(codec) => codec.write_embeddable(embeddable, dst),
            Codec::External(codec) => codec.write_embeddable(embeddable, dst),
        }
    }
}

impl<R: Read + Seek> Embed for Codec<R, ()> {
    fn embeddable(&self, bytes: &[u8]) -> Embeddable {
        match self {
            Codec::Gif(codec) => codec.embeddable(bytes),
            Codec::C2pa(codec) => todo!(),
            Codec::Svg(codec) => codec.embeddable(bytes),
            // TODO: this case should be unreachable, it shouldn't be possible to call from_external(()), maybe panic
            Codec::External(_) => todo!(),
        }
    }

    fn read_embeddable(&mut self) -> Embeddable {
        match self {
            Codec::Gif(codec) => codec.read_embeddable(),
            Codec::C2pa(codec) => todo!(),
            Codec::Svg(codec) => codec.read_embeddable(),
            // TODO: same here
            Codec::External(_) => todo!(),
        }
    }

    fn write_embeddable(
        &mut self,
        embeddable: Embeddable,
        dst: impl Write,
    ) -> Result<(), CodecError> {
        match self {
            Codec::Gif(codec) => codec.write_embeddable(embeddable, dst),
            Codec::C2pa(codec) => todo!(),
            Codec::Svg(codec) => codec.write_embeddable(embeddable, dst),
            // TODO: same here
            Codec::External(_) => todo!(),
        }
    }
}

impl<R: Read + Seek, E: Span> Span for Codec<R, E> {
    fn hash(&mut self) -> Result<Hash, CodecError> {
        match self {
            Codec::Gif(codec) => codec.hash(),
            Codec::C2pa(codec) => codec.hash(),
            Codec::Svg(codec) => codec.hash(),
            Codec::External(codec) => codec.hash(),
        }
    }

    fn data_hash(&mut self) -> Result<DataHash, CodecError> {
        match self {
            Codec::Gif(codec) => codec.data_hash(),
            Codec::C2pa(codec) => codec.data_hash(),
            Codec::Svg(codec) => codec.data_hash(),
            Codec::External(codec) => codec.data_hash(),
        }
    }

    fn box_hash(&mut self) -> Result<BoxHash, CodecError> {
        match self {
            Codec::Gif(codec) => codec.box_hash(),
            Codec::C2pa(codec) => codec.box_hash(),
            Codec::Svg(codec) => codec.box_hash(),
            Codec::External(codec) => codec.box_hash(),
        }
    }

    fn bmff_hash(&mut self) -> Result<BmffHash, CodecError> {
        match self {
            Codec::Gif(codec) => codec.bmff_hash(),
            Codec::C2pa(codec) => codec.bmff_hash(),
            Codec::Svg(codec) => codec.bmff_hash(),
            Codec::External(codec) => codec.bmff_hash(),
        }
    }

    fn collection_hash(&mut self) -> Result<CollectionHash, CodecError> {
        match self {
            Codec::Gif(codec) => codec.collection_hash(),
            Codec::C2pa(codec) => codec.collection_hash(),
            Codec::Svg(codec) => codec.collection_hash(),
            Codec::External(codec) => codec.collection_hash(),
        }
    }
}

impl<R: Read + Seek> Span for Codec<R, ()> {
    fn hash(&mut self) -> Result<Hash, CodecError> {
        match self {
            Codec::Gif(codec) => codec.hash(),
            Codec::C2pa(codec) => codec.hash(),
            Codec::Svg(codec) => codec.hash(),
            Codec::External(_) => Err(CodecError::Unsupported),
        }
    }

    fn data_hash(&mut self) -> Result<DataHash, CodecError> {
        match self {
            Codec::Gif(codec) => codec.data_hash(),
            Codec::C2pa(codec) => codec.data_hash(),
            Codec::Svg(codec) => codec.data_hash(),
            Codec::External(_) => Err(CodecError::Unsupported),
        }
    }

    fn box_hash(&mut self) -> Result<BoxHash, CodecError> {
        match self {
            Codec::Gif(codec) => codec.box_hash(),
            Codec::C2pa(codec) => codec.box_hash(),
            Codec::Svg(codec) => codec.box_hash(),
            Codec::External(_) => Err(CodecError::Unsupported),
        }
    }

    fn bmff_hash(&mut self) -> Result<BmffHash, CodecError> {
        match self {
            Codec::Gif(codec) => codec.bmff_hash(),
            Codec::C2pa(codec) => codec.bmff_hash(),
            Codec::Svg(codec) => codec.bmff_hash(),
            Codec::External(_) => Err(CodecError::Unsupported),
        }
    }

    fn collection_hash(&mut self) -> Result<CollectionHash, CodecError> {
        match self {
            Codec::Gif(codec) => codec.collection_hash(),
            Codec::C2pa(codec) => codec.collection_hash(),
            Codec::Svg(codec) => codec.collection_hash(),
            Codec::External(_) => Err(CodecError::Unsupported),
        }
    }
}

impl Support for Codec<()> {
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
pub enum CodecError {
    // NOTE: unsupported refers to a function that is explicitly not supported in the spec
    #[error("TODO")]
    Unsupported,

    // NOTE: whereas, unimplemented is not yet implemented, but is supported in the spec
    #[error("TODO")]
    Unimplemented,

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
    InvalidAsset {
        src: Option<String>,
        context: String,
    },

    #[error("TODO")]
    SeekOutOfBounds(num::TryFromIntError),

    // TODO: use quick_xml
    // TODO: it may be more ideal to convert this error to a string, the user most likely doesn't care the exact type
    //       and we don't want to add an external API to our API
    // This occurs when we fail to parse the XML in the XMP string.
    #[error("TODO")]
    XmpParseError(#[source] fast_xml::Error),

    #[error("TODO")]
    IoError(#[from] io::Error),
}
