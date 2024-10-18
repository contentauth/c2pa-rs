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

use codecs::{c2pa::C2paCodec, gif::GifCodec, jpeg::JpegCodec, svg::SvgCodec};
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
    Jpeg(JpegCodec<R>),
    External(E),
}

impl<R: Read + Seek> Codec<R> {
    pub fn from_stream(mut src: R) -> Result<Self, CodecError> {
        src.rewind()?;
        let mut signature = vec![0; Codec::MAX_SIGNATURE_LEN];
        src.read_exact(&mut signature)?;

        // TODO: if one of these methods error, then skip it
        // TODO: also need to rewind streams in the case of svg
        if C2paCodec::supports_signature(&signature) {
            Ok(Self::C2pa(C2paCodec::new(src)))
        } else if GifCodec::supports_signature(&signature) {
            Ok(Self::Gif(GifCodec::new(src)))
        } else if JpegCodec::supports_signature(&signature) {
            Ok(Self::Jpeg(JpegCodec::new(src)))
        } else {
            src.rewind()?;
            if SvgCodec::supports_stream(&mut src)? {
                Ok(Self::Svg(SvgCodec::new(src)))
            } else {
                Err(CodecError::UnknownFormat)
            }
        }
    }

    pub fn from_extension(extension: &str, src: R) -> Result<Self, CodecError> {
        if C2paCodec::supports_extension(extension) {
            Ok(Self::C2pa(C2paCodec::new(src)))
        } else if GifCodec::supports_extension(extension) {
            Ok(Self::Gif(GifCodec::new(src)))
        } else if SvgCodec::supports_extension(extension) {
            Ok(Self::Svg(SvgCodec::new(src)))
        } else if JpegCodec::supports_extension(extension) {
            Ok(Self::Jpeg(JpegCodec::new(src)))
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
        } else if JpegCodec::supports_mime(mime) {
            Ok(Self::Jpeg(JpegCodec::new(src)))
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
            Codec::Jpeg(codec) => codec.write_c2pa(dst, c2pa),
            Codec::External(codec) => codec.write_c2pa(dst, c2pa),
        }
    }

    fn remove_c2pa(&mut self, dst: impl Write) -> Result<bool, CodecError> {
        match self {
            Codec::Gif(codec) => codec.remove_c2pa(dst),
            Codec::C2pa(codec) => codec.remove_c2pa(dst),
            Codec::Svg(codec) => codec.remove_c2pa(dst),
            Codec::Jpeg(codec) => codec.remove_c2pa(dst),
            Codec::External(codec) => codec.remove_c2pa(dst),
        }
    }

    fn write_xmp(&mut self, dst: impl Write, xmp: &str) -> Result<(), CodecError> {
        match self {
            Codec::Gif(codec) => codec.write_xmp(dst, xmp),
            Codec::C2pa(codec) => codec.write_xmp(dst, xmp),
            Codec::Svg(codec) => codec.write_xmp(dst, xmp),
            Codec::Jpeg(codec) => codec.write_xmp(dst, xmp),
            Codec::External(codec) => codec.write_xmp(dst, xmp),
        }
    }
}

impl<R: Read + Write + Seek, E: EncodeInPlace> EncodeInPlace for Codec<R, E> {
    fn patch_c2pa(&mut self, c2pa: &[u8]) -> Result<(), CodecError> {
        match self {
            Codec::Gif(codec) => codec.patch_c2pa(c2pa),
            Codec::C2pa(codec) => codec.patch_c2pa(c2pa),
            Codec::Svg(codec) => codec.patch_c2pa(c2pa),
            // TODO:
            Codec::Jpeg(_) => Err(CodecError::Unsupported),
            Codec::External(codec) => codec.patch_c2pa(c2pa),
        }
    }
}

impl<R: Read + Seek, E: Decode> Decode for Codec<R, E> {
    fn read_c2pa(&mut self) -> Result<Option<Vec<u8>>, CodecError> {
        match self {
            Codec::Gif(codec) => codec.read_c2pa(),
            Codec::C2pa(codec) => codec.read_c2pa(),
            Codec::Svg(codec) => codec.read_c2pa(),
            Codec::Jpeg(codec) => codec.read_c2pa(),
            Codec::External(codec) => codec.read_c2pa(),
        }
    }

    fn read_xmp(&mut self) -> Result<Option<String>, CodecError> {
        match self {
            Codec::Gif(codec) => codec.read_xmp(),
            Codec::C2pa(codec) => codec.read_xmp(),
            Codec::Svg(codec) => codec.read_xmp(),
            Codec::Jpeg(codec) => codec.read_xmp(),
            Codec::External(codec) => codec.read_xmp(),
        }
    }
}

impl<R: Read + Seek, E: Embed> Embed for Codec<R, E> {
    fn embeddable(bytes: &[u8]) -> Result<Embeddable, CodecError> {
        Err(CodecError::Unsupported)
    }

    fn embed(&mut self, embeddable: Embeddable, dst: impl Write) -> Result<(), CodecError> {
        match self {
            Codec::Gif(codec) => codec.embed(embeddable, dst),
            Codec::C2pa(codec) => codec.embed(embeddable, dst),
            Codec::Svg(codec) => codec.embed(embeddable, dst),
            Codec::Jpeg(codec) => codec.embed(embeddable, dst),
            Codec::External(codec) => codec.embed(embeddable, dst),
        }
    }
}

impl<R: Read + Seek, E: Span> Span for Codec<R, E> {
    fn span(&mut self) -> Result<DefaultSpan, CodecError> {
        match self {
            Codec::Gif(codec) => codec.span(),
            Codec::C2pa(codec) => codec.span(),
            Codec::Svg(codec) => codec.span(),
            Codec::Jpeg(codec) => codec.span(),
            Codec::External(codec) => codec.span(),
        }
    }

    fn c2pa_span(&mut self) -> Result<C2paSpan, CodecError> {
        match self {
            Codec::Gif(codec) => codec.c2pa_span(),
            Codec::C2pa(codec) => codec.c2pa_span(),
            Codec::Svg(codec) => codec.c2pa_span(),
            Codec::Jpeg(codec) => codec.c2pa_span(),
            Codec::External(codec) => codec.c2pa_span(),
        }
    }

    fn box_span(&mut self) -> Result<BoxSpan, CodecError> {
        match self {
            Codec::Gif(codec) => codec.box_span(),
            Codec::C2pa(codec) => codec.box_span(),
            Codec::Svg(codec) => codec.box_span(),
            Codec::Jpeg(codec) => codec.box_span(),
            Codec::External(codec) => codec.box_span(),
        }
    }

    fn bmff_span(&mut self) -> Result<BmffSpan, CodecError> {
        match self {
            Codec::Gif(codec) => codec.bmff_span(),
            Codec::C2pa(codec) => codec.bmff_span(),
            Codec::Svg(codec) => codec.bmff_span(),
            Codec::Jpeg(codec) => codec.bmff_span(),
            Codec::External(codec) => codec.bmff_span(),
        }
    }

    fn collection_span(&mut self) -> Result<CollectionSpan, CodecError> {
        match self {
            Codec::Gif(codec) => codec.collection_span(),
            Codec::C2pa(codec) => codec.collection_span(),
            Codec::Svg(codec) => codec.collection_span(),
            Codec::Jpeg(codec) => codec.collection_span(),
            Codec::External(codec) => codec.collection_span(),
        }
    }
}

impl Support for Codec<()> {
    // TODO: find max signatuture len among all codecs via Supporter::MAX_SIGNATURE_LEN
    const MAX_SIGNATURE_LEN: usize = 13;

    fn supports_signature(signature: &[u8]) -> bool {
        GifCodec::supports_signature(signature)
            || C2paCodec::supports_signature(signature)
            || JpegCodec::supports_signature(signature)
    }

    fn supports_stream(mut src: impl Read + Seek) -> Result<bool, CodecError> {
        src.rewind()?;
        let mut signature = vec![0; Codec::MAX_SIGNATURE_LEN];
        src.read_exact(&mut signature)?;

        match Codec::supports_signature(&signature) {
            true => Ok(true),
            false => {
                src.rewind()?;
                SvgCodec::supports_stream(src)
            }
        }
    }

    fn supports_extension(extension: &str) -> bool {
        GifCodec::supports_extension(extension)
            || C2paCodec::supports_extension(extension)
            || SvgCodec::supports_extension(extension)
            || JpegCodec::supports_extension(extension)
    }

    fn supports_mime(mime: &str) -> bool {
        GifCodec::supports_mime(mime)
            || SvgCodec::supports_mime(mime)
            || C2paCodec::supports_mime(mime)
            || JpegCodec::supports_mime(mime)
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

    #[error("Unknown format while creating the Codec.")]
    UnknownFormat,

    #[error("Incorrect file format for the codec.")]
    IncorrectFormat,

    #[error("Attempted to patch a file without an existing manifest.")]
    NothingToPatch,

    #[error("Invalid size of patch, expected {expected}, got {actual}.")]
    InvalidPatchSize { expected: u64, actual: u64 },

    #[error("More than one C2PA manifest was found inside the file.")]
    MoreThanOneC2pa,

    // This case occurs, for instance, when the magic trailer at the end of an XMP block in a GIF
    // does not conform to spec or the string is not valid UTF-8.
    #[error("XMP was found, but failed to validate.")]
    InvalidXmpBlock,

    #[error("TODO")]
    InvalidAsset {
        src: Option<String>,
        context: String,
    },

    #[error("Attempted to seek out of bounds.")]
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
