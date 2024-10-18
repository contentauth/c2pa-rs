use std::{
    io::{self, BufRead, BufReader, Read, Seek, Write},
    num,
};

use crate::{
    codecs::{c2pa::C2paCodec, gif::GifCodec, svg::SvgCodec},
    protocols::*,
    Codec, CodecError,
}; // TODO: for now

macro_rules! codec_list {
    ($macro:ident) => {
        $macro_id! {
            C2paCodec, GifCodec, SvgCodec,
        }
    };
}

macro_rules! codec_from {
    ($src:expr, $check_fn:ident, $($codec:tt),*) => {
        $(
            if $codec::$check_fn($src)? {
                return Ok(Self::$codec($codec::new($src)));
            }
        )*
        Err(CodecError::UnknownFormat)
    };
}

impl<R: Read + Seek> Codec<R> {
    pub fn from_stream(mut src: R) -> Result<Self, CodecError> {
        src.rewind()?;
        let mut src = BufReader::with_capacity(Codec::MAX_SIGNATURE_LEN, src);
        src.fill_buf()?;

        codec_list!(codec_from)
        codec_from!(&mut src, supports_stream, codec_list!())
    }
}
