use std::io::{Cursor, Read};

use c2pa_codecs::{Codec, CodecError, Support};
use common::ASSETS;

mod common;

#[test]
fn test_supporter_stream() -> Result<(), CodecError> {
    for asset in ASSETS {
        let mut src = Cursor::new(asset.bytes);

        let mut signature = Vec::with_capacity(asset.max_signature_len);
        src.read_exact(&mut signature)?;

        assert!(Codec::supports_signature(&signature));
        // assert!(matches!(
        //     Codec::supports_signature_from_stream(src),
        //     Ok(true)
        // ));
    }
    Ok(())
}

#[test]
fn test_supporter_extension() -> Result<(), CodecError> {
    for asset in ASSETS {
        assert!(Codec::supports_extension(asset.extension));
    }
    Ok(())
}

#[test]
fn test_supporter_mime() -> Result<(), CodecError> {
    for asset in ASSETS {
        assert!(Codec::supports_mime(asset.mime));
    }
    Ok(())
}
