use std::io::Cursor;

use c2pa_codecs::{Codec, CodecError, Support};
use common::ASSETS;

mod common;

#[test]
fn test_supports_stream() -> Result<(), CodecError> {
    for asset in ASSETS {
        if !asset.supports_supports_stream {
            continue;
        }

        assert!(matches!(
            Codec::supports_stream(&mut Cursor::new(asset.bytes)),
            Ok(true)
        ));
    }
    Ok(())
}

#[test]
fn test_supports_extension() -> Result<(), CodecError> {
    for asset in ASSETS {
        if !asset.supports_supports_extension {
            continue;
        }

        assert!(Codec::supports_extension(asset.extension));
    }
    Ok(())
}

#[test]
fn test_supports_mime() -> Result<(), CodecError> {
    for asset in ASSETS {
        if !asset.supports_supports_mime {
            continue;
        }

        assert!(Codec::supports_mime(asset.mime));
    }
    Ok(())
}
