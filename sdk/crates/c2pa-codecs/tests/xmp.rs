use std::io::Cursor;

use c2pa_codecs::{Codec, Decode, Encode, CodecError};
use common::ASSETS;

mod common;

#[test]
fn test_xmp_read() -> Result<(), CodecError> {
    for asset in ASSETS {
        let mut src = Cursor::new(asset.bytes);

        let mut codec = Codec::from_stream(&mut src)?;
        assert!(matches!(codec.read_xmp(), Ok(None)));
    }

    Ok(())
}

#[test]
fn test_xmp_write() -> Result<(), CodecError> {
    for asset in ASSETS {
        let mut src = Cursor::new(asset.bytes);

        let mut codec = Codec::from_stream(&mut src)?;
        assert!(matches!(codec.read_xmp(), Ok(None)));

        let mut dst = Cursor::new(Vec::new());
        assert!(matches!(codec.write_xmp(&mut dst, "test"), Ok(())));

        let mut codec = Codec::from_stream(&mut dst)?;
        assert_eq!(codec.read_xmp()?, Some("test".to_string()));
    }

    Ok(())
}

#[test]
fn test_xmp_write_provenance() -> Result<(), CodecError> {
    for asset in ASSETS {
        let mut src = Cursor::new(asset.bytes);

        let mut codec = Codec::from_stream(&mut src)?;
        assert!(matches!(codec.read_xmp(), Ok(None)));

        let mut dst = Cursor::new(Vec::new());
        assert!(matches!(
            codec.write_xmp_provenance(&mut dst, "test"),
            Ok(())
        ));

        let mut codec = Codec::from_stream(&mut dst)?;
        assert_eq!(codec.read_xmp_provenance()?, Some("test".to_string()));
        assert_eq!(codec.read_xmp()?, Some("TODO".to_string()));
    }

    Ok(())
}

#[test]
fn test_xmp_remove() -> Result<(), CodecError> {
    for asset in ASSETS {
        // TODO
    }
    Ok(())
}

#[test]
fn test_xmp_remove_provenance() -> Result<(), CodecError> {
    for asset in ASSETS {
        // TODO
    }
    Ok(())
}
