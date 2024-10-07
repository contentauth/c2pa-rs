use std::io::Cursor;

use c2pa_codecs::{Codec, CodecError, Decode, Encode};
use common::{ASSETS, RANDOM_XMP};

mod common;

#[test]
fn test_xmp_read() -> Result<(), CodecError> {
    for asset in ASSETS {
        if !asset.supports_read_xmp {
            continue;
        }

        let mut src = Cursor::new(asset.bytes);

        let mut codec = Codec::from_stream(&mut src)?;
        assert!(matches!(codec.read_xmp(), Ok(None)));
    }

    Ok(())
}

#[test]
fn test_xmp_write() -> Result<(), CodecError> {
    for asset in ASSETS {
        if !asset.supports_read_xmp || !asset.supports_write_xmp {
            continue;
        }

        let mut src = Cursor::new(asset.bytes);

        let mut codec = Codec::from_stream(&mut src)?;
        assert!(matches!(codec.read_xmp(), Ok(None)));

        let mut dst = Cursor::new(Vec::new());
        assert!(matches!(codec.write_xmp(&mut dst, RANDOM_XMP), Ok(())));

        let mut codec = Codec::from_stream(&mut dst)?;
        assert_eq!(codec.read_xmp()?, Some(RANDOM_XMP.to_string()));
    }

    Ok(())
}

#[test]
fn test_xmp_write_provenance() -> Result<(), CodecError> {
    for asset in ASSETS {
        if !asset.supports_read_xmp
            || !asset.supports_write_xmp_provenance
            || !asset.supports_read_xmp_provenance
        {
            continue;
        }

        let mut src = Cursor::new(asset.bytes);

        let mut codec = Codec::from_stream(&mut src)?;
        assert!(matches!(codec.read_xmp(), Ok(None)));

        let random_xmp = "test";
        let mut dst = Cursor::new(Vec::new());
        assert!(matches!(
            codec.write_xmp_provenance(&mut dst, random_xmp),
            Ok(())
        ));

        let mut codec = Codec::from_stream(&mut dst)?;
        assert_eq!(codec.read_xmp_provenance()?, Some(random_xmp.to_string()));
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
