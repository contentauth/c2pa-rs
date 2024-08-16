use std::io::{self, Cursor};

use c2pa_codecs::{Codec, CodecError, Decode, Encode, EncodeInPlace};
use common::{ASSETS, RANDOM_JUMBF_BYTES1, RANDOM_JUMBF_BYTES2, RANDOM_JUMBF_BYTES3};

mod common;

#[test]
fn test_c2pa_read() -> Result<(), CodecError> {
    for asset in ASSETS {
        if !asset.supports_read_c2pa {
            continue;
        }

        let mut src = Cursor::new(asset.bytes);

        // Read the c2pa (none should exist).
        let mut codec = Codec::from_stream(&mut src)?;
        assert!(matches!(codec.read_c2pa(), Ok(None)));
    }
    Ok(())
}

#[test]
fn test_c2pa_write() -> Result<(), CodecError> {
    for asset in ASSETS {
        if !asset.supports_read_c2pa || !asset.supports_write_c2pa {
            continue;
        }

        let mut src = Cursor::new(asset.bytes);

        // Read the c2pa (none should exist).
        let mut codec = Codec::from_stream(&mut src)?;
        assert!(matches!(codec.read_c2pa(), Ok(None)));

        // Write random bytes.
        let random_bytes = RANDOM_JUMBF_BYTES1;
        let mut dst = Cursor::new(Vec::new());
        assert!(matches!(codec.write_c2pa(&mut dst, random_bytes), Ok(())));

        // Read the c2pa.
        let mut codec = Codec::from_stream(&mut dst)?;
        assert_eq!(codec.read_c2pa()?.as_deref(), Some(random_bytes));
    }
    Ok(())
}

#[test]
fn test_c2pa_replace() -> Result<(), CodecError> {
    for asset in ASSETS {
        if !asset.supports_read_c2pa || !asset.supports_remove_c2pa || !asset.supports_write_c2pa {
            continue;
        }

        let mut src = Cursor::new(asset.bytes);

        // Read the c2pa (none should exist).
        let mut codec = Codec::from_stream(&mut src)?;
        assert!(matches!(codec.read_c2pa(), Ok(None)));

        // Write random bytes.
        let random_bytes = RANDOM_JUMBF_BYTES1;
        let mut dst = Cursor::new(Vec::new());
        assert!(matches!(codec.write_c2pa(&mut dst, random_bytes), Ok(())));

        // Write some more random bytes (should replace).
        let random_bytes = RANDOM_JUMBF_BYTES2;
        let mut codec = Codec::from_stream(&mut dst)?;
        let mut dst = Cursor::new(Vec::new());
        assert!(matches!(codec.write_c2pa(&mut dst, random_bytes), Ok(())));

        // Read the new replaced c2pa.
        let mut codec = Codec::from_stream(&mut dst)?;
        assert_eq!(codec.read_c2pa()?.as_deref(), Some(random_bytes));

        // Remove the replaced c2pa (should exist).
        let mut codec = Codec::from_stream(&mut dst)?;
        let mut dst = Cursor::new(Vec::new());
        assert!(codec.remove_c2pa(&mut dst)?);

        // Read the c2pa (none should exist).
        let mut codec = Codec::from_stream(&mut dst)?;
        assert_eq!(codec.read_c2pa()?.as_deref(), None);

        // TODO: svg isn't cleaning up the entire c2pa block on remove!
        // Ensure dst is back to src.
        // assert_eq!(src.into_inner(), dst.into_inner());
    }
    Ok(())
}

#[test]
fn test_c2pa_remove() -> Result<(), CodecError> {
    for asset in ASSETS {
        if !asset.supports_read_c2pa || !asset.supports_remove_c2pa || !asset.supports_write_c2pa {
            continue;
        }

        let mut src = Cursor::new(asset.bytes);

        // Read the c2pa (none should exist).
        let mut codec = Codec::from_stream(&mut src)?;
        assert!(matches!(codec.read_c2pa(), Ok(None)));

        // Remove the c2pa (none should be found).
        assert!(!codec.remove_c2pa(&mut io::empty())?);

        // Write random bytes.
        let random_bytes = RANDOM_JUMBF_BYTES1;
        let mut codec = Codec::from_stream(&mut src)?;
        let mut dst = Cursor::new(Vec::new());
        assert!(matches!(codec.write_c2pa(&mut dst, random_bytes), Ok(())));

        // Remove the c2pa (it should exist).
        let mut codec = Codec::from_stream(&mut dst)?;
        let mut dst = Cursor::new(Vec::new());
        assert!(codec.remove_c2pa(&mut dst)?);

        // TODO: svg isn't cleaning up the entire c2pa block on remove!
        // Ensure dst is back to src.
        // assert_eq!(src.into_inner(), dst.into_inner());
    }
    Ok(())
}

#[test]
fn test_c2pa_patch() -> Result<(), CodecError> {
    for asset in ASSETS {
        if !asset.supports_read_c2pa
            || !asset.supports_patch_c2pa
            || !asset.supports_write_c2pa
            || !asset.supports_remove_c2pa
        {
            continue;
        }

        let mut src = Cursor::new(asset.bytes);

        // Read the c2pa (none should exist).
        let mut codec = Codec::from_stream(&mut src)?;
        assert!(matches!(codec.read_c2pa(), Ok(None)));

        // Try to patch bytes (should not work).
        let random_bytes = RANDOM_JUMBF_BYTES1;
        let mut dst = Cursor::new(asset.bytes.to_owned());
        let mut codec = Codec::from_stream(&mut dst)?;
        assert!(matches!(
            codec.patch_c2pa(random_bytes),
            Err(CodecError::NothingToPatch)
        ));

        // Write random bytes.
        let mut dst = Cursor::new(Vec::new());
        assert!(matches!(codec.write_c2pa(&mut dst, random_bytes), Ok(())));

        // Patch bytes.
        let random_bytes = RANDOM_JUMBF_BYTES2;
        let mut codec = Codec::from_stream(&mut dst)?;
        assert!(matches!(codec.patch_c2pa(random_bytes), Ok(())));

        // Read the c2pa.
        assert_eq!(codec.read_c2pa()?.as_deref(), Some(random_bytes));

        // Patch bytes with incorrect size.
        let random_bytes = RANDOM_JUMBF_BYTES3;
        assert!(matches!(
            codec.patch_c2pa(random_bytes).unwrap_err(),
            // We don't know what the expected/actual patch size is because they are
            // based on the encoding of the individual file formats block.
            CodecError::InvalidPatchSize {
                expected: _,
                actual: _
            }
        ));

        // Remove the c2pa (it should exist).
        let mut codec = Codec::from_stream(&mut dst)?;
        let mut dst = Cursor::new(Vec::new());
        assert!(codec.remove_c2pa(&mut dst)?);

        // TODO: svg isn't cleaning up the entire c2pa block on remove!
        // Ensure dst is back to src.
        // assert_eq!(src.into_inner(), dst.into_inner());
    }
    Ok(())
}
