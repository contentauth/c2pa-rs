use std::io::Cursor;

use c2pa_codecs::{Codec, Decoder, ParseError};

// TODO: this would run over 1 of each file type
const SAMPLE: &[u8] = include_bytes!("../../../tests/fixtures/sample1.gif");

#[test]
fn test_xmp_read() -> Result<(), ParseError> {
    let mut src = Cursor::new(SAMPLE);

    let mut codec = Codec::from_stream(&mut src)?;
    assert!(matches!(codec.read_xmp(), Ok(None)));

    Ok(())
}

#[test]
fn test_xmp_write() -> Result<(), ParseError> {
    Ok(())
}
