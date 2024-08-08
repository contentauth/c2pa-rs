mod common;
use c2pa::{Reader, Result};
use common::fixture_stream;

#[test]
fn test_reader_ts_changed() -> Result<()> {
    let (format, mut stream) = fixture_stream("CA_ct.jpg")?;
    let reader = Reader::from_stream(&format, &mut stream).unwrap();

    let vl = reader.validation_status().unwrap();

    assert!(!vl.is_empty());
    Ok(())
}
