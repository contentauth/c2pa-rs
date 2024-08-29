mod common;
use std::io::Cursor;

use c2pa::{Reader, Result};

#[test]
fn test_reader_ts_changed() -> Result<()> {
    let asset = Cursor::new(include_bytes!("fixtures/CA_ct.jpg"));
    let reader = Reader::from_stream("image/jpeg", asset)?;

    let vl = reader.validation_status().unwrap();

    assert!(!vl.is_empty());
    Ok(())
}
