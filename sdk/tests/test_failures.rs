mod common;
use c2pa::{validation_status, Reader, Result};
use common::fixture_stream;

#[test]
fn test_reader_ts_changed() -> Result<()> {
    let (format, mut stream) = fixture_stream("CA_ct.jpg")?;
    let reader = Reader::from_stream(&format, &mut stream).unwrap();
    // in the older validation statuses, this was an error, but now it is informational
    assert_eq!(
        reader
            .validation_results()
            .unwrap()
            .active_manifest()
            .unwrap()
            .informational[0]
            .code(),
        validation_status::TIMESTAMP_MALFORMED
    );

    Ok(())
}
