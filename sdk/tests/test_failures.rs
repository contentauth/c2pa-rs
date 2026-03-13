mod common;
use std::io::Cursor;

use c2pa::{
    assertions::DataHash, settings::Settings, validation_status, Builder, BuilderIntent, Error,
    HashRange, Reader, Result,
};
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

#[test]
fn test_bad_data_hash() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    const TEST_IMAGE: &[u8] = include_bytes!("fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);

    use c2pa::assertions::Action;
    builder.add_action(Action::new("c2pa.published"))?;

    builder.add_action(serde_json::json!({
        "action": "c2pa.edited",
        "parameters": {
            "description": "edited",
            "name": "any value"
        },
        "softwareAgent": {
            "name": "TestApp",
            "version": "1.0.0"
        }
    }))?;

    // add empty data hash
    let empty_hash =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .expect("Invalid hex");

    let mut malicious_data_hash = DataHash::new("malicious", "sha256");
    malicious_data_hash.exclusions = Some(vec![HashRange::new(0, 0)]); // THE EXPLOIT!
    malicious_data_hash.set_hash(empty_hash.clone());

    builder.add_assertion("c2pa.hash.data", &malicious_data_hash)?;

    let mut dest = Cursor::new(Vec::new());

    let result = builder.sign(&Settings::signer()?, format, &mut source, &mut dest);
    assert!(matches!(result, Err(Error::HashMismatch(..))));

    Ok(())
}
