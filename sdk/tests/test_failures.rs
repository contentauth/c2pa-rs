mod common;
use std::io::Cursor;

use c2pa::{
    assertions::DataHash, validation_status, Builder, BuilderIntent, Error, HashRange, Reader,
    Result,
};
use common::{fixture_stream, test_context};

#[test]
fn test_reader_ts_changed() -> Result<()> {
    let (format, mut stream) = fixture_stream("CA_ct.jpg")?;
    let reader = Reader::default().with_stream(&format, &mut stream).unwrap();
    // in the older validation statuses, this was an error, but now it is informational
    assert!(reader
        .validation_results()
        .unwrap()
        .active_manifest()
        .unwrap()
        .informational()
        .iter()
        .find(|i| i.code() == validation_status::TIMESTAMP_MALFORMED)
        .is_some());

    Ok(())
}

#[test]
fn test_bad_data_hash() -> Result<()> {
    let context = test_context().into_shared();

    const TEST_IMAGE: &[u8] = include_bytes!("fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    let mut builder = Builder::from_shared_context(&context);
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

    let err = builder
        .sign(context.signer()?, format, &mut source, &mut dest)
        .unwrap_err();

    let validation_results = match err {
        Error::InvalidManifest(validation_results) => validation_results,
        other => panic!("{other:?}"),
    };

    assert_eq!(
        validation_results.active_manifest().unwrap().failure[0].code(),
        validation_status::ASSERTION_DATAHASH_MISMATCH
    );

    Ok(())
}

/// Signs CA.jpg with the given `c2pa.actions.v2` assertion and returns the active manifest's
/// failure codes, from the sign-time validation or from reading the result back.
fn created_action_failures(actions: serde_json::Value) -> Result<Vec<String>> {
    let context = test_context().into_shared();
    let format = "image/jpeg";
    let mut source = Cursor::new(include_bytes!("fixtures/CA.jpg"));
    let mut builder = Builder::from_shared_context(&context);
    builder.add_assertion("c2pa.actions.v2", &actions)?;

    let mut dest = Cursor::new(Vec::new());
    let results = match builder.sign(context.signer()?, format, &mut source, &mut dest) {
        Ok(_) => {
            dest.set_position(0);
            Reader::from_shared_context(&context)
                .with_stream(format, &mut dest)?
                .validation_results()
                .cloned()
                .unwrap()
        }
        Err(Error::InvalidManifest(validation_results)) => *validation_results,
        Err(other) => return Err(other),
    };
    let codes = results.active_manifest().unwrap().failure().iter();
    Ok(codes
        .map(|s| s.code().to_owned())
        .filter(|c| c != validation_status::SIGNING_CREDENTIAL_UNTRUSTED)
        .collect())
}

#[test]
fn test_created_action_digital_source_type_from_template() -> Result<()> {
    const SOURCE_TYPE: &str = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture";

    // The action takes its digitalSourceType from a same-named template, or from `*`.
    for template in ["c2pa.created", "*"] {
        let failures = created_action_failures(serde_json::json!({
            "actions": [{ "action": "c2pa.created" }],
            "templates": [{ "action": template, "digitalSourceType": SOURCE_TYPE }],
            "allActionsIncluded": true,
        }))?;
        assert!(failures.is_empty(), "template {template}: {failures:?}");
    }

    // A template for a different action does not supply one.
    let failures = created_action_failures(serde_json::json!({
        "actions": [{ "action": "c2pa.created" }],
        "templates": [{ "action": "c2pa.edited", "digitalSourceType": SOURCE_TYPE }],
        "allActionsIncluded": true,
    }))?;
    assert_eq!(failures, [validation_status::ASSERTION_ACTION_MALFORMED]);

    Ok(())
}

#[test]
fn test_created_action_missing_digital_source_type() -> Result<()> {
    let context = test_context().into_shared();

    const TEST_IMAGE: &[u8] = include_bytes!("fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    let mut builder = Builder::from_shared_context(&context);

    // Manually craft a c2pa.created action without a digitalSourceType, bypassing
    // the BuilderIntent::Create API (which requires a DigitalSourceType at the type level).
    builder.add_action(serde_json::json!({
        "action": "c2pa.created"
    }))?;

    let mut dest = Cursor::new(Vec::new());
    let err = builder
        .sign(context.signer()?, format, &mut source, &mut dest)
        .unwrap_err();

    let validation_results = match err {
        Error::InvalidManifest(validation_results) => validation_results,
        other => panic!("{other:?}"),
    };

    assert_eq!(
        validation_results.active_manifest().unwrap().failure[0].code(),
        validation_status::ASSERTION_ACTION_MALFORMED
    );

    Ok(())
}
