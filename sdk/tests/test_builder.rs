use std::io::Cursor;

use c2pa::{Builder, Result};

mod common;
use common::{compare_stream_to_known_good, fixtures_path, test_signer};

#[test]
fn test_builder_ca_jpg() -> Result<()> {
    let manifest_def = std::fs::read_to_string(fixtures_path("simple_manifest.json"))?;
    let mut builder = Builder::from_json(&manifest_def)?;

    const TEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    let mut dest = Cursor::new(Vec::new());
    builder.sign(format, &mut source, &mut dest, &test_signer())?;

    // dest.set_position(0);
    // let path = common::known_good_path("CA_test.json");
    // let reader = c2pa::Reader::from_stream(format, &mut dest)?;
    // std::fs::write(path, reader.json())?;

    compare_stream_to_known_good(&mut dest, format, "CA_test.json")
}
