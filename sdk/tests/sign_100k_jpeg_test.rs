use std::fs::File;

use c2pa::{settings::Settings, Builder, Signer};

// IMPORTANT: Choose a different settings file to configure different experiment variables.
const TEST_SETTINGS: &str = include_str!("../benches/fixtures/c2pa-with-ed25519.toml");

const MANIFEST_JSON: &str = include_str!("../tests/fixtures/simple_manifest.json");

fn create_signer() -> Box<dyn Signer> {
    Settings::from_toml(TEST_SETTINGS).unwrap();
    Settings::signer().unwrap()
}

fn create_builder() -> Builder {
    Builder::from_json(MANIFEST_JSON).expect("failed to create builder from manifest JSON")
}

#[test]
#[should_panic] // Expecting this to panic due to your injected panic
fn test_sign_100k_jpeg() {
    let mut builder = create_builder();
    let signer = create_signer();
    let format = "image/jpeg";

    let mut source = File::open("/Users/scouten/Adobe/c2pa-rs/sdk/benches/fixtures/100kb.jpg").expect("Failed to open source file");
    let mut dest = File::create("/Users/scouten/Desktop/output.jpg").expect("Failed to create output file");
    
    // This should trigger your injected panic and show the full stack trace
    let result = builder.sign(&signer, format, &mut source, &mut dest);
    
    // Print the result in case it doesn't panic
    println!("Sign result: {:?}", result);
}
