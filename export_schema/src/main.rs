use std::{fs, path::Path};

use anyhow::Result;
use c2pa::ManifestStore;
use schemars::gen::SchemaSettings;

fn main() -> Result<()> {
    println!("Exporting JSON schema");
    let settings = SchemaSettings::draft07();
    let gen = settings.into_generator();
    let schema = gen.into_root_schema_for::<ManifestStore>();
    let output = serde_json::to_string_pretty(&schema).expect("Failed to serialize schema");
    let output_dir = Path::new("./target/schema");
    fs::create_dir_all(output_dir).expect("Could not create schema directory");
    let output_path = output_dir.join("ManifestStore.schema.json");
    fs::write(&output_path, output).expect("Unable to write schema");
    println!("Wrote schema to {}", output_path.display());
    Ok(())
}
