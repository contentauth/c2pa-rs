use std::{fs, path::Path};

use anyhow::Result;
use c2pa::{settings::Settings, ManifestStore};
use schemars::{schema::RootSchema, schema_for};

fn write_schema(schema: &RootSchema, name: &str) {
    println!("Exporting JSON schema for {}", name);
    let output = serde_json::to_string_pretty(schema).expect("Failed to serialize schema");
    let output_dir = Path::new("./target/schema");
    fs::create_dir_all(output_dir).expect("Could not create schema directory");
    let output_path = output_dir.join(format!("{}.schema.json", name));
    fs::write(&output_path, output).expect("Unable to write schema");
    println!("Wrote schema to {}", output_path.display());
}

fn main() -> Result<()> {
    let manifest_store = schema_for!(ManifestStore);
    write_schema(&manifest_store, "ManifestStore");

    let settings = schema_for!(Settings);
    write_schema(&settings, "Settings");

    Ok(())
}
