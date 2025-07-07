use std::{fs, path::Path};

use anyhow::Result;
use c2pa::{settings::Settings, Builder, ManifestDefinition, Reader};
use schemars::{schema::RootSchema, schema_for};

fn write_schema(schema: &RootSchema, name: &str) {
    println!("Exporting JSON schema for {name}");
    let output = serde_json::to_string_pretty(schema).expect("Failed to serialize schema");
    let output_dir = Path::new("./target/schema");
    fs::create_dir_all(output_dir).expect("Could not create schema directory");
    let output_path = output_dir.join(format!("{name}.schema.json"));
    fs::write(&output_path, output).expect("Unable to write schema");
    println!("Wrote schema to {}", output_path.display());
}

fn main() -> Result<()> {
    let builder = schema_for!(Builder);
    write_schema(&builder, "Builder");

    let manifest_definition = schema_for!(ManifestDefinition);
    write_schema(&manifest_definition, "ManifestDefinition");

    let reader = schema_for!(Reader);
    write_schema(&reader, "Reader");

    let settings = schema_for!(Settings);
    write_schema(&settings, "Settings");

    Ok(())
}
