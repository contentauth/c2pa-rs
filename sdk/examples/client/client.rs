// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Example C2PA client application

use std::path::PathBuf;

use anyhow::Result;
use c2pa::{
    assertions::{c2pa_action, labels, Action, Actions, CreativeWork, Exif, SchemaDotOrgPerson},
    create_signer, Builder, ClaimGeneratorInfo, Ingredient, Reader, Relationship,
};
use c2pa_crypto::raw_signature::SigningAlg;

const GENERATOR: &str = "test_app";
const INDENT_SPACE: usize = 2;

// Example for reading the contents of a manifest store, recursively showing nested manifests
fn show_manifest(reader: &Reader, manifest_label: &str, level: usize) -> Result<()> {
    let indent = " ".repeat(level * INDENT_SPACE);

    println!("{indent}manifest_label: {manifest_label}");
    if let Some(manifest) = reader.get_manifest(manifest_label) {
        println!(
            "{}title: {} , format: {}, instance_id: {}",
            indent,
            manifest.title().unwrap_or("None"),
            manifest.format().unwrap_or("None"),
            manifest.instance_id()
        );

        for assertion in manifest.assertions().iter() {
            println!("{}", assertion.label_with_instance());
            match assertion.label() {
                labels::ACTIONS => {
                    let actions: Actions = assertion.to_assertion()?;
                    for action in actions.actions {
                        println!("{}{}", indent, action.action());
                    }
                }
                labels::CREATIVE_WORK => {
                    let creative_work: CreativeWork = assertion.to_assertion()?;
                    if let Some(authors) = creative_work.author() {
                        for author in authors {
                            if let Some(name) = author.name() {
                                println!("{indent}author = {name} ");
                            }
                        }
                    }
                    if let Some(url) = creative_work.get::<String>("url") {
                        println!("{indent}url = {url} ");
                    }
                }
                _ => {}
            }
        }

        for ingredient in manifest.ingredients().iter() {
            println!(
                "{}Ingredient title:{}",
                indent,
                ingredient.title().unwrap_or("None")
            );
            if let Some(validation_status) = ingredient.validation_status() {
                for status in validation_status {
                    println!(
                        "Ingredient validation status: {}: {}",
                        status.code(),
                        status.explanation().unwrap_or_default()
                    );
                }
            }
            if let Some(label) = ingredient.active_manifest() {
                show_manifest(reader, label, level + 1)?;
            }
        }
    }
    Ok(())
}

pub fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    // allow passing in source and dest paths or use defaults
    let (src, dst) = match args.len() >= 3 {
        true => (args[1].as_str(), args[2].as_str()),
        false => (
            "sdk/tests/fixtures/earth_apollo17.jpg",
            "target/tmp/client.jpg",
        ),
    };

    let source = PathBuf::from(src);
    let dest = PathBuf::from(dst);
    // if a filepath was provided on the command line, read it as a parent file
    let mut parent = Ingredient::from_file(source.as_path())?;
    parent.set_relationship(Relationship::ParentOf);

    // overwrite the destination file if it exists
    if dest.exists() {
        std::fs::remove_file(&dest)?;
    }

    // create an action assertion stating that we imported this file
    let actions = Actions::new().add_action(
        Action::new(c2pa_action::OPENED)
            .set_parameter("identifier", parent.instance_id().to_owned())?,
    );

    // build a creative work assertion
    let creative_work =
        CreativeWork::new().add_author(SchemaDotOrgPerson::new().set_name("me")?)?;

    let exif = Exif::from_json_str(
        r#"{
        "@context" : {
          "exif": "http://ns.adobe.com/exif/1.0/"
        },
        "exif:GPSVersionID": "2.2.0.0",
        "exif:GPSLatitude": "39,21.102N",
        "exif:GPSLongitude": "74,26.5737W",
        "exif:GPSAltitudeRef": 0,
        "exif:GPSAltitude": "100963/29890",
        "exif:GPSTimeStamp": "2019-09-22T18:22:57Z"
    }"#,
    )?;

    // create a new Manifest
    let mut builder = Builder::new();
    builder.definition.claim_version = Some(2);
    let mut generator = ClaimGeneratorInfo::new(GENERATOR);
    generator.set_version("0.1");
    builder
        .set_claim_generator_info(generator)
        .add_ingredient(parent)
        .add_assertion(Actions::LABEL, &actions)?
        .add_assertion(CreativeWork::LABEL, &creative_work)?
        .add_assertion(Exif::LABEL, &exif)?;

    // sign and embed into the target file
    let signcert_path = "sdk/tests/fixtures/certs/es256.pub";
    let pkey_path = "sdk/tests/fixtures/certs/es256.pem";
    let signer = create_signer::from_files(signcert_path, pkey_path, SigningAlg::Es256, None)?;

    builder.sign_file(&*signer, &source, &dest)?;

    let reader = Reader::from_file(&dest)?;

    // example of how to print out the whole manifest as json
    println!("{reader}\n");

    // walk through the manifests and show the contents
    if let Some(manifest_label) = reader.active_label() {
        show_manifest(&reader, manifest_label, 0)?;
    }
    if let Some(validation_status) = reader.validation_status() {
        for status in validation_status {
            println!(
                "Validation status: {}: {}",
                status.code(),
                status.explanation().unwrap_or_default()
            );
        }
    }
    Ok(())
}
