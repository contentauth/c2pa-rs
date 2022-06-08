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

use anyhow::Result;

use c2pa::{
    assertions::{c2pa_action, labels, Action, Actions, CreativeWork},
    get_temp_signer, Ingredient, Manifest, ManifestStore,
};
use std::path::PathBuf;
use tempfile::tempdir;

const GENERATOR: &str = "test_app/0.1";
const CREATIVE_WORK_URL: &str = r#"{"@type":"CreativeWork","@context":"https://schema.org","url":"http://contentauthenticity.org"}"#;

const INDENT_SPACE: usize = 2;

// Example for reading the contents of a manifest store, recursively showing nested manifests
fn show_manifest(manifest_store: &ManifestStore, manifest_label: &str, level: usize) -> Result<()> {
    let indent = " ".repeat(level * INDENT_SPACE);

    println!("{}manifest_label: {}", indent, manifest_label);
    if let Some(manifest) = manifest_store.get(manifest_label) {
        if let Some(asset) = manifest.asset().as_ref() {
            println!(
                "{}title: {} , format: {}, instance_id: {}",
                indent,
                asset.title(),
                asset.format(),
                asset.instance_id()
            );
        }

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
                                println!("{}author = {} ", indent, name);
                            }
                        }
                    }
                    if let Some(url) = creative_work.get::<String>("url") {
                        println!("{}url = {} ", indent, url);
                    }
                }
                _ => {}
            }
        }

        for ingredient in manifest.ingredients().iter() {
            println!("{}Ingredient title:{}", indent, ingredient.title());
            if let Some(label) = ingredient.active_manifest() {
                show_manifest(manifest_store, label, level + 1)?;
            }
        }
    }
    Ok(())
}

pub fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!("This requires a path to a source image and a path to an output file. Both must be jpg or png files.");
        return Ok(());
    }
    let source = PathBuf::from(&args[1]);
    let dest = PathBuf::from(&args[2]);

    // create a new Manifest
    let mut manifest = Manifest::new(GENERATOR.to_owned());

    // if a filepath was provided on the command line, read it as a parent file
    let parent = Ingredient::from_file(source)?;
    let source = PathBuf::from(&args[1]);

    // create an action assertion stating that we imported this file
    let actions = Actions::new().add_action(
        Action::new(c2pa_action::PLACED)
            .set_parameter("identifier".to_owned(), parent.instance_id().to_owned())?,
    );
    manifest.add_assertion(&actions)?;

    // set the parent ingredient
    manifest.set_parent(parent)?;

    let creative_work = CreativeWork::from_json_str(CREATIVE_WORK_URL)?;
    manifest.add_assertion(&creative_work)?;

    // sign and embed into the target file
    let temp_dir = tempdir()?;
    let (signer, _) = get_temp_signer(&temp_dir.path());
    manifest.embed(&source, &dest, &signer)?;

    let manifest_store = ManifestStore::from_file(&dest)?;

    // example of how to print out the whole manifest as json
    println!("{}\n", manifest_store);

    // walk through the manifest and access data.
    if let Some(manifest_label) = manifest_store.active_label() {
        show_manifest(&manifest_store, manifest_label, 0)?;
    }

    Ok(())
}
