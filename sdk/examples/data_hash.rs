// Copyright 2023 Adobe. All rights reserved.
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

// Example code (in unit test) for how you might use client DataHash values.  This allows clients
// to perform the manifest embedding and optionally the hashing

#[cfg(not(target_arch = "wasm32"))]
use std::{
    io::{Read, Seek, Write},
    path::PathBuf,
};

#[cfg(not(target_arch = "wasm32"))]
use c2pa::{
    assertions::{
        c2pa_action, labels::*, Action, Actions, CreativeWork, DataHash, Exif, SchemaDotOrgPerson,
    },
    create_signer, hash_stream_by_alg, ClaimGeneratorInfo, HashRange, Ingredient,
    ManifestDefinition, Reader, Result, SigningAlg,
};

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("DataHash demo");

    #[cfg(not(target_arch = "wasm32"))]
    user_data_hash_with_sdk_hashing()?;
    println!("Done with SDK hashing1");
    #[cfg(not(target_arch = "wasm32"))]
    user_data_hash_with_user_hashing()?;
    println!("Done with SDK hashing2");
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn user_data_hash_with_sdk_hashing() -> Result<()> {
    const GENERATOR: &str = "test_app";

    // You will often implement your own Signer trait to perform on device signing
    let signcert_path = "sdk/tests/fixtures/certs/es256.pub";
    let pkey_path = "sdk/tests/fixtures/certs/es256.pem";
    let signer = create_signer::from_files(signcert_path, pkey_path, SigningAlg::Es256, None)?;

    let src = "sdk/tests/fixtures/earth_apollo17.jpg";
    let dst = "target/tmp/output.jpg";

    let source = PathBuf::from(src);
    let dest = PathBuf::from(dst);

    let mut input_file = std::fs::OpenOptions::new().read(true).open(&source)?;

    let mut output_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&dest)?;

    let mut parent = Ingredient::from_file(source.as_path())?;
    parent.set_is_parent();
    // create an action assertion stating that we imported this file
    let actions = Actions::new().add_action(
        Action::new(c2pa_action::PLACED)
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

    let mut claim_generator = ClaimGeneratorInfo::new(GENERATOR);
    claim_generator.set_version("0.1");

    let mut manifest_def = ManifestDefinition::new();
    manifest_def
        .set_claim_generator_info(claim_generator)
        // todo: add the parent ingredient here
        .add_assertion(ACTIONS, &actions)?
        .add_assertion(CREATIVE_WORK, &creative_work)?
        .add_assertion(EXIF, &exif)?;
    manifest_def.ingredients.push(parent);

    let mut builder = c2pa::Builder::from_manifest_definition(manifest_def);

    let unfinished_manifest =
        builder.data_hashed_placeholder(signer.reserve_size(), "image/jpeg")?;

    // Figure out where you want to put the manifest, let's put it at the beginning of the JPEG as first segment
    // generate new file inserting unfinished manifest into file
    input_file.rewind()?;
    let mut before = vec![0u8; 2];
    input_file.read_exact(before.as_mut_slice())?;

    output_file.write_all(&before)?;

    // write completed final manifest
    output_file.write_all(&unfinished_manifest)?;

    // write bytes after
    let mut after_buf = Vec::new();
    input_file.read_to_end(&mut after_buf)?;
    output_file.write_all(&after_buf)?;

    // we need to add a data hash that excludes the manifest
    let mut dh = DataHash::new("my_manifest", "sha265");
    let hr = HashRange::new(2, unfinished_manifest.len());
    dh.add_exclusion(hr);

    // tell SDK to fill in the hash and sign to complete the manifest
    output_file.rewind()?;
    let final_manifest = builder.sign_data_hashed_embeddable(
        signer.as_ref(),
        &dh,
        "image/jpeg",
        Some(&mut output_file),
    )?;

    // replace temporary manifest with final signed manifest
    // move to location where we inserted manifest,
    // note: temporary manifest and final manifest will be the same size
    output_file.seek(std::io::SeekFrom::Start(2))?;

    // write completed final manifest bytes over temporary bytes
    output_file.write_all(&final_manifest)?;

    // make sure the output file is correct
    let reader = Reader::from_file(&dest)?;

    // example of how to print out the whole manifest as json
    println!("{reader}\n");

    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn user_data_hash_with_user_hashing() -> Result<()> {
    const GENERATOR: &str = "test_app";

    // You will often implement your own Signer trait to perform on device signing
    let signcert_path = "sdk/tests/fixtures/certs/es256.pub";
    let pkey_path = "sdk/tests/fixtures/certs/es256.pem";
    let signer = create_signer::from_files(signcert_path, pkey_path, SigningAlg::Es256, None)?;

    let src = "sdk/tests/fixtures/earth_apollo17.jpg";
    let dst = "target/tmp/output.jpg";

    let source = PathBuf::from(src);
    let dest = PathBuf::from(dst);

    let mut input_file = std::fs::OpenOptions::new().read(true).open(&source)?;

    let mut output_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&dest)?;

    let parent = Ingredient::from_file(source.as_path())?;

    // create an action assertion stating that we imported this file
    let actions = Actions::new().add_action(
        Action::new(c2pa_action::PLACED)
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

    let mut claim_generator = ClaimGeneratorInfo::new(GENERATOR);
    claim_generator.set_version("0.1");

    let mut manifest_def = ManifestDefinition::new();
    manifest_def
        .set_claim_generator_info(claim_generator)
        // .set_parent(parent)
        // .unwrap()
        .add_assertion(ACTIONS, &actions)?
        .add_assertion(CREATIVE_WORK, &creative_work)?
        .add_assertion(EXIF, &exif)?;

    manifest_def.ingredients.push(parent);

    let mut builder = c2pa::Builder::from_manifest_definition(manifest_def);

    // get the composed manifest ready to insert into a file (returns manifest of same length as finished manifest)
    let unfinished_manifest = builder.data_hashed_placeholder(signer.reserve_size(), "jpg")?;

    // Figure out where you want to put the manifest, let's put it at the beginning of the JPEG as first segment
    // we will need to add a data hash that excludes the manifest
    let mut dh = DataHash::new("my_manifest", "sha265");
    let hr = HashRange::new(2, unfinished_manifest.len());
    dh.add_exclusion(hr);

    // since the only thing we are excluding in this example is the manifest we can just hash all the bytes
    // if you have additional exclusions you can add them to the DataHash and pass them to this function to be '
    // excluded from the hash generation
    let hash = hash_stream_by_alg("sha256", &mut input_file, None, true)?;
    dh.set_hash(hash);

    // tell SDK to fill in the hash and sign to complete the manifest
    output_file.rewind()?;
    let final_manifest =
        builder.sign_data_hashed_embeddable(signer.as_ref(), &dh, "jpg", Some(&mut output_file))?;

    // replace temporary manifest with final signed manifest
    // move to location where we inserted manifest,
    // note: temporary manifest and final manifest will be the same size
    output_file.seek(std::io::SeekFrom::Start(2))?;

    // write completed final manifest bytes over temporary bytes
    output_file.write_all(&final_manifest)?;

    // make sure the output file is correct
    let reader = Reader::from_file(&dest)?;

    // example of how to print out the whole manifest as json
    println!("{reader}\n");

    Ok(())
}
