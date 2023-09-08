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
    assertions::{c2pa_action, Action, Actions, CreativeWork, DataHash, Exif, SchemaDotOrgPerson},
    create_signer, hash_stream_by_alg, HashRange, Ingredient, Manifest, ManifestStore, SigningAlg,
};

fn main() {
    println!("DataHash demo");

    #[cfg(not(target_arch = "wasm32"))]
    user_data_hash_with_sdk_hashing();

    #[cfg(not(target_arch = "wasm32"))]
    user_data_hash_with_user_hashing();
}

#[cfg(not(target_arch = "wasm32"))]
fn user_data_hash_with_sdk_hashing() {
    const GENERATOR: &str = "test_app/0.1";

    // You will often implement your own Signer trait to perform on device signing
    let signcert_path = "sdk/tests/fixtures/certs/es256.pub";
    let pkey_path = "sdk/tests/fixtures/certs/es256.pem";
    let signer =
        create_signer::from_files(signcert_path, pkey_path, SigningAlg::Es256, None).unwrap();

    let src = "sdk/tests/fixtures/earth_apollo17.jpg";
    let dst = "target/tmp/output.jpg";

    let source = PathBuf::from(src);
    let dest = PathBuf::from(dst);

    let mut input_file = std::fs::OpenOptions::new()
        .read(true)
        .open(&source)
        .unwrap();

    let mut output_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&dest)
        .unwrap();

    let parent = Ingredient::from_file(source.as_path()).unwrap();

    // create an action assertion stating that we imported this file
    let actions = Actions::new().add_action(
        Action::new(c2pa_action::PLACED)
            .set_parameter("identifier", parent.instance_id().to_owned())
            .unwrap(),
    );

    // build a creative work assertion
    let creative_work = CreativeWork::new()
        .add_author(SchemaDotOrgPerson::new().set_name("me").unwrap())
        .unwrap();

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
    )
    .unwrap();

    // create a new Manifest
    let mut manifest = Manifest::new(GENERATOR.to_owned());
    // add parent and assertions
    manifest
        .set_parent(parent)
        .unwrap()
        .add_assertion(&actions)
        .unwrap()
        .add_assertion(&creative_work)
        .unwrap()
        .add_assertion(&exif)
        .unwrap();

    // get the composed manifest ready to insert into a file (returns manifest of same length as finished manifest)
    let unfinished_manifest = manifest
        .data_hash_placeholder(signer.as_ref(), "jpg")
        .unwrap();

    // Figure out where you want to put the manifest, let's put it at the beginning of the JPEG as first segment
    // generate new file inserting unfinished manifest into file
    input_file.rewind().unwrap();
    let mut before = vec![0u8; 2];
    input_file.read_exact(before.as_mut_slice()).unwrap();

    output_file.write_all(&before).unwrap();

    // write completed final manifest
    output_file.write_all(&unfinished_manifest).unwrap();

    // write bytes after
    let mut after_buf = Vec::new();
    input_file.read_to_end(&mut after_buf).unwrap();
    output_file.write_all(&after_buf).unwrap();

    // we need to add a data hash that excludes the manifest
    let mut dh = DataHash::new("my_manifest", "sha265");
    let hr = HashRange::new(2, unfinished_manifest.len());
    dh.add_exclusion(hr);

    // tell SDK to fill in the hash and sign to complete the manifest
    output_file.rewind().unwrap();
    let final_manifest = manifest
        .data_hash_embeddable_manifest(&dh, signer.as_ref(), "jpg", Some(&mut output_file))
        .unwrap();

    // replace temporary manifest with final signed manifest
    // move to location where we inserted manifest,
    // note: temporary manifest and final manifest will be the same size
    output_file.seek(std::io::SeekFrom::Start(2)).unwrap();

    // write completed final manifest bytes over temporary bytes
    output_file.write_all(&final_manifest).unwrap();

    // make sure the output file is correct
    let manifest_store = ManifestStore::from_file(&dest).unwrap();

    // example of how to print out the whole manifest as json
    println!("{manifest_store}\n");
}

#[cfg(not(target_arch = "wasm32"))]
fn user_data_hash_with_user_hashing() {
    const GENERATOR: &str = "test_app/0.1";

    // You will often implement your own Signer trait to perform on device signing
    let signcert_path = "sdk/tests/fixtures/certs/es256.pub";
    let pkey_path = "sdk/tests/fixtures/certs/es256.pem";
    let signer =
        create_signer::from_files(signcert_path, pkey_path, SigningAlg::Es256, None).unwrap();

    let src = "sdk/tests/fixtures/earth_apollo17.jpg";
    let dst = "target/tmp/output.jpg";

    let source = PathBuf::from(src);
    let dest = PathBuf::from(dst);

    let mut input_file = std::fs::OpenOptions::new()
        .read(true)
        .open(&source)
        .unwrap();

    let mut output_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&dest)
        .unwrap();

    let parent = Ingredient::from_file(source.as_path()).unwrap();

    // create an action assertion stating that we imported this file
    let actions = Actions::new().add_action(
        Action::new(c2pa_action::PLACED)
            .set_parameter("identifier", parent.instance_id().to_owned())
            .unwrap(),
    );

    // build a creative work assertion
    let creative_work = CreativeWork::new()
        .add_author(SchemaDotOrgPerson::new().set_name("me").unwrap())
        .unwrap();

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
    )
    .unwrap();

    // create a new Manifest
    let mut manifest = Manifest::new(GENERATOR.to_owned());
    // add parent and assertions
    manifest
        .set_parent(parent)
        .unwrap()
        .add_assertion(&actions)
        .unwrap()
        .add_assertion(&creative_work)
        .unwrap()
        .add_assertion(&exif)
        .unwrap();

    // get the composed manifest ready to insert into a file (returns manifest of same length as finished manifest)
    let unfinished_manifest = manifest
        .data_hash_placeholder(signer.as_ref(), "jpg")
        .unwrap();

    // Figure out where you want to put the manifest, let's put it at the beginning of the JPEG as first segment
    // we will need to add a data hash that excludes the manifest
    let mut dh = DataHash::new("my_manifest", "sha265");
    let hr = HashRange::new(2, unfinished_manifest.len());
    dh.add_exclusion(hr);

    // since the only thing we are excluding in this example is the manifest we can just hash all the bytes
    // if you have additional exclusions you can add them to the DataHash and pass them to this function to be '
    // excluded from the hash generation
    let hash = hash_stream_by_alg("sha256", &mut input_file, None, true).unwrap();
    dh.set_hash(hash);

    // tell SDK to fill we will provide the hash and sign to complete the manifest
    let final_manifest = manifest
        .data_hash_embeddable_manifest(&dh, signer.as_ref(), "jpg", None)
        .unwrap();

    // generate new file inserting final manifest into file
    input_file.rewind().unwrap();
    let mut before = vec![0u8; 2];
    input_file.read_exact(before.as_mut_slice()).unwrap();

    output_file.write_all(&before).unwrap();

    // write completed final manifest
    output_file.write_all(&final_manifest).unwrap();

    // write bytes after
    let mut after_buf = Vec::new();
    input_file.read_to_end(&mut after_buf).unwrap();
    output_file.write_all(&after_buf).unwrap();

    // make sure the output file is correct
    let manifest_store = ManifestStore::from_file(&dest).unwrap();

    // example of how to print out the whole manifest as json
    println!("{manifest_store}\n");
}
