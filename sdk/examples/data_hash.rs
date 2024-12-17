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
    io::{Cursor, Read, Seek, Write},
    path::{Path, PathBuf},
};

#[cfg(feature = "openssl_sign")]
use c2pa::create_signer;

#[cfg(not(target_arch = "wasm32"))]
use c2pa::{
    assertions::{
        c2pa_action, labels::*, Action, Actions, CreativeWork, DataHash, Exif, SchemaDotOrgPerson,
    },
    hash_stream_by_alg, Builder, ClaimGeneratorInfo, HashRange, Ingredient, Reader, Relationship,
    Result,
};
#[cfg(not(target_arch = "wasm32"))]
use c2pa_crypto::SigningAlg;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("DataHash demo");

    #[cfg(all(feature = "openssl_sign", feature = "file_io"))]
    user_data_hash_with_sdk_hashing()?;
    println!("Done with SDK hashing1");
    #[cfg(all(feature = "openssl_sign", feature = "file_io"))]
    user_data_hash_with_user_hashing()?;
    println!("Done with SDK hashing2");
    Ok(())
}

#[cfg(feature = "file_io")]
fn builder_from_source<S: AsRef<Path>>(source: S) -> Result<Builder> {
    let mut parent = Ingredient::from_file(source.as_ref())?;
    parent.set_relationship(Relationship::ParentOf);
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

    let mut builder = Builder::default();

    let mut claim_generator = ClaimGeneratorInfo::new("test_app".to_string());
    claim_generator.set_version("0.1");

    builder
        .set_claim_generator_info(claim_generator)
        .add_ingredient(parent)
        .add_assertion(ACTIONS, &actions)?
        .add_assertion_json(CREATIVE_WORK, &creative_work)?
        .add_assertion_json(EXIF, &exif)?;

    Ok(builder)
}

#[cfg(all(feature = "openssl_sign", feature = "file_io"))]
fn user_data_hash_with_sdk_hashing() -> Result<()> {
    // You will often implement your own Signer trait to perform on device signing
    let signcert_path = "sdk/tests/fixtures/certs/es256.pub";
    let pkey_path = "sdk/tests/fixtures/certs/es256.pem";
    let signer = create_signer::from_files(signcert_path, pkey_path, SigningAlg::Es256, None)?;

    let src = "sdk/tests/fixtures/earth_apollo17.jpg";

    let source = PathBuf::from(src);

    let mut builder = builder_from_source(&source)?; // c2pa::Builder::from_manifest_definition(manifest_definition(&source)?);

    let placeholder_manifest =
        builder.data_hashed_placeholder(signer.reserve_size(), "image/jpeg")?;

    let bytes = std::fs::read(&source)?;
    let mut output: Vec<u8> = Vec::with_capacity(bytes.len() + placeholder_manifest.len());

    // Generate new file inserting unfinished manifest into file.
    // Figure out where you want to put the manifest.
    // Here we put it at the beginning of the JPEG as first segment after the 2 byte SOI marker.
    let manifest_pos = 2;
    output.extend_from_slice(&bytes[0..manifest_pos]);
    output.extend_from_slice(&placeholder_manifest);
    output.extend_from_slice(&bytes[manifest_pos..]);

    // make a stream from the output bytes
    let mut output_stream = Cursor::new(output);

    // we need to add a data hash that excludes the manifest
    let mut dh = DataHash::new("my_manifest", "sha265");
    let hr = HashRange::new(manifest_pos, placeholder_manifest.len());
    dh.add_exclusion(hr.clone());

    // Hash the bytes excluding the manifest we inserted
    let hash = hash_stream_by_alg("sha256", &mut output_stream, Some([hr].to_vec()), true)?;
    dh.set_hash(hash);

    // tell SDK to fill in the hash and sign to complete the manifest
    let final_manifest = builder.sign_data_hashed_embeddable(signer.as_ref(), &dh, "image/jpeg")?;

    // replace temporary manifest with final signed manifest
    // move to location where we inserted manifest,
    // note: temporary manifest and final manifest will be the same size
    output_stream.seek(std::io::SeekFrom::Start(2))?;

    // write completed final manifest bytes over temporary bytes
    output_stream.write_all(&final_manifest)?;

    output_stream.rewind()?;
    // make sure the output stream is correct
    let reader = Reader::from_stream("image/jpeg", &mut output_stream)?;

    // example of how to print out the whole manifest as json
    println!("{reader}\n");

    Ok(())
}

#[cfg(all(feature = "openssl_sign", feature = "file_io"))]
fn user_data_hash_with_user_hashing() -> Result<()> {
    // You will often implement your own Signer trait to perform on device signing
    let signcert_path = "sdk/tests/fixtures/certs/es256.pub";
    let pkey_path = "sdk/tests/fixtures/certs/es256.pem";
    let signer = create_signer::from_files(signcert_path, pkey_path, SigningAlg::Es256, None)?;

    let src = "sdk/tests/fixtures/earth_apollo17.jpg";
    let dst = "target/tmp/output_hashed.jpg";

    let source = PathBuf::from(src);
    let dest = PathBuf::from(dst);

    let mut input_file = std::fs::OpenOptions::new().read(true).open(&source)?;

    let mut output_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(dest)?;

    let mut builder = builder_from_source(&source)?;
    // get the composed manifest ready to insert into a file (returns manifest of same length as finished manifest)
    let placeholder_manifest =
        builder.data_hashed_placeholder(signer.reserve_size(), "image/jpeg")?;

    // Figure out where you want to put the manifest, let's put it at the beginning of the JPEG as first segment
    // we will need to add a data hash that excludes the manifest
    let mut dh = DataHash::new("my_manifest", "sha265");
    let hr = HashRange::new(2, placeholder_manifest.len());
    dh.add_exclusion(hr);

    // since the only thing we are excluding in this example is the manifest we can just hash all the bytes
    // if you have additional exclusions you can add them to the DataHash and pass them to this function to be '
    // excluded from the hash generation
    let hash = hash_stream_by_alg("sha256", &mut input_file, None, true)?;
    dh.set_hash(hash);

    // tell SDK to fill in the hash and sign to complete the manifest
    let final_manifest: Vec<u8> =
        builder.sign_data_hashed_embeddable(signer.as_ref(), &dh, "image/jpeg")?;

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
    output_file.rewind()?;
    let reader = Reader::from_stream("image/jpeg", output_file)?;

    // example of how to print out the whole manifest as json
    println!("{reader}\n");

    Ok(())
}
