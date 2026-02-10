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

const EXIF_METADATA: &str = r#"{
    "@context" : {
    "exif": "http://ns.adobe.com/exif/1.0/"
    },
    "exif:GPSVersionID": "2.2.0.0",
    "exif:GPSLatitude": "39,21.102N",
    "exif:GPSLongitude": "74,26.5737W",
    "exif:GPSAltitudeRef": 0,
    "exif:GPSAltitude": "100963/29890",
    "exif:GPSTimeStamp": "2019-09-22T18:22:57Z"
}"#;

use std::{
    io::{Cursor, Read, Seek, Write},
    path::PathBuf,
};

use c2pa::{
    assertions::{c2pa_action, Action, DataHash, Metadata},
    hash_stream_by_alg, Builder, ClaimGeneratorInfo, Context, HashRange, Reader, Result, Settings,
};
use serde_json::json;
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("DataHash demo");

    user_data_hash_with_user_hashing()?;
    println!("Done with SDK hashing2");

    user_data_hash_with_placeholder_api()?;
    println!("Done with new placeholder API");
    Ok(())
}

fn user_data_hash_with_user_hashing() -> Result<()> {
    let src = "sdk/tests/fixtures/earth_apollo17.jpg";
    let dst = "target/tmp/output_hashed.jpg";
    let format = "image/jpeg";

    let source = PathBuf::from(src);
    let dest = PathBuf::from(dst);

    let mut input_file = std::fs::OpenOptions::new().read(true).open(&source)?;

    let mut output_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(dest)?;

    let settings =
        Settings::new().with_json(include_str!("../tests/fixtures/test_settings.json"))?;
    let context = Context::new().with_settings(settings)?.into_shared();
    let signer = context.signer()?;

    let mut claim_generator = ClaimGeneratorInfo::new("test_app".to_string());
    claim_generator.set_version("0.1");

    let mut builder = Builder::from_shared_context(&context);
    builder.set_claim_generator_info(claim_generator);

    let parent_json = json!({"relationship": "parentOf", "label": "parent_label"});
    builder.add_ingredient_from_stream(parent_json.to_string(), format, &mut input_file)?;
    builder.add_action(
        Action::new(c2pa_action::OPENED).set_parameter("ingredientIds", ["parent_label"])?,
    )?;
    let metadata = Metadata::new("c2pa.metadata", EXIF_METADATA)?;
    builder.add_assertion_json(metadata.get_label(), &metadata)?;

    // get the composed manifest ready to insert into a file (returns manifest of same length as finished manifest)
    let placeholder_manifest = builder.placeholder(format)?;

    // Figure out where you want to put the manifest, let's put it at the beginning of the JPEG as first segment
    // we will need to add a data hash that excludes the manifest
    let mut dh = DataHash::new("my_manifest", "sha265");
    let hr = HashRange::new(2, placeholder_manifest.len() as u64);
    dh.add_exclusion(hr);

    // since the only thing we are excluding in this example is the manifest we can just hash all the bytes
    // if you have additional exclusions you can add them to the DataHash and pass them to this function to be '
    // excluded from the hash generation
    let hash = hash_stream_by_alg("sha256", &mut input_file, None, true)?;
    dh.set_hash(hash);

    // tell SDK to fill in the hash and sign to complete the manifest
    let final_manifest: Vec<u8> = builder.sign_data_hashed_embeddable(signer, &dh, "image/jpeg")?;

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

fn user_data_hash_with_placeholder_api() -> Result<()> {
    use c2pa::{Context, Settings};

    let mut claim_generator = ClaimGeneratorInfo::new("test_app".to_string());
    claim_generator.set_version("0.1");

    // Use Settings to configure signer with CAWG support
    let settings =
        Settings::new().with_json(include_str!("../tests/fixtures/test_settings.json"))?;

    let src = "sdk/tests/fixtures/earth_apollo17.jpg";
    let format = "image/jpeg";
    let source = PathBuf::from(src);

    // Create a Builder with Context from Settings
    let context = Context::new().with_settings(settings)?.into_shared();
    let mut builder = Builder::from_shared_context(&context);

    let parent_json = json!({"relationship": "parentOf", "label": "parent_label"});
    builder.add_ingredient_from_stream(
        parent_json.to_string(),
        format,
        &mut std::fs::File::open(&source)?,
    )?;
    builder.add_action(
        Action::new(c2pa_action::PLACED).set_parameter("ingredientIds", ["parent_label"])?,
    )?;

    // Use the new placeholder() API which supports dynamic assertions
    // Returns raw JUMBF bytes, format is only used here if the hard binding isn't already in the builder.
    let placeholder = builder.placeholder("image/jpeg")?;

    // Compose the manifest for the target format (JPEG)
    let jpeg_placeholder = Builder::composed_manifest(&placeholder, "image/jpeg")?;

    let bytes = std::fs::read(&source)?;
    let mut output: Vec<u8> = Vec::with_capacity(bytes.len() + jpeg_placeholder.len());

    // Insert placeholder at beginning of JPEG (after SOI marker)
    let manifest_pos = 2;
    output.extend_from_slice(&bytes[0..manifest_pos]);
    output.extend_from_slice(&jpeg_placeholder);
    output.extend_from_slice(&bytes[manifest_pos..]);

    let mut output_stream = Cursor::new(output);

    // Create data hash with exclusion for the manifest
    let mut dh = DataHash::new("my_manifest", "sha256");
    let hr = HashRange::new(manifest_pos as u64, jpeg_placeholder.len() as u64);
    dh.add_exclusion(hr.clone());

    // Hash the bytes excluding the manifest
    let hash = hash_stream_by_alg("sha256", &mut output_stream, Some([hr].to_vec()), true)?;
    dh.set_hash(hash);

    // Sign with dynamic assertions (if configured)
    // The signer from context is used automatically
    let signer = context.signer()?;
    let final_manifest = builder.sign_data_hashed_embeddable(signer, &dh, "image/jpeg")?;

    // Replace placeholder with final signed manifest
    output_stream.seek(std::io::SeekFrom::Start(manifest_pos as u64))?;
    output_stream.write_all(&final_manifest)?;

    output_stream.rewind()?;
    let reader = Reader::from_stream("image/jpeg", &mut output_stream)?;

    println!("Manifest with placeholder API (supports dynamic assertions):");
    println!("{reader}\n");

    Ok(())
}
