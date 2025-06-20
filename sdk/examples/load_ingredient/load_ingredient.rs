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
use std::{
    io::{Cursor, Seek},
    path::Path,
};

use anyhow::Result;
use c2pa::{crypto::raw_signature::SigningAlg, Builder, CallbackSigner, Reader};

const CERTS: &[u8] = include_bytes!("../../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../../tests/fixtures/certs/ed25519.pem");
const TEST_IMAGE: &[u8] = include_bytes!("../../tests/fixtures/C.jpg");

#[allow(clippy::incompatible_msrv)]
pub fn main() -> Result<()> {
    let mut source = Cursor::new(TEST_IMAGE);
    let format: &'static str = "image/jpeg";

    let mut builder = Builder::new();

    builder.load_ingredient_from_folder(Path::new("ingredient"))?;

    // // Retrieve ingredient json from folder
    // let ingredient_json = str::from_utf8(include_bytes!("ingredient/ingredient.json")).unwrap();

    // // Construct ingredient from json
    // let mut ingredient = Ingredient::from_json(ingredient_json).unwrap();

    // // Specify ingredient is parent
    // ingredient.set_is_parent();

    // // Make sure we will have access to thumbnail
    // if let Some(thumbnail_ref) = ingredient.thumbnail_ref() {
    //     let thumbnail = Cursor::new(include_bytes!("ingredient/contentauth_urn_uuid_b2b1f7fa-b119-4de1-9c0d-c97fbea3f2c3/c2pa.assertions/c2pa.thumbnail.claim.jpeg"));
    //     let _ = builder.add_resource(&thumbnail_ref.identifier, thumbnail);
    // }

    // // Make sure we will have access to manifest
    // if let Some(manifest_data_ref) = ingredient.manifest_data_ref() {
    //     let manifest_data = Cursor::new(include_bytes!("ingredient/manifest_data.c2pa"));
    //     let _ = builder.add_resource(&manifest_data_ref.identifier, manifest_data);
    // }

    // // Add ingredient to builder's manifest definition
    // builder.add_ingredient(ingredient);

    // Write the manifest builder to a zipped stream
    let mut zipped = Cursor::new(Vec::new());
    builder.to_archive(&mut zipped)?;

    // Unzip the manifest builder from the zipped stream
    let _ = zipped.rewind();

    let ed_signer =
        |_context: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);

    let mut dest = Cursor::new(Vec::new());
    builder.sign(&signer, format, &mut source, &mut dest)?;

    let reader = Reader::from_stream(format, &mut dest)?;
    println!("{}", reader.json());

    Ok(())
}
