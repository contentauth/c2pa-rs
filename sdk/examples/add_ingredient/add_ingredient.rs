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

#[cfg(feature = "file_io")]
pub fn main() -> Result<()> {
    let mut source = Cursor::new(TEST_IMAGE);
    let format: &'static str = "image/jpeg";

    let mut builder = Builder::new();

    builder.add_ingredient_from_folder(Path::new("sdk/examples/add_ingredient/ingredient"))?;

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
