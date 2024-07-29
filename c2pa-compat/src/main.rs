// Copyright 2024 Adobe. All rights reserved.
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
    fs::{self, File},
    io::Cursor,
    path::Path,
};

use c2pa::{Builder, CallbackSigner, Error, Reader, Result, SigningAlg};
use serde::Serialize;

// const FULL_MANIFEST: &str = include_str!("./full-manifest.json");
const FULL_MANIFEST: &str = include_str!("../../sdk/tests/fixtures/simple_manifest.json");

// TODO: these assets should be as small as possible
const DETAILS: CompatDetails = CompatDetails::new(&[
    CompatAssetDetails::new("C.jpg", "jpeg"),
    // CompatAssetDetails::new("sample1.gif", "gif"), // TODO: PR open to fix GIF
    CompatAssetDetails::new("sample1.svg", "svg"),
    CompatAssetDetails::new("video1.mp4", "bmff"),
    // CompatAssetDetails::new("sample1.wav", "riff"), // TODO: errors w/ no embed in RIFF
    CompatAssetDetails::new("sample1.mp3", "mp3"),
    CompatAssetDetails::new("libpng-test.png", "png"),
    CompatAssetDetails::new("TUSCANY.TIF", "tiff"),
    // TODO: add an asset from each parser category
]);

const BASE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../sdk/tests/fixtures");

#[derive(Debug, Serialize)]
pub struct CompatAssetDetails {
    asset: &'static str,
    category: &'static str,
}

impl CompatAssetDetails {
    pub const fn new(asset: &'static str, category: &'static str) -> Self {
        Self { asset, category }
    }
}

// Redefined in `sdk/tests/compat.rs`, can't make lib.rs without circular dependency or a separate crate.
#[derive(Debug, Serialize)]
pub struct CompatDetails {
    assets: &'static [CompatAssetDetails],
    public_key: &'static str,
    private_key: &'static str,
    // TODO: allow algo to be specified
    // algorithm: SigningAlg,
    // tsa_url: &'static str,
}

impl CompatDetails {
    pub const fn new(assets: &'static [CompatAssetDetails]) -> Self {
        Self {
            assets,
            public_key: "certs/ed25519.pub",
            private_key: "certs/ed25519.pem",
            // algorithm: SigningAlg::Ps256,
            // tsa_url: "TODO",
        }
    }
}

// TODO: ideally this tool will run from CI on publish (if tests fail, cancel)
// TODO: also, we need to have a predefined set of hash assertions that are added on a per-asset basis,
//       maybe the hash assertion should be specified in compat-details?
fn main() -> Result<()> {
    let compat_dir = fixture_path(&format!("compat/{}", c2pa::VERSION));
    // TODO: temp
    if Path::new(&compat_dir).exists() {
        fs::remove_dir_all(&compat_dir)?;
    }
    fs::create_dir(&compat_dir)?;

    fs::write(format!("{compat_dir}/manifest.json"), FULL_MANIFEST)?;
    fs::write(
        format!("{compat_dir}/compat-details.json"),
        serde_json::to_string(&DETAILS)?,
    )?;

    let public_key = fs::read(fixture_path(DETAILS.public_key))?;
    let private_key = fs::read(fixture_path(DETAILS.private_key))?;

    for asset_details in DETAILS.assets {
        let format = c2pa::format_from_path(asset_details.asset).unwrap();
        let asset_path = Path::new(asset_details.asset);
        let extension = asset_path.extension().unwrap().to_str().unwrap();

        let private_key = private_key.clone();
        let signer = CallbackSigner::new(
            move |_context: *const (), data: &[u8]| ed_sign(data, &private_key),
            SigningAlg::Ed25519,
            public_key.clone(),
        );

        let mut signed_embedded_asset = Cursor::new(Vec::new());
        let embedded_c2pa_manifest = Builder::from_json(FULL_MANIFEST)?.sign(
            &signer,
            &format,
            &mut File::open(fixture_path(asset_details.asset))?,
            &mut signed_embedded_asset,
        )?;
        // TODO: need to set resource base path

        let embedded_reader = &Reader::from_manifest_data_and_stream(
            &embedded_c2pa_manifest,
            &format,
            &mut signed_embedded_asset,
        )?;

        let dir_path = format!("{compat_dir}/{}", asset_details.category);
        fs::create_dir(&dir_path)?;

        // TODO: can we share the builder or does it mutate itself?
        let mut signed_remote_asset = Cursor::new(Vec::new());
        let mut remote_builder = Builder::from_json(FULL_MANIFEST)?;
        remote_builder.no_embed = true;
        remote_builder.remote_url = Some(format!(
            "http://localhost:8000/{}/{}/remote.c2pa",
            c2pa::VERSION,
            asset_details.category
        ));
        // TODO: need to set resource base path
        let remote_c2pa_manifest = remote_builder.sign(
            &signer,
            &format,
            &mut File::open(fixture_path(asset_details.asset))?,
            &mut signed_remote_asset,
        );
        match remote_c2pa_manifest {
            Ok(remote_c2pa_manifest) => {
                let remote_reader = &Reader::from_manifest_data_and_stream(
                    &remote_c2pa_manifest,
                    &format,
                    &mut signed_remote_asset,
                )?;

                fs::write(
                    format!("{dir_path}/remote.{extension}"),
                    signed_remote_asset.into_inner(),
                )?;
                fs::write(format!("{dir_path}/remote.c2pa"), remote_c2pa_manifest)?;
                let mut remote_json_manifest = File::create(format!("{dir_path}/remote.json"))?;
                serde_json::to_writer(&mut remote_json_manifest, &remote_reader)?;
            }
            Err(Error::XmpNotSupported) => {}
            Err(err) => return Err(err),
        }

        // TODO: we don't need to store the entire asset, only the binary diff from the original asset

        fs::write(format!("{dir_path}/embedded.c2pa"), embedded_c2pa_manifest)?;
        fs::write(
            format!("{dir_path}/embedded.{extension}"),
            signed_embedded_asset.into_inner(),
        )?;
        // TODO: we store separate remote/embedded manifest because some fields (e.g. bmff hash) differ
        //       ideally we store the hash assertions in a separate json as to not have duplicate json manifests
        // Use serde_json::to_writer to avoid escaping
        let mut embedded_json_manifest = File::create(format!("{dir_path}/embedded.json"))?;
        serde_json::to_writer(&mut embedded_json_manifest, &embedded_reader)?;
    }

    Ok(())
}

fn fixture_path(subpath: &str) -> String {
    format!("{BASE_PATH}/{subpath}")
}

// TODO: taken from v2pai example, WASM compatible?
fn ed_sign(data: &[u8], private_key: &[u8]) -> c2pa::Result<Vec<u8>> {
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use pem::parse;

    // Parse the PEM data to get the private key
    let pem = parse(private_key).map_err(|e| c2pa::Error::OtherError(Box::new(e)))?;
    // For Ed25519, the key is 32 bytes long, so we skip the first 16 bytes of the PEM data
    let key_bytes = &pem.contents()[16..];
    let signing_key =
        SigningKey::try_from(key_bytes).map_err(|e| c2pa::Error::OtherError(Box::new(e)))?;
    // Sign the data
    let signature: Signature = signing_key.sign(data);
    Ok(signature.to_bytes().to_vec())
}
