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
    path::{Path, PathBuf},
};

use c2pa::{Builder, CallbackSigner, Error, Reader, Result, SigningAlg};
use serde::Serialize;

// const FULL_MANIFEST: &str = include_str!("./full-manifest.json");
const FULL_MANIFEST: &str = include_str!("../../sdk/tests/fixtures/simple_manifest.json");

const FIXTURES_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../sdk/tests/fixtures");

#[derive(Debug, Serialize)]
pub struct CompatAssetDetails {
    asset: PathBuf,
    category: String,
    uncompressed_remote_size: Option<usize>,
    uncompressed_embedded_size: Option<usize>,
}

impl CompatAssetDetails {
    pub fn new(asset: impl Into<PathBuf>, category: impl Into<String>) -> Self {
        Self {
            asset: asset.into(),
            category: category.into(),
            uncompressed_remote_size: None,
            uncompressed_embedded_size: None,
        }
    }
}

// Redefined in `sdk/tests/compat.rs`, can't make lib.rs without circular dependency or a separate crate.
#[derive(Debug, Serialize)]
pub struct CompatDetails {
    assets: Vec<CompatAssetDetails>,
    public_key: PathBuf,
    private_key: PathBuf,
    // TODO: allow algo to be specified
    // algorithm: SigningAlg,
    // tsa_url: &'static str,
}

impl CompatDetails {
    pub fn new(assets: Vec<CompatAssetDetails>) -> Self {
        Self {
            assets,
            public_key: PathBuf::from("certs/ed25519.pub"),
            private_key: PathBuf::from("certs/ed25519.pem"),
            // algorithm: SigningAlg::Ps256,
            // tsa_url: "TODO",
        }
    }
}

// TODO: ideally this tool will run from CI on publish (if tests fail, cancel)
// TODO: also, we need to have a predefined set of hash assertions that are added on a per-asset basis,
//       maybe the hash assertion should be specified in compat-details?
fn main() -> Result<()> {
    // TODO: these assets should be as small as possible
    let mut details = CompatDetails::new(vec![
        CompatAssetDetails::new("C.jpg", "jpeg"),
        CompatAssetDetails::new("sample1.gif", "gif"),
        CompatAssetDetails::new("sample1.svg", "svg"),
        CompatAssetDetails::new("video1.mp4", "bmff"),
        // CompatAssetDetails::new("sample1.wav", "riff"), // TODO: https://github.com/contentauth/c2pa-rs/issues/530
        CompatAssetDetails::new("sample1.mp3", "mp3"),
        CompatAssetDetails::new("libpng-test.png", "png"),
        CompatAssetDetails::new("TUSCANY.TIF", "tiff"),
        // TODO: add an asset from each parser category
    ]);
    let fixtures_path = PathBuf::from(FIXTURES_PATH);

    let compat_dir = fixtures_path.join("compat").join(c2pa::VERSION);
    // TODO: temp
    if Path::new(&compat_dir).exists() {
        fs::remove_dir_all(&compat_dir)?;
    }
    fs::create_dir(&compat_dir)?;

    let public_key = fs::read(fixtures_path.join(&details.public_key))?;
    let private_key = fs::read(fixtures_path.join(&details.private_key))?;

    for asset_details in &mut details.assets {
        let format = c2pa::format_from_path(&asset_details.asset).unwrap();
        let original_asset = fs::read(fixtures_path.join(&asset_details.asset))?;

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
            &mut Cursor::new(&original_asset),
            &mut signed_embedded_asset,
        )?;
        // TODO: need to set resource base path

        let embedded_reader = &Reader::from_manifest_data_and_stream(
            &embedded_c2pa_manifest,
            &format,
            &mut signed_embedded_asset,
        )?;

        let dir_path = compat_dir.join(&asset_details.category);
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
            &mut Cursor::new(&original_asset),
            &mut signed_remote_asset,
        );
        match remote_c2pa_manifest {
            Ok(remote_c2pa_manifest) => {
                let remote_reader = &Reader::from_manifest_data_and_stream(
                    &remote_c2pa_manifest,
                    &format,
                    &mut signed_remote_asset,
                )?;

                let mut signed_remote_asset_patch = Vec::new();
                bsdiff::diff(
                    &original_asset,
                    &signed_remote_asset.into_inner(),
                    &mut signed_remote_asset_patch,
                )?;
                asset_details.uncompressed_remote_size = Some(signed_remote_asset_patch.len());
                let signed_remote_asset_patch = lz4_flex::compress(&signed_remote_asset_patch);

                fs::write(dir_path.join("remote.patch"), signed_remote_asset_patch)?;
                fs::write(dir_path.join("remote.c2pa"), remote_c2pa_manifest)?;
                let mut remote_json_manifest = File::create(dir_path.join("remote.json"))?;
                serde_json::to_writer(&mut remote_json_manifest, &remote_reader)?;
            }
            Err(Error::XmpNotSupported) => {}
            Err(err) => return Err(err),
        }

        // TODO: we don't need to store the entire asset, only the binary diff from the original asset

        let mut signed_embedded_asset_patch = Vec::new();
        bsdiff::diff(
            &original_asset,
            &signed_embedded_asset.into_inner(),
            &mut signed_embedded_asset_patch,
        )?;
        asset_details.uncompressed_embedded_size = Some(signed_embedded_asset_patch.len());
        let signed_embedded_asset_patch = lz4_flex::compress(&signed_embedded_asset_patch);

        fs::write(dir_path.join("embedded.patch"), signed_embedded_asset_patch)?;
        fs::write(dir_path.join("embedded.c2pa"), embedded_c2pa_manifest)?;
        // TODO: we store separate remote/embedded manifest because some fields (e.g. bmff hash) differ
        //       ideally we store the hash assertions in a separate json as to not have duplicate json manifests
        // Use serde_json::to_writer to avoid escaping
        let mut embedded_json_manifest = File::create(dir_path.join("embedded.json"))?;
        serde_json::to_writer(&mut embedded_json_manifest, &embedded_reader)?;
    }

    fs::write(compat_dir.join("manifest.json"), FULL_MANIFEST)?;
    fs::write(
        compat_dir.join("compat-details.json"),
        serde_json::to_string(&details)?,
    )?;

    Ok(())
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
