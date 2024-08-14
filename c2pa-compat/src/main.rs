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

// TODO: finish up full-manifest
// const FULL_MANIFEST: &str = include_str!("./full-manifest.json");
const FULL_MANIFEST: &str = include_str!("../../sdk/tests/fixtures/simple_manifest.json");

const FIXTURES_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../sdk/tests/fixtures");

#[derive(Debug, Serialize)]
pub struct BinarySize {
    uncompressed_patch_size: usize,
    applied_size: usize,
}

#[derive(Debug, Serialize)]
pub struct CompatAssetDetails {
    asset: PathBuf,
    category: String,
    remote_size: Option<BinarySize>,
    embedded_size: Option<BinarySize>,
}

impl CompatAssetDetails {
    pub fn new(asset: impl Into<PathBuf>, category: impl Into<String>) -> Self {
        Self {
            asset: asset.into(),
            category: category.into(),
            remote_size: None,
            embedded_size: None,
        }
    }
}

// Redefined in `sdk/tests/compat.rs`, can't make lib.rs without circular dependency or a separate crate.
#[derive(Debug, Serialize)]
pub struct CompatDetails {
    assets: Vec<CompatAssetDetails>,
    certificate: PathBuf,
    private_key: PathBuf,
    algorithm: SigningAlg,
    // tsa_url: String,
}

impl CompatDetails {
    pub fn new(assets: Vec<CompatAssetDetails>) -> Self {
        Self {
            assets,
            certificate: PathBuf::from("certs/ed25519.pub"),
            private_key: PathBuf::from("certs/ed25519.pem"),
            algorithm: SigningAlg::Ed25519,
            // tsa_url: "TODO",
        }
    }
}

fn main() -> Result<()> {
    // TODO: these assets should ideally be as small as possible (however, they are diffed anyways)
    let mut details = CompatDetails::new(vec![
        CompatAssetDetails::new("C.jpg", "jpeg"),
        CompatAssetDetails::new("sample1.gif", "gif"),
        CompatAssetDetails::new("sample1.svg", "svg"),
        CompatAssetDetails::new("video1.mp4", "bmff"),
        CompatAssetDetails::new("sample1.wav", "riff"),
        CompatAssetDetails::new("sample1.mp3", "mp3"),
        CompatAssetDetails::new("libpng-test.png", "png"),
        CompatAssetDetails::new("TUSCANY.TIF", "tiff"),
    ]);
    let fixtures_path = PathBuf::from(FIXTURES_PATH);

    let compat_dir = fixtures_path.join("compat").join(c2pa::VERSION);
    if Path::new(&compat_dir).exists() {
        fs::remove_dir_all(&compat_dir)?;
    }
    fs::create_dir(&compat_dir)?;

    let public_key = fs::read(fixtures_path.join(&details.certificate))?;
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

        let mut embedded_builder = Builder::from_json(FULL_MANIFEST)?;
        embedded_builder.base_path = Some(PathBuf::from(FIXTURES_PATH));

        let mut signed_embedded_asset = Cursor::new(Vec::new());
        let embedded_c2pa_manifest = embedded_builder.sign(
            &signer,
            &format,
            &mut Cursor::new(&original_asset),
            &mut signed_embedded_asset,
        )?;

        let embedded_size = signed_embedded_asset.get_ref().len();

        let embedded_reader = &Reader::from_manifest_data_and_stream(
            &embedded_c2pa_manifest,
            &format,
            &mut signed_embedded_asset,
        )?;

        let dir_path = compat_dir.join(&asset_details.category);
        fs::create_dir(&dir_path)?;

        let mut remote_builder = Builder::from_json(FULL_MANIFEST)?;
        remote_builder.base_path = Some(PathBuf::from(FIXTURES_PATH));
        remote_builder.no_embed = true;
        remote_builder.remote_url = Some(format!(
            "http://localhost:8000/{}/{}/remote.c2pa",
            c2pa::VERSION,
            asset_details.category
        ));

        let mut signed_remote_asset = Cursor::new(Vec::new());
        let remote_c2pa_manifest = remote_builder.sign(
            &signer,
            &format,
            &mut Cursor::new(&original_asset),
            &mut signed_remote_asset,
        );
        match remote_c2pa_manifest {
            Ok(remote_c2pa_manifest) => {
                let remote_size = signed_remote_asset.get_ref().len();

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
                )
                .expect("Failed to make remote diff.");

                asset_details.remote_size = Some(BinarySize {
                    uncompressed_patch_size: signed_remote_asset_patch.len(),
                    applied_size: remote_size,
                });

                let signed_remote_asset_patch = lz4_flex::compress(&signed_remote_asset_patch);

                fs::write(dir_path.join("remote.patch"), signed_remote_asset_patch)?;
                fs::write(dir_path.join("remote.c2pa"), remote_c2pa_manifest)?;
                let mut remote_json_manifest = File::create(dir_path.join("remote.json"))?;
                serde_json::to_writer(&mut remote_json_manifest, &remote_reader)?;
            }
            Err(Error::XmpNotSupported) => {}
            Err(err) => return Err(err),
        }

        let mut signed_embedded_asset_patch = Vec::new();
        bsdiff::diff(
            &original_asset,
            &signed_embedded_asset.into_inner(),
            &mut signed_embedded_asset_patch,
        )
        .expect("Failed to make embedded diff.");

        asset_details.embedded_size = Some(BinarySize {
            uncompressed_patch_size: signed_embedded_asset_patch.len(),
            applied_size: embedded_size,
        });

        let signed_embedded_asset_patch = lz4_flex::compress(&signed_embedded_asset_patch);

        fs::write(dir_path.join("embedded.patch"), signed_embedded_asset_patch)?;
        fs::write(dir_path.join("embedded.c2pa"), embedded_c2pa_manifest)?;
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
