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

use crate::{config::Config, fix_relative_path};
use anyhow::{Context, Result};
/// Provides a method to read configured certs and generate a singer
///
use c2pa::{create_signer, Signer, SigningAlg};
use std::{env, path::Path};

pub fn get_ta_url() -> Option<String> {
    std::env::var("C2PA_TA_URL").ok()
}

// Pull in default certs so the binary can self config
const DEFAULT_CERTS: &[u8] = include_bytes!("../sample/es256_certs.pem");
const DEFAULT_KEY: &[u8] = include_bytes!("../sample/es256_private.key");

pub fn get_c2pa_signer(config: &Config, base_path: &Path) -> Result<Box<dyn Signer>> {
    let alg = config.alg.as_deref().unwrap_or("es256").to_lowercase();
    let alg: SigningAlg = alg.parse().map_err(|_| c2pa::Error::UnsupportedType)?;
    let tsa_url = config.ta_url.clone().or_else(get_ta_url);

    let mut private_key = None;
    let mut sign_cert = None;

    if let Some(path) = config.private_key.as_deref() {
        let path = fix_relative_path(path, base_path);
        private_key =
            Some(std::fs::read(&path).context(format!("Reading private key: {:?}", &path))?);
    }

    if private_key.is_none() {
        if let Ok(key) = env::var("C2PA_PRIVATE_KEY") {
            private_key = Some(key.as_bytes().to_vec());
        }
    };

    if let Some(path) = config.sign_cert.as_deref() {
        let path = fix_relative_path(path, base_path);
        sign_cert = Some(std::fs::read(&path).context(format!("Reading sign cert: {:?}", &path))?);
    }

    if sign_cert.is_none() {
        if let Ok(cert) = env::var("C2PA_SIGN_CERT") {
            sign_cert = Some(cert.as_bytes().to_vec());
        }
    };

    if let Some(private_key) = private_key {
        if let Some(sign_cert) = sign_cert {
            let signer = create_signer::from_keys(&sign_cert, &private_key, alg, tsa_url)
                .context("Invalid certification data")?;
            return Ok(signer);
        }
    }

    eprintln!(
        "\n\n-----------\n\n\
        Note: Using default private key and signing certificate. This is only valid for development.\n\
        A permanent key and cert should be provided in the manifest definition or in the environment variables.\n");

    let signer = create_signer::from_keys(DEFAULT_CERTS, DEFAULT_KEY, alg, tsa_url)
        .context("Invalid certification data")?;

    Ok(signer)
}
