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

/// Provides a method to read configured certs and generate a singer
///
use crate::{config::Config, fix_relative_path};

use anyhow::{Context, Result};
use c2pa::{get_signer, Signer};

use std::{env, path::Path, process::exit};

pub fn get_ta_url() -> Option<String> {
    std::env::var("C2PA_TA_URL").ok()
}

/// Generates a signature from local keys specified by the environment
/// keys can be directly in environment variables
/// or in a folder referenced by CAI_KEY_PATH
/// also supports default dev environment keys
pub fn get_c2pa_signer(config: &Config, base_path: &Path) -> Result<Box<dyn Signer>> {
    let alg = config.alg.as_deref().unwrap_or("ps256").to_lowercase();
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
            let signer = get_signer(&sign_cert, &private_key, &alg, tsa_url)?;
            return Ok(signer);
        }
    }

    eprintln!(
        "\n\n-----------\n\n\
        Claim creation requires a private key and signing certificate \n\
        Set the config file fields, private_key and sign_cert to paths to the required files.
        \n\
        You can generate a throwaway RSAPSS SSH private key and cert for testing on macos by \n\
        pasting the following line into a terminal and hitting enter\n\
        openssl req -new -newkey rsa:4096 -sigopt rsa_padding_mode:pss -days 180 -extensions v3_ca -addext \"keyUsage = digitalSignature\" -addext \"extendedKeyUsage = emailProtection\" -nodes -x509 -keyout private.key -out certs.pem -sha256\n\
        \n\
        You then need to reference those files in config.private_key and config.sign_cert\n\
        \n\
        The private key can alternatively be passed in the environment var C2PA_PRIVATE_KEY
        The signing cert can alternatively be passed in the environment var C2PA_SIGN_CERT
        -----------\n\n");
    exit(1);
}
