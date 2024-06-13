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
    env,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use c2pa::{create_signer, Signer, SigningAlg};
use serde::Deserialize;

// Pull in default certs so the binary can self config
const DEFAULT_CERTS: &[u8] = include_bytes!("../sample/es256_certs.pem");
const DEFAULT_KEY: &[u8] = include_bytes!("../sample/es256_private.key");

pub fn get_ta_url() -> Option<String> {
    std::env::var("C2PA_TA_URL").ok()
}
#[derive(Debug, Default, Deserialize)]
pub struct SignConfig {
    /// Signing algorithm to use - must match the associated certs
    ///
    /// Must be one of [ ps256 | ps384 | ps512 | es256 | es384 | es512 | ed25519 ]
    /// Defaults to es256
    pub alg: Option<String>,
    /// A path to a file containing the private key required for signing
    pub private_key: Option<PathBuf>,
    /// A path to a file containing the signing cert required for signing
    pub sign_cert: Option<PathBuf>,
    /// A Url to a Time Authority to use when signing the manifest
    pub ta_url: Option<String>,
}

impl SignConfig {
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).context("reading manifest configuration")
    }

    // set a base for all non-absolute paths
    pub fn set_base_path<P: AsRef<Path>>(&mut self, base: P) -> &Self {
        if let Some(path) = self.private_key.as_ref() {
            if !path.is_absolute() {
                self.private_key = Some(base.as_ref().join(path));
            }
        }
        if let Some(path) = self.sign_cert.as_ref() {
            if !path.is_absolute() {
                self.sign_cert = Some(base.as_ref().join(path));
            }
        }
        self
    }

    pub fn signer(&self) -> Result<Box<dyn Signer>> {
        let alg = self.alg.as_deref().unwrap_or("es256").to_lowercase();
        let alg: SigningAlg = alg.parse().map_err(|_| c2pa::Error::UnsupportedType)?;
        let tsa_url = self.ta_url.clone().or_else(get_ta_url);

        let mut private_key = None;
        let mut sign_cert = None;

        if let Some(path) = self.private_key.as_deref() {
            private_key =
                Some(std::fs::read(path).context(format!("Reading private key: {:?}", &path))?);
        }

        if private_key.is_none() {
            if let Ok(key) = env::var("C2PA_PRIVATE_KEY") {
                private_key = Some(key.as_bytes().to_vec());
            }
        };

        if let Some(path) = self.sign_cert.as_deref() {
            sign_cert =
                Some(std::fs::read(path).context(format!("Reading sign cert: {:?}", &path))?);
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
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs;

    use c2pa::{Manifest, ManifestStore};

    use super::*;

    const CONFIG: &str = r#"{    
        "alg": "es256",
        "private_key": "es256_private.key",
        "sign_cert": "es256_certs.pem",
        "ta_url": "http://timestamp.digicert.com"
    }"#;

    #[test]
    fn test_sign_config() {
        let mut sign_config = SignConfig::from_json(CONFIG).expect("from_json");
        sign_config.set_base_path("sample");

        let signer = sign_config.signer().expect("get signer");
        assert_eq!(signer.alg(), SigningAlg::Es256);
    }

    #[test]
    fn test_sign_default() {
        let sign_config = SignConfig::default();

        let signer = sign_config.signer().expect("get signer");
        assert_eq!(signer.alg(), SigningAlg::Es256);
    }

    #[test]
    fn test_sign_from() {
        let sign_config = SignConfig::default();

        let signer = sign_config.signer().expect("get signer");
        assert_eq!(signer.alg(), SigningAlg::Es256);
    }

    const CONFIG_ASSERTIONS: &str = r#"{
        "alg": "es256",
        "private_key": "es256_private.key",
        "sign_cert": "es256_certs.pem",
        "ta_url": "http://timestamp.digicert.com",
        "assertions": [
            {
                "label": "org.contentauth.test",
                 "data": {"my_key": "whatever I want"}
            }
        ]
    }"#;

    #[test]
    fn test_manifest_config() {
        const SOURCE_PATH: &str = "tests/fixtures/earth_apollo17.jpg";
        const OUTPUT_PATH: &str = "target/tmp/unit_out.jpg";
        fs::create_dir_all("target/tmp").expect("create_dir");
        let mut manifest = Manifest::from_json(CONFIG_ASSERTIONS).expect("from_json");

        let signer = SignConfig::from_json(CONFIG_ASSERTIONS)
            .unwrap()
            .set_base_path("sample")
            .signer()
            .expect("get_signer");

        let _result = manifest
            .embed(SOURCE_PATH, OUTPUT_PATH, signer.as_ref())
            .expect("embed");

        let ms = ManifestStore::from_file(OUTPUT_PATH)
            .expect("from_file")
            .to_string();
        //let ms = report_from_path(&OUTPUT_PATH, false).expect("report_from_path");
        assert!(ms.contains("my_key"));
    }
}
