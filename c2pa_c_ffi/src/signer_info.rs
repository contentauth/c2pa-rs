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

use c2pa::{create_signer, Signer, SigningAlg};
use serde::Deserialize;

use crate::{Error, Result};

/// SignerInfo provides the information needed to create a signer
/// and sign a manifest.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct SignerInfo {
    /// The alg field is used to determine the signing algorithm.
    pub alg: String,
    /// The public certificate used to sign the manifest in PEM format.
    pub sign_cert: Vec<u8>,
    /// The private key used to sign the manifest in PEM format.
    pub private_key: Vec<u8>,
    /// The ta_url field is an optional URL used to specify a timestamp server.
    pub ta_url: Option<String>,
}

impl SignerInfo {
    /// Create a SignerInfo from a JSON formatted SignerInfo string
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::Json(e.to_string()))
    }

    // Returns the signing algorithm converted from string format
    fn alg(&self) -> Result<SigningAlg> {
        self.alg
            .to_lowercase()
            .parse()
            .map_err(|_| Error::Other("Invalid signing algorithm".to_string()))
    }

    /// Create a signer from the SignerInfo
    pub fn signer(&self) -> Result<Box<dyn Signer>> {
        create_signer::from_keys(
            &self.sign_cert,
            &self.private_key,
            self.alg()?,
            self.ta_url.clone(),
        )
        .map_err(Error::from_c2pa_error)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_signer_info_valid() {
        let json = json!({
            "alg": "Es256",
            "sign_cert": b"test_cert".to_vec(), // Convert string to Vec<u8>
            "private_key": b"test_key".to_vec(), // Convert string to Vec<u8>
            "ta_url": "https://timestamp.example.com"
        })
        .to_string();

        let signer_info = SignerInfo::from_json(&json).unwrap();
        assert_eq!(signer_info.alg, "Es256");
        assert_eq!(signer_info.sign_cert, b"test_cert");
        assert_eq!(signer_info.private_key, b"test_key");
        assert_eq!(
            signer_info.ta_url.as_deref(),
            Some("https://timestamp.example.com")
        );
    }

    #[test]
    fn test_signer_info_missing_fields() {
        let json = json!({
            "alg": "Es256",
            "sign_cert": b"test_cert".to_vec() // Convert string to Vec<u8>
        })
        .to_string();

        let result = SignerInfo::from_json(&json);
        assert!(result.is_err());
        let signer_info = result.unwrap_err();
        assert!(signer_info
            .to_string()
            .starts_with("Json: missing field `private_key`"));
    }

    #[test]
    fn test_signer_info_invalid_json() {
        let json = r#"
        {
            "alg": "Es256",
            "sign_cert": [100, 71, 86, 122, 100, 70, 57, 106, 90, 88, 74, 48],
            "private_key": [100, 71, 86, 122, 100, 70, 57, 114, 90, 88, 107, 61],
        }
        "#; // Invalid JSON due to trailing comma
        let result = SignerInfo::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_signer_info_invalid_algorithm() {
        let json = json!({
            "alg": "invalid_alg",
            "sign_cert": b"test_cert".to_vec(), // Convert string to Vec<u8>
            "private_key": b"test_key".to_vec() // Convert string to Vec<u8>
        })
        .to_string();

        let signer_info = SignerInfo::from_json(&json).unwrap();
        let result = signer_info.alg();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Other: Invalid signing algorithm"
        );
    }

    #[test]
    fn test_signer_creation_fail() {
        let json = json!({
            "alg": "Es256",
            "sign_cert": b"test_cert".to_vec(), // Convert string to Vec<u8>
            "private_key": b"test_key".to_vec() // Convert string to Vec<u8>
        })
        .to_string();

        let signer_info = SignerInfo::from_json(&json).unwrap();
        let signer = signer_info.signer();
        assert!(signer.is_err());
    }
}
