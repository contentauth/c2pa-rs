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
///
/// The signer is created from the signcert and pkey fields.
///
/// The alg field is used to determine the signing algorithm.
///
/// The tsa_url field is optional and is used to specify a timestamp server.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct SignerInfo {
    pub alg: String,
    pub sign_cert: Vec<u8>,
    pub private_key: Vec<u8>,
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
