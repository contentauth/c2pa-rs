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

use chrono::{DateTime, Utc};
use x509_parser::num_bigint::BigUint;

#[cfg(feature = "openssl_sign")]
use crate::openssl::{EcValidator, EdValidator, RsaValidator};
use crate::{Result, SigningAlg};

#[derive(Debug, Default)]
pub struct ValidationInfo {
    pub alg: Option<SigningAlg>, // validation algorithm
    pub date: Option<DateTime<Utc>>,
    pub cert_serial_number: Option<BigUint>,
    pub issuer_org: Option<String>,
    pub validated: bool,     // claim signature is valid
    pub cert_chain: Vec<u8>, // certificate chain used to validate signature
}

/// Trait to support validating a signature against the provided data
pub(crate) trait CoseValidator {
    /// validate signature "sig" for given "data using provided public key"
    fn validate(&self, sig: &[u8], data: &[u8], pkey: &[u8]) -> Result<bool>;
}

pub struct DummyValidator;
impl CoseValidator for DummyValidator {
    fn validate(&self, _sig: &[u8], _data: &[u8], _pkey: &[u8]) -> Result<bool> {
        println!("This signature verified by DummyValidator.  Results not valid!");
        Ok(true)
    }
}

// C2PA Supported Signature type
// • ES256 (ECDSA using P-256 and SHA-256)
// • ES384 (ECDSA using P-384 and SHA-384)
// • ES512 (ECDSA using P-521 and SHA-512)
// • PS256 (RSASSA-PSS using SHA-256 and MGF1 with SHA-256)
// • PS384 (RSASSA-PSS using SHA-384 and MGF1 with SHA-384)
// • PS512 (RSASSA-PSS using SHA-512 and MGF1 with SHA-512)
// • RS256	RSASSA-PKCS1-v1_5 using SHA-256
// • RS384	RSASSA-PKCS1-v1_5 using SHA-384
// • RS512	RSASSA-PKCS1-v1_5 using SHA-512
// • ED25519 Edwards Curve ED25519

/// return validator for supported C2PA  algorithms
#[cfg(feature = "openssl")]
pub(crate) fn get_validator(alg: SigningAlg) -> Box<dyn CoseValidator> {
    match alg {
        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => {
            Box::new(EcValidator::new(alg))
        }
        SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512 => {
            Box::new(RsaValidator::new(alg))
        }
        // "rs256" => Some(Box::new(RsaValidator::new("rs256"))),
        // "rs384" => Some(Box::new(RsaValidator::new("rs384"))),
        // "rs512" => Some(Box::new(RsaValidator::new("rs512"))),
        SigningAlg::Ed25519 => Box::new(EdValidator::new(alg)),
    }
}

#[cfg(not(feature = "openssl_sign"))]
#[allow(dead_code)]
pub(crate) fn get_validator(_alg: SigningAlg) -> Box<dyn CoseValidator> {
    Box::new(DummyValidator)
}
