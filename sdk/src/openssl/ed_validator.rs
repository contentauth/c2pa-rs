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

use openssl::pkey::PKey;

use crate::{validator::CoseValidator, Error, Result, SigningAlg};

pub struct EdValidator {
    _alg: SigningAlg,
}

impl EdValidator {
    pub fn new(alg: SigningAlg) -> Self {
        EdValidator { _alg: alg }
    }
}

impl CoseValidator for EdValidator {
    fn validate(&self, sig: &[u8], data: &[u8], pkey: &[u8]) -> Result<bool> {
        let public_key = PKey::public_key_from_der(pkey).map_err(|_err| Error::CoseSignature)?;

        let mut verifier = openssl::sign::Verifier::new_without_digest(&public_key)
            .map_err(|_err| Error::CoseSignature)?;

        verifier
            .verify_oneshot(sig, data)
            .map_err(|_err| Error::CoseSignature)
    }
}

#[cfg(test)]
#[cfg(feature = "file_io")]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{openssl::temp_signer, utils::test::fixture_path, Signer, SigningAlg};

    #[test]
    fn sign_and_validate() {
        let cert_dir = fixture_path("certs");

        let (signer, cert_path) = temp_signer::get_ed_signer(&cert_dir, SigningAlg::Ed25519, None);

        let data = b"some sample content to sign";
        println!("data len = {}", data.len());

        let signature = signer.sign(data).unwrap();
        println!("signature.len = {}", signature.len());
        assert!(signature.len() >= 64);
        assert!(signature.len() <= signer.reserve_size());

        let cert_bytes = std::fs::read(&cert_path).unwrap();

        let signcert = openssl::x509::X509::from_pem(&cert_bytes).unwrap();
        let pub_key = signcert.public_key().unwrap().public_key_to_der().unwrap();
        let validator = EdValidator::new(SigningAlg::Ed25519);
        assert!(validator.validate(&signature, data, &pub_key).unwrap());
    }

    #[test]
    fn bad_data() {
        let cert_dir = fixture_path("certs");

        let (signer, cert_path) = temp_signer::get_ed_signer(&cert_dir, SigningAlg::Ed25519, None);

        let mut data = b"some sample content to sign".to_vec();
        println!("data len = {}", data.len());
        let signature = signer.sign(&data).unwrap();

        data[5] = 10;
        data[6] = 11;

        let cert_bytes = std::fs::read(&cert_path).unwrap();
        let signcert = openssl::x509::X509::from_pem(&cert_bytes).unwrap();
        let pub_key = signcert.public_key().unwrap().public_key_to_der().unwrap();

        let validator = EdValidator::new(SigningAlg::Es256);
        // ^^ REVIEW with @mfisher: Is this correct? Shouldn't it be ed25519?

        assert!(!validator.validate(&signature, &data, &pub_key).unwrap());
    }
}
