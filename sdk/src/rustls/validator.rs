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

use crate::rustls::common::get_algorithm_data;
use crate::{validator::CoseValidator, Error, Result};
use ring::signature;

pub struct Validator {
    alg: String,
}

impl Validator {
    pub fn new(alg: &str) -> Self {
        Validator {
            alg: alg.to_owned(),
        }
    }
}

impl CoseValidator for Validator {
    fn validate(&self, sig: &[u8], data: &[u8], pkey: &[u8]) -> Result<bool> {
        let algorithm_data = &get_algorithm_data(&self.alg).map_err(|_err| Error::CoseSignature)?;

        let public_key = signature::UnparsedPublicKey::new(
            algorithm_data.verification_alg,
            &pkey[algorithm_data.spk_offset..],
        );

        Ok(public_key.verify(data, sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::rustls::temp_signer;
    use crate::Signer;
    use rustls_pemfile::certs;
    use std::io::BufReader;
    use tempfile::tempdir;

    #[test]
    fn verify_signatures() {
        const MESSAGE: &[u8] = b"hello, world";

        for item in ["rs256", "rs384", "rs512", "ps256", "ps384", "ps512"].iter() {
            let temp_dir = tempdir().unwrap();
            let (signer, cert_path) = temp_signer::get_rsa_signer(&temp_dir.path(), item, None);

            let cert_bytes: &[u8] = &std::fs::read(&cert_path).unwrap();
            let signature = signer.sign(MESSAGE).unwrap();
            let signcerts = certs(&mut BufReader::new(cert_bytes)).unwrap();
            let public_key: &[u8] = signcerts[0].as_ref();
            let validator = Validator::new(item);
            assert!(validator.validate(&signature, MESSAGE, public_key).is_ok());
        }

        // No es512
        for item in ["es256", "es384"].iter() {
            let temp_dir = tempdir().unwrap();
            let (signer, cert_path) = temp_signer::get_ec_signer(&temp_dir.path(), item, None);

            let cert_bytes: &[u8] = &std::fs::read(&cert_path).unwrap();
            let signature = signer.sign(MESSAGE).unwrap();
            let signcerts = certs(&mut BufReader::new(cert_bytes)).unwrap();
            let public_key: &[u8] = signcerts[0].as_ref();
            let validator = Validator::new(item);
            assert!(validator.validate(&signature, MESSAGE, public_key).is_ok());
        }

        let item = "ed25519";
        let temp_dir = tempdir().unwrap();
        let (signer, cert_path) = temp_signer::get_ed_signer(&temp_dir.path(), item, None);

        let cert_bytes: &[u8] = &std::fs::read(&cert_path).unwrap();
        let signature = signer.sign(MESSAGE).unwrap();
        let signcerts = certs(&mut BufReader::new(cert_bytes)).unwrap();
        let public_key: &[u8] = signcerts[0].as_ref();
        let validator = Validator::new(item);
        assert!(validator.validate(&signature, MESSAGE, public_key).is_ok());
    }
}
