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

use std::convert::TryFrom;

use ring::signature;
use spki::SubjectPublicKeyInfo;

use crate::{
    rustls::common::{ensure_asn_sig, get_algorithm_data},
    validator::CoseValidator,
    Error, Result, SigningAlg,
};

pub struct Validator {
    alg: SigningAlg,
}

impl Validator {
    pub fn new(alg: SigningAlg) -> Self {
        Validator {
            alg: alg.to_owned(),
        }
    }
}

impl CoseValidator for Validator {
    fn validate(&self, sig: &[u8], data: &[u8], pkey: &[u8]) -> Result<bool> {
        let algorithm_data = &get_algorithm_data(&self.alg).map_err(|_err| Error::CoseSignature)?;
        let spki = SubjectPublicKeyInfo::try_from(pkey).map_err(|_err| Error::CoseSignature)?;

        let sig_asn = ensure_asn_sig(sig, self.alg)?;
        let public_key = signature::UnparsedPublicKey::new(
            algorithm_data.verification_alg,
            spki.subject_public_key,
        );

        Ok(public_key.verify(data, &sig_asn).is_ok())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use x509_parser::parse_x509_certificate;

    use super::*;
    use crate::{rustls::temp_signer, Signer};

    #[test]
    fn verify_signatures() {
        const MESSAGE: &[u8] = b"hello, world";

        // No verifying with RSA-PSS and SigningAlg::Es512.
        // This is a ring limitation, see reference in PR description.

        for alg in [SigningAlg::Es256, SigningAlg::Es384].iter() {
            let cert_dir = crate::utils::test::fixture_path("certs");
            let (signer, _cert_path) = temp_signer::get_ec_signer(&cert_dir, *alg, None);

            let signature = signer.sign(MESSAGE).unwrap();

            let leaf_certificate = match signer.certs() {
                Ok(certificate) => certificate,
                Err(_) => {
                    println!("Could not parse certificate");
                    return;
                }
            };

            let certificate = match parse_x509_certificate(&leaf_certificate[0]) {
                Ok((_rem, certificate)) => certificate,
                Err(_) => {
                    println!("Could not parse certificate");
                    return;
                }
            };

            let public_key = certificate.public_key();

            let validator = Validator::new(*alg);
            assert!(validator
                .validate(&signature, MESSAGE, public_key.raw)
                .is_ok());
        }

        let alg = SigningAlg::Ed25519;
        let cert_dir = crate::utils::test::fixture_path("certs");
        let (signer, _cert_path) = temp_signer::get_ed_signer(cert_dir, alg, None);
        let signature = signer.sign(MESSAGE).unwrap();

        let leaf_certificate = match signer.certs() {
            Ok(certificate) => certificate,
            Err(_) => {
                println!("Could not parse certificate");
                return;
            }
        };

        let certificate = match parse_x509_certificate(&leaf_certificate[0]) {
            Ok((_rem, certificate)) => certificate,
            Err(_) => {
                println!("Could not parse certificate");
                return;
            }
        };

        let public_key = certificate.public_key();

        let validator = Validator::new(alg);
        assert!(validator
            .validate(&signature, MESSAGE, public_key.raw)
            .is_ok());
    }
}
