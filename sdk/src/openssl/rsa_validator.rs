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

use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa};

use crate::{validator::CoseValidator, Error, Result, SigningAlg};

pub struct RsaValidator {
    alg: SigningAlg,
}

impl RsaValidator {
    pub fn new(alg: SigningAlg) -> Self {
        RsaValidator { alg }
    }
}

impl CoseValidator for RsaValidator {
    fn validate(&self, sig: &[u8], data: &[u8], pkey: &[u8]) -> Result<bool> {
        let rsa = Rsa::public_key_from_der(pkey).map_err(|_err| Error::CoseSignature)?;
        let pkey = PKey::from_rsa(rsa).map_err(|_err| Error::CoseSignature)?;

        let mut verifier = match self.alg {
            SigningAlg::Ps256 => {
                let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha256(), &pkey)?;
                verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?; // use C2PA recommended padding
                verifier.set_rsa_mgf1_md(MessageDigest::sha256())?;
                verifier
            }
            SigningAlg::Ps384 => {
                let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha384(), &pkey)?;
                verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?; // use C2PA recommended padding
                verifier.set_rsa_mgf1_md(MessageDigest::sha384())?;
                verifier
            }
            SigningAlg::Ps512 => {
                let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha512(), &pkey)?;
                verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?; // use C2PA recommended padding
                verifier.set_rsa_mgf1_md(MessageDigest::sha512())?;
                verifier
            }
            // "rs256" => openssl::sign::Verifier::new(MessageDigest::sha256(), &pkey)?,
            // "rs384" => openssl::sign::Verifier::new(MessageDigest::sha384(), &pkey)?,
            // "rs512" => openssl::sign::Verifier::new(MessageDigest::sha512(), &pkey)?,
            _ => return Err(Error::UnsupportedType),
        };

        verifier
            .verify_oneshot(sig, data)
            .map_err(|_err| Error::CoseSignature)
    }
}

#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{signer::ConfigurableSigner, Signer, SigningAlg};

    #[test]
    fn verify_rsa_signatures() {
        let cert_bytes = include_bytes!("../../tests/fixtures/temp_cert.data");
        let key_bytes = include_bytes!("../../tests/fixtures/temp_priv_key.data");

        let signcert = openssl::x509::X509::from_pem(cert_bytes).unwrap();
        let pkey = signcert.public_key().unwrap().public_key_to_der().unwrap();

        let data = b"some sample content to sign";

        // println!("Test RS256");
        // let mut signer = crate::openssl::RsaSigner::from_signcert_and_pkey(
        //     cert_bytes,
        //     key_bytes,
        //     "rs256".to_string(),
        //     None,
        // )
        // .unwrap();

        // let mut signature = signer.sign(data).unwrap();
        // println!("signature len = {}", signature.len());
        // let mut validator = RsaValidator::new("rs256");
        // assert!(validator.validate(&signature, data, &pkey).unwrap());

        // println!("Test RS384");
        // signer = crate::openssl::RsaSigner::from_signcert_and_pkey(
        //     cert_bytes,
        //     key_bytes,
        //     "rs384".to_string(),
        //     None,
        // )
        // .unwrap();

        // signature = signer.sign(data).unwrap();
        // println!("signature len = {}", signature.len());
        // validator = RsaValidator::new("rs384");
        // assert!(validator.validate(&signature, data, &pkey).unwrap());

        // println!("Test RS512");
        // signer = crate::openssl::RsaSigner::from_signcert_and_pkey(
        //     cert_bytes,
        //     key_bytes,
        //     "rs512".to_string(),
        //     None,
        // )
        // .unwrap();

        // signature = signer.sign(data).unwrap();
        // println!("signature len = {}", signature.len());
        // validator = RsaValidator::new("rs512");
        // assert!(validator.validate(&signature, data, &pkey).unwrap());

        println!("Test PS256");
        let mut signer = crate::openssl::RsaSigner::from_signcert_and_pkey(
            cert_bytes,
            key_bytes,
            SigningAlg::Ps256,
            None,
        )
        .unwrap();

        let mut signature = signer.sign(data).unwrap();
        println!("signature len = {}", signature.len());
        let mut validator = RsaValidator::new(SigningAlg::Ps256);
        assert!(validator.validate(&signature, data, &pkey).unwrap());

        println!("Test PS384");
        signer = crate::openssl::RsaSigner::from_signcert_and_pkey(
            cert_bytes,
            key_bytes,
            SigningAlg::Ps384,
            None,
        )
        .unwrap();

        signature = signer.sign(data).unwrap();
        println!("signature len = {}", signature.len());
        validator = RsaValidator::new(SigningAlg::Ps384);
        assert!(validator.validate(&signature, data, &pkey).unwrap());

        println!("Test PS512");
        signer = crate::openssl::RsaSigner::from_signcert_and_pkey(
            cert_bytes,
            key_bytes,
            SigningAlg::Ps512,
            None,
        )
        .unwrap();

        signature = signer.sign(data).unwrap();
        println!("signature len = {}", signature.len());
        validator = RsaValidator::new(SigningAlg::Ps512);
        assert!(validator.validate(&signature, data, &pkey).unwrap());
    }
}
