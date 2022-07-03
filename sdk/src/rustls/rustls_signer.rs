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

use super::check_chain_order;
use super::common::get_certificates;
use super::common::get_ec_private_keys;
use crate::rustls::common::get_algorithm_data;
use crate::{signer::ConfigurableSigner, Error, Result, Signer};
use rustls::{sign, PrivateKey};
use rustls::{sign::CertifiedKey, sign::Signer as SignerTrait, Certificate};
use rustls_pemfile::pkcs8_private_keys;
use std::io::BufReader;
use std::{fs, path::Path};

pub struct RustlsSigner {
    signcerts: Vec<Certificate>,
    pub certified_key: CertifiedKey,
    pub signer: Box<dyn SignerTrait>,

    certs_size: usize,
    timestamp_size: usize,

    alg: String,
    tsa_url: Option<String>,
}

fn get_private_key(alg: &str, pkey: &[u8]) -> Result<PrivateKey> {
    match alg {
        "ps256" | "ps384" | "ps512" | "rs256" | "rs384" | "rs512" | "ed25519" => {
            let mut reader = BufReader::new(pkey);
            let pkeys = pkcs8_private_keys(&mut reader)?;

            if pkeys.is_empty() {
                return Err(Error::BadParam("unusable private key".to_string()));
            }
            Ok(PrivateKey(pkeys[0].clone()))
        }
        "es256" | "es384" => {
            let pkeys = get_ec_private_keys(pkey).map_err(wrap_io_err)?;

            if pkeys.is_empty() {
                return Err(Error::BadParam("unusable private key".to_string()));
            }
            Ok(PrivateKey(pkeys[0].clone().0))
        }
        _ => Err(Error::RustlsUnknownAlgorithmError),
    }
}

impl ConfigurableSigner for RustlsSigner {
    fn from_files<P: AsRef<Path>>(
        signcert_path: P,
        pkey_path: P,
        alg: String,
        tsa_url: Option<String>,
    ) -> Result<Self> {
        let signcert = fs::read(signcert_path).map_err(wrap_io_err)?;
        let pkey = fs::read(pkey_path).map_err(wrap_io_err)?;

        Self::from_signcert_and_pkey(&signcert, &pkey, alg, tsa_url)
    }

    fn from_signcert_and_pkey(
        signcert: &[u8],
        pkey: &[u8],
        alg: String,
        tsa_url: Option<String>,
    ) -> Result<Self> {
        // Get signcerts, the certificates vector
        let signcerts = get_certificates(signcert);
        let pkey = get_private_key(&alg, pkey)?;

        check_chain_order(&signcerts);

        // make sure cert chains are in order
        if !check_chain_order(&signcerts) {
            return Err(Error::BadParam(
                "certificate chain is not in correct order".to_string(),
            ));
        }

        // Get signing key from der format key
        let signing_key = match sign::any_supported_type(&pkey) {
            Ok(signing_key) => signing_key,
            Err(_e) => {
                return Err(Error::BadParam("could not parse private key".to_string()));
            }
        };

        // Get certified_key from certificates+signing key.
        let certified_key = CertifiedKey::new(signcerts.clone(), signing_key);
        let signature_scheme = get_algorithm_data(alg.as_str())?;

        if let Some(signer) = certified_key
            .key
            .choose_scheme(&[signature_scheme.rustls_id])
        {
            Ok(Self {
                signcerts,
                certified_key,
                signer,
                certs_size: signcert.len(),
                timestamp_size: 4096,
                alg,
                tsa_url,
            })
        } else {
            Err(Error::RustlsInvalidSignatureSchemeError)
        }
    }
}

impl Signer for RustlsSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.signer.sign(data) {
            Ok(signed_data) => Ok(signed_data),
            Err(_) => Err(Error::RustlsCouldNotSignError),
        }
    }

    fn reserve_size(&self) -> usize {
        1024 + self.certs_size + self.timestamp_size
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        let certs = self.signcerts.iter().map(|cert| cert.0.clone()).collect();

        Ok(certs)
    }

    fn alg(&self) -> Option<String> {
        Some(self.alg.to_owned())
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }
}

#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::rustls::temp_signer::get_temp_signer;
    use crate::signer;
    use crate::Signer;
    use tempfile::tempdir;

    #[test]
    fn signer_from_files() {
        let temp_dir = tempdir().unwrap();

        let (signer, _) = get_temp_signer(&temp_dir.path());
        let data = b"some sample content to sign";

        let signature = signer.sign(data).unwrap();
        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());
    }

    #[test]
    fn sign_ps256() {
        let cert_bytes = include_bytes!("../../tests/fixtures/temp_cert.data");
        let key_bytes = include_bytes!("../../tests/fixtures/temp_priv_key.data");

        let signer =
            RustlsSigner::from_signcert_and_pkey(cert_bytes, key_bytes, "ps256".to_string(), None)
                .unwrap();

        let data = b"some sample content to sign";

        let signature = signer.sign(data).unwrap();
        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());
    }

    #[test]
    fn sign_rs256() {
        let cert_bytes = include_bytes!("../../tests/fixtures/temp_cert.data");
        let key_bytes = include_bytes!("../../tests/fixtures/temp_priv_key.data");

        let signer =
            RustlsSigner::from_signcert_and_pkey(cert_bytes, key_bytes, "rs256".to_string(), None)
                .unwrap();

        let data = b"some sample content to sign";

        let signature = signer.sign(data).unwrap();
        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());
    }
}

fn wrap_io_err(err: std::io::Error) -> Error {
    Error::IoError(err)
}
