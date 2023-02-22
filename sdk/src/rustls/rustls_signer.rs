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

use std::{fs, io::BufReader, path::Path};

use rustls::{
    sign,
    sign::{CertifiedKey, Signer as SignerTrait},
    Certificate, PrivateKey,
};
use rustls_pemfile::pkcs8_private_keys;
use x509_parser::der_parser::{
    self,
    der::{parse_der_integer, parse_der_sequence_defined_g},
};

use super::{
    check_chain_order,
    common::{ensure_p1363_sig, get_certificates, get_ec_private_keys},
};
use crate::{
    rustls::common::get_algorithm_data, signer::ConfigurableSigner, signing_alg, Error, Result,
    Signer, SigningAlg,
};

pub struct RustlsSigner {
    signcerts: Vec<Certificate>,
    pub certified_key: CertifiedKey,
    pub signer: Box<dyn SignerTrait>,

    certs_size: usize,
    timestamp_size: usize,

    alg: SigningAlg,
    tsa_url: Option<String>,
}

fn get_private_key(alg: &signing_alg::SigningAlg, pkey: &[u8]) -> Result<PrivateKey> {
    match alg {
        SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512 | SigningAlg::Ed25519 => {
            let mut reader = BufReader::new(pkey);
            let pkeys = pkcs8_private_keys(&mut reader)?;

            if pkeys.is_empty() {
                return Err(Error::BadParam("unusable Ps or Ed private key".to_string()));
            }
            Ok(PrivateKey(pkeys[0].clone()))
        }
        // SigningAlg::Es512
        SigningAlg::Es256 | SigningAlg::Es384 => {
            let pkeys = get_ec_private_keys(pkey)?;

            if pkeys.is_empty() {
                return Err(Error::BadParam("unusable Es private key".to_string()));
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
        alg: signing_alg::SigningAlg,
        tsa_url: Option<String>,
    ) -> Result<Self> {
        let signcert = fs::read(signcert_path).map_err(wrap_io_err)?;
        let pkey = fs::read(pkey_path).map_err(wrap_io_err)?;

        Self::from_signcert_and_pkey(&signcert, &pkey, alg, tsa_url)
    }

    fn from_signcert_and_pkey(
        signcert: &[u8],
        pkey: &[u8],
        alg: signing_alg::SigningAlg,
        tsa_url: Option<String>,
    ) -> Result<Self> {
        // Get signcerts, the certificates vector
        let signcerts = get_certificates(signcert);

        // make sure cert chains are in order
        if !check_chain_order(&signcerts) {
            return Err(Error::BadParam(
                "certificate chain is not in correct order".to_string(),
            ));
        }

        let pkey = get_private_key(&alg, pkey)?;

        // Get signing key from der format key
        let signing_key = match sign::any_supported_type(&pkey) {
            Ok(signing_key) => signing_key,
            Err(_e) => {
                return Err(Error::BadParam(_e.to_string()));
            }
        };

        // Get certified_key from certificates+signing key.
        let certified_key = CertifiedKey::new(signcerts.clone(), signing_key);
        let signature_scheme = get_algorithm_data(&alg)?;

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
        let signature = self.signer.sign(data)?;
        ensure_p1363_sig(&signature, self.alg)
    }

    fn reserve_size(&self) -> usize {
        1024 + self.certs_size + self.timestamp_size
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        let certs = self.signcerts.iter().map(|cert| cert.0.clone()).collect();

        Ok(certs)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }
}

// C2PA use P1363 format for EC signatures so we must
// convert from ASN.1 DER to IEEE P1363 format to verify.
struct ECSigComps<'a> {
    r: &'a [u8],
    s: &'a [u8],
}

fn parse_ec_sig(data: &[u8]) -> der_parser::error::BerResult<ECSigComps> {
    parse_der_sequence_defined_g(|content: &[u8], _| {
        let (rem1, r) = parse_der_integer(content)?;
        let (_rem2, s) = parse_der_integer(rem1)?;

        Ok((
            data,
            ECSigComps {
                r: r.as_slice()?,
                s: s.as_slice()?,
            },
        ))
    })(data)
}

#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tempfile::tempdir;

    use super::*;
    use crate::{rustls::temp_signer::get_temp_signer, signer, Signer};

    #[test]
    fn signer_from_files() {
        let temp_dir = tempdir().unwrap();

        let (signer, _) = get_temp_signer(temp_dir.path());
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
            RustlsSigner::from_signcert_and_pkey(cert_bytes, key_bytes, SigningAlg::Ps256, None)
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
