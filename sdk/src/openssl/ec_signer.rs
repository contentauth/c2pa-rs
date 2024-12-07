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

use c2pa_crypto::{openssl::OpenSslMutex, SigningAlg};
use openssl::{
    ec::EcKey,
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::X509,
};

use super::check_chain_order;
use crate::{
    error::{Error, Result},
    signer::ConfigurableSigner,
    utils::sig_utils::der_to_p1363,
    Signer,
};

/// Implements `Signer` trait using OpenSSL's implementation of
/// ECDSA encryption.
pub struct EcSigner {
    signcerts: Vec<X509>,
    pkey: EcKey<Private>,

    certs_size: usize,
    timestamp_size: usize,

    alg: SigningAlg,
    tsa_url: Option<String>,
}

impl ConfigurableSigner for EcSigner {
    fn from_signcert_and_pkey(
        signcert: &[u8],
        pkey: &[u8],
        alg: SigningAlg,
        tsa_url: Option<String>,
    ) -> Result<Self> {
        let _openssl = OpenSslMutex::acquire()?;

        let certs_size = signcert.len();
        let pkey = EcKey::private_key_from_pem(pkey).map_err(Error::OpenSslError)?;
        let signcerts = X509::stack_from_pem(signcert).map_err(Error::OpenSslError)?;

        // make sure cert chains are in order
        if !check_chain_order(&signcerts) {
            return Err(Error::BadParam(
                "certificate chain is not in correct order".to_string(),
            ));
        }

        Ok(EcSigner {
            signcerts,
            pkey,
            certs_size,
            timestamp_size: 10000, /* todo: call out to TSA to get actual timestamp and use that size */
            alg,
            tsa_url,
        })
    }
}

impl Signer for EcSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let _openssl = OpenSslMutex::acquire()?;

        let key = PKey::from_ec_key(self.pkey.clone()).map_err(Error::OpenSslError)?;

        let mut signer = match self.alg {
            SigningAlg::Es256 => openssl::sign::Signer::new(MessageDigest::sha256(), &key)?,
            SigningAlg::Es384 => openssl::sign::Signer::new(MessageDigest::sha384(), &key)?,
            SigningAlg::Es512 => openssl::sign::Signer::new(MessageDigest::sha512(), &key)?,
            _ => return Err(Error::UnsupportedType),
        };

        signer.update(data).map_err(Error::OpenSslError)?;
        let der_sig = signer.sign_to_vec().map_err(Error::OpenSslError)?;

        der_to_p1363(&der_sig, self.alg)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        let _openssl = OpenSslMutex::acquire()?;

        let mut certs: Vec<Vec<u8>> = Vec::new();

        for c in &self.signcerts {
            let cert = c.to_der().map_err(Error::OpenSslError)?;
            certs.push(cert);
        }

        Ok(certs)
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }

    fn reserve_size(&self) -> usize {
        1024 + self.certs_size + self.timestamp_size // the Cose_Sign1 contains complete certs and timestamps so account for size
    }
}

#[cfg(test)]
#[cfg(feature = "file_io")]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{openssl::temp_signer, utils::test::fixture_path};

    #[test]
    fn es256_signer() {
        let cert_dir = fixture_path("certs");

        let (signer, _) = temp_signer::get_ec_signer(cert_dir, SigningAlg::Es256, None);

        let data = b"some sample content to sign";
        println!("data len = {}", data.len());

        let signature = signer.sign(data).unwrap();
        println!("signature.len = {}", signature.len());
        assert!(signature.len() >= 64);
        assert!(signature.len() <= signer.reserve_size());
    }

    #[test]
    fn es384_signer() {
        let cert_dir = fixture_path("certs");

        let (signer, _) = temp_signer::get_ec_signer(cert_dir, SigningAlg::Es384, None);

        let data = b"some sample content to sign";
        println!("data len = {}", data.len());

        let signature = signer.sign(data).unwrap();
        println!("signature.len = {}", signature.len());
        assert!(signature.len() >= 64);
        assert!(signature.len() <= signer.reserve_size());
    }

    #[test]
    fn es512_signer() {
        let cert_dir = fixture_path("certs");

        let (signer, _) = temp_signer::get_ec_signer(cert_dir, SigningAlg::Es512, None);

        let data = b"some sample content to sign";
        println!("data len = {}", data.len());

        let signature = signer.sign(data).unwrap();
        println!("signature.len = {}", signature.len());
        assert!(signature.len() >= 64);
        assert!(signature.len() <= signer.reserve_size());
    }
}
