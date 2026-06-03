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

use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::{Rsa, RsaPrivateKeyBuilder},
    sign::Signer,
};

use crate::{openssl::OpenSslMutex, RawSigner, RawSignerError, SigningAlg};

enum RsaSigningAlg {
    Ps256,
    Ps384,
    Ps512,
}

/// Implements [`RawSigner`] trait using OpenSSL's implementation of SHA256 +
/// RSA encryption.
pub(crate) struct RsaSigner {
    alg: RsaSigningAlg,
    private_key: PKey<Private>,
}

impl RsaSigner {
    pub(crate) fn from_private_key(
        private_key: &[u8],
        alg: SigningAlg,
    ) -> Result<Self, RawSignerError> {
        let _openssl = OpenSslMutex::acquire()?;

        // Rebuild RSA keys to eliminate incompatible values.
        let private_key = Rsa::private_key_from_pem(private_key)?;

        let n = private_key.n().to_owned()?;
        let e = private_key.e().to_owned()?;
        let d = private_key.d().to_owned()?;
        let po = private_key.p();
        let qo = private_key.q();
        let dmp1o = private_key.dmp1();
        let dmq1o = private_key.dmq1();
        let iqmpo = private_key.iqmp();

        let mut pk_builder = RsaPrivateKeyBuilder::new(n, e, d)?;

        if let Some(p) = po {
            if let Some(q) = qo {
                pk_builder = pk_builder.set_factors(p.to_owned()?, q.to_owned()?)?;
            }
        }

        if let Some(dmp1) = dmp1o {
            if let Some(dmq1) = dmq1o {
                if let Some(iqmp) = iqmpo {
                    pk_builder = pk_builder.set_crt_params(
                        dmp1.to_owned()?,
                        dmq1.to_owned()?,
                        iqmp.to_owned()?,
                    )?;
                }
            }
        }

        let private_key = PKey::from_rsa(pk_builder.build())?;

        let alg: RsaSigningAlg = match alg {
            SigningAlg::Ps256 => RsaSigningAlg::Ps256,
            SigningAlg::Ps384 => RsaSigningAlg::Ps384,
            SigningAlg::Ps512 => RsaSigningAlg::Ps512,
            _ => {
                return Err(RawSignerError::InternalError(
                    "RsaSigner should be used only for SigningAlg::Ps***".to_string(),
                ));
            }
        };

        Ok(RsaSigner { alg, private_key })
    }
}

impl RawSigner for RsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        let _openssl = OpenSslMutex::acquire()?;

        let mut signer = match self.alg {
            RsaSigningAlg::Ps256 => {
                let mut signer = Signer::new(MessageDigest::sha256(), &self.private_key)?;
                signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?;
                signer.set_rsa_mgf1_md(MessageDigest::sha256())?;
                signer.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
                signer
            }

            RsaSigningAlg::Ps384 => {
                let mut signer = Signer::new(MessageDigest::sha384(), &self.private_key)?;
                signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?;
                signer.set_rsa_mgf1_md(MessageDigest::sha384())?;
                signer.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
                signer
            }

            RsaSigningAlg::Ps512 => {
                let mut signer = Signer::new(MessageDigest::sha512(), &self.private_key)?;
                signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?;
                signer.set_rsa_mgf1_md(MessageDigest::sha512())?;
                signer.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
                signer
            }
        };

        Ok(signer.sign_oneshot_to_vec(data)?)
    }

    fn max_signature_size(&self) -> usize {
        // An RSASSA-PSS signature is the size of the RSA modulus, which
        // OpenSSL reports as the key's maximum output size.
        self.private_key.size()
    }

    fn alg(&self) -> SigningAlg {
        match self.alg {
            RsaSigningAlg::Ps256 => SigningAlg::Ps256,
            RsaSigningAlg::Ps384 => SigningAlg::Ps384,
            RsaSigningAlg::Ps512 => SigningAlg::Ps512,
        }
    }
}
