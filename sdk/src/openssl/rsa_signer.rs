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

use std::cell::Cell;

use c2pa_crypto::{
    ocsp::OcspResponse,
    openssl::OpenSslMutex,
    raw_signature::{RawSigner, RawSignerError},
    time_stamp::TimeStampProvider,
    SigningAlg,
};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::{Rsa, RsaPrivateKeyBuilder},
    x509::X509,
};

use super::check_chain_order;
use crate::{signer::ConfigurableSigner, Error, Signer};

/// Implements `Signer` trait using OpenSSL's implementation of
/// SHA256 + RSA encryption.
pub struct RsaSigner {
    signcerts: Vec<X509>,
    pkey: PKey<Private>,

    certs_size: usize,
    timestamp_size: usize,
    ocsp_size: Cell<usize>,

    alg: SigningAlg,
    tsa_url: Option<String>,
    ocsp_rsp: Cell<OcspResponse>,
}

impl RsaSigner {
    // Sample of OCSP stapling while signing. This code is only for demo purposes and not for
    // production use since there is no caching in the SDK and fetching is expensive. This is behind the
    // feature flag 'psxxx_ocsp_stapling_experimental'
    fn update_ocsp(&self) {
        // IMPORTANT: ffi_mutex::acquire() should have been called by calling fn. Please
        // don't make this pub or pub(crate) without finding a way to ensure that
        // precondition.

        // do we need an update
        let now = chrono::offset::Utc::now();

        // is it time for an OCSP update
        let ocsp_data = self.ocsp_rsp.take();
        let next_update = ocsp_data.next_update;
        self.ocsp_rsp.set(ocsp_data);
        if now > next_update {
            #[cfg(feature = "psxxx_ocsp_stapling_experimental")]
            {
                if let Ok(certs) = self.certs_internal() {
                    if let Some(ocsp_rsp) = c2pa_crypto::ocsp::fetch_ocsp_response(&certs) {
                        self.ocsp_size.set(ocsp_rsp.len());
                        let mut validation_log =
                            c2pa_status_tracker::DetailedStatusTracker::default();
                        if let Ok(ocsp_response) =
                            OcspResponse::from_der_checked(&ocsp_rsp, None, &mut validation_log)
                        {
                            self.ocsp_rsp.set(ocsp_response);
                        }
                    }
                }
            }
        }
    }

    fn certs_internal(&self) -> Result<Vec<Vec<u8>>, RawSignerError> {
        // IMPORTANT: ffi_mutex::acquire() should have been called by calling fn. Please
        // don't make this pub or pub(crate) without finding a way to ensure that
        // precondition.

        let mut certs: Vec<Vec<u8>> = Vec::new();

        for c in &self.signcerts {
            let cert = c.to_der()?;
            certs.push(cert);
        }

        Ok(certs)
    }
}

impl ConfigurableSigner for RsaSigner {
    fn from_signcert_and_pkey(
        signcert: &[u8],
        pkey: &[u8],
        alg: SigningAlg,
        tsa_url: Option<String>,
    ) -> crate::Result<Self> {
        let _openssl = OpenSslMutex::acquire()?;

        let signcerts = X509::stack_from_pem(signcert).map_err(wrap_openssl_err)?;
        let rsa = Rsa::private_key_from_pem(pkey).map_err(wrap_openssl_err)?;

        // make sure cert chains are in order
        if !check_chain_order(&signcerts) {
            return Err(Error::BadParam(
                "certificate chain is not in correct order".to_string(),
            ));
        }

        // rebuild RSA keys to eliminate incompatible values
        let n = rsa.n().to_owned().map_err(wrap_openssl_err)?;
        let e = rsa.e().to_owned().map_err(wrap_openssl_err)?;
        let d = rsa.d().to_owned().map_err(wrap_openssl_err)?;
        let po = rsa.p();
        let qo = rsa.q();
        let dmp1o = rsa.dmp1();
        let dmq1o = rsa.dmq1();
        let iqmpo = rsa.iqmp();
        let mut builder = RsaPrivateKeyBuilder::new(n, e, d).map_err(wrap_openssl_err)?;

        if let Some(p) = po {
            if let Some(q) = qo {
                builder = builder
                    .set_factors(p.to_owned()?, q.to_owned()?)
                    .map_err(wrap_openssl_err)?;
            }
        }

        if let Some(dmp1) = dmp1o {
            if let Some(dmq1) = dmq1o {
                if let Some(iqmp) = iqmpo {
                    builder = builder
                        .set_crt_params(dmp1.to_owned()?, dmq1.to_owned()?, iqmp.to_owned()?)
                        .map_err(wrap_openssl_err)?;
                }
            }
        }

        let new_rsa = builder.build();

        let pkey = PKey::from_rsa(new_rsa).map_err(wrap_openssl_err)?;

        let signer = RsaSigner {
            signcerts,
            pkey,
            certs_size: signcert.len(),
            timestamp_size: 10000, /* todo: call out to TSA to get actual timestamp and use that size */
            ocsp_size: Cell::new(0),
            alg,
            tsa_url,
            ocsp_rsp: Cell::new(OcspResponse::default()),
        };

        // get OCSP if possible
        signer.update_ocsp();

        Ok(signer)
    }
}

impl Signer for RsaSigner {}

impl RawSigner for RsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        let mut signer = match self.alg {
            SigningAlg::Ps256 => {
                let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &self.pkey)?;

                signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?; // use C2PA recommended padding
                signer.set_rsa_mgf1_md(MessageDigest::sha256())?;
                signer.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
                signer
            }

            SigningAlg::Ps384 => {
                let mut signer = openssl::sign::Signer::new(MessageDigest::sha384(), &self.pkey)?;

                signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?; // use C2PA recommended padding
                signer.set_rsa_mgf1_md(MessageDigest::sha384())?;
                signer.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
                signer
            }

            SigningAlg::Ps512 => {
                let mut signer = openssl::sign::Signer::new(MessageDigest::sha512(), &self.pkey)?;

                signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?; // use C2PA recommended padding
                signer.set_rsa_mgf1_md(MessageDigest::sha512())?;
                signer.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
                signer
            }

            _ => unreachable!(),
        };

        let signed_data = signer.sign_oneshot_to_vec(data)?;

        // println!("sig: {}", Hexlify(&signed_data));

        Ok(signed_data)
    }

    fn reserve_size(&self) -> usize {
        1024 + self.certs_size + self.timestamp_size + self.ocsp_size.get() // the Cose_Sign1 contains complete certs, timestamps and ocsp so account for size
    }

    fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError> {
        let _openssl = OpenSslMutex::acquire()?;
        self.certs_internal()
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn ocsp_response(&self) -> Option<Vec<u8>> {
        let _openssl = OpenSslMutex::acquire().ok()?;

        // update OCSP if needed
        self.update_ocsp();

        let ocsp_data = self.ocsp_rsp.take();
        let ocsp_rsp = ocsp_data.ocsp_der.clone();
        self.ocsp_rsp.set(ocsp_data);
        if !ocsp_rsp.is_empty() {
            Some(ocsp_rsp)
        } else {
            None
        }
    }
}

impl TimeStampProvider for RsaSigner {
    fn time_stamp_service_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }
}

fn wrap_openssl_err(err: openssl::error::ErrorStack) -> Error {
    Error::OpenSslError(err)
}

#[allow(unused_imports)]
#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        utils::test::{fixture_path, temp_signer},
        Signer, SigningAlg,
    };

    #[test]
    fn signer_from_files() {
        let signer = temp_signer();
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
            RsaSigner::from_signcert_and_pkey(cert_bytes, key_bytes, SigningAlg::Ps256, None)
                .unwrap();

        let data = b"some sample content to sign";

        let signature = signer.sign(data).unwrap();
        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());
    }

    // #[test]
    // fn sign_rs256() {
    //     let cert_bytes = include_bytes!("../../tests/fixtures/temp_cert.data");
    //     let key_bytes = include_bytes!("../../tests/fixtures/temp_priv_key.data");

    //     let signer =
    //         RsaSigner::from_signcert_and_pkey(cert_bytes, key_bytes, "rs256".to_string(), None)
    //             .unwrap();

    //     let data = b"some sample content to sign";

    //     let signature = signer.sign(data).unwrap();
    //     println!("signature len = {}", signature.len());
    //     assert!(signature.len() <= signer.reserve_size());
    // }
}
