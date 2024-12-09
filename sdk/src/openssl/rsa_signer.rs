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

#[cfg(feature = "boringssl")]
use boring as openssl;
use c2pa_crypto::{ocsp::OcspResponse, openssl::OpenSslMutex, SigningAlg};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::{Rsa, RsaPrivateKeyBuilder},
    x509::X509,
};

use super::check_chain_order;
use crate::{signer::ConfigurableSigner, Error, Result, Signer};

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

    fn certs_internal(&self) -> Result<Vec<Vec<u8>>> {
        // IMPORTANT: ffi_mutex::acquire() should have been called by calling fn. Please
        // don't make this pub or pub(crate) without finding a way to ensure that
        // precondition.

        let mut certs: Vec<Vec<u8>> = Vec::new();

        for c in &self.signcerts {
            let cert = c.to_der().map_err(wrap_openssl_err)?;
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
    ) -> Result<Self> {
        let _openssl = OpenSslMutex::acquire()?;

        let signcerts = X509::stack_from_pem(signcert).map_err(wrap_openssl_err)?;

        let rsa: Rsa<_> = match Rsa::private_key_from_pem(pkey).map_err(wrap_openssl_err) {
            Ok(rsa) => rsa,
            #[cfg(all(test, feature = "boringssl"))]
            Err(err @ Error::OpenSslError(_)) => {
                use boring::bn::BigNum;
                use pkcs8::der::Decode;

                // BoringSSL can't parse RSA-PSS parameters. This doesn't matter, because
                // OpenSSL can't parse them either, and the C2PA SDK throws away
                // "incompatible values" anyway.

                // This signer is used only in tests.

                let der = pem::parse(pkey)
                    .ok()
                    .filter(|der| der.tag() == "PRIVATE KEY");

                let pk = der
                    .as_ref()
                    .and_then(|der| pkcs8::PrivateKeyInfo::from_der(der.contents()).ok())
                    .filter(|pk| {
                        // RSASSA-PSS ASN.1
                        pk.algorithm.oid
                            == pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10")
                    })
                    .and_then(|pk| pkcs1::RsaPrivateKey::try_from(pk.private_key).ok())
                    .ok_or(err)?;

                let n = BigNum::from_slice(pk.modulus.as_bytes())?;
                let e = BigNum::from_slice(pk.public_exponent.as_bytes())?;
                let d = BigNum::from_slice(pk.private_exponent.as_bytes())?;
                let p = BigNum::from_slice(pk.prime1.as_bytes())?;
                let q = BigNum::from_slice(pk.prime2.as_bytes())?;
                let dmp1 = BigNum::from_slice(pk.exponent1.as_bytes())?;
                let dmq1 = BigNum::from_slice(pk.exponent2.as_bytes())?;
                let iqmp = BigNum::from_slice(pk.coefficient.as_bytes())?;

                RsaPrivateKeyBuilder::new(n, e, d)?
                    .set_factors(p, q)?
                    .set_crt_params(dmp1, dmq1, iqmp)?
                    .build()
            }
            Err(err) => return Err(err),
        };

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

impl Signer for RsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut signer = match self.alg {
            SigningAlg::Ps256 => {
                let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &self.pkey)
                    .map_err(wrap_openssl_err)?;

                signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?; // use C2PA recommended padding
                signer.set_rsa_mgf1_md(MessageDigest::sha256())?;
                signer.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
                signer
            }
            SigningAlg::Ps384 => {
                let mut signer = openssl::sign::Signer::new(MessageDigest::sha384(), &self.pkey)
                    .map_err(wrap_openssl_err)?;

                signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?; // use C2PA recommended padding
                signer.set_rsa_mgf1_md(MessageDigest::sha384())?;
                signer.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
                signer
            }
            SigningAlg::Ps512 => {
                let mut signer = openssl::sign::Signer::new(MessageDigest::sha512(), &self.pkey)
                    .map_err(wrap_openssl_err)?;

                signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?; // use C2PA recommended padding
                signer.set_rsa_mgf1_md(MessageDigest::sha512())?;
                signer.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
                signer
            }
            // "rs256" => openssl::sign::Signer::new(MessageDigest::sha256(), &self.pkey)
            //     .map_err(wrap_openssl_err)?,
            // "rs384" => openssl::sign::Signer::new(MessageDigest::sha384(), &self.pkey)
            //     .map_err(wrap_openssl_err)?,
            // "rs512" => openssl::sign::Signer::new(MessageDigest::sha512(), &self.pkey)
            //     .map_err(wrap_openssl_err)?,
            _ => return Err(Error::UnsupportedType),
        };

        let signed_data = signer.sign_oneshot_to_vec(data)?;

        // println!("sig: {}", Hexlify(&signed_data));

        Ok(signed_data)
    }

    fn reserve_size(&self) -> usize {
        1024 + self.certs_size + self.timestamp_size + self.ocsp_size.get() // the Cose_Sign1 contains complete certs, timestamps and ocsp so account for size
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        let _openssl = OpenSslMutex::acquire()?;
        self.certs_internal()
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }

    fn ocsp_val(&self) -> Option<Vec<u8>> {
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
