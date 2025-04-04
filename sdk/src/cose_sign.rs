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

//! Provides access to COSE signature generation.

#![deny(missing_docs)]

use async_generic::async_generic;
use async_trait::async_trait;
use c2pa_crypto::{
    cose::{
        check_end_entity_certificate_profile, sign, sign_async, CertificateTrustPolicy,
        TimeStampStorage,
    },
    raw_signature::{AsyncRawSigner, RawSigner, RawSignerError, SigningAlg},
    time_stamp::{AsyncTimeStampProvider, TimeStampError, TimeStampProvider},
};
use c2pa_status_tracker::{ErrorBehavior, StatusTracker};

use crate::{
    claim::Claim, cose_validator::verify_cose, settings::get_settings_value, AsyncSigner, Error,
    Result, Signer,
};

/// Generate a COSE signature for a block of bytes which must be a valid C2PA
/// claim structure.
///
/// Should only be used when the underlying signature mechanism is detached
/// from the generation of the C2PA manifest (and thus the claim embedded in it).
///
/// ## Actions taken
///
/// 1. Verifies that the data supplied is a valid C2PA claim. The function will
///    respond with [`Error::ClaimDecoding`] if not.
/// 2. Signs the data using the provided [`Signer`] instance. Will ensure that
///    the signature is padded to match `box_size`, which should be the number of
///    bytes reserved for the `c2pa.signature` JUMBF box in this claim's manifest.
///    (If `box_size` is too small for the generated signature, this function
///    will respond with an error.)
/// 3. Verifies that the signature is valid COSE. Will respond with an error
///    [`Error::CoseSignature`] if unable to validate.
#[async_generic(async_signature(
    claim_bytes: &[u8],
    signer: &dyn AsyncSigner,
    box_size: usize
))]
pub fn sign_claim(claim_bytes: &[u8], signer: &dyn Signer, box_size: usize) -> Result<Vec<u8>> {
    // Must be a valid claim.
    let label = "dummy_label";
    let claim = Claim::from_data(label, claim_bytes)?;

    let tss = if claim.version() > 1 {
        TimeStampStorage::V2_sigTst2_CTT
    } else {
        TimeStampStorage::V1_sigTst
    };

    let signed_bytes = if _sync {
        cose_sign(signer, claim_bytes, box_size, tss)
    } else {
        cose_sign_async(signer, claim_bytes, box_size, tss).await
    };

    match signed_bytes {
        Ok(signed_bytes) => {
            // Sanity check: Ensure that this signature is valid.
            let mut cose_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
            let passthrough_cap = CertificateTrustPolicy::default();

            match verify_cose(
                &signed_bytes,
                claim_bytes,
                b"",
                true,
                &passthrough_cap,
                &mut cose_log,
            ) {
                Ok(r) => {
                    if !r.validated {
                        Err(Error::CoseSignature)
                    } else {
                        Ok(signed_bytes)
                    }
                }
                Err(err) => Err(err),
            }
        }
        Err(err) => Err(err),
    }
}

/// Returns signed Cose_Sign1 bytes for `data`.
/// The Cose_Sign1 will be signed with the algorithm from [`Signer`].
#[async_generic(async_signature(
    signer: &dyn AsyncSigner,
    data: &[u8],
    box_size: usize,
    time_stamp_storage: TimeStampStorage,
))]
pub(crate) fn cose_sign(
    signer: &dyn Signer,
    data: &[u8],
    box_size: usize,
    time_stamp_storage: TimeStampStorage,
) -> Result<Vec<u8>> {
    // Make sure the signing cert is valid.
    let certs = signer.certs()?;
    if let Some(signing_cert) = certs.first() {
        signing_cert_valid(signing_cert)?;
    } else {
        return Err(Error::CoseNoCerts);
    }

    if _sync {
        match signer.raw_signer() {
            Some(raw_signer) => Ok(sign(*raw_signer, data, Some(box_size), time_stamp_storage)?),
            None => {
                let wrapper = SignerWrapper(signer);
                Ok(sign(&wrapper, data, Some(box_size), time_stamp_storage)?)
            }
        }
    } else {
        match signer.async_raw_signer() {
            Some(raw_signer) => {
                Ok(sign_async(*raw_signer, data, Some(box_size), time_stamp_storage).await?)
            }
            None => {
                let wrapper = AsyncSignerWrapper(signer);
                Ok(sign_async(&wrapper, data, Some(box_size), time_stamp_storage).await?)
            }
        }
    }
}

fn signing_cert_valid(signing_cert: &[u8]) -> Result<()> {
    // make sure signer certs are valid
    let mut cose_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut passthrough_cap = CertificateTrustPolicy::default();

    // allow user EKUs through this check if configured
    if let Ok(Some(trust_config)) = get_settings_value::<Option<String>>("trust.trust_config") {
        passthrough_cap.add_valid_ekus(trust_config.as_bytes());
    }

    Ok(check_end_entity_certificate_profile(
        signing_cert,
        &passthrough_cap,
        &mut cose_log,
        None,
    )?)
}

struct SignerWrapper<'a>(&'a dyn Signer);

impl RawSigner for SignerWrapper<'_> {
    fn sign(&self, data: &[u8]) -> std::result::Result<Vec<u8>, RawSignerError> {
        Ok(self.0.sign(data)?)
    }

    fn alg(&self) -> SigningAlg {
        self.0.alg()
    }

    fn cert_chain(&self) -> std::result::Result<Vec<Vec<u8>>, RawSignerError> {
        Ok(self.0.certs()?)
    }

    fn reserve_size(&self) -> usize {
        self.0.reserve_size()
    }

    fn ocsp_response(&self) -> Option<Vec<u8>> {
        self.0.ocsp_val()
    }
}

impl TimeStampProvider for SignerWrapper<'_> {
    fn time_stamp_service_url(&self) -> Option<String> {
        self.0.time_authority_url()
    }

    fn time_stamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        self.0.timestamp_request_headers()
    }

    fn time_stamp_request_body(
        &self,
        message: &[u8],
    ) -> std::result::Result<Vec<u8>, TimeStampError> {
        Ok(self.0.timestamp_request_body(message)?)
    }

    fn send_time_stamp_request(
        &self,
        message: &[u8],
    ) -> Option<std::result::Result<Vec<u8>, TimeStampError>> {
        self.0
            .send_timestamp_request(message)
            .map(|r| r.map_err(|e| e.into()))
    }
}

struct AsyncSignerWrapper<'a>(&'a dyn AsyncSigner);

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AsyncRawSigner for AsyncSignerWrapper<'_> {
    async fn sign(&self, data: Vec<u8>) -> std::result::Result<Vec<u8>, RawSignerError> {
        Ok(self.0.sign(data).await?)
    }

    fn alg(&self) -> SigningAlg {
        self.0.alg()
    }

    fn cert_chain(&self) -> std::result::Result<Vec<Vec<u8>>, RawSignerError> {
        Ok(self.0.certs()?)
    }

    fn reserve_size(&self) -> usize {
        self.0.reserve_size()
    }

    async fn ocsp_response(&self) -> Option<Vec<u8>> {
        self.0.ocsp_val().await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AsyncTimeStampProvider for AsyncSignerWrapper<'_> {
    fn time_stamp_service_url(&self) -> Option<String> {
        self.0.time_authority_url()
    }

    fn time_stamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        self.0.timestamp_request_headers()
    }

    fn time_stamp_request_body(
        &self,
        message: &[u8],
    ) -> std::result::Result<Vec<u8>, TimeStampError> {
        Ok(self.0.timestamp_request_body(message)?)
    }

    async fn send_time_stamp_request(
        &self,
        message: &[u8],
    ) -> Option<std::result::Result<Vec<u8>, TimeStampError>> {
        self.0
            .send_timestamp_request(message)
            .await
            .map(|r| r.map_err(|e| e.into()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use c2pa_crypto::raw_signature::SigningAlg;

    use super::sign_claim;
    #[cfg(feature = "file_io")]
    use crate::utils::test_signer::async_test_signer;
    use crate::{claim::Claim, utils::test_signer::test_signer, Result, Signer};

    #[test]
    fn test_sign_claim() {
        // todo: we have to disable trust checks here for now because these
        // tests use the passthrough mode:
        // let passthrough_cap = CertificateTrustPolicy::default();
        // mode which does not pass through the top level (c2pa-rs) unit tests
        //configuration so the test trust list is not loaded
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        let mut claim = Claim::new("extern_sign_test", Some("contentauth"), 1);
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let signer = test_signer(SigningAlg::Ps256);
        let box_size = Signer::reserve_size(signer.as_ref());

        let cose_sign1 = sign_claim(&claim_bytes, signer.as_ref(), box_size).unwrap();

        assert_eq!(cose_sign1.len(), box_size);
    }

    #[cfg(feature = "file_io")]
    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(target_os = "wasi", wstd::test)]
    async fn test_sign_claim_async() {
        // todo: we have to disable trust checks here for now because these
        // tests use the passthrough mode:
        // let passthrough_cap = CertificateTrustPolicy::default();
        // mode which does not pass through the top level (c2pa-rs) unit tests
        //configuration so the test trust list is not loaded
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        use c2pa_crypto::raw_signature::SigningAlg;

        use crate::{cose_sign::sign_claim_async, AsyncSigner};

        let mut claim = Claim::new("extern_sign_test", Some("contentauth"), 1);
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let signer = async_test_signer(SigningAlg::Ps256);
        let box_size = signer.reserve_size();

        let cose_sign1 = sign_claim_async(&claim_bytes, &signer, box_size)
            .await
            .unwrap();

        assert_eq!(cose_sign1.len(), box_size);
    }

    struct BogusSigner {}

    impl BogusSigner {
        pub fn new() -> Self {
            BogusSigner {}
        }
    }

    impl Signer for BogusSigner {
        fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
            eprintln!("Canary, canary, please cause this deploy to fail!");
            Ok(b"totally bogus signature".to_vec())
        }

        fn alg(&self) -> c2pa_crypto::raw_signature::SigningAlg {
            c2pa_crypto::raw_signature::SigningAlg::Ps256
        }

        fn certs(&self) -> Result<Vec<Vec<u8>>> {
            let cert_vec: Vec<u8> = Vec::new();
            let certs = vec![cert_vec];
            Ok(certs)
        }

        fn reserve_size(&self) -> usize {
            1024
        }

        fn send_timestamp_request(&self, _message: &[u8]) -> Option<crate::error::Result<Vec<u8>>> {
            Some(Ok(Vec::new()))
        }
    }

    #[test]
    fn test_bogus_signer() {
        let mut claim = Claim::new("bogus_sign_test", Some("contentauth"), 1);
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let box_size = 10000;

        let signer = BogusSigner::new();

        let _cose_sign1 = sign_claim(&claim_bytes, &signer, box_size);

        assert!(_cose_sign1.is_err());
    }
}
