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
use c2pa_raw_crypto::{RawSignerError, SigningAlg};

use crate::{
    claim::Claim,
    cose_validator::verify_cose,
    crypto::{
        cose::{
            sign, sign_async, AsyncCoseSigner, CertificateRole, CertificateTrustPolicy, CoseSigner,
            TimeStampStorage,
        },
        time_stamp::{AsyncTimeStampProvider, TimeStampError, TimeStampProvider},
    },
    settings::Settings,
    status_tracker::{ErrorBehavior, StatusTracker},
    AsyncSigner, Context, Error, Result, Signer,
};

/// Generate a COSE signature for a block of bytes which must be a valid C2PA
/// claim structure.
///
/// Should only be used when the underlying signature mechanism is detached
/// from the generation of the C2PA manifest (and thus the claim embedded in it).
/// `context` supplies signing settings and the HTTP resolver/network policy for timestamps.
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
    box_size: usize,
    context: &Context,
))]
pub fn sign_claim(
    claim_bytes: &[u8],
    signer: &dyn Signer,
    box_size: usize,
    context: &Context,
) -> Result<Vec<u8>> {
    let settings = context.settings();
    // Must be a valid claim.
    let label = "dummy_label";
    let claim = Claim::from_data(label, claim_bytes)?;

    let tss = if claim.version() > 1 {
        TimeStampStorage::V2_sigTst2_CTT
    } else {
        TimeStampStorage::V1_sigTst
    };

    let signed_bytes = if _sync {
        cose_sign(signer, claim_bytes, box_size, tss, context)
    } else {
        cose_sign_async(signer, claim_bytes, box_size, tss, context).await
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
                None,
                &mut cose_log,
                settings,
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
    context: &Context,
))]
pub(crate) fn cose_sign(
    signer: &dyn Signer,
    data: &[u8],
    box_size: usize,
    time_stamp_storage: TimeStampStorage,
    context: &Context,
) -> Result<Vec<u8>> {
    let settings = context.settings();
    // Make sure the signing cert is valid.
    let certs = signer.certs()?;
    if let Some(signing_cert) = certs.first() {
        signing_cert_valid(signing_cert, settings)?;
    } else {
        return Err(Error::CoseNoCerts);
    }

    if _sync {
        let wrapper = SignerWrapper(signer);
        Ok(sign(
            &wrapper,
            data,
            Some(box_size),
            time_stamp_storage,
            context,
        )?)
    } else {
        let wrapper = AsyncSignerWrapper(signer);
        Ok(sign_async(&wrapper, data, Some(box_size), time_stamp_storage, context).await?)
    }
}

fn signing_cert_valid(signing_cert: &[u8], settings: &Settings) -> Result<()> {
    // make sure signer certs are valid
    let mut cose_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut passthrough_cap = CertificateTrustPolicy::default();
    if !settings.trust.use_default_ekus {
        passthrough_cap.clear_ekus();
    }

    // Allow user EKUs through this check if configured.
    // TODO (https://github.com/contentauth/c2pa-rs/issues/1313):
    // Need to determine if we're using C2PA or CAWG trust config here.
    if let Some(trust_config) = &settings.trust.trust_config {
        // allow for JSON-encoded PEMs with \n
        let trust_config = trust_config.to_owned().replace("\\n", "\n").into_bytes();

        passthrough_cap.add_valid_ekus(&trust_config);
    }

    Ok(CertificateRole::ClaimSigner.check_profile(
        signing_cert,
        &passthrough_cap,
        &mut cose_log,
        None,
    )?)
}

struct SignerWrapper<'a>(&'a dyn Signer);

impl CoseSigner for SignerWrapper<'_> {
    fn sign(&self, data: &[u8]) -> std::result::Result<Vec<u8>, RawSignerError> {
        self.0
            .sign(data)
            .map_err(|e| RawSignerError::InternalError(e.to_string()))
    }

    fn alg(&self) -> SigningAlg {
        self.0.alg()
    }

    fn cert_chain(&self) -> std::result::Result<Vec<Vec<u8>>, RawSignerError> {
        self.0
            .certs()
            .map_err(|e| RawSignerError::InternalError(e.to_string()))
    }

    fn ocsp_responses(&self) -> Vec<Vec<u8>> {
        self.0.ocsp_vals()
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
        context: &Context,
    ) -> Option<std::result::Result<Vec<u8>, TimeStampError>> {
        self.0
            .send_timestamp_request(message, context)
            .map(|r| r.map_err(|e| e.into()))
    }
}

struct AsyncSignerWrapper<'a>(&'a dyn AsyncSigner);

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AsyncCoseSigner for AsyncSignerWrapper<'_> {
    async fn sign(&self, data: Vec<u8>) -> std::result::Result<Vec<u8>, RawSignerError> {
        self.0
            .sign(data)
            .await
            .map_err(|e| RawSignerError::InternalError(e.to_string()))
    }

    fn alg(&self) -> SigningAlg {
        self.0.alg()
    }

    fn cert_chain(&self) -> std::result::Result<Vec<Vec<u8>>, RawSignerError> {
        self.0
            .certs()
            .map_err(|e| RawSignerError::InternalError(e.to_string()))
    }

    async fn ocsp_responses(&self) -> Vec<Vec<u8>> {
        self.0.ocsp_vals().await
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
        context: &Context,
    ) -> Option<std::result::Result<Vec<u8>, TimeStampError>> {
        self.0
            .send_timestamp_request(message, context)
            .await
            .map(|r| r.map_err(|e| e.into()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::{
        io::{Cursor, Read},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use http::{Request, Response};

    use crate::{
        http::{AsyncHttpResolver, HttpResolverError, RequestTimeout, SyncHttpResolver},
        Context,
    };

    #[derive(Clone, Default)]
    struct TimestampResolver(Arc<Mutex<Vec<Duration>>>);

    impl SyncHttpResolver for TimestampResolver {
        fn http_resolve(
            &self,
            request: Request<Vec<u8>>,
        ) -> std::result::Result<Response<Box<dyn Read>>, HttpResolverError> {
            assert_eq!(request.headers()["x-timestamp-hook"], "preserved");
            assert!(!request.body().is_empty());
            self.0
                .lock()
                .unwrap()
                .push(request.extensions().get::<RequestTimeout>().unwrap().0);
            Ok(Response::builder()
                .status(503)
                .body(Box::new(Cursor::new(Vec::<u8>::new())) as Box<dyn Read>)
                .unwrap())
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl AsyncHttpResolver for TimestampResolver {
        async fn http_resolve_async(
            &self,
            request: Request<Vec<u8>>,
        ) -> std::result::Result<Response<Box<dyn Read>>, HttpResolverError> {
            self.http_resolve(request)
        }
    }

    struct ContextSigner(crate::signer::BoxedSigner, Arc<Mutex<usize>>);

    impl Signer for ContextSigner {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
            self.0.sign(data)
        }

        fn alg(&self) -> SigningAlg {
            self.0.alg()
        }

        fn certs(&self) -> Result<Vec<Vec<u8>>> {
            self.0.certs()
        }

        fn reserve_size(&self) -> usize {
            self.0.reserve_size()
        }

        fn time_authority_url(&self) -> Option<String> {
            Some("https://tsa.example/".into())
        }

        fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
            Some(vec![("x-timestamp-hook".into(), "preserved".into())])
        }

        fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
            *self.1.lock().unwrap() += 1;
            crate::crypto::time_stamp::default_rfc3161_message(message).map_err(Into::into)
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl crate::AsyncSigner for ContextSigner {
        async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>> {
            self.0.sign(&data)
        }

        fn alg(&self) -> SigningAlg {
            self.0.alg()
        }

        fn certs(&self) -> Result<Vec<Vec<u8>>> {
            self.0.certs()
        }

        fn reserve_size(&self) -> usize {
            self.0.reserve_size()
        }

        fn time_authority_url(&self) -> Option<String> {
            Signer::time_authority_url(self)
        }

        fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
            Signer::timestamp_request_headers(self)
        }

        fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
            Signer::timestamp_request_body(self, message)
        }
    }

    fn timestamp_context(resolver: TimestampResolver, attempts: u32, timeout: u64) -> Context {
        Context::new()
            .with_settings_value("core.time_stamp_request_attempts", attempts)
            .unwrap()
            .with_settings_value("core.time_stamp_request_timeout_in_ms", timeout)
            .unwrap()
            .with_settings_value("core.time_stamp_retry_delay_in_ms", 0u64)
            .unwrap()
            .with_resolver(resolver.clone())
            .with_resolver_async(resolver)
    }

    #[c2pa_test_async]
    async fn signing_wrapper_uses_instance_timestamp_context() {
        let signer = ContextSigner(test_signer(SigningAlg::Ps256), Arc::new(Mutex::new(0)));
        for (attempts, timeout) in [(2, 37), (4, 83)] {
            let resolver = TimestampResolver::default();
            let context = timestamp_context(resolver.clone(), attempts, timeout);
            #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
            let context = context
                .with_settings_value("core.time_stamp_retry_delay_in_ms", 500u64)
                .unwrap();
            assert!(super::cose_sign(
                &signer,
                b"claim",
                Signer::reserve_size(&signer),
                crate::crypto::cose::TimeStampStorage::V1_sigTst,
                &context
            )
            .is_err());
            assert_eq!(
                *resolver.0.lock().unwrap(),
                vec![
                    Duration::from_millis(timeout);
                    if cfg!(all(target_arch = "wasm32", not(target_os = "wasi"))) {
                        1
                    } else {
                        attempts as usize
                    }
                ]
            );
            resolver.0.lock().unwrap().clear();
            assert!(super::cose_sign_async(
                &signer,
                b"claim",
                Signer::reserve_size(&signer),
                crate::crypto::cose::TimeStampStorage::V2_sigTst2_CTT,
                &context
            )
            .await
            .is_err());
            assert_eq!(
                *resolver.0.lock().unwrap(),
                vec![Duration::from_millis(timeout)]
            );
        }
        assert_eq!(*signer.1.lock().unwrap(), 4);
        let context = Context::new()
            .with_settings_value("core.allowed_network_hosts", vec!["other.example"])
            .unwrap();
        let error = super::cose_sign(
            &signer,
            b"claim",
            Signer::reserve_size(&signer),
            crate::crypto::cose::TimeStampStorage::V1_sigTst,
            &context,
        )
        .unwrap_err();
        assert!(
            format!("{error:?}").contains("not permitted by the allowed list"),
            "{error:?}"
        );
        let error = super::cose_sign_async(
            &signer,
            b"claim",
            Signer::reserve_size(&signer),
            crate::crypto::cose::TimeStampStorage::V2_sigTst2_CTT,
            &context,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:?}").contains("not permitted by the allowed list"),
            "{error:?}"
        );
    }

    struct OverrideSigner;

    impl Signer for OverrideSigner {
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>> {
            unreachable!()
        }

        fn alg(&self) -> SigningAlg {
            SigningAlg::Ps256
        }

        fn certs(&self) -> Result<Vec<Vec<u8>>> {
            unreachable!()
        }

        fn reserve_size(&self) -> usize {
            0
        }

        fn time_authority_url(&self) -> Option<String> {
            Some("https://must-not-be-called.example/".into())
        }

        fn send_timestamp_request(
            &self,
            message: &[u8],
            context: &Context,
        ) -> Option<Result<Vec<u8>>> {
            assert_eq!(context.settings().core.time_stamp_request_timeout_in_ms, 37);
            Some(Ok(message.to_vec()))
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl crate::AsyncSigner for OverrideSigner {
        async fn sign(&self, _: Vec<u8>) -> Result<Vec<u8>> {
            unreachable!()
        }

        fn alg(&self) -> SigningAlg {
            SigningAlg::Ps256
        }

        fn certs(&self) -> Result<Vec<Vec<u8>>> {
            unreachable!()
        }

        fn reserve_size(&self) -> usize {
            0
        }

        fn time_authority_url(&self) -> Option<String> {
            Signer::time_authority_url(self)
        }

        async fn send_timestamp_request(
            &self,
            message: &[u8],
            context: &Context,
        ) -> Option<Result<Vec<u8>>> {
            Signer::send_timestamp_request(self, message, context)
        }
    }

    #[c2pa_test_async]
    async fn timestamp_overrides_keep_dispatch_and_context() {
        use crate::crypto::time_stamp::{AsyncTimeStampProvider, TimeStampProvider};
        let resolver = TimestampResolver::default();
        let context = timestamp_context(resolver.clone(), 2, 37);
        assert_eq!(
            super::SignerWrapper(&OverrideSigner)
                .send_time_stamp_request(b"custom", &context)
                .unwrap()
                .unwrap(),
            b"custom"
        );
        assert_eq!(
            super::AsyncSignerWrapper(&OverrideSigner)
                .send_time_stamp_request(b"custom", &context)
                .await
                .unwrap()
                .unwrap(),
            b"custom"
        );
        assert!(resolver.0.lock().unwrap().is_empty());
    }
    use c2pa_macros::c2pa_test_async;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::sign_claim;
    use crate::{
        claim::Claim,
        settings::Settings,
        utils::test_signer::{async_test_signer, test_signer},
        Result, Signer, SigningAlg,
    };

    #[test]
    fn test_sign_claim() {
        // todo: we have to disable trust checks here for now because these
        // tests use the passthrough mode:
        // let passthrough_cap = CertificateTrustPolicy::default();
        // mode which does not pass through the top level (c2pa-rs) unit tests
        //configuration so the test trust list is not loaded
        let mut settings = Settings::default();
        settings.verify.verify_trust = false;

        let mut claim = Claim::new("extern_sign_test", Some("contentauth"), 1);
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let signer = test_signer(SigningAlg::Ps256);
        let box_size = Signer::reserve_size(signer.as_ref());

        let context = Context::new().with_settings(settings).unwrap();
        let cose_sign1 = sign_claim(&claim_bytes, signer.as_ref(), box_size, &context).unwrap();

        assert_eq!(cose_sign1.len(), box_size);
    }

    #[c2pa_test_async]
    async fn test_sign_claim_async() {
        // todo: we have to disable trust checks here for now because these
        // tests use the passthrough mode:
        // let passthrough_cap = CertificateTrustPolicy::default();
        // mode which does not pass through the top level (c2pa-rs) unit tests
        //configuration so the test trust list is not loaded
        let mut settings = Settings::default();
        settings.verify.verify_trust = false;

        use crate::{cose_sign::sign_claim_async, AsyncSigner, SigningAlg};

        let mut claim = Claim::new("extern_sign_test", Some("contentauth"), 1);
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let signer = async_test_signer(SigningAlg::Ps256);
        let box_size = signer.reserve_size();

        let context = Context::new().with_settings(settings).unwrap();
        let cose_sign1 = sign_claim_async(&claim_bytes, &signer, box_size, &context)
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

        fn alg(&self) -> crate::SigningAlg {
            crate::SigningAlg::Ps256
        }

        fn certs(&self) -> Result<Vec<Vec<u8>>> {
            let cert_vec: Vec<u8> = Vec::new();
            let certs = vec![cert_vec];
            Ok(certs)
        }

        fn reserve_size(&self) -> usize {
            1024
        }

        fn send_timestamp_request(
            &self,
            _message: &[u8],
            _context: &Context,
        ) -> Option<crate::error::Result<Vec<u8>>> {
            Some(Ok(Vec::new()))
        }
    }

    #[test]
    fn test_bogus_signer() {
        let settings = Settings::default();

        let mut claim = Claim::new("bogus_sign_test", Some("contentauth"), 1);
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let box_size = 10000;

        let signer = BogusSigner::new();

        let context = Context::new().with_settings(settings).unwrap();
        let _cose_sign1 = sign_claim(&claim_bytes, &signer, box_size, &context);

        assert!(_cose_sign1.is_err());
    }
}
