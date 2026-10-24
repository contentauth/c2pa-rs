// Copyright 2026 Adobe. All rights reserved.
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

//! Signing abstractions used internally by the COSE layer.
//!
//! Unlike [`RawSigner`](crate::RawSigner), which produces only a raw signature,
//! a [`CoseSigner`] bundles the raw signature with the time stamp and OCSP
//! information the COSE `Sign1` builder needs. The raw-signature primitive lives
//! in `c2pa-raw-crypto`; time stamping and OCSP are concerns of this crate, so
//! they are layered on here.

use async_trait::async_trait;
use c2pa_raw_crypto::{RawSigner, RawSignerError, SigningAlg};

use crate::{
    crypto::time_stamp::{AsyncTimeStampProvider, TimeStampProvider},
    maybe_send_sync::{MaybeSend, MaybeSync},
};

/// A `CoseSigner` produces a raw signature and supplies the time stamp and OCSP
/// information needed to assemble a COSE `Sign1` structure.
///
/// If an implementation _can_ be asynchronous, prefer [`AsyncCoseSigner`].
pub(crate) trait CoseSigner: TimeStampProvider {
    /// Return a raw signature over `data`.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError>;

    /// Return the algorithm implemented by this signer.
    fn alg(&self) -> SigningAlg;

    /// Return the signing certificate chain, end-entity first, each in DER form.
    fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError>;

    /// Return a pre-queried OCSP response for the signing certificate, if any.
    fn ocsp_response(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Asynchronous counterpart to [`CoseSigner`].
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub(crate) trait AsyncCoseSigner: AsyncTimeStampProvider + MaybeSync + MaybeSend {
    /// Return a raw signature over `data`.
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>, RawSignerError>;

    /// Return the algorithm implemented by this signer.
    fn alg(&self) -> SigningAlg;

    /// Return the signing certificate chain, end-entity first, each in DER form.
    fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError>;

    /// Return a pre-queried OCSP response for the signing certificate, if any.
    async fn ocsp_response(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Adapts a bare [`RawSigner`] plus its signing certificate chain into a
/// [`CoseSigner`].
///
/// The raw signer carries no certificate chain, time stamp service, or OCSP
/// information, so the chain is supplied here and the resulting COSE signature
/// has no time stamp or OCSP. (Those are configured at higher layers when
/// needed.)
pub(crate) struct RawSignerCoseSigner<'a> {
    signer: &'a dyn RawSigner,
    cert_chain: &'a [Vec<u8>],
}

impl<'a> RawSignerCoseSigner<'a> {
    pub(crate) fn new(signer: &'a dyn RawSigner, cert_chain: &'a [Vec<u8>]) -> Self {
        Self { signer, cert_chain }
    }
}

impl CoseSigner for RawSignerCoseSigner<'_> {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        self.signer.sign(data)
    }

    fn alg(&self) -> SigningAlg {
        self.signer.alg()
    }

    fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError> {
        Ok(self.cert_chain.to_vec())
    }
}

impl TimeStampProvider for RawSignerCoseSigner<'_> {}

#[cfg(test)]
pub(super) mod tests {
    #![allow(clippy::unwrap_used)]

    use c2pa_raw_crypto::signer_from_private_key;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;
    use crate::{
        crypto::{cert_chain_pem_to_der, time_stamp::TimeStampError},
        utils::test_signer::cert_chain_and_private_key_for_alg,
    };

    pub(crate) struct TestSigner {
        pub alg: SigningAlg,
        pub certs: Vec<Vec<u8>>,
        pub signature: Option<Vec<u8>>,
        pub timestamp: Option<Vec<u8>>,
        pub ocsp: Option<Vec<u8>>,
        pub fail_sign: bool,
        pub fail_certs: bool,
    }

    impl TestSigner {
        pub fn new(alg: SigningAlg) -> Self {
            let (certs, _) = cert_chain_and_private_key_for_alg(alg);
            Self {
                alg,
                certs: cert_chain_pem_to_der(certs).unwrap(),
                signature: None,
                timestamp: None,
                ocsp: None,
                fail_sign: false,
                fail_certs: false,
            }
        }
    }

    impl CoseSigner for TestSigner {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
            if self.fail_sign {
                return Err(RawSignerError::InternalError("test signing failure".into()));
            }

            if let Some(signature) = &self.signature {
                return Ok(signature.clone());
            }

            let (_, key) = cert_chain_and_private_key_for_alg(self.alg);
            signer_from_private_key(key, self.alg)?.sign(data)
        }

        fn alg(&self) -> SigningAlg {
            self.alg
        }

        fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError> {
            if self.fail_certs {
                return Err(RawSignerError::InternalError(
                    "test certificate failure".into(),
                ));
            }
            Ok(self.certs.clone())
        }

        fn ocsp_response(&self) -> Option<Vec<u8>> {
            self.ocsp.clone()
        }
    }

    impl TimeStampProvider for TestSigner {
        fn send_time_stamp_request(
            &self,
            _message: &[u8],
        ) -> Option<Result<Vec<u8>, TimeStampError>> {
            self.timestamp.clone().map(Ok)
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl AsyncCoseSigner for TestSigner {
        async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>, RawSignerError> {
            CoseSigner::sign(self, &data)
        }

        fn alg(&self) -> SigningAlg {
            self.alg
        }

        fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError> {
            CoseSigner::cert_chain(self)
        }

        async fn ocsp_response(&self) -> Option<Vec<u8>> {
            self.ocsp.clone()
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl AsyncTimeStampProvider for TestSigner {
        async fn send_time_stamp_request(
            &self,
            _message: &[u8],
        ) -> Option<Result<Vec<u8>, TimeStampError>> {
            self.timestamp.clone().map(Ok)
        }
    }

    #[test]
    fn raw_signer_adapter_preserves_signature_and_chain_without_services() {
        let (pem, key) = cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);
        let raw = signer_from_private_key(key, SigningAlg::Ed25519).unwrap();
        let certs = cert_chain_pem_to_der(pem).unwrap();
        let adapter = RawSignerCoseSigner::new(raw.as_ref(), &certs);
        assert_eq!(adapter.alg(), SigningAlg::Ed25519);
        assert_eq!(adapter.cert_chain().unwrap(), certs);
        assert_eq!(
            adapter.sign(b"payload").unwrap(),
            raw.sign(b"payload").unwrap()
        );
        assert!(adapter.ocsp_response().is_none());
        assert!(adapter.send_time_stamp_request(b"payload").is_none());
    }

    #[c2pa_macros::c2pa_test_async]
    async fn async_signer_defaults_have_no_ocsp_response() {
        struct DefaultOcsp;
        #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
        #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
        impl AsyncTimeStampProvider for DefaultOcsp {}
        #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
        #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
        impl AsyncCoseSigner for DefaultOcsp {
            async fn sign(&self, _data: Vec<u8>) -> Result<Vec<u8>, RawSignerError> {
                Ok(Vec::new())
            }

            fn alg(&self) -> SigningAlg {
                SigningAlg::Ed25519
            }

            fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError> {
                Ok(Vec::new())
            }
        }

        assert!(DefaultOcsp.ocsp_response().await.is_none());
    }
}
