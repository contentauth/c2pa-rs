// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for thema
// specific language governing permissions and limitations under
// each license.

#![allow(dead_code)] // TEMPORARY: figure this out later

#[cfg(target_arch = "wasm32")]
use crate::{internal::base64, TrustHandlerConfig, TrustPassThrough};
#[cfg(feature = "openssl")]
use crate::{
    openssl::RsaSigner, signer::ConfigurableSigner,
    tests::openssl::temp_signer_async::AsyncSignerAdapter, TrustHandlerConfig, TrustPassThrough,
};
use crate::{RemoteSigner, Result, Signer, SigningAlg};

pub(crate) struct TestGoodSigner {}
impl crate::Signer for TestGoodSigner {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
        Ok(b"not a valid signature".to_vec())
    }

    fn alg(&self) -> SigningAlg {
        SigningAlg::Ps256
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }

    fn reserve_size(&self) -> usize {
        1024
    }

    fn send_timestamp_request(&self, _message: &[u8]) -> Option<crate::error::Result<Vec<u8>>> {
        Some(Ok(Vec::new()))
    }
}

pub(crate) struct AsyncTestGoodSigner {}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl crate::AsyncSigner for AsyncTestGoodSigner {
    async fn sign(&self, _data: Vec<u8>) -> Result<Vec<u8>> {
        Ok(b"not a valid signature".to_vec())
    }

    fn alg(&self) -> SigningAlg {
        SigningAlg::Ps256
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }

    fn reserve_size(&self) -> usize {
        1024
    }

    async fn send_timestamp_request(
        &self,
        _message: &[u8],
    ) -> Option<crate::error::Result<Vec<u8>>> {
        Some(Ok(Vec::new()))
    }
}

/// Create a [`Signer`] instance that can be used for testing purposes using
/// ps256 alg.
///
/// # Returns
///
/// Returns a boxed [`Signer`] instance.
#[cfg(test)]
pub(crate) fn temp_signer() -> Box<dyn Signer> {
    #[cfg(feature = "openssl")]
    {
        #![allow(clippy::expect_used)]
        let sign_cert = include_bytes!("../tests/fixtures/test_certs/ps256.pub").to_vec();
        let pem_key = include_bytes!("../tests/fixtures/test_certs/ps256.pem").to_vec();

        let signer =
            RsaSigner::from_signcert_and_pkey(&sign_cert, &pem_key, SigningAlg::Ps256, None)
                .expect("get_temp_signer");

        Box::new(signer)
    }

    // todo: the will be a RustTLS signer shortly
    #[cfg(not(feature = "openssl"))]
    {
        Box::new(TestGoodSigner {})
    }
}

#[cfg(any(target_arch = "wasm32", feature = "openssl"))]
pub fn temp_async_signer() -> Box<dyn crate::signer::AsyncSigner> {
    #[cfg(feature = "openssl")]
    {
        Box::new(AsyncSignerAdapter::new(SigningAlg::Es256))
    }

    #[cfg(target_arch = "wasm32")]
    {
        let sign_cert = include_str!("../tests/fixtures/test_certs/es256.pub");
        let pem_key = include_str!("../tests/fixtures/test_certs/es256.pem");
        let signer = WebCryptoSigner::new("es256", sign_cert, pem_key);
        Box::new(signer)
    }
}

struct TempRemoteSigner {}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl crate::signer::RemoteSigner for TempRemoteSigner {
    async fn sign_remote(&self, claim_bytes: &[u8]) -> crate::error::Result<Vec<u8>> {
        #[cfg(feature = "openssl")]
        {
            let signer = crate::tests::openssl::temp_signer_async::AsyncSignerAdapter::new(
                SigningAlg::Ps256,
            );

            let tp = TrustPassThrough::new();

            // this would happen on some remote server
            crate::cose_sign::cose_sign_async(&signer, claim_bytes, Some(self.reserve_size()), &tp)
                .await
        }

        #[cfg(all(not(feature = "openssl"), not(target_arch = "wasm32")))]
        {
            use std::io::{Seek, Write};

            let mut sign_bytes = std::io::Cursor::new(vec![0u8; self.reserve_size()]);

            sign_bytes.rewind()?;
            sign_bytes.write_all(claim_bytes)?;

            // fake sig
            Ok(sign_bytes.into_inner())
        }

        #[cfg(target_arch = "wasm32")]
        {
            let signer = crate::wasm::RsaWasmSignerAsync::new();

            let tp = TrustPassThrough::new();

            crate::cose_sign::cose_sign_async(&signer, claim_bytes, Some(self.reserve_size()), &tp)
                .await
        }
    }

    fn reserve_size(&self) -> usize {
        10000
    }
}

#[cfg(target_arch = "wasm32")]
struct WebCryptoSigner {
    signing_alg: SigningAlg,
    signing_alg_name: String,
    certs: Vec<Vec<u8>>,
    key: Vec<u8>,
}

#[cfg(target_arch = "wasm32")]
impl WebCryptoSigner {
    pub fn new(alg: &str, cert: &str, key: &str) -> Self {
        static START_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";
        static END_CERTIFICATE: &str = "-----END CERTIFICATE-----";
        static START_KEY: &str = "-----BEGIN PRIVATE KEY-----";
        static END_KEY: &str = "-----END PRIVATE KEY-----";

        let mut name = alg.to_owned().to_uppercase();
        name.insert(2, '-');

        let key = key
            .replace("\n", "")
            .replace(START_KEY, "")
            .replace(END_KEY, "");
        let key = base64::decode(&key).unwrap();

        let certs = cert
            .replace("\n", "")
            .replace(START_CERTIFICATE, "")
            .split(END_CERTIFICATE)
            .map(|x| base64::decode(x).unwrap())
            .collect();

        Self {
            signing_alg: alg.parse().unwrap(),
            signing_alg_name: name,
            certs,
            key,
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait(?Send)]
impl crate::signer::AsyncSigner for WebCryptoSigner {
    fn alg(&self) -> SigningAlg {
        self.signing_alg
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.certs.clone())
    }

    async fn sign(&self, claim_bytes: Vec<u8>) -> crate::error::Result<Vec<u8>> {
        use js_sys::{Array, Object, Reflect, Uint8Array};
        use wasm_bindgen_futures::JsFuture;
        use web_sys::CryptoKey;

        use crate::wasm::context::WindowOrWorker;
        let context = WindowOrWorker::new().unwrap();
        let crypto = context.subtle_crypto().unwrap();

        let mut data = claim_bytes.clone();
        let promise = crypto
            .digest_with_str_and_u8_array("SHA-256", &mut data)
            .unwrap();
        let result = JsFuture::from(promise).await.unwrap();
        let mut digest = Uint8Array::new(&result).to_vec();

        let key = Uint8Array::new_with_length(self.key.len() as u32);
        key.copy_from(&self.key);
        let usages = Array::new();
        usages.push(&"sign".into());
        let alg = Object::new();
        Reflect::set(&alg, &"name".into(), &"ECDSA".into()).unwrap();
        Reflect::set(&alg, &"namedCurve".into(), &"P-256".into()).unwrap();

        let promise = crypto
            .import_key_with_object("pkcs8", &key, &alg, true, &usages)
            .unwrap();
        let key: CryptoKey = JsFuture::from(promise).await.unwrap().into();

        let alg = Object::new();
        Reflect::set(&alg, &"name".into(), &"ECDSA".into()).unwrap();
        Reflect::set(&alg, &"hash".into(), &"SHA-256".into()).unwrap();
        let promise = crypto
            .sign_with_object_and_u8_array(&alg, &key, &mut digest)
            .unwrap();
        let result = JsFuture::from(promise).await.unwrap();
        Ok(Uint8Array::new(&result).to_vec())
    }

    fn reserve_size(&self) -> usize {
        10000
    }

    async fn send_timestamp_request(&self, _: &[u8]) -> Option<Result<Vec<u8>>> {
        None
    }
}

/// Create a [`RemoteSigner`] instance that can be used for testing purposes.
///
/// # Returns
///
/// Returns a boxed [`RemoteSigner`] instance.
pub fn temp_remote_signer() -> Box<dyn RemoteSigner> {
    Box::new(TempRemoteSigner {})
}

/// Create an AsyncSigner that acts as a RemoteSigner
struct TempAsyncRemoteSigner {
    signer: TempRemoteSigner,
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl crate::signer::AsyncSigner for TempAsyncRemoteSigner {
    // this will not be called but requires an implementation
    async fn sign(&self, claim_bytes: Vec<u8>) -> Result<Vec<u8>> {
        #[cfg(feature = "openssl")]
        {
            let signer = crate::tests::openssl::temp_signer_async::AsyncSignerAdapter::new(
                SigningAlg::Ps256,
            );

            let tp = TrustPassThrough::new();

            // this would happen on some remote server
            crate::cose_sign::cose_sign_async(&signer, &claim_bytes, Some(self.reserve_size()), &tp)
                .await
        }

        #[cfg(target_arch = "wasm32")]
        {
            let signer = crate::wasm::rsa_wasm_signer::RsaWasmSignerAsync::new();
            let tp = TrustPassThrough::new();

            crate::cose_sign::cose_sign_async(&signer, &claim_bytes, Some(self.reserve_size()), &tp)
                .await
        }

        #[cfg(all(not(feature = "openssl"), not(target_arch = "wasm32")))]
        {
            use std::io::{Seek, Write};

            let mut sign_bytes = std::io::Cursor::new(vec![0u8; self.reserve_size()]);

            sign_bytes.rewind()?;
            sign_bytes.write_all(&claim_bytes)?;

            // fake sig
            Ok(sign_bytes.into_inner())
        }
    }

    // signer will return a COSE structure
    fn direct_cose_handling(&self) -> bool {
        true
    }

    fn alg(&self) -> SigningAlg {
        SigningAlg::Ps256
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }

    fn reserve_size(&self) -> usize {
        10000
    }

    async fn send_timestamp_request(
        &self,
        _message: &[u8],
    ) -> Option<crate::error::Result<Vec<u8>>> {
        Some(Ok(Vec::new()))
    }
}

/// Create a [`AsyncSigner`] that does it's own COSE handling for testing.
///
/// # Returns
///
/// Returns a boxed [`RemoteSigner`] instance.
pub fn temp_async_remote_signer() -> Box<dyn crate::signer::AsyncSigner> {
    Box::new(TempAsyncRemoteSigner {
        signer: TempRemoteSigner {},
    })
}
