// Copyright 2025 Adobe. All rights reserved.
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

//! This module binds Rust native logic for generating raw signatures to this
//! crate's [`RawSigner`] trait.

use crate::crypto::raw_signature::{RawSigner, RawSignerError, SigningAlg};

mod ecdsa_signer;
mod ed25519_signer;
mod rsa_signer;

/// Return a built-in [`RawSigner`] instance using the provided signing
/// certificate and private key.
///
/// Which signers are available may vary depending on the platform and which
/// crate features were enabled.
///
/// Returns `None` if the signing algorithm is unsupported. May return an `Err`
/// response if the certificate chain or private key are invalid.
pub(crate) fn signer_from_cert_chain_and_private_key(
    cert_chain: &[u8],
    private_key: &[u8],
    alg: SigningAlg,
    time_stamp_service_url: Option<String>,
) -> Result<Box<dyn RawSigner + Send + Sync>, RawSignerError> {
    match alg {
        SigningAlg::Ed25519 => Ok(Box::new(
            ed25519_signer::Ed25519Signer::from_cert_chain_and_private_key(
                cert_chain,
                private_key,
                time_stamp_service_url,
            )?,
        )),

        SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512 => Ok(Box::new(
            rsa_signer::RsaSigner::from_cert_chain_and_private_key(
                cert_chain,
                private_key,
                alg,
                time_stamp_service_url,
            )?,
        )),

        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => Ok(Box::new(
            ecdsa_signer::EcdsaSigner::from_cert_chain_and_private_key(
                cert_chain,
                private_key,
                alg,
                time_stamp_service_url,
            )?,
        )),

        _ => Err(RawSignerError::InternalError(format!(
            "unsupported signing algorithm {alg}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::crypto::raw_signature::{rust_native, SigningAlg};

    /* Not implemented in rust_native yet.
    #[test]
    // #[cfg_attr(all(target_arch = "wasm32", not(target_os = "wasi")), wasm_bindgen_test)]
    fn es256() {
        let cert_chain = include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es256.pub");
        let private_key = include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es256.priv");

        let signer =
            rust_native::signers::signer_from_cert_chain_and_private_key(cert_chain, private_key, SigningAlg::Es256, None)
                .unwrap();

        let data = b"some sample content to sign";
        let signature = signer.sign(data).unwrap();

        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());

        let pub_key = include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es256.pub_key");

        let validator = rust_native::validators::validator_for_signing_alg(SigningAlg::Es256).unwrap();
        validator.validate(&signature, data, pub_key).unwrap();
    }

    #[test]
    // #[cfg_attr(all(target_arch = "wasm32", not(target_os = "wasi")), wasm_bindgen_test)]
    fn es384() {
        let cert_chain = include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es384.pub");
        let private_key = include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es384.priv");

        let signer =
            rust_native::signers::signer_from_cert_chain_and_private_key(cert_chain, private_key, SigningAlg::Es384, None)
                .unwrap();

        let data = b"some sample content to sign";
        let signature = signer.sign(data).unwrap();

        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());

        let pub_key = include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es384.pub_key");

        let validator = rust_native::validators::validator_for_signing_alg(SigningAlg::Es384).unwrap();
        validator.validate(&signature, data, pub_key).unwrap();
    }

    #[test]
    // #[cfg_attr(all(target_arch = "wasm32", not(target_os = "wasi")), wasm_bindgen_test)]
    fn es512() {
        let cert_chain = include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es512.pub");
        let private_key = include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es512.priv");

        let signer =
            rust_native::signers::signer_from_cert_chain_and_private_key(cert_chain, private_key, SigningAlg::Es512, None)
                .unwrap();

        let data = b"some sample content to sign";
        let signature = signer.sign(data).unwrap();

        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());

        let pub_key = include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es512.pub_key");

        let validator = rust_native::validators::validator_for_signing_alg(SigningAlg::Es512).unwrap();
        validator.validate(&signature, data, pub_key).unwrap();
    }
    */

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn ed25519() {
        let cert_chain =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ed25519.pub");
        let private_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ed25519.priv");

        let signer = rust_native::signers::signer_from_cert_chain_and_private_key(
            cert_chain,
            private_key,
            SigningAlg::Ed25519,
            None,
        )
        .unwrap();

        let data = b"some sample content to sign";
        let signature = signer.sign(data).unwrap();

        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());

        let pub_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ed25519.pub_key");

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Ed25519).unwrap();
        validator.validate(&signature, data, pub_key).unwrap();
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn ps256() {
        let cert_chain =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps256.pub");
        let private_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps256.priv");

        let signer = rust_native::signers::signer_from_cert_chain_and_private_key(
            cert_chain,
            private_key,
            SigningAlg::Ps256,
            None,
        )
        .unwrap();

        let data = b"some sample content to sign";
        let signature = signer.sign(data).unwrap();

        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());

        let pub_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps256.pub_key");

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Ps256).unwrap();
        validator.validate(&signature, data, pub_key).unwrap();
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn ps384() {
        let cert_chain =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps384.pub");
        let private_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps384.priv");

        let signer = rust_native::signers::signer_from_cert_chain_and_private_key(
            cert_chain,
            private_key,
            SigningAlg::Ps384,
            None,
        )
        .unwrap();

        let data = b"some sample content to sign";
        let signature = signer.sign(data).unwrap();

        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());

        let pub_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps384.pub_key");

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Ps384).unwrap();
        validator.validate(&signature, data, pub_key).unwrap();
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn ps512() {
        let cert_chain =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps512.pub");
        let private_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps512.priv");

        let signer = rust_native::signers::signer_from_cert_chain_and_private_key(
            cert_chain,
            private_key,
            SigningAlg::Ps512,
            None,
        )
        .unwrap();

        let data = b"some sample content to sign";
        let signature = signer.sign(data).unwrap();

        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());

        let pub_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps512.pub_key");

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Ps512).unwrap();
        validator.validate(&signature, data, pub_key).unwrap();
    }
}

#[cfg(test)]
mod async_signer_tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]
    #![allow(unused)] // test fns appear unused on WASM

    use c2pa_macros::c2pa_test_async;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::crypto::raw_signature::{
        async_signer_from_cert_chain_and_private_key, validator_for_signing_alg, SigningAlg,
    };

    #[c2pa_test_async]
    async fn es256() {
        let cert_chain =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es256.pub");
        let private_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es256.priv");

        let signer = async_signer_from_cert_chain_and_private_key(
            cert_chain,
            private_key,
            SigningAlg::Es256,
            None,
        )
        .unwrap();

        let data = b"some sample content to sign";
        let signature = signer.sign(data.to_vec()).await.unwrap();

        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());

        let pub_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es256.pub_key");

        let validator = validator_for_signing_alg(SigningAlg::Es256).unwrap();
        validator.validate(&signature, data, pub_key).unwrap();
    }

    #[c2pa_test_async]
    async fn es384() {
        let cert_chain =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es384.pub");
        let private_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es384.priv");

        let signer = async_signer_from_cert_chain_and_private_key(
            cert_chain,
            private_key,
            SigningAlg::Es384,
            None,
        )
        .unwrap();

        let data = b"some sample content to sign";
        let signature = signer.sign(data.to_vec()).await.unwrap();

        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());

        let pub_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es384.pub_key");

        let validator = validator_for_signing_alg(SigningAlg::Es384).unwrap();
        validator.validate(&signature, data, pub_key).unwrap();
    }

    #[c2pa_test_async]
    async fn es512() {
        let cert_chain =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es512.pub");
        let private_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es512.priv");

        let signer = async_signer_from_cert_chain_and_private_key(
            cert_chain,
            private_key,
            SigningAlg::Es512,
            None,
        )
        .unwrap();

        let data = b"some sample content to sign";
        let signature = signer.sign(data.to_vec()).await.unwrap();

        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());

        let pub_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/es512.pub_key");

        let validator = validator_for_signing_alg(SigningAlg::Es512).unwrap();
        validator.validate(&signature, data, pub_key).unwrap();
    }

    #[c2pa_test_async]
    async fn ed25519() {
        let cert_chain =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ed25519.pub");
        let private_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ed25519.priv");

        let signer = async_signer_from_cert_chain_and_private_key(
            cert_chain,
            private_key,
            SigningAlg::Ed25519,
            None,
        )
        .unwrap();

        let data = b"some sample content to sign";
        let signature = signer.sign(data.to_vec()).await.unwrap();

        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());

        let pub_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ed25519.pub_key");

        let validator = validator_for_signing_alg(SigningAlg::Ed25519).unwrap();
        validator.validate(&signature, data, pub_key).unwrap();
    }

    #[c2pa_test_async]
    async fn ps256() {
        let cert_chain =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps256.pub");
        let private_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps256.priv");

        let signer = async_signer_from_cert_chain_and_private_key(
            cert_chain,
            private_key,
            SigningAlg::Ps256,
            None,
        )
        .unwrap();

        let data = b"some sample content to sign";
        let signature = signer.sign(data.to_vec()).await.unwrap();

        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());

        let pub_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps256.pub_key");

        let validator = validator_for_signing_alg(SigningAlg::Ps256).unwrap();
        validator.validate(&signature, data, pub_key).unwrap();
    }

    #[c2pa_test_async]
    async fn ps384() {
        let cert_chain =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps384.pub");
        let private_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps384.priv");

        let signer = async_signer_from_cert_chain_and_private_key(
            cert_chain,
            private_key,
            SigningAlg::Ps384,
            None,
        )
        .unwrap();

        let data = b"some sample content to sign";
        let signature = signer.sign(data.to_vec()).await.unwrap();

        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());

        let pub_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps384.pub_key");

        let validator = validator_for_signing_alg(SigningAlg::Ps384).unwrap();
        validator.validate(&signature, data, pub_key).unwrap();
    }

    #[c2pa_test_async]
    async fn ps512() {
        let cert_chain =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps512.pub");
        let private_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps512.priv");

        let signer = async_signer_from_cert_chain_and_private_key(
            cert_chain,
            private_key,
            SigningAlg::Ps512,
            None,
        )
        .unwrap();

        let data = b"some sample content to sign";
        let signature = signer.sign(data.to_vec()).await.unwrap();

        println!("signature len = {}", signature.len());
        assert!(signature.len() <= signer.reserve_size());

        let pub_key =
            include_bytes!("../../../../../tests/fixtures/crypto/raw_signature/ps512.pub_key");

        let validator = validator_for_signing_alg(SigningAlg::Ps512).unwrap();
        validator.validate(&signature, data, pub_key).unwrap();
    }
}
