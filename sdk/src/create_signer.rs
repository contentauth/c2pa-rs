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

#![deny(missing_docs)]

//! The `create_signer` module provides a way to obtain a [`Signer`]
//! instance for each signing format supported by this crate.
#[cfg(feature = "file_io")]
use std::path::Path;

use c2pa_raw_crypto::{signer_from_private_key, SigningAlg};

use crate::{crypto::cert_chain_pem_to_der, error::Result, signer::RawSignerWrapper, BoxedSigner};

/// Creates a [`Signer`](crate::Signer) instance using signing certificate and private key
/// as byte slices.
///
/// The signing certificate and private key are passed to the underlying
/// C++ code, which copies them into its own storage.
///
/// # Arguments
///
/// * `signcert` - Signing certificate
/// * `pkey` - Private key
/// * `alg` - Format for signing
/// * `tsa_url` - Optional URL for a timestamp authority
pub fn from_keys(
    signcert: &[u8],
    pkey: &[u8],
    alg: SigningAlg,
    tsa_url: Option<String>,
) -> Result<BoxedSigner> {
    Ok(Box::new(RawSignerWrapper::new(
        signer_from_private_key(pkey, alg)?,
        cert_chain_pem_to_der(signcert)?,
        tsa_url,
    )))
}

/// Creates a [`Signer`](crate::Signer) instance using signing certificate and
/// private key files.
///
/// # Arguments
///
/// * `signcert_path` - Path to the signing certificate file
/// * `pkey_path` - Path to the private key file
/// * `alg` - Format for signing
/// * `tsa_url` - Optional URL for a timestamp authority
#[cfg(feature = "file_io")]
pub fn from_files<P: AsRef<Path>>(
    signcert_path: P,
    pkey_path: P,
    alg: SigningAlg,
    tsa_url: Option<String>,
) -> Result<BoxedSigner> {
    let cert_chain = std::fs::read(signcert_path)?;
    let private_key = std::fs::read(pkey_path)?;

    from_keys(&cert_chain, &private_key, alg, tsa_url)
}

/// Creates a combined [`Signer`](crate::Signer) that signs the C2PA claim with
/// `c2pa_signer` and embeds an X.509 identity assertion signed by `identity_signer`.
///
/// # Arguments
///
/// * `c2pa_signer` - Signs the C2PA claim
/// * `identity_signer` - Signs the X.509 identity assertion (`cawg.x509.cose`)
/// * `referenced_assertions` - Assertion labels to include in the identity assertion
/// * `roles` - Named actor roles to attach to the identity assertion
pub fn from_x509_identity(
    c2pa_signer: BoxedSigner,
    identity_signer: BoxedSigner,
    referenced_assertions: &[&str],
    roles: &[&str],
) -> BoxedSigner {
    Box::new(
        crate::settings::signer::CawgX509IdentitySigner::from_signer(
            c2pa_signer,
            identity_signer,
            referenced_assertions,
            roles,
        ),
    )
}

/// Creates a combined [`Signer`](crate::Signer) that signs the C2PA claim with
/// `c2pa_signer` and embeds one CAWG identity assertion whose `signature` is
/// produced by `credential_holder`.
///
/// Use this for credential types other than X.509, such as an identity claims
/// aggregation credential (`cawg.identity_claims_aggregation`) obtained from an
/// aggregator at signing time. The holder's [`sign`] receives the finished
/// `signer_payload` (referenced assertions with their final hashes), which is
/// only known during signing.
///
/// Dynamic assertions already contributed by `c2pa_signer` are kept, so an
/// X.509 identity signer from [`from_x509_identity`] can be wrapped to emit
/// both identity assertions.
///
/// # Arguments
///
/// * `c2pa_signer` - Signs the C2PA claim
/// * `credential_holder` - Produces the identity assertion's `signature`
/// * `referenced_assertions` - Assertion labels to include in the identity assertion
/// * `roles` - Named actor roles to attach to the identity assertion
///
/// [`sign`]: crate::identity::builder::CredentialHolder::sign
pub fn from_credential_holder(
    c2pa_signer: BoxedSigner,
    credential_holder: Box<dyn crate::identity::builder::CredentialHolder + Send + Sync>,
    referenced_assertions: &[&str],
    roles: &[&str],
) -> BoxedSigner {
    Box::new(crate::settings::signer::CawgIdentitySigner::new(
        c2pa_signer,
        credential_holder,
        referenced_assertions,
        roles,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::{Cursor, Seek};

    use c2pa_macros::c2pa_test_async;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::{
        identity::tests::fixtures::{manifest_json, parent_json},
        utils::test_signer::test_signer,
        Builder, Reader, SigningAlg,
    };

    const TEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
    const TEST_THUMBNAIL: &[u8] = include_bytes!("../tests/fixtures/thumbnail.jpg");

    /// Verify that `from_x509_identity` produces a valid manifest containing
    /// one X.509 identity assertion signed by the identity signer and
    /// one valid C2PA claim signed by the C2PA signer.
    #[c2pa_test_async]
    async fn from_x509_identity_signs_and_validates() {
        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::default().with_definition(manifest_json()).unwrap();
        builder
            .add_ingredient_from_stream(parent_json(), format, &mut source)
            .unwrap();
        builder
            .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
            .unwrap();

        let c2pa_signer = test_signer(SigningAlg::Ps256);
        let identity_signer = test_signer(SigningAlg::Ed25519);

        let signer =
            super::from_x509_identity(c2pa_signer, identity_signer, &["c2pa.actions"], &[]);

        builder
            .sign(signer.as_ref(), format, &mut source, &mut dest)
            .unwrap();

        dest.rewind().unwrap();

        let manifest_store = Reader::default().with_stream(format, &mut dest).unwrap();
        assert_eq!(
            manifest_store.validation_state(),
            crate::ValidationState::Trusted
        );

        let manifest = manifest_store.active_manifest().unwrap();
        assert!(manifest
            .assertions()
            .iter()
            .any(|a| a.label().contains("cawg.identity")));
    }

    /// A credential holder that records the `signer_payload` it was asked to
    /// sign and returns its CBOR serialization as the "signature".
    struct RecordingCredentialHolder {
        sig_type: &'static str,
        seen: std::sync::Mutex<Vec<crate::identity::SignerPayload>>,
    }

    impl crate::identity::builder::CredentialHolder for RecordingCredentialHolder {
        fn sig_type(&self) -> &'static str {
            self.sig_type
        }

        fn reserve_size(&self) -> usize {
            1000
        }

        fn sign(
            &self,
            signer_payload: &crate::identity::SignerPayload,
        ) -> std::result::Result<Vec<u8>, crate::identity::builder::IdentityBuilderError> {
            self.seen.lock().unwrap().push(signer_payload.clone());
            let mut cbor: Vec<u8> = vec![];
            c2pa_cbor::to_writer(&mut cbor, signer_payload)?;
            Ok(cbor)
        }
    }

    /// Verify that `from_credential_holder` hands the holder a `signer_payload`
    /// carrying its `sig_type` and the hard binding, embeds what the holder
    /// returns, and keeps the X.509 identity assertion of a wrapped signer, so
    /// the manifest ends up with both identity assertions.
    #[c2pa_test_async]
    async fn from_credential_holder_adds_second_identity_assertion() {
        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let settings = crate::settings::Settings::default()
            .with_value("core.decode_identity_assertions", false)
            .unwrap();
        let context = crate::Context::new()
            .with_settings(settings)
            .unwrap()
            .into_shared();

        let mut builder = Builder::from_shared_context(&context)
            .with_definition(manifest_json())
            .unwrap();
        builder
            .add_ingredient_from_stream(parent_json(), format, &mut source)
            .unwrap();
        builder
            .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
            .unwrap();

        let c2pa_signer = test_signer(SigningAlg::Ps256);
        let identity_signer = test_signer(SigningAlg::Ed25519);
        let x509 = super::from_x509_identity(c2pa_signer, identity_signer, &["c2pa.actions"], &[]);

        let holder = std::sync::Arc::new(RecordingCredentialHolder {
            sig_type: "INVALID.identity.recording_credential",
            seen: std::sync::Mutex::new(vec![]),
        });
        struct Shared(std::sync::Arc<RecordingCredentialHolder>);
        impl crate::identity::builder::CredentialHolder for Shared {
            fn sig_type(&self) -> &'static str {
                self.0.sig_type()
            }
            fn reserve_size(&self) -> usize {
                self.0.reserve_size()
            }
            fn sign(
                &self,
                signer_payload: &crate::identity::SignerPayload,
            ) -> std::result::Result<Vec<u8>, crate::identity::builder::IdentityBuilderError>
            {
                self.0.sign(signer_payload)
            }
        }

        let signer = super::from_credential_holder(
            x509,
            Box::new(Shared(holder.clone())),
            &["c2pa.actions.v2"],
            &["cawg.creator"],
        );

        builder
            .sign(signer.as_ref(), format, &mut source, &mut dest)
            .unwrap();

        // The holder was asked to sign exactly once per pass, and saw the
        // hard binding plus the referenced c2pa.actions assertion and its role.
        let seen = holder.seen.lock().unwrap();
        assert!(!seen.is_empty());
        let payload = seen.last().unwrap();
        assert_eq!(payload.sig_type, "INVALID.identity.recording_credential");
        assert_eq!(payload.roles, vec!["cawg.creator".to_string()]);
        assert!(payload
            .referenced_assertions
            .iter()
            .any(|a| a.url().contains("c2pa.assertions/c2pa.hash.")));
        assert!(payload
            .referenced_assertions
            .iter()
            .any(|a| a.url().ends_with("c2pa.assertions/c2pa.actions.v2")));
        drop(seen);

        dest.rewind().unwrap();
        let reader = Reader::from_shared_context(&context)
            .with_stream(format, &mut dest)
            .unwrap();
        let manifest = reader.active_manifest().unwrap();
        let identity_labels: Vec<String> = manifest
            .assertions()
            .iter()
            .filter(|a| a.label().starts_with("cawg.identity"))
            .map(|a| a.label().to_string())
            .collect();
        assert_eq!(
            identity_labels.len(),
            2,
            "expected the X.509 and the credential-holder identity assertions, got {identity_labels:?}"
        );
    }
}
