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

//! The `create_signer` module provides a way to obtain a [`Signer`](crate::Signer)
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
}
