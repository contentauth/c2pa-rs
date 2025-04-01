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

use std::io::{Cursor, Seek};

use async_trait::async_trait;
use c2pa::{Builder, HashedUri, Reader, SigningAlg};
use c2pa_crypto::{
    cose::{sign_async, sign_v2_embedded_async, CosePayload, TimeStampStorage},
    raw_signature::{self, AsyncRawSigner},
};
use c2pa_status_tracker::StatusTracker;
use chrono::{DateTime, FixedOffset, Utc};
use coset::{iana::OkpKeyParameter, RegisteredLabel};
use iref::UriBuf;
use nonempty_collections::{nev, NEVec};
use x509_parser::pem::Pem;

use super::ica_credential_example::ica_example_identities;
use crate::{
    builder::{
        AsyncCredentialHolder, AsyncIdentityAssertionBuilder, AsyncIdentityAssertionSigner,
        IdentityBuilderError,
    },
    claim_aggregation::{
        w3c_vc::jwk::{Algorithm, Base64urlUInt, Jwk, OctetParams, Params},
        IcaCredential, IcaSignatureVerifier, IdentityClaimsAggregationVc, VerifiedIdentity,
    },
    tests::fixtures::{cert_chain_and_private_key_for_alg, manifest_json, parent_json},
    IdentityAssertion, SignerPayload,
};

/// An implementation of [`AsyncCredentialHolder`] that generates an identity
/// claims aggregation credential.
///
/// This is not intended for production use; it has only been used so far to
/// generate error test cases.
pub struct IcaExampleCredentialHolder {
    /// Verified identities to be used for this named actor.
    pub verified_identities: NEVec<VerifiedIdentity>,

    /// Signer for the COSE envelope (i.e. the credential of the example
    /// identity claims aggregator).
    pub ica_signer: Box<dyn AsyncRawSigner + Send + Sync + 'static>,

    /// DID for the simulated identity claims aggregator.
    pub issuer_did: String,
}

impl IcaExampleCredentialHolder {
    /// Create an `IcaExampleCredentialHolder` instance by wrapping an instance
    /// of [`AsyncRawSigner`].
    ///
    /// The [`AsyncRawSigner`] implementation actually holds (or has access to)
    /// the relevant certificates and private key material.
    ///
    /// This will generate a sample set of verified identities to match the
    /// example used in the CAWG specification.
    ///
    /// [`AsyncRawSigner`]: c2pa_crypto::raw_signature::AsyncRawSigner
    pub fn from_async_raw_signer(
        ica_signer: Box<dyn AsyncRawSigner + Send + Sync + 'static>,
        issuer_did: String,
    ) -> Self {
        Self {
            verified_identities: ica_example_identities(),
            ica_signer,
            issuer_did,
        }
    }
}

#[async_trait]
impl AsyncCredentialHolder for IcaExampleCredentialHolder {
    fn sig_type(&self) -> &'static str {
        crate::claim_aggregation::CAWG_ICA_SIG_TYPE
    }

    fn reserve_size(&self) -> usize {
        // TO DO: Refine the guessing mechanism. Should also account for the size of
        // verified_identities.
        self.ica_signer.reserve_size() + 1500
    }

    async fn sign(&self, signer_payload: &SignerPayload) -> Result<Vec<u8>, IdentityBuilderError> {
        // IMPORTANT: Since this is test-quality code, I am using .unwrap() liberally
        // here. These would need to be replaced with proper error handling in order to
        // make this into production-level code.

        // Pre-process signer_payload to base64 encode the hash references.

        let mut signer_payload = signer_payload.clone();

        let encoded_assertions = signer_payload
            .referenced_assertions
            .iter()
            .map(|a| {
                let encoded_hash = c2pa_crypto::base64::encode(&a.hash());
                HashedUri::new(a.url(), a.alg(), encoded_hash.as_bytes())
            })
            .collect();

        signer_payload.referenced_assertions = encoded_assertions;

        // Generate VC to embed.
        let ica_subject = IdentityClaimsAggregationVc {
            c2pa_asset: signer_payload.clone(),
            verified_identities: self.verified_identities.clone(),
        };

        let issuer_did = UriBuf::new(self.issuer_did.as_bytes().to_vec()).unwrap();
        let mut ica_vc = IcaCredential::new(None, issuer_did, nev![ica_subject]);

        // TO DO: Bring in substitute for now() on Wasm.
        #[cfg(not(target_arch = "wasm32"))]
        {
            ica_vc.valid_from = Some(Utc::now().fixed_offset());
        }

        let ica_json = serde_json::to_string(&ica_vc).unwrap();

        // TO DO: Check signing cert validity. (See signing_cert_valid in c2pa-rs's
        // cose_sign.)

        Ok(sign_v2_embedded_async(
            self.ica_signer.as_ref(),
            ica_json.as_bytes(),
            None,
            CosePayload::Embedded,
            Some(RegisteredLabel::Text("application/vc".to_string())),
            TimeStampStorage::V2_sigTst2_CTT,
        )
        .await
        .map_err(|e| IdentityBuilderError::SignerError(e.to_string()))?)
    }
}

const TEST_IMAGE: &[u8] = include_bytes!("../../../../../sdk/tests/fixtures/CA.jpg");
const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../../../sdk/tests/fixtures/thumbnail.jpg");

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn ica_signing() {
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_json(&manifest_json()).unwrap();
    builder
        .add_ingredient_from_stream(parent_json(), format, &mut source)
        .unwrap();

    builder
        .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
        .unwrap();

    let mut c2pa_signer = AsyncIdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

    let (cawg_cert_chain, cawg_private_key) =
        cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);

    let cawg_raw_signer = raw_signature::async_signer_from_cert_chain_and_private_key(
        &cawg_cert_chain,
        &cawg_private_key,
        SigningAlg::Ed25519,
        None,
    )
    .unwrap();

    // HACK: Parse end-entity cert and find public key so we can build a did:jwk for
    // it.
    let first_pem = Pem::iter_from_buffer(&cawg_cert_chain)
        .next()
        .unwrap()
        .unwrap();
    let cert = first_pem.parse_x509().unwrap();
    let spki = &cert.tbs_certificate.subject_pki;
    let public_key = spki.subject_public_key.as_ref();

    let jwk = Jwk {
        public_key_use: None,
        key_operations: None,
        algorithm: Some(Algorithm::EdDsa),
        key_id: None, // Maybe we need this?
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
        params: Params::Okp(OctetParams {
            curve: "Ed25519".to_owned(),
            public_key: Base64urlUInt(public_key.to_vec()),
            private_key: None,
        }),
    };

    let jwk_id = serde_json::to_string(&jwk).unwrap();
    let jwk_base64 = c2pa_crypto::base64::encode(jwk_id.as_bytes());
    let issuer_did = format!("did:example:{jwk_base64}");

    let ica_holder = IcaExampleCredentialHolder::from_async_raw_signer(cawg_raw_signer, issuer_did);
    let iab = AsyncIdentityAssertionBuilder::for_credential_holder(ica_holder);
    c2pa_signer.add_identity_assertion(iab);

    builder
        .sign_async(&c2pa_signer, format, &mut source, &mut dest)
        .await
        .unwrap();

    // Write the sample file.
    std::fs::create_dir_all("src/tests/fixtures/claim_aggregation/ica_validation").unwrap();

    std::fs::write(
        "src/tests/fixtures/claim_aggregation/ica_validation/unsupported_did_method.jpg",
        dest.get_ref(),
    )
    .unwrap();

    // --- THE REST OF THIS EXAMPLE IS TEST CODE ONLY. ---
    //
    // The following code reads back the content from the file that was just
    // generated and verifies that it is valid.
    //
    // In a normal scenario when generating an asset with a CAWG identity assertion,
    // you could stop at this point.

    dest.rewind().unwrap();

    let manifest_store = Reader::from_stream(format, &mut dest).unwrap();
    assert_eq!(manifest_store.validation_status(), None);

    let manifest = manifest_store.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    let ica_verifier = IcaSignatureVerifier {};
    let ica_vc = ia.validate(manifest, &mut st, &ica_verifier).await.unwrap();

    dbg!(ica_vc);
    panic!("Now what?");
}
