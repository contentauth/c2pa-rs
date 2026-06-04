// Copyright 2024 Adobe. All rights reserved.
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

#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

mod claim_aggregation;
mod examples;
pub(crate) mod fixtures;
mod validation_method;

/// The `did:jwk` issuer that the bundled CAWG ICA `ica_validation` fixtures are
/// signed with.
pub(crate) const ICA_FIXTURE_JWK_ISSUER: &str = "did:jwk:eyJhbGciOiJFZERTQSIsImt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiTXA1LTBlODNuTmdRaGRoQlc4UnNoa2p5OTBzYTFBOUpJemtJdGNEcUN1SSJ9";

/// The `did:web` issuer that the Adobe connected-identities fixtures are signed
/// with.
pub(crate) const ICA_FIXTURE_WEB_ISSUER: &str =
    "did:web:connected-identities.identity-stage.adobe.com";

/// An [`IcaSignatureVerifier`](crate::identity::claim_aggregation::IcaSignatureVerifier)
/// that trusts the issuers used by the bundled CAWG ICA test fixtures.
///
/// Tests that exercise a directly-constructed verifier use this so that an
/// otherwise-valid fixture is treated as having a trusted issuer (and therefore
/// produces `cawg.ica.credential_valid`). To exercise the untrusted-issuer path,
/// construct a verifier with a different (or empty) `trusted_issuers` list.
pub(crate) fn ica_test_verifier() -> crate::identity::claim_aggregation::IcaSignatureVerifier {
    crate::identity::claim_aggregation::IcaSignatureVerifier {
        trusted_issuers: vec![
            ICA_FIXTURE_JWK_ISSUER.to_string(),
            ICA_FIXTURE_WEB_ISSUER.to_string(),
        ],
    }
}

/// Read a manifest store with identity assertion decoding disabled so the raw
/// assertion bytes are preserved for manual validation in tests.
pub(crate) async fn read_manifest<R: std::io::Read + std::io::Seek + Send>(
    format: &str,
    source: &mut R,
) -> crate::Reader {
    let settings = crate::settings::Settings::default()
        .with_value("core.decode_identity_assertions", false)
        .unwrap();
    let context = crate::Context::new()
        .with_settings(settings)
        .unwrap()
        .into_shared();
    crate::Reader::from_shared_context(&context)
        .with_stream_async(format, source)
        .await
        .unwrap()
}
