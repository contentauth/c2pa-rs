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

//! SDK trust selection and association; deterministic mechanics live in contentauth-pki.

use contentauth_pki::x509::chain::{self, ChainError};
use web_time::{SystemTime, UNIX_EPOCH};

use crate::crypto::cose::{CertificateTrustError, CertificateTrustPolicy, TrustAnchorType};

pub(crate) fn check_certificate_trust(
    ctp: &CertificateTrustPolicy,
    anchor_type: Option<TrustAnchorType>,
    chain_der: &[Vec<u8>],
    cert_der: &[u8],
    signing_time_epoch: Option<i64>,
) -> Result<(TrustAnchorType, String), CertificateTrustError> {
    let anchors = ctp.anchor_sets_for_certificate(anchor_type, cert_der)?;

    let time = match signing_time_epoch {
        Some(time) => time,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CertificateTrustError::InternalError("system time invalid".into()))?
            .as_secs() as i64,
    };

    let mut ca_outside_validity = false;

    for anchor in anchors {
        match chain::validate_chain_to_anchors(chain_der, cert_der, &anchor.trust_anchor_ders, time)
        {
            Ok(_) => return Ok((anchor.trust_anchor_type, anchor.trust_anchor_uri.clone())),
            Err(ChainError::NoAnchorAssociation) => {}
            Err(ChainError::CaCertificateOutsideValidity) => ca_outside_validity = true,
            Err(error) => return Err(error.into()),
        }
    }

    if ca_outside_validity {
        return Err(CertificateTrustError::CaCertificateOutsideValidity);
    }

    Err(CertificateTrustError::CertificateNotTrusted)
}

impl From<ChainError> for CertificateTrustError {
    fn from(error: ChainError) -> Self {
        match error {
            ChainError::NoAnchorAssociation | ChainError::SignatureMismatch => {
                Self::CertificateNotTrusted
            }
            ChainError::CaCertificateOutsideValidity => Self::CaCertificateOutsideValidity,
            ChainError::InvalidCertificate => Self::InvalidCertificate,
            ChainError::CryptoLibraryError(error) => Self::CryptoLibraryError(error),
            ChainError::InternalError(error) => Self::InternalError(error),
        }
    }
}

#[cfg(all(test, feature = "rust_native_crypto"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use c2pa_raw_crypto::SigningAlg;
    use rasn::types;
    use rasn_pkix::Certificate;

    use super::*;
    use crate::{
        crypto::cert_chain_pem_to_der, utils::test_signer::cert_chain_and_private_key_for_alg,
    };

    fn oid(value: &[u32]) -> types::ObjectIdentifier {
        types::ObjectIdentifier::new(value.to_vec()).unwrap()
    }

    fn certificate() -> Certificate {
        let (pem, _) = cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);

        rasn::der::decode(&cert_chain_pem_to_der(pem).unwrap()[0]).unwrap()
    }

    #[test]
    fn leaf_eku_failures_are_distinct_from_untrusted_chain() {
        let mut policy = CertificateTrustPolicy::new();
        policy
            .add_trust_anchors(
                include_bytes!(
                    "../../../../tests/fixtures/crypto/raw_signature/test_cert_root_bundle.pem"
                ),
                "urn:test:roots",
                TrustAnchorType::Manifest,
                None,
            )
            .unwrap();

        for remove_eku in [false, true] {
            let mut cert = certificate();
            let extensions = cert.tbs_certificate.extensions.as_mut().unwrap();

            if remove_eku {
                extensions.retain(|ext| ext.extn_id != oid(&[2, 5, 29, 37]));
            } else {
                extensions
                    .iter_mut()
                    .find(|ext| ext.extn_id == oid(&[2, 5, 29, 37]))
                    .unwrap()
                    .extn_value = rasn::der::encode(&vec![oid(&[1, 2, 3, 4])]).unwrap().into();
            }

            assert_eq!(
                check_certificate_trust(
                    &policy,
                    None,
                    &[],
                    &rasn::der::encode(&cert).unwrap(),
                    None
                ),
                Err(CertificateTrustError::InvalidEku)
            );
        }

        assert_eq!(
            check_certificate_trust(&policy, None, &[], &[0], None),
            Err(CertificateTrustError::InvalidCertificate)
        );
    }
}
