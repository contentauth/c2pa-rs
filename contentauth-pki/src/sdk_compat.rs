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

//! Provisional bridges for deferred SDK policy and legacy COSE consumers.
//!
//! Enabled only by `sdk-compat`. These decoded values carry no verification,
//! profile-validity, or trust guarantees. This bridge is not a stable public API.

pub use crate::asn1::{AlgorithmIdentifier, GeneralizedTime};

/// Timestamp structures still consumed by SDK timestamp, OCSP, and acquisition adapters.
pub mod rfc3161 {
    pub use crate::asn1::rfc3161::{Accuracy, MessageImprint, TimeStampReq, TstInfo};
}

/// Adapt fully cryptographically verified facts to the SDK's deferred policy API.
///
/// The returned legacy structure does not establish profile validity or trust.
/// This narrow bridge avoids exposing CMS/signers or raw ASN.1 through the
/// supported verification API, while SDK profile/OCSP consumers still use TstInfo.
pub fn verified_timestamp_info(
    timestamp: &crate::timestamp::verification::VerifiedTimestamp<'_>,
) -> rfc3161::TstInfo {
    timestamp.legacy_info()
}

/// Legacy `coset` structures needed to preserve public SDK APIs and orchestration.
///
/// This bridge carries parsed, **unverified** headers, including timestamp and
/// OCSP metadata. Only `verify_signature` establishes payload signature validity;
/// it does not authenticate unprotected headers or establish profile/trust.
pub mod cose {
    use c2pa_raw_crypto::SigningAlg;
    use coset::CoseSign1;

    use crate::cose::{
        CertificateHeaderPolicy, ParsedSign1, SignatureVerifiedPayload, VerificationError,
    };

    /// Parse tagged Sign1 into the SDK's legacy structural representation.
    pub fn parse_tagged(bytes: &[u8]) -> Result<CoseSign1, VerificationError> {
        ParsedSign1::from_tagged_slice(bytes).map(|parsed| parsed.sign1)
    }

    /// Decode the protected algorithm without authenticating it.
    pub fn signing_algorithm(sign1: &CoseSign1) -> Result<SigningAlg, VerificationError> {
        crate::cose::signing_algorithm(sign1)
    }

    /// Borrow unverified certificate bytes under an explicit host-selected policy.
    pub fn certificate_chain(
        sign1: &CoseSign1,
        policy: CertificateHeaderPolicy,
    ) -> Result<Vec<&[u8]>, VerificationError> {
        crate::cose::certificate_chain(sign1, policy)
    }

    /// Check signature encoding before the SDK performs profile/trust reporting.
    pub fn check_signature_encoding(
        sign1: &CoseSign1,
        algorithm: SigningAlg,
    ) -> Result<(), VerificationError> {
        crate::cose::check_signature_encoding(sign1, algorithm)
    }

    /// Verify the SDK's supplied payload, overriding any encoded payload.
    pub fn verify_signature<'a>(
        sign1: &'a CoseSign1,
        payload: &'a [u8],
        external_aad: &[u8],
        policy: CertificateHeaderPolicy,
    ) -> Result<SignatureVerifiedPayload<'a>, VerificationError> {
        crate::cose::verify_signature(sign1, payload, external_aad, policy)
    }
}
