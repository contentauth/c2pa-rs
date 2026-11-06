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

//! Provisional timestamp-fact bridge for deferred SDK policy consumers.
//!
//! Enabled only by `sdk-compat`. These decoded values carry no verification,
//! profile-validity, or trust guarantees. This bridge is not a stable public API.

pub use crate::asn1::{AlgorithmIdentifier, GeneralizedTime};

/// Timestamp structures still consumed by SDK profile, trust, OCSP and acquisition adapters.
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
