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

//! Provisional codec bridge for the SDK's existing timestamp verifier.
//!
//! Enabled only by `sdk-compat`. These decoded values carry no verification,
//! profile-validity, or trust guarantees. This bridge is not a stable public API.

pub use crate::{
    asn1::{AlgorithmIdentifier, GeneralizedTime},
    timestamp::response::TimeStampResponse,
};

/// Timestamp structures still consumed by SDK verification and COSE packaging.
pub mod rfc3161 {
    pub use crate::asn1::rfc3161::{
        Accuracy, MessageImprint, PkiStatus, TimeStampReq, TimeStampResp, TimeStampToken, TstInfo,
    };
}

/// CMS structures required by the SDK's legacy codec regression tests.
pub mod rfc5652 {
    pub use crate::asn1::rfc5652::{ContentInfo, SignedData, SignerInfo, OID_ID_SIGNED_DATA};
}
