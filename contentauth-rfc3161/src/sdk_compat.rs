// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

//! Temporary codec bridge for the C2PA SDK's existing verification and COSE code.
//!
//! Available only with `sdk-compat`. These types are not part of the acquisition
//! API and carry no signature or trust guarantees. The bridge is provisional
//! and should disappear as verification is extracted.

pub use crate::{
    asn1::{AlgorithmIdentifier, GeneralizedTime},
    response::TimeStampResponse,
};

/// Timestamp structures required by the SDK's existing verifier.
pub mod rfc3161 {
    pub use crate::asn1::rfc3161::{
        Accuracy, MessageImprint, PkiStatus, TimeStampReq, TimeStampResp, TimeStampToken, TstInfo,
    };
}

/// CMS codecs required by SDK decoding and legacy codec regression tests.
pub mod rfc5652 {
    pub use crate::asn1::rfc5652::{ContentInfo, SignedData, SignerInfo, OID_ID_SIGNED_DATA};
}
