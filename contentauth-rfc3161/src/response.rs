// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use bcder::{decode::Constructed, encode::Values};
use rasn::prelude::*;
use rasn_cms::SignedData;

use crate::{
    asn1::{
        rfc3161::{PkiStatus, TimeStampResp, TstInfo},
        rfc5652::OID_ID_SIGNED_DATA,
    },
    AcquisitionError,
};

/// Decoded response envelope; no cryptographic verification is performed.
pub struct TimeStampResponse(
    /// Parsed status and optional timestamp token.
    pub TimeStampResp,
);

impl std::ops::Deref for TimeStampResponse {
    type Target = TimeStampResp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TimeStampResponse {
    /// Whether the TSA reports granted or granted-with-modifications status.
    pub fn is_success(&self) -> bool {
        matches!(
            self.0.status.status,
            PkiStatus::Granted | PkiStatus::GrantedWithMods
        )
    }

    /// Decode the token's CMS SignedData, if a token is present.
    ///
    /// This neither checks the response status nor verifies the signature.
    pub fn signed_data(&self) -> Result<Option<SignedData>, AcquisitionError> {
        if let Some(token) = &self.0.time_stamp_token {
            if token.content_type != OID_ID_SIGNED_DATA {
                return Err(AcquisitionError::DecodeError(
                    "Invalid OID for signed data".to_string(),
                ));
            }

            let mut bytes = Vec::new();

            token
                .content
                .write_encoded(bcder::Mode::Der, &mut bytes)
                .map_err(|_| AcquisitionError::DecodeError("time stamp invalid".to_string()))?;

            rasn::der::decode(&bytes)
                .map(Some)
                .map_err(|_| AcquisitionError::DecodeError("time stamp invalid".to_string()))
        } else {
            Ok(None)
        }
    }

    /// Decode embedded timestamp information, if present and of the expected type.
    ///
    /// The decoded values remain unverified.
    pub fn tst_info(&self) -> Result<Option<TstInfo>, AcquisitionError> {
        let Some(signed_data) = self.signed_data()? else {
            return Ok(None);
        };

        if signed_data.encap_content_info.content_type
            != Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_SMIME_CT_TSTINFO
        {
            return Ok(None);
        }

        let Some(content) = signed_data.encap_content_info.content else {
            return Ok(None);
        };

        Constructed::decode(content.as_ref(), bcder::Mode::Der, TstInfo::take_from)
            .map(Some)
            .map_err(|err| AcquisitionError::DecodeError(err.to_string()))
    }
}
