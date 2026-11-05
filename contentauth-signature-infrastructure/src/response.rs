// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use bcder::{decode::Constructed, encode::Values, Integer};
use rasn::prelude::*;
use rasn_cms::SignedData;

use crate::{
    asn1::{
        rfc3161::{PkiStatus, TimeStampResp, TstInfo},
        rfc5652::OID_ID_SIGNED_DATA,
    },
    AcquisitionError,
};

pub(crate) fn check_nonce(bytes: &[u8], nonce: Option<Integer>) -> Result<(), AcquisitionError> {
    let response = TimeStampResponse(
        Constructed::decode(bytes, bcder::Mode::Der, TimeStampResp::take_from)
            .map_err(|err| AcquisitionError::DecodeError(err.to_string()))?,
    );

    // Preserve the SDK's acquisition behavior: non-granted responses and absent
    // tokens are returned unverified for the verifier to reject.
    if response.is_success() {
        if let Some(info) = response.tst_info()? {
            if info.nonce != nonce {
                return Err(AcquisitionError::NonceMismatch);
            }
        }
    }

    Ok(())
}

/// Parsed response envelope, without cryptographic or policy validation.
pub struct TimeStampResponse(
    /// Parsed status and optional token.
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
            self.status.status,
            PkiStatus::Granted | PkiStatus::GrantedWithMods
        )
    }

    /// Decode CMS signed data if present, without verifying it.
    pub fn signed_data(&self) -> Result<Option<SignedData>, AcquisitionError> {
        let Some(token) = &self.time_stamp_token else {
            return Ok(None);
        };

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
    }

    /// Decode timestamp information, if present and of the expected type.
    ///
    /// This does not verify its message imprint, signature or trustworthiness.
    pub fn tst_info(&self) -> Result<Option<TstInfo>, AcquisitionError> {
        if let Some(signed_data) = self.signed_data()? {
            if signed_data.encap_content_info.content_type
                == Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_SMIME_CT_TSTINFO
            {
                if let Some(content) = signed_data.encap_content_info.content {
                    return Constructed::decode(
                        content.as_ref(),
                        bcder::Mode::Der,
                        TstInfo::take_from,
                    )
                    .map(Some)
                    .map_err(|err| AcquisitionError::DecodeError(err.to_string()));
                }
            }
        }

        Ok(None)
    }
}
