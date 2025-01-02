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

use bcder::decode::Constructed;
use rasn::{AsnType, Decode, Decoder, Encode, Encoder};

#[cfg(not(target_arch = "wasm32"))]
use crate::asn1::rfc3161::PkiStatus;
use crate::{
    asn1::{
        rfc3161::{TimeStampResp, TimeStampToken, TstInfo, OID_CONTENT_TYPE_TST_INFO},
        rfc5652::{SignedData, OID_ID_SIGNED_DATA},
    },
    time_stamp::TimeStampError,
};

#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct TimeStampResponse(pub TimeStampResp);

#[cfg(not(target_arch = "wasm32"))]
impl std::ops::Deref for TimeStampResponse {
    type Target = TimeStampResp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl TimeStampResponse {
    /// Return `true` if the request was successful.
    pub(crate) fn is_success(&self) -> bool {
        matches!(
            self.0.status.status,
            PkiStatus::Granted | PkiStatus::GrantedWithMods
        )
    }

    pub(crate) fn signed_data(&self) -> Result<Option<SignedData>, TimeStampError> {
        if let Some(token) = &self.0.time_stamp_token {
            if token.content_type == OID_ID_SIGNED_DATA {
                Ok(Some(
                    token
                        .content
                        .clone()
                        .decode(SignedData::take_from)
                        .map_err(|e| TimeStampError::DecodeError(e.to_string()))?,
                ))
            } else {
                Err(TimeStampError::DecodeError(
                    "Invalid OID for signed data".to_string(),
                ))
            }
        } else {
            Ok(None)
        }
    }

    pub(crate) fn tst_info(&self) -> Result<Option<TstInfo>, TimeStampError> {
        if let Some(signed_data) = self.signed_data()? {
            if signed_data.content_info.content_type == OID_CONTENT_TYPE_TST_INFO {
                if let Some(content) = signed_data.content_info.content {
                    Ok(Some(
                        Constructed::decode(content.to_bytes(), bcder::Mode::Der, |cons| {
                            TstInfo::take_from(cons)
                        })
                        .map_err(|e| TimeStampError::DecodeError(e.to_string()))?,
                    ))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ContentInfo {
    pub(crate) content_type: rasn::types::ObjectIdentifier,

    #[rasn(tag(explicit(0)))]
    pub(crate) content: rasn::types::Any,
}

/// TO REVIEW: Does this need to be public after refactoring?
pub(crate) fn signed_data_from_time_stamp_response(
    ts_resp: &[u8],
) -> Result<Option<SignedData>, TimeStampError> {
    let time_stamp_token = if let Ok(ts) = Constructed::decode(ts_resp, bcder::Mode::Der, |cons| {
        TimeStampResp::take_from(cons)
    })
    .map_err(|e| TimeStampError::DecodeError(e.to_string()))
    {
        ts.time_stamp_token
    } else if let Ok(ts) = Constructed::decode(ts_resp, bcder::Mode::Der, |cons| {
        TimeStampToken::take_opt_from(cons)
    }) {
        ts
    } else {
        return Err(TimeStampError::DecodeError(
            "no time stamp found".to_string(),
        ));
    };

    let Some(token) = &time_stamp_token else {
        return Ok(None);
    };

    if token.content_type != OID_ID_SIGNED_DATA {
        return Err(TimeStampError::DecodeError(
            "time stamp has invalid OID".to_string(),
        ));
    }

    Ok(Some(
        token
            .content
            .clone()
            .decode(SignedData::take_from)
            .map_err(|_err| TimeStampError::DecodeError("time stamp invalid".to_string()))?,
    ))
}

/// TO REVIEW: Does this need to be public after refactoring?
pub fn tst_info_from_signed_data(
    signed_data: &SignedData,
) -> Result<Option<TstInfo>, TimeStampError> {
    if signed_data.content_info.content_type != OID_CONTENT_TYPE_TST_INFO {
        return Ok(None);
    }

    let Some(content) = &signed_data.content_info.content else {
        return Ok(None);
    };

    Ok(Some(
        Constructed::decode(content.to_bytes(), bcder::Mode::Der, |cons| {
            TstInfo::take_from(cons)
        })
        .map_err(|err| TimeStampError::DecodeError(err.to_string()))?,
    ))
}
