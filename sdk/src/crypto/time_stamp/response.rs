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

use ::rasn::prelude::*;
use bcder::{decode::Constructed, encode::Values};
use rasn_cms::SignedData;

use crate::crypto::{
    asn1::{
        rfc3161::{PkiStatus, TimeStampResp, TimeStampToken, TstInfo},
        rfc5652::OID_ID_SIGNED_DATA,
    },
    time_stamp::TimeStampError,
};

pub(crate) struct TimeStampResponse(pub TimeStampResp);

impl std::ops::Deref for TimeStampResponse {
    type Target = TimeStampResp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TimeStampResponse {
    /// Return `true` if the request was successful.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn is_success(&self) -> bool {
        use crate::crypto::asn1::rfc3161::PkiStatus;

        matches!(
            self.0.status.status,
            PkiStatus::Granted | PkiStatus::GrantedWithMods
        )
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn signed_data(&self) -> Result<Option<SignedData>, TimeStampError> {
        if let Some(token) = &self.0.time_stamp_token {
            if token.content_type == OID_ID_SIGNED_DATA {
                let mut sd_bytes = Vec::new();
                token
                    .content
                    .write_encoded(bcder::Mode::Der, &mut sd_bytes)
                    .map_err(|_err| {
                        TimeStampError::DecodeError("time stamp invalid".to_string())
                    })?;

                // decode ContentInfo as SignedData
                match rasn::der::decode(&sd_bytes) {
                    Ok(signed_data) => Ok(Some(signed_data)),
                    Err(_) => Err(TimeStampError::DecodeError(
                        "time stamp invalid".to_string(),
                    )),
                }
            } else {
                Err(TimeStampError::DecodeError(
                    "Invalid OID for signed data".to_string(),
                ))
            }
        } else {
            Ok(None)
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn tst_info(&self) -> Result<Option<TstInfo>, TimeStampError> {
        if let Some(signed_data) = self.signed_data()? {
            if signed_data.encap_content_info.content_type
                == Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_SMIME_CT_TSTINFO
            {
                if let Some(content) = signed_data.encap_content_info.content {
                    Ok(Some(
                        Constructed::decode(content.as_ref(), bcder::Mode::Der, |cons| {
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

pub(crate) fn signed_data_from_time_stamp_response(
    ts_resp: &[u8],
) -> Result<Option<SignedData>, TimeStampError> {
    let time_stamp_token = if let Ok(ts) = Constructed::decode(ts_resp, bcder::Mode::Der, |cons| {
        TimeStampResp::take_from(cons)
    })
    .map_err(|e| TimeStampError::DecodeError(e.to_string()))
    {
        if ts.status.status == PkiStatus::Granted || ts.status.status == PkiStatus::GrantedWithMods
        {
            ts.time_stamp_token
        } else {
            return Err(TimeStampError::DecodeError(
                "time stamp status not granted".to_string(),
            ));
        }
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

    let mut sd_bytes = Vec::new();
    token
        .content
        .write_encoded(bcder::Mode::Der, &mut sd_bytes)
        .map_err(|_err| TimeStampError::DecodeError("time stamp invalid".to_string()))?;

    // decode ContentInfo DER as SignedData
    match rasn::der::decode(&sd_bytes) {
        Ok(signed_data) => Ok(Some(signed_data)),
        Err(_) => Err(TimeStampError::DecodeError(
            "time stamp invalid".to_string(),
        )),
    }
}

pub(crate) fn tst_info_from_signed_data(
    signed_data: &SignedData,
) -> Result<Option<TstInfo>, TimeStampError> {
    if signed_data.encap_content_info.content_type
        != Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_SMIME_CT_TSTINFO
    {
        return Ok(None);
    }

    let Some(content) = &signed_data.encap_content_info.content else {
        return Ok(None);
    };

    Ok(Some(
        Constructed::decode(content.as_ref(), bcder::Mode::Der, |cons| {
            TstInfo::take_from(cons)
        })
        .map_err(|err| TimeStampError::DecodeError(err.to_string()))?,
    ))
}
