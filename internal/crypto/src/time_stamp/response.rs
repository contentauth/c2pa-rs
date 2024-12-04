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

use asn1_rs::nom::AsBytes;
use bcder::decode::Constructed;
use rasn::{AsnType, Decode, Encode};

use crate::{
    asn1::{
        rfc3161::{PkiStatus, TimeStampResp, TstInfo, OID_CONTENT_TYPE_TST_INFO},
        rfc5652::{SignedData, OID_ID_SIGNED_DATA},
    },
    time_stamp::TimeStampError,
};

/// TO REVIEW: Does this need to be public?
pub struct TimeStampResponse(pub TimeStampResp);

impl std::ops::Deref for TimeStampResponse {
    type Target = TimeStampResp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TimeStampResponse {
    /// Return `true` if the request was successful.
    pub fn is_success(&self) -> bool {
        matches!(
            self.0.status.status,
            PkiStatus::Granted | PkiStatus::GrantedWithMods
        )
    }

    /// TO REVIEW: Does this need to be public?
    pub fn signed_data(&self) -> Result<Option<SignedData>, TimeStampError> {
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

    /// TO REVIEW: Does this need to be public?
    pub fn tst_info(&self) -> Result<Option<TstInfo>, TimeStampError> {
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

    /// Convert this time stamp response to a time stamp token.
    pub fn time_stamp_token(&self) -> Option<Vec<u8>> {
        let tst = self.0.time_stamp_token.as_ref()?;

        let a: Result<Vec<u32>, TimeStampError> = tst
            .content_type
            .iter()
            .map(|v| {
                v.to_u32().ok_or(TimeStampError::DecodeError(
                    "no content type specified".to_string(),
                ))
            })
            .collect();

        let ci = ContentInfo {
            content_type: rasn::types::ObjectIdentifier::new(a.ok()?)?,
            content: rasn::types::Any::new(tst.content.as_bytes().to_vec()),
        };

        rasn::der::encode(&ci).ok()
    }
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ContentInfo {
    content_type: rasn::types::ObjectIdentifier,

    #[rasn(tag(explicit(0)))]
    content: rasn::types::Any,
}
