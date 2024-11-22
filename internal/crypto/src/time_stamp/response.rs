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

use crate::{
    asn1::{
        rfc3161::{PkiStatus, TimeStampResp, TstInfo, OID_CONTENT_TYPE_TST_INFO},
        rfc5652::{SignedData, OID_ID_SIGNED_DATA},
    },
    time_stamp::TimeStampError,
};

/// A wrapper for [`TimeStampResp`] that allows us to provide additional
/// interfaces.
pub(crate) struct TimeStampResponse(pub(crate) TimeStampResp);

impl TimeStampResponse {
    /// Returns `true` if the time stamp request was successful.
    #[allow(unused)]
    pub(crate) fn is_success(&self) -> bool {
        matches!(
            self.0.status.status,
            PkiStatus::Granted | PkiStatus::GrantedWithMods
        )
    }

    pub(crate) fn signed_data(&self) -> Result<Option<SignedData>, TimeStampError> {
        let Some(token) = &self.0.time_stamp_token else {
            return Ok(None);
        };

        if token.content_type != OID_ID_SIGNED_DATA {
            return Err(TimeStampError::DecodeError(
                "invalid OID for signed data".to_string(),
            ));
        }

        Ok(Some(
            token
                .content
                .clone()
                .decode(SignedData::take_from)
                .map_err(|e| TimeStampError::DecodeError(e.to_string()))?,
        ))
    }

    pub(crate) fn tst_info(&self) -> Result<Option<TstInfo>, TimeStampError> {
        let Some(signed_data) = self.signed_data()? else {
            return Ok(None);
        };

        if signed_data.content_info.content_type != OID_CONTENT_TYPE_TST_INFO {
            return Ok(None);
        }

        let Some(content) = signed_data.content_info.content else {
            return Ok(None);
        };

        Ok(Some(
            Constructed::decode(content.to_bytes(), bcder::Mode::Der, |cons| {
                TstInfo::take_from(cons)
            })
            .map_err(|e| TimeStampError::DecodeError(e.to_string()))?,
        ))
    }
}

impl std::ops::Deref for TimeStampResponse {
    type Target = TimeStampResp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
