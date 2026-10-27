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
pub(crate) use contentauth_rfc3161::sdk_compat::TimeStampResponse;
use rasn_cms::SignedData;

use crate::crypto::{
    asn1::{
        rfc3161::{PkiStatus, TimeStampResp, TimeStampToken, TstInfo},
        rfc5652::OID_ID_SIGNED_DATA,
    },
    time_stamp::TimeStampError,
};

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

    // Decode the ContentInfo DER as SignedData.
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

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    pub(crate) fn response_der(status: u8, token: Option<&[u8]>) -> Vec<u8> {
        #[derive(AsnType, Encode)]
        struct Status {
            status: rasn::types::Integer,
        }

        #[derive(AsnType, Encode)]
        struct Response {
            status: Status,
            token: Option<Any>,
        }

        rasn::der::encode(&Response {
            status: Status {
                status: status.into(),
            },

            token: token.map(|token| Any::new(token.to_vec())),
        })
        .unwrap()
    }

    fn decode(bytes: &[u8]) -> TimeStampResponse {
        TimeStampResponse(
            Constructed::decode(bytes, bcder::Mode::Der, TimeStampResp::take_from).unwrap(),
        )
    }

    #[test]
    fn status_and_absent_token_are_independent() {
        for status in 0..=5 {
            let der = response_der(status, None);
            let response = decode(&der);
            assert_eq!(response.is_success(), status <= 1);
            assert!(response.time_stamp_token.is_none());
            assert!(response.signed_data().unwrap().is_none());
            assert!(response.tst_info().unwrap().is_none());
            let result = signed_data_from_time_stamp_response(&der);
            assert_eq!(result.is_ok(), status <= 1);

            if status <= 1 {
                assert!(result.unwrap().is_none());
            }
        }

        assert!(signed_data_from_time_stamp_response(&[0x30, 1, 0]).is_err());

        // A non-SEQUENCE prefix is currently treated as an absent optional token.
        assert!(signed_data_from_time_stamp_response(b"bad DER")
            .unwrap()
            .is_none());
    }

    #[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
    #[test]
    fn token_and_response_decoding_agree_and_reject_malformed_content() {
        use openssl::hash::MessageDigest;

        use crate::crypto::time_stamp::verify::message_imprint_regression::{
            build_token, OID_SHA256,
        };

        let token = build_token(OID_SHA256, MessageDigest::sha256(), b"data");
        let response = decode(&response_der(0, Some(&token)));
        let signed_data = response.signed_data().unwrap().unwrap();

        assert_eq!(
            signed_data_from_time_stamp_response(&token)
                .unwrap()
                .unwrap(),
            signed_data
        );

        let expected = response.tst_info().unwrap().unwrap();

        assert_eq!(
            tst_info_from_signed_data(&signed_data).unwrap().unwrap(),
            expected
        );

        let mut missing = signed_data.clone();
        missing.encap_content_info.content = None;
        assert!(tst_info_from_signed_data(&missing).unwrap().is_none());
        let mut unrelated = signed_data.clone();
        unrelated.encap_content_info.content_type = ObjectIdentifier::new(vec![1, 2, 3]).unwrap();
        assert!(tst_info_from_signed_data(&unrelated).unwrap().is_none());
        let mut malformed = signed_data;
        malformed.encap_content_info.content = Some(vec![0].into());
        assert!(tst_info_from_signed_data(&malformed).is_err());

        for content_type in [vec![1, 2, 3], vec![1, 2, 840, 113549, 1, 7, 2]] {
            let malformed = ContentInfo {
                content_type: ObjectIdentifier::new(content_type).unwrap(),
                content: Any::new(vec![0x30, 0]),
            };

            let token = rasn::der::encode(&malformed).unwrap();
            let response = decode(&response_der(0, Some(&token)));
            assert!(response.signed_data().is_err());
            assert!(response.tst_info().is_err());
            assert!(signed_data_from_time_stamp_response(&token).is_err());
        }
    }
}
