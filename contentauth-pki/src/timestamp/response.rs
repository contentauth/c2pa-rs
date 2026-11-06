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

use bcder::{decode::Constructed, encode::Values, Integer};
use rasn::prelude::*;
use rasn_cms::SignedData;

use super::acquisition::AcquisitionError;
use crate::asn1::{
    rfc3161::{PkiStatus, TimeStampResp, TstInfo},
    rfc5652::OID_ID_SIGNED_DATA,
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
    /// This does not verify its message imprint, signature, or trustworthiness.
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use bcder::{
        encode::{self, PrimitiveContent},
        Captured, Mode, Tag,
    };

    use super::*;
    use crate::asn1::rfc5652::ContentInfo;

    fn response() -> TimeStampResponse {
        TimeStampResponse(
            Constructed::decode(
                [0x30, 5, 0x30, 3, 2, 1, 0].as_slice(),
                Mode::Der,
                TimeStampResp::take_from,
            )
            .unwrap(),
        )
    }

    fn with_content(content_type: &Oid, content: Option<&[u8]>) -> TimeStampResponse {
        let content_oid: bcder::Oid = content_type.to_string().parse().unwrap();

        let cms = Captured::from_values(
            Mode::Der,
            encode::sequence((
                3_u8.encode(),
                encode::set(None::<bcder::Captured>),
                encode::sequence((
                    content_oid.encode_ref(),
                    content
                        .map(|bytes| bcder::OctetString::encode_slice(bytes).explicit(Tag::CTX_0)),
                )),
                encode::set(None::<bcder::Captured>),
            )),
        );

        let mut response = response();
        response.0.time_stamp_token = Some(ContentInfo {
            content_type: "1.2.840.113549.1.7.2".parse().unwrap(),
            content: cms,
        });
        response
    }

    #[test]
    fn absent_tokens_and_timestamp_content_are_not_verified_evidence() {
        let response = response();
        assert!(response.signed_data().unwrap().is_none());
        assert!(response.tst_info().unwrap().is_none());

        let absent_info = with_content(Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_SMIME_CT_TSTINFO, None);
        assert!(absent_info.signed_data().unwrap().is_some());
        assert!(absent_info.tst_info().unwrap().is_none());

        let wrong_content_type =
            with_content(Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS7_DATA, Some(&[0]));
        assert!(wrong_content_type.tst_info().unwrap().is_none());
    }

    #[test]
    fn wrong_token_type_and_malformed_cms_are_explicit_decode_errors() {
        let mut response = response();
        response.0.time_stamp_token = Some(ContentInfo {
            content_type: bcder::Oid(bytes::Bytes::from_static(&[0x2a, 3, 4])),
            content: Captured::from_values(Mode::Der, 0_u8.encode()),
        });

        assert!(matches!(
            response.signed_data(),
            Err(AcquisitionError::DecodeError(message)) if message == "Invalid OID for signed data"
        ));

        response.0.time_stamp_token.as_mut().unwrap().content_type =
            "1.2.840.113549.1.7.2".parse().unwrap();

        assert!(matches!(
            response.signed_data(),
            Err(AcquisitionError::DecodeError(message)) if message == "time stamp invalid"
        ));

        assert!(matches!(
            response.tst_info(),
            Err(AcquisitionError::DecodeError(_))
        ));
    }

    #[test]
    fn malformed_embedded_timestamp_information_is_a_decode_error() {
        let response = with_content(
            Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_SMIME_CT_TSTINFO,
            Some(&[0]),
        );

        assert!(matches!(
            response.tst_info(),
            Err(AcquisitionError::DecodeError(_))
        ));
    }

    fn response_der(status: u8, token: Option<&[u8]>) -> Result<Vec<u8>, rasn::error::EncodeError> {
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
            token: token.map(|bytes| Any::new(bytes.to_vec())),
        })
    }

    #[test]
    fn status_and_absent_token_are_independent() -> Result<(), Box<dyn std::error::Error>> {
        for status in 0..=5 {
            let bytes = response_der(status, None)?;
            let result = signed_data_from_time_stamp_response(&bytes);
            assert_eq!(result.is_ok(), status <= 1);
            if status <= 1 {
                assert!(result?.is_none());
            }
        }

        assert!(signed_data_from_time_stamp_response(&[0x30, 1, 0]).is_err());
        assert!(signed_data_from_time_stamp_response(b"bad DER")?.is_none());
        Ok(())
    }

    #[test]
    fn token_and_response_decoding_preserve_content() -> Result<(), Box<dyn std::error::Error>> {
        let token = include_bytes!("../../tests/fixtures/time_stamp/ps256.tst");
        let sd = signed_data_from_time_stamp_response(token)?.ok_or("missing CMS")?;
        let response = response_der(0, Some(token))?;
        assert_eq!(
            signed_data_from_time_stamp_response(&response)?,
            Some(sd.clone())
        );
        assert_eq!(
            super::super::verification::token_from_response(&response)?,
            token.as_slice()
        );
        assert!(tst_info_from_signed_data(&sd)?.is_some());

        let mut missing = sd.clone();
        missing.encap_content_info.content = None;
        assert!(tst_info_from_signed_data(&missing)?.is_none());
        let mut unrelated = sd.clone();
        unrelated.encap_content_info.content_type =
            ObjectIdentifier::new(vec![1, 2, 3]).ok_or("invalid test OID")?;
        assert!(tst_info_from_signed_data(&unrelated)?.is_none());
        let mut malformed = sd;
        malformed.encap_content_info.content = Some(vec![0].into());
        assert!(tst_info_from_signed_data(&malformed).is_err());

        for oid in [vec![1, 2, 3], vec![1, 2, 840, 113549, 1, 7, 2]] {
            let invalid = super::ContentInfo {
                content_type: ObjectIdentifier::new(oid).ok_or("invalid test OID")?,
                content: Any::new(vec![0x30, 0]),
            };
            assert!(signed_data_from_time_stamp_response(&rasn::der::encode(&invalid)?).is_err());
        }

        Ok(())
    }
}

use super::verification::VerificationErrorKind;
use crate::asn1::rfc3161::TimeStampToken;

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ContentInfo {
    pub(crate) content_type: rasn::types::ObjectIdentifier,

    #[rasn(tag(explicit(0)))]
    pub(crate) content: rasn::types::Any,
}

pub(crate) fn signed_data_from_time_stamp_response(
    ts_resp: &[u8],
) -> Result<Option<SignedData>, VerificationErrorKind> {
    Ok(signed_data_and_bytes_from_time_stamp_response(ts_resp)?.map(|(sd, _)| sd))
}

// Keep the exact SignedData encoding supplied to rasn so timestamp verification
// can bind the signature input to the decoded attributes without reparsing the
// outer TimeStampResp/ContentInfo envelope with a different parser.
pub(crate) fn signed_data_and_bytes_from_time_stamp_response(
    ts_resp: &[u8],
) -> Result<Option<(SignedData, Vec<u8>)>, VerificationErrorKind> {
    let time_stamp_token = if let Ok(ts) = Constructed::decode(ts_resp, bcder::Mode::Der, |cons| {
        TimeStampResp::take_from(cons)
    })
    .map_err(|e| VerificationErrorKind::DecodeError(e.to_string()))
    {
        if ts.status.status == PkiStatus::Granted || ts.status.status == PkiStatus::GrantedWithMods
        {
            ts.time_stamp_token
        } else {
            return Err(VerificationErrorKind::DecodeError(
                "time stamp status not granted".to_string(),
            ));
        }
    } else if let Ok(ts) = Constructed::decode(ts_resp, bcder::Mode::Der, |cons| {
        TimeStampToken::take_opt_from(cons)
    }) {
        ts
    } else {
        return Err(VerificationErrorKind::DecodeError(
            "no time stamp found".to_string(),
        ));
    };

    let Some(token) = &time_stamp_token else {
        return Ok(None);
    };

    if token.content_type != OID_ID_SIGNED_DATA {
        return Err(VerificationErrorKind::DecodeError(
            "time stamp has invalid OID".to_string(),
        ));
    }

    let mut sd_bytes = Vec::new();
    token
        .content
        .write_encoded(bcder::Mode::Der, &mut sd_bytes)
        .map_err(|_err| VerificationErrorKind::DecodeError("time stamp invalid".to_string()))?;

    // decode ContentInfo DER as SignedData
    match rasn::der::decode(&sd_bytes) {
        Ok(signed_data) => Ok(Some((signed_data, sd_bytes))),
        Err(_) => Err(VerificationErrorKind::DecodeError(
            "time stamp invalid".to_string(),
        )),
    }
}

pub(crate) fn tst_info_from_signed_data(
    signed_data: &SignedData,
) -> Result<Option<TstInfo>, VerificationErrorKind> {
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
        .map_err(|err| VerificationErrorKind::DecodeError(err.to_string()))?,
    ))
}
