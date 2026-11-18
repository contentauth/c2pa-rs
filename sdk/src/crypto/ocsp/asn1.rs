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

use der::{
    asn1::{Any, BitString, Int, ObjectIdentifier, OctetString},
    DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag, Writer,
};
use spki::AlgorithmIdentifierOwned;
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset};

// Keep original time values for response-signature verification. Unlike der's
// GeneralizedTime, OCSP timestamps can represent dates before the Unix epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GeneralizedTime {
    value: Vec<u8>,
    pub(crate) datetime: OffsetDateTime,
}

impl FixedTag for GeneralizedTime {
    const TAG: Tag = Tag::GeneralizedTime;
}

impl TryFrom<OffsetDateTime> for GeneralizedTime {
    type Error = der::Error;

    fn try_from(datetime: OffsetDateTime) -> der::Result<Self> {
        let datetime = datetime
            .checked_to_offset(UtcOffset::UTC)
            .filter(|datetime| datetime.year() >= 0)
            .ok_or_else(|| Self::TAG.value_error())?;
        let mut value = datetime
            .format(time::macros::format_description!(
                "[year][month][day][hour][minute][second]"
            ))
            .map_err(|_| Self::TAG.value_error())?;

        if datetime.nanosecond() != 0 {
            value.push('.');
            value.push_str(format!("{:09}", datetime.nanosecond()).trim_end_matches('0'));
        }
        value.push('Z');

        Ok(Self {
            value: value.into_bytes(),
            datetime,
        })
    }
}

impl<'a> DecodeValue<'a> for GeneralizedTime {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let value = reader.read_slice(header.length())?;
        if value.len() < 15
            || value.last() != Some(&b'Z')
            || !value[..14].iter().all(u8::is_ascii_digit)
        {
            return Err(Self::TAG.value_error().into());
        }

        let text = std::str::from_utf8(value).map_err(|_| Self::TAG.value_error())?;
        let datetime = PrimitiveDateTime::parse(
            &text[..14],
            time::macros::format_description!("[year][month][day][hour][minute][second]"),
        )
        .map_err(|_| Self::TAG.value_error())?;
        let fraction = &text[14..text.len() - 1];
        let nanoseconds = if fraction.is_empty() {
            0
        } else {
            let digits = fraction
                .strip_prefix('.')
                .filter(|digits| {
                    !digits.is_empty()
                        && digits.len() <= 9
                        && digits.bytes().all(|byte| byte.is_ascii_digit())
                })
                .ok_or_else(|| Self::TAG.value_error())?;

            digits.parse::<u32>().map_err(|_| Self::TAG.value_error())?
                * 10u32.pow(9 - digits.len() as u32)
        };
        let datetime = datetime
            .replace_nanosecond(nanoseconds)
            .map_err(|_| Self::TAG.value_error())?
            .assume_offset(UtcOffset::UTC);

        Ok(Self {
            value: value.to_vec(),
            datetime,
        })
    }
}

impl EncodeValue for GeneralizedTime {
    fn value_len(&self) -> der::Result<Length> {
        self.value.len().try_into()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        writer.write(&self.value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, der::Enumerated)]
#[repr(u32)]
pub(crate) enum OcspResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct Response {
    pub(crate) status: OcspResponseStatus,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) bytes: Option<ResponseBytes>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct ResponseBytes {
    pub(crate) response_type: ObjectIdentifier,
    pub(crate) response: OctetString,
}

// Certificate validity is deliberately decoded by x509-parser, not the
// epoch-limited typed certificate decoder.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct BasicOcspResponse {
    pub(crate) tbs_response_data: ResponseData,
    pub(crate) signature_algorithm: AlgorithmIdentifierOwned,
    pub(crate) signature: BitString,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) certs: Option<Vec<Any>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct ResponseData {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) version: Option<Int>,
    pub(crate) responder_id: ResponderId,
    pub(crate) produced_at: GeneralizedTime,
    pub(crate) responses: Vec<SingleResponse>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) response_extensions: Option<Vec<Extension>>,
}

#[derive(Clone, Debug, Eq, PartialEq, der::Choice)]
pub(crate) enum ResponderId {
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    ByName(Any),
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    ByKey(OctetString),
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct SingleResponse {
    pub(crate) cert_id: CertId,
    pub(crate) cert_status: CertStatus,
    pub(crate) this_update: GeneralizedTime,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) next_update: Option<GeneralizedTime>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) single_extensions: Option<Vec<Extension>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct CertId {
    pub(crate) hash_algorithm: AlgorithmIdentifierOwned,
    pub(crate) issuer_name_hash: OctetString,
    pub(crate) issuer_key_hash: OctetString,
    pub(crate) serial_number: Int,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct OcspRequest {
    pub(crate) tbs_request: TbsRequest,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) optional_signature: Option<Any>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct TbsRequest {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) version: Option<Int>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) requestor_name: Option<Any>,
    pub(crate) request_list: Vec<Request>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) request_extensions: Option<Vec<Extension>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct Request {
    pub(crate) req_cert: CertId,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) single_request_extensions: Option<Vec<Extension>>,
}

#[derive(Clone, Debug, Eq, PartialEq, der::Choice)]
pub(crate) enum CertStatus {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Good(()),
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Revoked(RevokedInfo),
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    Unknown(()),
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct RevokedInfo {
    pub(crate) revocation_time: GeneralizedTime,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) revocation_reason: Option<CrlReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, der::Enumerated)]
#[repr(u32)]
pub(crate) enum CrlReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCRL = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct Extension {
    pub(crate) extn_id: ObjectIdentifier,
    #[asn1(default = "Default::default")]
    pub(crate) critical: bool,
    pub(crate) extn_value: OctetString,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use der::{asn1::Any, Decode, Encode, Tag};
    use time::macros::datetime;

    use super::{BasicOcspResponse, GeneralizedTime, Response};

    fn encoded_time(value: &str) -> Vec<u8> {
        Any::new(Tag::GeneralizedTime, value.as_bytes())
            .unwrap()
            .to_der()
            .unwrap()
    }

    #[test]
    fn dates_before_epoch_and_fractional_signature_input_are_preserved() {
        for (value, seconds, nanoseconds) in [
            ("19500101000000Z", -631_152_000, 0),
            ("19691231235959.5Z", -1, 500_000_000),
            ("19700101000000.000Z", 0, 0),
            ("20500101000000Z", 2_524_608_000, 0),
        ] {
            let encoded = encoded_time(value);
            let decoded = GeneralizedTime::from_der(&encoded).unwrap();
            assert_eq!(decoded.datetime.unix_timestamp(), seconds);
            assert_eq!(decoded.datetime.nanosecond(), nanoseconds);
            assert_eq!(decoded.to_der().unwrap(), encoded);
        }
    }

    #[test]
    fn date_construction_preserves_epoch_boundaries_fractions_and_offsets() {
        for (datetime, expected) in [
            (datetime!(1950-01-01 00:00 UTC), "19500101000000Z"),
            (datetime!(1969-12-31 23:59:59.5 UTC), "19691231235959.5Z"),
            (datetime!(1970-01-01 05:30 +05:30), "19700101000000Z"),
            (datetime!(2050-01-01 00:00 UTC), "20500101000000Z"),
        ] {
            let value = GeneralizedTime::try_from(datetime).unwrap();
            let encoded = value.to_der().unwrap();
            assert_eq!(encoded, encoded_time(expected));
            assert_eq!(
                GeneralizedTime::from_der(&encoded).unwrap().datetime,
                datetime
            );
        }

        assert!(GeneralizedTime::try_from(datetime!(-0001-01-01 00:00 UTC)).is_err());
    }

    #[test]
    fn leap_seconds_and_invalid_dates_are_rejected_without_normalization() {
        for value in [
            "20161231235960Z",
            "20161231235960.1Z",
            "20230229000000Z",
            "20250101240000Z",
            "20250101000000",
            "20250101000000+0000",
            "20250101000000.Z",
            "20250101000000.1234567890Z",
            "20250101000000.123xZ",
        ] {
            assert!(
                GeneralizedTime::from_der(&encoded_time(value)).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn signed_response_round_trips_without_changing_signature_input() {
        let encoded = include_bytes!("../../../tests/fixtures/crypto/ocsp/response_good.der");
        let response = Response::from_der(encoded).unwrap();
        assert_eq!(response.to_der().unwrap(), encoded);

        let basic_der = response.bytes.unwrap().response;
        let basic = BasicOcspResponse::from_der(basic_der.as_bytes()).unwrap();
        assert_eq!(basic.to_der().unwrap(), basic_der.as_bytes());
    }
}
