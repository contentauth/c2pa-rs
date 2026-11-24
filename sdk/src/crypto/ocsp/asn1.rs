// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.
//
// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! RFC 6960 sections 4.1.1 and 4.2.1, with RFC 5280 extension/reason types.
//!
//! RustCrypto supplies the envelope, responder identifier, extension/reason types,
//! AlgorithmIdentifier, and codecs. The remaining structures are manually declared,
//! spec-checked compatibility models, not specification-generated definitions.
//! Certificates remain opaque and times retain their received encoding because
//! the upstream typed certificate/time models cannot represent pre-epoch dates.
//! CertId and its enclosing requests retain signed, unrestricted-length serials;
//! the upstream RFC 5280 certificate profile instead constrains serial numbers.

use chrono::{DateTime, NaiveDateTime, Timelike, Utc};
pub(crate) use cms::x509_cert::ext::{pkix::crl::CrlReason, Extension};
use der::{
    asn1::{Any, AnyRef, BitString, Int, OctetString},
    Decode, DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Sequence, SliceReader, Tag,
    Writer,
};
use spki::AlgorithmIdentifierOwned;
pub(crate) use x509_ocsp::{OcspResponse as Response, OcspResponseStatus, ResponderId};

// Keep original time values for response-signature verification. Unlike der's
// GeneralizedTime, OCSP timestamps can represent dates before the Unix epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OcspGeneralizedTime {
    value: Vec<u8>,
    pub(crate) datetime: DateTime<Utc>,
}

impl FixedTag for OcspGeneralizedTime {
    const TAG: Tag = Tag::GeneralizedTime;
}

impl<'a> DecodeValue<'a> for OcspGeneralizedTime {
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
        if &text[12..14] == "60" {
            return Err(Self::TAG.value_error().into());
        }

        let datetime = NaiveDateTime::parse_from_str(&text[..14], "%Y%m%d%H%M%S")
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
            .with_nanosecond(nanoseconds)
            .ok_or_else(|| Self::TAG.value_error())?
            .and_utc();

        Ok(Self {
            value: value.to_vec(),
            datetime,
        })
    }
}

impl EncodeValue for OcspGeneralizedTime {
    fn value_len(&self) -> der::Result<Length> {
        self.value.len().try_into()
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        writer.write(&self.value)
    }
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

impl BasicOcspResponse {
    pub(crate) fn decode_with_signed_data(encoded: &[u8]) -> der::Result<(Self, &[u8])> {
        // As with the OCSP envelope, retain acceptance of trailing bytes after
        // a complete BasicOcspResponse, but never include them in signed data.
        let response = Self::decode(&mut SliceReader::new(encoded)?)?;
        let sequence = AnyRef::decode(&mut SliceReader::new(encoded)?)?;
        let mut fields = SliceReader::new(sequence.value())?;
        let signed_data = fields.tlv_bytes()?;

        Ok((response, signed_data))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct ResponseData {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) version: Option<Int>,
    pub(crate) responder_id: ResponderId,
    pub(crate) produced_at: OcspGeneralizedTime,
    pub(crate) responses: Vec<SingleResponse>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) response_extensions: Option<Vec<Extension>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct SingleResponse {
    pub(crate) cert_id: CertId,
    pub(crate) cert_status: CertStatus,
    pub(crate) this_update: OcspGeneralizedTime,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) next_update: Option<OcspGeneralizedTime>,
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
    pub(crate) revocation_time: OcspGeneralizedTime,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) revocation_reason: Option<CrlReason>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use chrono::Timelike;
    use der::{asn1::Any, Decode, Encode, Tag};

    use super::{BasicOcspResponse, OcspGeneralizedTime, Response};

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
            let decoded = OcspGeneralizedTime::from_der(&encoded).unwrap();
            assert_eq!(decoded.datetime.timestamp(), seconds);
            assert_eq!(decoded.datetime.nanosecond(), nanoseconds);
            assert_eq!(decoded.to_der().unwrap(), encoded);
        }
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
                OcspGeneralizedTime::from_der(&encoded_time(value)).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn signed_response_round_trips_without_changing_signature_input() {
        let encoded = include_bytes!("../../../tests/fixtures/crypto/ocsp/response_good.der");
        let response = Response::from_der(encoded).unwrap();
        assert_eq!(response.to_der().unwrap(), encoded);

        let basic_der = response.response_bytes.unwrap().response;
        let (basic, signed_data) =
            BasicOcspResponse::decode_with_signed_data(basic_der.as_bytes()).unwrap();
        assert_eq!(basic.to_der().unwrap(), basic_der.as_bytes());
        assert_eq!(signed_data, basic.tbs_response_data.to_der().unwrap());

        let mut with_trailing = basic_der.as_bytes().to_vec();
        with_trailing.push(0);
        let (decoded, received) =
            BasicOcspResponse::decode_with_signed_data(&with_trailing).unwrap();
        assert_eq!(decoded, basic);
        assert_eq!(received, signed_data);
    }
}
