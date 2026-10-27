// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! ASN.1 types defined by [RFC 3161].
//!
//! [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161

use bcder::{
    decode::{Constructed, DecodeError, Primitive, Source},
    encode::{self, PrimitiveContent, Values},
    Integer, OctetString, Oid, Tag,
};

use super::{AlgorithmIdentifier, Extensions, GeneralName, GeneralizedTime};
use crate::asn1::{rfc4210::PkiFreeText, rfc5652::ContentInfo};

/// A time-stamp request.
///
/// ```ASN.1
/// TimeStampReq ::= SEQUENCE  {
///    version                  INTEGER  { v1(1) },
///    messageImprint           MessageImprint,
///      --a hash algorithm OID and the hash value of the data to be
///      --time-stamped
///    reqPolicy                TSAPolicyId                OPTIONAL,
///    nonce                    INTEGER                    OPTIONAL,
///    certReq                  BOOLEAN                    DEFAULT FALSE,
///    extensions               [0] IMPLICIT Extensions    OPTIONAL  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeStampReq {
    /// Protocol version; RFC 3161 defines version 1.
    pub version: Integer,

    /// Hash algorithm and digest of the data to be time-stamped.
    pub message_imprint: MessageImprint,

    /// Optional timestamp policy OID requested from the TSA.
    pub req_policy: Option<TsaPolicyId>,

    /// Optional client nonce that the TSA must echo in the timestamp token.
    pub nonce: Option<Integer>,

    /// Whether to include the TSA signing certificate in the response.
    ///
    /// An omitted value defaults to `false`.
    pub cert_req: Option<bool>,

    /// Optional extensions carrying additional information for the TSA.
    pub extensions: Option<Extensions>,
}

impl TimeStampReq {
    /// Decode a timestamp request from its ASN.1 `SEQUENCE`.
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let version = Integer::take_from(cons)?;
            let message_imprint = MessageImprint::take_from(cons)?;
            let req_policy = TsaPolicyId::take_opt_from(cons)?;

            let nonce =
                cons.take_opt_primitive_if(Tag::INTEGER, |prim| Integer::from_primitive(prim))?;

            let cert_req = cons.take_opt_bool()?;

            let extensions = cons
                .take_opt_constructed_if(Tag::CTX_0, |cons| Extensions::from_constructed(cons))?;

            Ok(Self {
                version,
                message_imprint,
                req_policy,
                nonce,
                cert_req,
                extensions,
            })
        })
    }

    /// Borrow an encoder for the timestamp request.
    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            (&self.version).encode(),
            self.message_imprint.encode_ref(),
            self.req_policy
                .as_ref()
                .map(|req_policy| req_policy.encode_ref()),
            self.nonce.as_ref().map(|nonce| nonce.encode()),
            self.cert_req.as_ref().map(|cert_req| cert_req.encode_ref()),
            self.extensions
                .as_ref()
                .map(|extensions| extensions.encode_ref_as(Tag::CTX_0)),
        ))
    }
}

/// Message imprint.
///
/// ```ASN.1
/// MessageImprint ::= SEQUENCE  {
///      hashAlgorithm                AlgorithmIdentifier,
///      hashedMessage                OCTET STRING  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageImprint {
    /// Algorithm used to hash the data to be time-stamped.
    pub hash_algorithm: AlgorithmIdentifier,

    /// Digest of the data, computed using `hash_algorithm`.
    pub hashed_message: OctetString,
}

impl MessageImprint {
    /// Decode a message imprint from its ASN.1 `SEQUENCE`.
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let hash_algorithm = AlgorithmIdentifier::take_from(cons)?;
            let hashed_message = OctetString::take_from(cons)?;

            Ok(Self {
                hash_algorithm,
                hashed_message,
            })
        })
    }

    /// Borrow an encoder for the message imprint.
    pub(crate) fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((&self.hash_algorithm, self.hashed_message.encode_ref()))
    }
}

/// Object identifier of a timestamp authority's policy.
pub(crate) type TsaPolicyId = Oid;

/// Timestamp response.
///
/// ```ASN.1
/// TimeStampResp ::= SEQUENCE  {
///      status                  PKIStatusInfo,
///      timeStampToken          TimeStampToken     OPTIONAL  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeStampResp {
    /// TSA processing status and optional failure details.
    pub status: PkiStatusInfo,

    /// CMS timestamp token, when supplied by the TSA.
    pub time_stamp_token: Option<TimeStampToken>,
}

impl TimeStampResp {
    /// Decode a timestamp response from its ASN.1 `SEQUENCE`.
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let status = PkiStatusInfo::take_from(cons)?;
            let time_stamp_token = TimeStampToken::take_opt_from(cons)?;

            Ok(Self {
                status,
                time_stamp_token,
            })
        })
    }
}

/// PKI status information.
///
/// ```ASN.1
/// PKIStatusInfo ::= SEQUENCE {
///     status        PKIStatus,
///     statusString  PKIFreeText     OPTIONAL,
///     failInfo      PKIFailureInfo  OPTIONAL  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PkiStatusInfo {
    /// Outcome of the timestamp request.
    pub status: PkiStatus,

    /// Optional human-readable status messages from the TSA.
    pub(crate) status_string: Option<PkiFreeText>,

    /// Optional reason the TSA could not fulfill the request.
    pub(crate) fail_info: Option<PkiFailureInfo>,
}

impl PkiStatusInfo {
    /// Decode the status and optional details from their ASN.1 `SEQUENCE`.
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let status = PkiStatus::take_from(cons)?;
            let status_string = PkiFreeText::take_opt_from(cons)?;
            let fail_info = PkiFailureInfo::take_opt_from(cons)?;

            Ok(Self {
                status,
                status_string,
                fail_info,
            })
        })
    }
}

/// PKI status.
///
/// ```ASN.1
/// PKIStatus ::= INTEGER {
///     granted                (0),
///     -- when the PKIStatus contains the value zero a TimeStampToken, as
///        requested, is present.
///     grantedWithMods        (1),
///      -- when the PKIStatus contains the value one a TimeStampToken,
///        with modifications, is present.
///     rejection              (2),
///     waiting                (3),
///     revocationWarning      (4),
///      -- this message contains a warning that a revocation is
///      -- imminent
///     revocationNotification (5)
///      -- notification that a revocation has occurred   }
///
///     -- When the TimeStampToken is not present
///     -- failInfo indicates the reason why the
///     -- time-stamp request was rejected and
///     -- may be one of the following values.
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PkiStatus {
    /// The requested timestamp was granted.
    Granted = 0,

    /// A timestamp was granted with modifications to the request.
    GrantedWithMods = 1,

    /// The request was rejected.
    Rejection = 2,

    /// The request is still pending.
    Waiting = 3,

    /// Revocation is imminent.
    RevocationWarning = 4,

    /// Revocation has occurred.
    RevocationNotification = 5,
}

impl PkiStatus {
    /// Decode a supported status value from its ASN.1 `INTEGER`.
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        match cons.take_primitive_if(Tag::INTEGER, Integer::i8_from_primitive)? {
            0 => Ok(Self::Granted),
            1 => Ok(Self::GrantedWithMods),
            2 => Ok(Self::Rejection),
            3 => Ok(Self::Waiting),
            4 => Ok(Self::RevocationWarning),
            5 => Ok(Self::RevocationNotification),
            _ => Err(cons.content_err("unknown PKIStatus value")),
        }
    }

    /// Encode the status as its ASN.1 `INTEGER` value.
    #[cfg(test)]
    pub(crate) fn encode(self) -> impl Values {
        u8::from(self).encode()
    }
}

impl From<PkiStatus> for u8 {
    fn from(v: PkiStatus) -> u8 {
        match v {
            PkiStatus::Granted => 0,
            PkiStatus::GrantedWithMods => 1,
            PkiStatus::Rejection => 2,
            PkiStatus::Waiting => 3,
            PkiStatus::RevocationWarning => 4,
            PkiStatus::RevocationNotification => 5,
        }
    }
}

/// PKI failure information.
///
/// ```ASN.1
/// PKIFailureInfo ::= BIT STRING {
///     badAlg               (0),
///       -- unrecognized or unsupported Algorithm Identifier
///     badRequest           (2),
///       -- transaction not permitted or supported
///     badDataFormat        (5),
///       -- the data submitted has the wrong format
///     timeNotAvailable    (14),
///       -- the TSA's time source is not available
///     unacceptedPolicy    (15),
///       -- the requested TSA policy is not supported by the TSA.
///     unacceptedExtension (16),
///       -- the requested extension is not supported by the TSA.
///     addInfoNotAvailable (17)
///       -- the additional information requested could not be understood
///       -- or is not available
///     systemFailure       (25)
///       -- the request cannot be handled due to system failure  }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PkiFailureInfo {
    /// The requested algorithm is unsupported or unrecognized.
    BadAlg = 0,

    /// The request is not permitted or supported.
    BadRequest = 1,

    /// The submitted data has the wrong format.
    BadDataFormat = 5,

    /// The TSA's time source is unavailable.
    TimeNotAvailable = 14,

    /// The requested timestamp policy is unsupported.
    UnacceptedPolicy = 15,

    /// The requested extension is unsupported.
    UnacceptedExtension = 16,

    /// Required additional information is unavailable.
    AddInfoNotAvailable = 17,

    /// An internal TSA failure prevented processing.
    SystemFailure = 25,
}

impl PkiFailureInfo {
    /// Decode an optional failure value using this codec's `INTEGER` representation.
    pub(crate) fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_primitive_if(Tag::INTEGER, Self::from_primitive)
    }

    /// Decode a required failure value using this codec's `INTEGER` representation.
    #[cfg(test)]
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_primitive_if(Tag::INTEGER, Self::from_primitive)
    }

    /// Map a primitive `INTEGER` to a supported failure value.
    pub(crate) fn from_primitive<S: Source>(
        prim: &mut Primitive<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        match Integer::i8_from_primitive(prim)? {
            0 => Ok(Self::BadAlg),
            1 => Ok(Self::BadRequest),
            5 => Ok(Self::BadDataFormat),
            14 => Ok(Self::TimeNotAvailable),
            15 => Ok(Self::UnacceptedPolicy),
            16 => Ok(Self::UnacceptedExtension),
            17 => Ok(Self::AddInfoNotAvailable),
            25 => Ok(Self::SystemFailure),
            _ => Err(prim.content_err("Unknown PKIFailureInfo value")),
        }
    }

    /// Encode the failure value using this codec's `INTEGER` representation.
    #[cfg(test)]
    pub(crate) fn encode(self) -> impl Values {
        u8::from(self).encode()
    }
}

impl From<PkiFailureInfo> for u8 {
    fn from(v: PkiFailureInfo) -> u8 {
        match v {
            PkiFailureInfo::BadAlg => 0,
            PkiFailureInfo::BadRequest => 1,
            PkiFailureInfo::BadDataFormat => 5,
            PkiFailureInfo::TimeNotAvailable => 14,
            PkiFailureInfo::UnacceptedPolicy => 15,
            PkiFailureInfo::UnacceptedExtension => 16,
            PkiFailureInfo::AddInfoNotAvailable => 17,
            PkiFailureInfo::SystemFailure => 25,
        }
    }
}

/// Timestamp token.
///
/// ```ASN.1
/// TimeStampToken ::= ContentInfo
/// ```
pub type TimeStampToken = ContentInfo;

/// Timestamp token information.
///
/// ```ASN.1
/// TSTInfo ::= SEQUENCE  {
///     version                      INTEGER  { v1(1) },
///     policy                       TSAPolicyId,
///     messageImprint               MessageImprint,
///       -- MUST have the same value as the similar field in
///       -- TimeStampReq
///     serialNumber                 INTEGER,
///      -- Time-Stamping users MUST be ready to accommodate integers
///      -- up to 160 bits.
///     genTime                      GeneralizedTime,
///     accuracy                     Accuracy                 OPTIONAL,
///     ordering                     BOOLEAN             DEFAULT FALSE,
///     nonce                        INTEGER                  OPTIONAL,
///       -- MUST be present if the similar field was present
///       -- in TimeStampReq.  In that case it MUST have the same value.
///     tsa                          [0] GeneralName          OPTIONAL,
///     extensions                   [1] IMPLICIT Extensions  OPTIONAL   }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TstInfo {
    /// Timestamp token information version; RFC 3161 defines version 1.
    pub version: Integer,

    /// TSA policy under which the token was issued.
    pub policy: TsaPolicyId,

    /// Hash algorithm and digest of the time-stamped data.
    pub message_imprint: MessageImprint,

    /// Token serial number assigned by the TSA.
    pub serial_number: Integer,

    /// Time at which the TSA generated the token.
    pub gen_time: GeneralizedTime,

    /// Optional bounds on the precision of `gen_time`.
    pub accuracy: Option<Accuracy>,

    /// Whether `gen_time` orders tokens from this TSA regardless of accuracy.
    pub ordering: Option<bool>,

    /// Client nonce echoed from the request, if one was supplied.
    pub nonce: Option<Integer>,

    /// Optional name identifying the TSA.
    pub tsa: Option<GeneralName>,

    /// Optional extensions included by the TSA.
    pub extensions: Option<Extensions>,
}

impl TstInfo {
    /// Decode timestamp token information from its ASN.1 `SEQUENCE`.
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let version = Integer::take_from(cons)?;
            let policy = TsaPolicyId::take_from(cons)?;
            let message_imprint = MessageImprint::take_from(cons)?;
            let serial_number = Integer::take_from(cons)?;
            let gen_time = GeneralizedTime::take_from_allow_fractional_z(cons)?;
            let accuracy = Accuracy::take_opt_from(cons)?;
            let ordering = cons.take_opt_bool()?;

            let nonce =
                cons.take_opt_primitive_if(Tag::INTEGER, |prim| Integer::from_primitive(prim))?;

            let tsa =
                cons.take_opt_constructed_if(Tag::CTX_0, |cons| GeneralName::take_from(cons))?;

            let extensions = cons
                .take_opt_constructed_if(Tag::CTX_1, |cons| Extensions::from_constructed(cons))?;

            Ok(Self {
                version,
                policy,
                message_imprint,
                serial_number,
                gen_time,
                accuracy,
                ordering,
                nonce,
                tsa,
                extensions,
            })
        })
    }

    #[cfg(test)]
    pub(crate) fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            (&self.version).encode(),
            self.policy.encode_ref(),
            self.message_imprint.encode_ref(),
            (&self.serial_number).encode(),
            self.gen_time.encode_ref(),
            self.accuracy.as_ref().map(|accuracy| accuracy.encode_ref()),
            self.ordering.as_ref().map(|ordering| ordering.encode_ref()),
            self.nonce.as_ref().map(|nonce| nonce.encode()),
            self.tsa
                .as_ref()
                .map(|tsa| tsa.encode_ref().explicit(Tag::CTX_0)),
            self.extensions
                .as_ref()
                .map(|extensions| extensions.encode_ref_as(Tag::CTX_1)),
        ))
    }
}

/// Timestamp accuracy.
///
/// ```ASN.1
/// Accuracy ::= SEQUENCE {
///                 seconds        INTEGER           OPTIONAL,
///                 millis     [0] INTEGER  (1..999) OPTIONAL,
///                 micros     [1] INTEGER  (1..999) OPTIONAL  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Accuracy {
    /// Whole seconds of uncertainty around the generation time.
    pub seconds: Option<Integer>,

    /// Additional milliseconds of uncertainty, in the range 1 through 999.
    pub millis: Option<Integer>,

    /// Additional microseconds of uncertainty, in the range 1 through 999.
    pub micros: Option<Integer>,
}

impl Accuracy {
    /// Decode an optional accuracy `SEQUENCE`.
    pub(crate) fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| Self::from_sequence(cons))
    }

    /// Decode accuracy components after entering their `SEQUENCE`.
    pub(crate) fn from_sequence<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let seconds =
            cons.take_opt_primitive_if(Tag::INTEGER, |prim| Integer::from_primitive(prim))?;

        let millis =
            cons.take_opt_primitive_if(Tag::CTX_0, |prim| Integer::from_primitive(prim))?;

        let micros =
            cons.take_opt_primitive_if(Tag::CTX_1, |prim| Integer::from_primitive(prim))?;

        Ok(Self {
            seconds,
            millis,
            micros,
        })
    }

    #[cfg(test)]
    pub(crate) fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            self.seconds.as_ref().map(|seconds| seconds.encode()),
            self.millis.as_ref().map(|millis| millis.encode()),
            self.micros.as_ref().map(|micros| micros.encode()),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::str::FromStr;

    use bcder::Mode;
    use chrono::{TimeZone, Utc};

    use super::*;

    fn encoded(value: impl Values) -> Vec<u8> {
        let mut bytes = Vec::new();
        value.write_encoded(Mode::Der, &mut bytes).unwrap();
        bytes
    }

    fn imprint() -> MessageImprint {
        MessageImprint {
            hash_algorithm: AlgorithmIdentifier {
                algorithm: Oid::from_str("2.16.840.1.101.3.4.2.1").unwrap(),
            },

            hashed_message: OctetString::new(vec![0xab; 32].into()),
        }
    }

    fn extensions() -> Extensions {
        Constructed::decode([0x30, 0].as_slice(), Mode::Der, |cons| {
            cons.take_sequence(Extensions::from_constructed)
        })
        .unwrap()
    }

    #[test]
    fn request_roundtrips_optional_policy_nonce_certificate_and_extensions() {
        for include_optional in [false, true] {
            let request = TimeStampReq {
                version: 1.into(),
                message_imprint: imprint(),
                req_policy: include_optional.then(|| Oid::from_str("1.2.3.4").unwrap()),
                nonce: include_optional.then(|| Integer::from(u64::MAX)),
                cert_req: include_optional.then_some(true),
                extensions: None,
            };

            let der = encoded(request.encode_ref());

            let decoded =
                Constructed::decode(der.as_slice(), Mode::Der, TimeStampReq::take_from).unwrap();

            assert_eq!(decoded, request);

            assert!(
                Constructed::decode(&der[..der.len() - 1], Mode::Der, TimeStampReq::take_from)
                    .is_err()
            );
        }

        let request = TimeStampReq {
            version: 1.into(),
            message_imprint: imprint(),
            req_policy: None,
            nonce: None,
            cert_req: None,
            extensions: Some(extensions()),
        };

        let mut der = encoded(request.encode_ref());

        // Existing Extensions encoding emits a primitive context tag, whereas
        // its decoder (and RFC 3161) expects a constructed tag.
        assert_eq!(der[der.len() - 2], 0x80);

        assert!(Constructed::decode(der.as_slice(), Mode::Der, TimeStampReq::take_from).is_err());

        let tag_pos = der.len() - 2;
        der[tag_pos] = 0xa0;

        assert_eq!(
            Constructed::decode(der.as_slice(), Mode::Der, TimeStampReq::take_from).unwrap(),
            request
        );
    }

    #[test]
    fn tst_info_preserves_optional_fields_and_large_serials() {
        let info = TstInfo {
            version: 1.into(),
            policy: Oid::from_str("1.2.3.4").unwrap(),
            message_imprint: imprint(),
            serial_number: u64::MAX.into(),

            gen_time: Utc
                .timestamp_opt(1_577_836_800, 0)
                .single()
                .unwrap()
                .try_into()
                .unwrap(),

            accuracy: Some(Accuracy {
                seconds: Some(2.into()),
                millis: None,
                micros: None,
            }),

            ordering: Some(true),
            nonce: Some(42.into()),
            tsa: None,
            extensions: None,
        };

        let mut der = encoded(info.encode_ref());

        // GeneralizedTime::encode_ref currently wraps the complete time DER
        // in an OCTET STRING, so TstInfo encoding does not round trip as-is.
        assert!(Constructed::decode(der.as_slice(), Mode::Der, TstInfo::take_from).is_err());

        let time = info.gen_time.as_der_bytes();

        let time_pos = der
            .windows(time.len())
            .position(|window| window == time)
            .unwrap();

        assert_eq!(&der[time_pos - 2..time_pos], &[4, time.len() as u8]);

        der.drain(time_pos - 2..time_pos);
        der[1] -= 2;

        assert_eq!(
            Constructed::decode(der.as_slice(), Mode::Der, TstInfo::take_from).unwrap(),
            info
        );

        let optional = [0xa0, 5, 0x82, 3, b't', b's', b'a', 0xa1, 0];
        assert!(der.len() + optional.len() < 128);
        der[1] += optional.len() as u8;
        der.extend(optional);

        let decoded = Constructed::decode(der.as_slice(), Mode::Der, TstInfo::take_from).unwrap();
        assert!(decoded.tsa.is_some());
        assert!(decoded.extensions.is_some());
        assert_eq!(decoded.nonce, info.nonce);
    }

    #[test]
    fn accuracy_decodes_implicit_subseconds_but_encoder_uses_integer_tags() {
        let der = [0x30, 9, 2, 1, 2, 0x80, 1, 3, 0x81, 1, 4];

        let accuracy = Constructed::decode(der.as_slice(), Mode::Der, Accuracy::take_opt_from)
            .unwrap()
            .unwrap();

        assert_eq!(accuracy.seconds, Some(2.into()));
        assert_eq!(accuracy.millis, Some(3.into()));
        assert_eq!(accuracy.micros, Some(4.into()));

        // Characterize the existing non-round-tripping encoder; RFC 3161
        // requires context tags on millis/micros, not universal INTEGER tags.
        assert_eq!(
            encoded(accuracy.encode_ref()),
            [0x30, 9, 2, 1, 2, 2, 1, 3, 2, 1, 4]
        );

        assert!(Constructed::decode(
            encoded(accuracy.encode_ref()).as_slice(),
            Mode::Der,
            Accuracy::take_opt_from
        )
        .is_err());
    }

    #[test]
    fn response_status_text_and_legacy_integer_failure_info_are_decoded() {
        for status in [
            PkiStatus::Granted,
            PkiStatus::GrantedWithMods,
            PkiStatus::Rejection,
            PkiStatus::Waiting,
            PkiStatus::RevocationWarning,
            PkiStatus::RevocationNotification,
        ] {
            let der = encoded(encode::sequence(encode::sequence(status.encode())));

            let response =
                Constructed::decode(der.as_slice(), Mode::Der, TimeStampResp::take_from).unwrap();

            assert_eq!(response.status.status, status);
            assert!(response.time_stamp_token.is_none());
        }

        for failure in [
            PkiFailureInfo::BadAlg,
            PkiFailureInfo::BadRequest,
            PkiFailureInfo::BadDataFormat,
            PkiFailureInfo::TimeNotAvailable,
            PkiFailureInfo::UnacceptedPolicy,
            PkiFailureInfo::UnacceptedExtension,
            PkiFailureInfo::AddInfoNotAvailable,
            PkiFailureInfo::SystemFailure,
        ] {
            let der = encoded(encode::sequence(encode::sequence((
                PkiStatus::Rejection.encode(),
                encode::sequence((
                    bcder::Utf8String::from_str("rejected").unwrap().encode(),
                    bcder::Utf8String::from_str("retry").unwrap().encode(),
                )),
                failure.encode(),
            ))));

            let response =
                Constructed::decode(der.as_slice(), Mode::Der, TimeStampResp::take_from).unwrap();

            assert_eq!(response.status.fail_info, Some(failure));
            assert!(response.status.status_string.is_some());
            let der = encoded(failure.encode());

            assert_eq!(
                Constructed::decode(der.as_slice(), Mode::Der, PkiFailureInfo::take_from).unwrap(),
                failure
            );
        }

        for bad in [-1i8, 6, 127] {
            let der = encoded(bad.encode());
            assert!(Constructed::decode(der.as_slice(), Mode::Der, PkiStatus::take_from).is_err());

            assert!(
                Constructed::decode(der.as_slice(), Mode::Der, PkiFailureInfo::take_from).is_err()
            );
        }

        // The existing failure parser accepts INTEGER rather than the
        // BIT STRING required by RFC 3161; standard badAlg is rejected.
        let standard = [0x30, 9, 0x30, 7, 2, 1, 2, 3, 2, 7, 0x80];

        assert!(
            Constructed::decode(standard.as_slice(), Mode::Der, TimeStampResp::take_from).is_err()
        );
    }
}
