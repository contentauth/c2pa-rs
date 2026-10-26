// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! ASN.1 types defined by [RFC 5652].
//!
//! [RFC 5652]: https://datatracker.ietf.org/doc/html/rfc5652
//!
//! The types defined in this module are intended to be extremely low-level and
//! only to be used for (de)serialization. See types outside the `asn1` module
//! tree for higher-level functionality.
//!
//! Some RFC 5652 types are defined in the `x509-certificate` crate, which this
//! crate relies on for certificate parsing functionality.

use std::{
    fmt::{Debug, Formatter},
    io::Write,
    ops::{Deref, DerefMut},
};

use bcder::{
    decode::{Constructed, DecodeError, Primitive, Source},
    encode,
    encode::{PrimitiveContent, Values},
    BitString, Captured, ConstOid, Integer, Mode, OctetString, Oid, Tag,
};
use der::Decode;

// Re-use common types from parent module
use super::{AlgorithmIdentifier, GeneralizedTime};
use crate::asn1::rfc3281::AttributeCertificate;

// Define local bcder-compatible types to replace x509_certificate imports

/// UTC time compatible with bcder - hybrid approach using der crate
#[derive(Clone, Debug)]
pub(crate) struct UtcTime {
    // Store the der type for proper time parsing (handles Y2K correctly)
    der_time: der::asn1::UtcTime,

    // Cache the DER encoding for bcder compatibility
    der_bytes: Vec<u8>,
}

impl PartialEq for UtcTime {
    fn eq(&self, other: &Self) -> bool {
        self.der_time == other.der_time
    }
}

impl Eq for UtcTime {}

impl UtcTime {
    pub(crate) fn from_primitive<S: Source>(
        prim: &mut Primitive<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        // Get the raw bytes (without tag/length)
        let bytes = prim.take_all()?;

        // Reconstruct DER encoding using helper (tag 0x17 = UTC_TIME)
        let der_bytes = super::reconstruct_der_bytes(0x17, bytes.as_ref())
            .map_err(|_| DecodeError::content("failed to reconstruct DER bytes", prim.pos()))?;

        // Parse with der crate - it handles Y2K correctly and validates format
        let der_time = der::asn1::UtcTime::from_der(&der_bytes)
            .map_err(|_| DecodeError::content("invalid UtcTime", prim.pos()))?;

        Ok(UtcTime {
            der_time,
            der_bytes,
        })
    }

    /// Convert to chrono DateTime
    pub(crate) fn to_datetime(&self) -> chrono::DateTime<chrono::Utc> {
        // Convert der's time to SystemTime, then to chrono
        let system_time = self.der_time.to_system_time();
        system_time.into()
    }
}

impl Values for UtcTime {
    fn encoded_len(&self, _mode: Mode) -> usize {
        self.der_bytes.len()
    }

    fn write_encoded<W: Write>(&self, _mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        target.write_all(&self.der_bytes)
    }
}

/// Name type (opaque - just captures the DER encoding)
#[derive(Clone, Debug)]
pub struct Name(Captured);

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for Name {}

impl Name {
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.capture_one().map(Name)
    }

    pub(crate) fn encode_ref(&self) -> impl Values + '_ {
        &self.0
    }
}

/// Certificate type (opaque - just captures the DER encoding)
#[derive(Clone, Debug)]
pub(crate) struct Certificate(Captured);

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for Certificate {}

impl Certificate {
    pub(crate) fn from_sequence<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.capture_all().map(Certificate)
    }

    pub(crate) fn encode_ref(&self) -> impl Values + '_ {
        &self.0
    }
}

/// Attribute type with type and values fields
#[derive(Clone, Debug)]
pub(crate) struct Attribute {
    pub(crate) typ: Oid,

    pub(crate) values: Captured,
}

impl PartialEq for Attribute {
    fn eq(&self, other: &Self) -> bool {
        self.typ == other.typ && self.values.as_slice() == other.values.as_slice()
    }
}

impl Eq for Attribute {}

impl Attribute {
    pub(crate) fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let typ = Oid::take_from(cons)?;
            let values = cons.capture_all()?;
            Ok(Attribute { typ, values })
        })
    }

    pub(crate) fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((self.typ.encode_ref(), &self.values))
    }
}

impl PrimitiveContent for Attribute {
    const TAG: Tag = Tag::SEQUENCE;

    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

/// Certificate list type (opaque - just captures the DER encoding)
#[derive(Clone, Debug)]
pub(crate) struct CertificateList(Captured);

impl PartialEq for CertificateList {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for CertificateList {}

/// The signed-data content type.
///
/// 1.2.840.113549.1.7.2
pub const OID_ID_SIGNED_DATA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 2]);

/// Identifies the message-digest attribute.
///
/// 1.2.840.113549.1.9.4
pub(crate) const OID_MESSAGE_DIGEST: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 4]);

/// Identifies the signing-time attribute.
///
/// 1.2.840.113549.1.9.5
pub(crate) const OID_SIGNING_TIME: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 5]);

/// Content info.
///
/// ```ASN.1
/// ContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   content [0] EXPLICIT ANY DEFINED BY contentType }
/// ```
#[derive(Clone, Debug)]
pub struct ContentInfo {
    /// Object identifier selecting the syntax of the encapsulated content.
    pub content_type: ContentType,

    /// Captured encoded content, not a verified signature or trust result.
    pub content: Captured,
}

impl PartialEq for ContentInfo {
    fn eq(&self, other: &Self) -> bool {
        self.content_type == other.content_type
            && self.content.as_slice() == other.content.as_slice()
    }
}

impl Eq for ContentInfo {}

impl ContentInfo {
    /// Decode an optional CMS content envelope from its SEQUENCE.
    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| Self::from_sequence(cons))
    }

    pub(crate) fn from_sequence<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let content_type = ContentType::take_from(cons)?;
        let content = cons.take_constructed_if(Tag::CTX_0, |cons| cons.capture_all())?;

        Ok(Self {
            content_type,
            content,
        })
    }
}

impl Values for ContentInfo {
    fn encoded_len(&self, mode: Mode) -> usize {
        encode::sequence((self.content_type.encode_ref(), &self.content)).encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        encode::sequence((self.content_type.encode_ref(), &self.content))
            .write_encoded(mode, target)
    }
}

/// Represents signed data.
///
/// ASN.1 type specification:
///
/// ```ASN.1
/// SignedData ::= SEQUENCE {
///   version CMSVersion,
///   digestAlgorithms DigestAlgorithmIdentifiers,
///   encapContentInfo EncapsulatedContentInfo,
///   certificates [0] IMPLICIT CertificateSet OPTIONAL,
///   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///   signerInfos SignerInfos }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedData {
    pub(crate) version: CmsVersion,

    /// Digest algorithms declared by the CMS signers.
    pub digest_algorithms: DigestAlgorithmIdentifiers,

    pub(crate) content_info: EncapsulatedContentInfo,

    pub(crate) certificates: Option<CertificateSet>,

    pub(crate) crls: Option<RevocationInfoChoices>,

    /// Per-signer signature metadata.
    pub signer_infos: SignerInfos,
}

impl SignedData {
    /// Decode CMS SignedData without verifying its signatures.
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let version = CmsVersion::take_from(cons)?;
            let digest_algorithms = DigestAlgorithmIdentifiers::take_from(cons)?;
            let content_info = EncapsulatedContentInfo::take_from(cons)?;

            let certificates =
                cons.take_opt_constructed_if(Tag::CTX_0, |cons| CertificateSet::take_from(cons))?;

            let crls = cons.take_opt_constructed_if(Tag::CTX_1, |cons| {
                RevocationInfoChoices::take_from(cons)
            })?;

            let signer_infos = SignerInfos::take_from(cons)?;

            Ok(Self {
                version,
                digest_algorithms,
                content_info,
                certificates,
                crls,
                signer_infos,
            })
        })
    }
}

/// Digest algorithm identifiers.
///
/// ```ASN.1
/// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DigestAlgorithmIdentifiers(Vec<DigestAlgorithmIdentifier>);

impl Deref for DigestAlgorithmIdentifiers {
    type Target = Vec<DigestAlgorithmIdentifier>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DigestAlgorithmIdentifiers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl DigestAlgorithmIdentifiers {
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_set(|cons| {
            let mut identifiers = Vec::new();

            while let Some(identifier) = AlgorithmIdentifier::take_opt_from(cons)? {
                identifiers.push(identifier);
            }

            Ok(Self(identifiers))
        })
    }
}

pub(crate) type DigestAlgorithmIdentifier = AlgorithmIdentifier;

/// Signer infos.
///
/// ```ASN.1
/// SignerInfos ::= SET OF SignerInfo
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SignerInfos(Vec<SignerInfo>);

impl Deref for SignerInfos {
    type Target = Vec<SignerInfo>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SignerInfos {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl SignerInfos {
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_set(|cons| {
            let mut infos = Vec::new();

            while let Some(info) = SignerInfo::take_opt_from(cons)? {
                infos.push(info);
            }

            Ok(Self(infos))
        })
    }
}

/// Encapsulated content info.
///
/// ```ASN.1
/// EncapsulatedContentInfo ::= SEQUENCE {
///   eContentType ContentType,
///   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct EncapsulatedContentInfo {
    pub(crate) content_type: ContentType,

    pub(crate) content: Option<OctetString>,
}

impl Debug for EncapsulatedContentInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("EncapsulatedContentInfo");
        s.field("content_type", &format_args!("{}", self.content_type));

        s.field(
            "content",
            &format_args!(
                "{:?}",
                self.content
                    .as_ref()
                    .map(|x| hex::encode(x.clone().to_bytes().as_ref()))
            ),
        );

        s.finish()
    }
}

impl EncapsulatedContentInfo {
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let content_type = ContentType::take_from(cons)?;

            let content =
                cons.take_opt_constructed_if(Tag::CTX_0, |cons| OctetString::take_from(cons))?;

            Ok(Self {
                content_type,
                content,
            })
        })
    }
}

/// Per-signer information.
///
/// ```ASN.1
/// SignerInfo ::= SEQUENCE {
///   version CMSVersion,
///   sid SignerIdentifier,
///   digestAlgorithm DigestAlgorithmIdentifier,
///   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///   signatureAlgorithm SignatureAlgorithmIdentifier,
///   signature SignatureValue,
///   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct SignerInfo {
    pub(crate) version: CmsVersion,

    /// Certificate identifier of the signer.
    pub sid: SignerIdentifier,

    pub(crate) digest_algorithm: DigestAlgorithmIdentifier,

    pub(crate) signed_attributes: Option<SignedAttributes>,

    pub(crate) signature_algorithm: SignatureAlgorithmIdentifier,

    /// Raw CMS signature value.
    pub signature: SignatureValue,

    pub(crate) unsigned_attributes: Option<UnsignedAttributes>,

    /// Raw bytes backing signed attributes data.
    ///
    /// Does not include constructed tag or length bytes.
    pub signed_attributes_data: Option<Vec<u8>>,
}

impl SignerInfo {
    /// Decode optional signer metadata without verifying its signature.
    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| Self::from_sequence(cons))
    }

    pub(crate) fn from_sequence<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let version = CmsVersion::take_from(cons)?;
        let sid = SignerIdentifier::take_from(cons)?;
        let digest_algorithm = DigestAlgorithmIdentifier::take_from(cons)?;

        let signed_attributes = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
            // RFC 5652 Section 5.3: SignedAttributes MUST be DER encoded, even if the
            // rest of the structure is BER encoded. So buffer all data so we can
            // feed into a new decoder.
            let der = cons.capture_all()?;

            // But wait there's more! The raw data constituting the signed
            // attributes is also digested and used for content/signature
            // verification. Because our DER serialization may not roundtrip
            // losslessly, we stash away a copy of these bytes so they may be
            // referenced as part of verification.
            let der_data = der.as_slice().to_vec();

            Ok((
                Constructed::decode(der.as_slice(), bcder::Mode::Der, |cons| {
                    SignedAttributes::take_from_set(cons)
                })
                .map_err(|e| e.convert())?,
                der_data,
            ))
        })?;

        let (signed_attributes, signed_attributes_data) = if let Some((x, y)) = signed_attributes {
            (Some(x), Some(y))
        } else {
            (None, None)
        };

        let signature_algorithm = SignatureAlgorithmIdentifier::take_from(cons)?;
        let signature = SignatureValue::take_from(cons)?;

        let unsigned_attributes = cons
            .take_opt_constructed_if(Tag::CTX_1, |cons| UnsignedAttributes::take_from_set(cons))?;

        Ok(Self {
            version,
            sid,
            digest_algorithm,
            signed_attributes,
            signature_algorithm,
            signature,
            unsigned_attributes,
            signed_attributes_data,
        })
    }

    /// Borrow an encoder for the signer metadata.
    ///
    /// Use `signed_attributes_digested_content` for signature input instead.
    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            u8::from(self.version).encode(),
            &self.sid,
            &self.digest_algorithm,
            // Always write signed attributes with DER encoding per RFC 5652.
            self.signed_attributes
                .as_ref()
                .map(|attrs| SignedAttributesDer::new(attrs.clone(), Some(Tag::CTX_0))),
            &self.signature_algorithm,
            self.signature.encode_ref(),
            self.unsigned_attributes
                .as_ref()
                .map(|attrs| attrs.encode_ref_as(Tag::CTX_1)),
        ))
    }

    /// Obtain content representing the signed attributes data to be digested.
    ///
    /// Computing the content to go into the digest calculation is nuanced.
    /// From RFC 5652:
    ///
    ///    The result of the message digest calculation process depends on
    ///    whether the signedAttrs field is present.  When the field is absent,
    ///    the result is just the message digest of the content as described
    ///    above.  When the field is present, however, the result is the message
    ///    digest of the complete DER encoding of the SignedAttrs value
    ///    contained in the signedAttrs field.  Since the SignedAttrs value,
    ///    when present, must contain the content-type and the message-digest
    ///    attributes, those values are indirectly included in the result.  The
    ///    content-type attribute MUST NOT be included in a countersignature
    ///    unsigned attribute as defined in Section 11.4.  A separate encoding
    ///    of the signedAttrs field is performed for message digest calculation.
    ///    The `IMPLICIT [0]` tag in the signedAttrs is not used for the DER
    ///    encoding, rather an EXPLICIT SET OF tag is used.  That is, the DER
    ///    encoding of the EXPLICIT SET OF tag, rather than of the `IMPLICIT
    /// [0]`    tag, MUST be included in the message digest calculation
    /// along with    the length and content octets of the SignedAttributes
    /// value.
    ///
    /// A few things to note here:
    ///
    /// * We must ensure DER (not BER) encoding of the entire SignedAttrs
    ///   values.
    /// * The SignedAttr tag must use `EXPLICIT SET OF` instead of `IMPLICIT
    ///   [0]`, so default encoding is not appropriate.
    /// * If this instance came into existence via a parse, we stashed away the
    ///   raw bytes constituting SignedAttributes to ensure we can do a lossless
    ///   copy.
    pub fn signed_attributes_digested_content(&self) -> Result<Option<Vec<u8>>, std::io::Error> {
        if let Some(signed_attributes) = &self.signed_attributes {
            if let Some(existing_data) = &self.signed_attributes_data {
                // +8 should be enough for tag + length.
                let mut buffer = Vec::with_capacity(existing_data.len() + 8);
                // EXPLICIT SET OF.
                buffer.write_all(&[0x31])?;

                // Length isn't exported by bcder :/ So do length encoding manually.
                if existing_data.len() < 0x80 {
                    buffer.write_all(&[existing_data.len() as u8])?;
                } else if existing_data.len() < 0x100 {
                    buffer.write_all(&[0x81, existing_data.len() as u8])?;
                } else if existing_data.len() < 0x10000 {
                    buffer.write_all(&[
                        0x82,
                        (existing_data.len() >> 8) as u8,
                        existing_data.len() as u8,
                    ])?;
                } else if existing_data.len() < 0x1000000 {
                    buffer.write_all(&[
                        0x83,
                        (existing_data.len() >> 16) as u8,
                        (existing_data.len() >> 8) as u8,
                        existing_data.len() as u8,
                    ])?;
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "signed attributes length too long",
                    ));
                }

                buffer.write_all(existing_data)?;

                Ok(Some(buffer))
            } else {
                // No existing copy present. Serialize from raw data structures.
                // But we obtain a sorted instance of those attributes first, because
                // bcder doesn't appear to follow DER encoding rules for sets.
                let signed_attributes = signed_attributes.as_sorted()?;
                let mut der = Vec::new();
                // The mode argument here is actually ignored.
                signed_attributes.write_encoded(Mode::Der, &mut der)?;

                Ok(Some(der))
            }
        } else {
            Ok(None)
        }
    }
}

impl Debug for SignerInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SignerInfo");

        s.field("version", &self.version);
        s.field("sid", &self.sid);
        s.field("digest_algorithm", &self.digest_algorithm);
        s.field("signed_attributes", &self.signed_attributes);
        s.field("signature_algorithm", &self.signature_algorithm);

        s.field(
            "signature",
            &format_args!(
                "{}",
                hex::encode(self.signature.clone().into_bytes().as_ref())
            ),
        );

        s.field("unsigned_attributes", &self.unsigned_attributes);

        s.field(
            "signed_attributes_data",
            &format_args!(
                "{:?}",
                self.signed_attributes_data.as_ref().map(hex::encode)
            ),
        );

        s.finish()
    }
}

impl Values for SignerInfo {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

/// Identifies the signer.
///
/// ```ASN.1
/// SignerIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier [0] SubjectKeyIdentifier }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignerIdentifier {
    /// Identify a signing certificate by its issuer and serial number.
    IssuerAndSerialNumber(IssuerAndSerialNumber),

    /// Identify a signing certificate by its subject key identifier.
    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

impl SignerIdentifier {
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        if let Some(identifier) =
            cons.take_opt_constructed_if(Tag::CTX_0, |cons| SubjectKeyIdentifier::take_from(cons))?
        {
            Ok(Self::SubjectKeyIdentifier(identifier))
        } else {
            Ok(Self::IssuerAndSerialNumber(
                IssuerAndSerialNumber::take_from(cons)?,
            ))
        }
    }
}

impl Values for SignerIdentifier {
    fn encoded_len(&self, mode: Mode) -> usize {
        match self {
            Self::IssuerAndSerialNumber(v) => v.encode_ref().encoded_len(mode),
            Self::SubjectKeyIdentifier(v) => v.encode_ref_as(Tag::CTX_0).encoded_len(mode),
        }
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        match self {
            Self::IssuerAndSerialNumber(v) => v.encode_ref().write_encoded(mode, target),

            Self::SubjectKeyIdentifier(v) => {
                v.encode_ref_as(Tag::CTX_0).write_encoded(mode, target)
            }
        }
    }
}

/// Signed attributes.
///
/// ```ASN.1
/// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct SignedAttributes(Vec<Attribute>);

impl Deref for SignedAttributes {
    type Target = Vec<Attribute>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SignedAttributes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl SignedAttributes {
    pub(crate) fn take_from_set<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let mut attributes = Vec::new();

        while let Some(attribute) = Attribute::take_opt_from(cons)? {
            attributes.push(attribute);
        }

        Ok(Self(attributes))
    }

    /// Obtain an instance where the attributes are sorted according to DER
    /// rules. See the comment in
    /// [SignerInfo::signed_attributes_digested_content].
    pub(crate) fn as_sorted(&self) -> Result<Self, std::io::Error> {
        // All elements of the set have the same type. So sorting is based on encoded
        // values, with shorter elements padded with 0s. Rust will sort a shorter value
        // with a prefix match against a longer value as less than, so we can avoid the
        // padding.

        let mut attributes = self
            .0
            .iter()
            .map(|x| {
                let mut encoded = vec![];
                x.values.write_encoded(Mode::Der, &mut encoded)?;

                Ok((encoded, x.clone()))
            })
            .collect::<Result<Vec<(_, _)>, std::io::Error>>()?;

        attributes.sort_by(|(a, _), (b, _)| a.cmp(b));

        Ok(Self(
            attributes.into_iter().map(|(_, x)| x).collect::<Vec<_>>(),
        ))
    }

    fn encode_ref(&self) -> impl Values + '_ {
        encode::set(encode::slice(&self.0, |x| x.clone().encode()))
    }

    fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::set_as(tag, encode::slice(&self.0, |x| x.clone().encode()))
    }
}

impl Values for SignedAttributes {
    // SignedAttributes are always written as DER encoded.
    fn encoded_len(&self, _: Mode) -> usize {
        self.encode_ref().encoded_len(Mode::Der)
    }

    fn write_encoded<W: Write>(&self, _: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(Mode::Der, target)
    }
}

pub(crate) struct SignedAttributesDer(SignedAttributes, Option<Tag>);

impl SignedAttributesDer {
    pub(crate) fn new(sa: SignedAttributes, tag: Option<Tag>) -> Self {
        Self(sa, tag)
    }
}

impl Values for SignedAttributesDer {
    fn encoded_len(&self, _: Mode) -> usize {
        if let Some(tag) = &self.1 {
            self.0.encode_ref_as(*tag).encoded_len(Mode::Der)
        } else {
            self.0.encode_ref().encoded_len(Mode::Der)
        }
    }

    fn write_encoded<W: Write>(&self, _: Mode, target: &mut W) -> Result<(), std::io::Error> {
        if let Some(tag) = &self.1 {
            self.0.encode_ref_as(*tag).write_encoded(Mode::Der, target)
        } else {
            self.0.encode_ref().write_encoded(Mode::Der, target)
        }
    }
}

/// Unsigned attributes.
///
/// ```ASN.1
/// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct UnsignedAttributes(Vec<Attribute>);

impl Deref for UnsignedAttributes {
    type Target = Vec<Attribute>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for UnsignedAttributes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl UnsignedAttributes {
    pub(crate) fn take_from_set<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let mut attributes = Vec::new();

        while let Some(attribute) = Attribute::take_opt_from(cons)? {
            attributes.push(attribute);
        }

        Ok(Self(attributes))
    }

    pub(crate) fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::set_as(tag, encode::slice(&self.0, |x| x.clone().encode()))
    }
}

pub(crate) type SignatureValue = OctetString;

/// Enveloped-data content type.
///
/// ```ASN.1
/// EnvelopedData ::= SEQUENCE {
///   version CMSVersion,
///   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
///   recipientInfos RecipientInfos,
///   encryptedContentInfo EncryptedContentInfo,
///   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EnvelopedData {
    pub(crate) version: CmsVersion,

    pub(crate) originator_info: Option<OriginatorInfo>,

    pub(crate) recipient_infos: RecipientInfos,

    pub(crate) encrypted_content_info: EncryptedContentInfo,

    pub(crate) unprotected_attributes: Option<UnprotectedAttributes>,
}

/// Originator info.
///
/// ```ASN.1
/// OriginatorInfo ::= SEQUENCE {
///   certs [0] IMPLICIT CertificateSet OPTIONAL,
///   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OriginatorInfo {
    pub(crate) certs: Option<CertificateSet>,

    pub(crate) crls: Option<RevocationInfoChoices>,
}

pub(crate) type RecipientInfos = Vec<RecipientInfo>;

/// Encrypted content info.
///
/// ```ASN.1
/// EncryptedContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
///   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EncryptedContentInfo {
    pub(crate) content_type: ContentType,

    pub(crate) content_encryption_algorithms: ContentEncryptionAlgorithmIdentifier,

    pub(crate) encrypted_content: Option<EncryptedContent>,
}

pub(crate) type EncryptedContent = OctetString;

pub(crate) type UnprotectedAttributes = Vec<Attribute>;

/// Recipient info.
///
/// ```ASN.1
/// RecipientInfo ::= CHOICE {
///   ktri KeyTransRecipientInfo,
///   kari [1] KeyAgreeRecipientInfo,
///   kekri [2] KEKRecipientInfo,
///   pwri [3] PasswordRecipientinfo,
///   ori [4] OtherRecipientInfo }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(unused)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum RecipientInfo {
    KeyTransRecipientInfo(KeyTransRecipientInfo),

    KeyAgreeRecipientInfo(KeyAgreeRecipientInfo),

    KekRecipientInfo(KekRecipientInfo),

    PasswordRecipientInfo(PasswordRecipientInfo),

    OtherRecipientInfo(OtherRecipientInfo),
}

pub(crate) type EncryptedKey = OctetString;

/// Key trans recipient info.
///
/// ```ASN.1
/// KeyTransRecipientInfo ::= SEQUENCE {
///   version CMSVersion,  -- always set to 0 or 2
///   rid RecipientIdentifier,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   encryptedKey EncryptedKey }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KeyTransRecipientInfo {
    pub(crate) version: CmsVersion,

    pub(crate) rid: RecipientIdentifier,

    pub(crate) key_encryption_algorithm: KeyEncryptionAlgorithmIdentifier,

    pub(crate) encrypted_key: EncryptedKey,
}

/// Recipient identifier.
///
/// ```ASN.1
/// RecipientIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier [0] SubjectKeyIdentifier }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(unused)]
pub(crate) enum RecipientIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),

    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

/// Key agreement recipient info.
///
/// ```ASN.1
/// KeyAgreeRecipientInfo ::= SEQUENCE {
///   version CMSVersion,  -- always set to 3
///   originator [0] EXPLICIT OriginatorIdentifierOrKey,
///   ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   recipientEncryptedKeys RecipientEncryptedKeys }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KeyAgreeRecipientInfo {
    pub(crate) version: CmsVersion,

    pub(crate) originator: OriginatorIdentifierOrKey,

    pub(crate) ukm: Option<UserKeyingMaterial>,

    pub(crate) key_encryption_algorithm: KeyEncryptionAlgorithmIdentifier,

    pub(crate) recipient_encrypted_keys: RecipientEncryptedKeys,
}

/// Originator identifier or key.
///
/// ```ASN.1
/// OriginatorIdentifierOrKey ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier [0] SubjectKeyIdentifier,
///   originatorKey [1] OriginatorPublicKey }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(unused)]
pub(crate) enum OriginatorIdentifierOrKey {
    IssuerAndSerialNumber(IssuerAndSerialNumber),

    SubjectKeyIdentifier(SubjectKeyIdentifier),

    OriginatorKey(OriginatorPublicKey),
}

/// Originator public key.
///
/// ```ASN.1
/// OriginatorPublicKey ::= SEQUENCE {
///   algorithm AlgorithmIdentifier,
///   publicKey BIT STRING }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OriginatorPublicKey {
    pub(crate) algorithm: AlgorithmIdentifier,

    pub(crate) public_key: BitString,
}

/// SEQUENCE of RecipientEncryptedKey.
type RecipientEncryptedKeys = Vec<RecipientEncryptedKey>;

/// Recipient encrypted key.
///
/// ```ASN.1
/// RecipientEncryptedKey ::= SEQUENCE {
///   rid KeyAgreeRecipientIdentifier,
///   encryptedKey EncryptedKey }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecipientEncryptedKey {
    pub(crate) rid: KeyAgreeRecipientInfo,

    pub(crate) encrypted_key: EncryptedKey,
}

/// Key agreement recipient identifier.
///
/// ```ASN.1
/// KeyAgreeRecipientIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   rKeyId [0] IMPLICIT RecipientKeyIdentifier }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(unused)]
pub(crate) enum KeyAgreeRecipientIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),

    RKeyId(RecipientKeyIdentifier),
}

/// Recipient key identifier.
///
/// ```ASN.1
/// RecipientKeyIdentifier ::= SEQUENCE {
///   subjectKeyIdentifier SubjectKeyIdentifier,
///   date GeneralizedTime OPTIONAL,
///   other OtherKeyAttribute OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecipientKeyIdentifier {
    pub(crate) subject_key_identifier: SubjectKeyIdentifier,

    pub(crate) date: Option<GeneralizedTime>,

    pub(crate) other: Option<OtherKeyAttribute>,
}

type SubjectKeyIdentifier = OctetString;

/// Key encryption key recipient info.
///
/// ```ASN.1
/// KEKRecipientInfo ::= SEQUENCE {
///   version CMSVersion,  -- always set to 4
///   kekid KEKIdentifier,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   encryptedKey EncryptedKey }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KekRecipientInfo {
    pub(crate) version: CmsVersion,

    pub(crate) kek_id: KekIdentifier,

    pub(crate) kek_encryption_algorithm: KeyEncryptionAlgorithmIdentifier,

    pub(crate) encrypted_key: EncryptedKey,
}

/// Key encryption key identifier.
///
/// ```ASN.1
/// KEKIdentifier ::= SEQUENCE {
///   keyIdentifier OCTET STRING,
///   date GeneralizedTime OPTIONAL,
///   other OtherKeyAttribute OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KekIdentifier {
    pub(crate) key_identifier: OctetString,

    pub(crate) date: Option<GeneralizedTime>,

    pub(crate) other: Option<OtherKeyAttribute>,
}

/// Password recipient info.
///
/// ```ASN.1
/// PasswordRecipientInfo ::= SEQUENCE {
///   version CMSVersion,   -- Always set to 0
///   keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
///                                OPTIONAL,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   encryptedKey EncryptedKey }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PasswordRecipientInfo {
    pub(crate) version: CmsVersion,

    pub(crate) key_derivation_algorithm: Option<KeyDerivationAlgorithmIdentifier>,

    pub(crate) key_encryption_algorithm: KeyEncryptionAlgorithmIdentifier,

    pub(crate) encrypted_key: EncryptedKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OtherRecipientInfo {
    pub(crate) ori_type: Oid,

    // TODO Any
    pub(crate) ori_value: Option<()>,
}

/// Digested data.
///
/// ```ASN.1
/// DigestedData ::= SEQUENCE {
///   version CMSVersion,
///   digestAlgorithm DigestAlgorithmIdentifier,
///   encapContentInfo EncapsulatedContentInfo,
///   digest Digest }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DigestedData {
    pub(crate) version: CmsVersion,

    pub(crate) digest_algorithm: DigestAlgorithmIdentifier,

    pub(crate) content_type: EncapsulatedContentInfo,

    pub(crate) digest: Digest,
}

pub(crate) type Digest = OctetString;

/// Encrypted data.
///
/// ```ASN.1
/// EncryptedData ::= SEQUENCE {
///   version CMSVersion,
///   encryptedContentInfo EncryptedContentInfo,
///   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EncryptedData {
    pub(crate) version: CmsVersion,

    pub(crate) encrypted_content_info: EncryptedContentInfo,

    pub(crate) unprotected_attributes: Option<UnprotectedAttributes>,
}

/// Authenticated data.
///
/// ```ASN.1
/// AuthenticatedData ::= SEQUENCE {
///   version CMSVersion,
///   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
///   recipientInfos RecipientInfos,
///   macAlgorithm MessageAuthenticationCodeAlgorithm,
///   digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
///   encapContentInfo EncapsulatedContentInfo,
///   authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
///   mac MessageAuthenticationCode,
///   unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedData {
    pub(crate) version: CmsVersion,

    pub(crate) originator_info: Option<OriginatorInfo>,

    pub(crate) recipient_infos: RecipientInfos,

    pub(crate) mac_algorithm: MessageAuthenticationCodeAlgorithm,

    pub(crate) digest_algorithm: Option<DigestAlgorithmIdentifier>,

    pub(crate) content_info: EncapsulatedContentInfo,

    pub(crate) authenticated_attributes: Option<AuthAttributes>,

    pub(crate) mac: MessageAuthenticationCode,

    pub(crate) unauthenticated_attributes: Option<UnauthAttributes>,
}

pub(crate) type AuthAttributes = Vec<Attribute>;

pub(crate) type UnauthAttributes = Vec<Attribute>;

pub(crate) type MessageAuthenticationCode = OctetString;

pub(crate) type SignatureAlgorithmIdentifier = AlgorithmIdentifier;

pub(crate) type KeyEncryptionAlgorithmIdentifier = AlgorithmIdentifier;

pub(crate) type ContentEncryptionAlgorithmIdentifier = AlgorithmIdentifier;

pub(crate) type MessageAuthenticationCodeAlgorithm = AlgorithmIdentifier;

pub(crate) type KeyDerivationAlgorithmIdentifier = AlgorithmIdentifier;

/// Revocation info choices.
///
/// ```ASN.1
/// RevocationInfoChoices ::= SET OF RevocationInfoChoice
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RevocationInfoChoices(Vec<RevocationInfoChoice>);

impl RevocationInfoChoices {
    pub(crate) fn take_from<S: Source>(
        cons: &Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        Err(cons.content_err("RevocationInfoChoices parsing not implemented"))
    }
}

/// Revocation info choice.
///
/// ```ASN.1
/// RevocationInfoChoice ::= CHOICE {
///   crl CertificateList,
///   other [1] IMPLICIT OtherRevocationInfoFormat }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(unused)]
pub(crate) enum RevocationInfoChoice {
    Crl(Box<CertificateList>),

    Other(OtherRevocationInfoFormat),
}

/// Other revocation info format.
///
/// ```ASN.1
/// OtherRevocationInfoFormat ::= SEQUENCE {
///   otherRevInfoFormat OBJECT IDENTIFIER,
///   otherRevInfo ANY DEFINED BY otherRevInfoFormat }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OtherRevocationInfoFormat {
    pub(crate) other_rev_info_info_format: Oid,

    // TODO Any
    pub(crate) other_rev_info: Option<()>,
}

/// Certificate choices.
///
/// ```ASN.1
/// CertificateChoices ::= CHOICE {
///   certificate Certificate,
///   extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
///   v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
///   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
///   other [3] IMPLICIT OtherCertificateFormat }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CertificateChoices {
    Certificate(Box<Certificate>),

    // ExtendedCertificate(ExtendedCertificate),
    // AttributeCertificateV1(AttributeCertificateV1),
    AttributeCertificateV2(Box<AttributeCertificateV2>),

    Other(Box<OtherCertificateFormat>),
}

impl CertificateChoices {
    pub(crate) fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_constructed_if(Tag::CTX_0, |cons| -> Result<(), DecodeError<S::Error>> {
            Err(cons.content_err("ExtendedCertificate parsing not implemented"))
        })?;

        cons.take_opt_constructed_if(Tag::CTX_1, |cons| -> Result<(), DecodeError<S::Error>> {
            Err(cons.content_err("AttributeCertificateV1 parsing not implemented"))
        })?;

        // TODO these first 2 need methods that parse an already entered SEQUENCE.
        if let Some(certificate) = cons
            .take_opt_constructed_if(Tag::CTX_2, |cons| AttributeCertificateV2::take_from(cons))?
        {
            Ok(Some(Self::AttributeCertificateV2(Box::new(certificate))))
        } else if let Some(certificate) = cons
            .take_opt_constructed_if(Tag::CTX_3, |cons| OtherCertificateFormat::take_from(cons))?
        {
            Ok(Some(Self::Other(Box::new(certificate))))
        } else if let Some(certificate) =
            cons.take_opt_constructed(|_, cons| Certificate::from_sequence(cons))?
        {
            Ok(Some(Self::Certificate(Box::new(certificate))))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn encode_ref(&self) -> impl Values + '_ {
        match self {
            Self::Certificate(cert) => cert.encode_ref(),
            Self::AttributeCertificateV2(_) => unimplemented!(),
            Self::Other(_) => unimplemented!(),
        }
    }
}

impl Values for CertificateChoices {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

/// Other certificate format.
///
/// ```ASN.1
/// OtherCertificateFormat ::= SEQUENCE {
///   otherCertFormat OBJECT IDENTIFIER,
///   otherCert ANY DEFINED BY otherCertFormat }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OtherCertificateFormat {
    pub(crate) other_cert_format: Oid,

    // TODO Any
    pub(crate) other_cert: Option<()>,
}

impl OtherCertificateFormat {
    pub(crate) fn take_from<S: Source>(
        cons: &Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        Err(cons.content_err("OtherCertificateFormat parsing not implemented"))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CertificateSet(Vec<CertificateChoices>);

impl Deref for CertificateSet {
    type Target = Vec<CertificateChoices>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CertificateSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl CertificateSet {
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let mut certs = Vec::new();

        while let Some(cert) = CertificateChoices::take_opt_from(cons)? {
            certs.push(cert);
        }

        Ok(Self(certs))
    }
}

/// Issuer and serial number.
///
/// ```ASN.1
/// IssuerAndSerialNumber ::= SEQUENCE {
///   issuer Name,
///   serialNumber CertificateSerialNumber }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerAndSerialNumber {
    pub(crate) issuer: Name,

    pub(crate) serial_number: CertificateSerialNumber,
}

impl IssuerAndSerialNumber {
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let issuer = Name::take_from(cons)?;
            let serial_number = Integer::take_from(cons)?;

            Ok(Self {
                issuer,
                serial_number,
            })
        })
    }

    pub(crate) fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((self.issuer.encode_ref(), (&self.serial_number).encode()))
    }
}

pub(crate) type CertificateSerialNumber = Integer;

/// Version number.
///
/// ```ASN.1
/// CMSVersion ::= INTEGER
///                { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CmsVersion {
    V0 = 0,

    V1 = 1,

    V2 = 2,

    V3 = 3,

    V4 = 4,

    V5 = 5,
}

impl CmsVersion {
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        match cons.take_primitive_if(Tag::INTEGER, Integer::i8_from_primitive)? {
            0 => Ok(Self::V0),
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            4 => Ok(Self::V4),
            5 => Ok(Self::V5),
            _ => Err(cons.content_err("unexpected CMSVersion")),
        }
    }

    pub(crate) fn encode(self) -> impl Values {
        u8::from(self).encode()
    }
}

impl From<CmsVersion> for u8 {
    fn from(v: CmsVersion) -> u8 {
        match v {
            CmsVersion::V0 => 0,
            CmsVersion::V1 => 1,
            CmsVersion::V2 => 2,
            CmsVersion::V3 => 3,
            CmsVersion::V4 => 4,
            CmsVersion::V5 => 5,
        }
    }
}

pub(crate) type UserKeyingMaterial = OctetString;

/// Other key attribute.
///
/// ```ASN.1
/// OtherKeyAttribute ::= SEQUENCE {
///   keyAttrId OBJECT IDENTIFIER,
///   keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OtherKeyAttribute {
    pub(crate) key_attribute_id: Oid,

    // TODO Any
    pub(crate) key_attribute: Option<()>,
}

pub(crate) type ContentType = Oid;

/// Time variant.
///
/// ```ASN.1
/// Time ::= CHOICE {
///   utcTime UTCTime,
///   generalizedTime GeneralizedTime }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Time {
    UtcTime(UtcTime),

    GeneralizedTime(GeneralizedTime),
}

impl Time {
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        if let Some(utc) =
            cons.take_opt_primitive_if(Tag::UTC_TIME, |prim| UtcTime::from_primitive(prim))?
        {
            Ok(Self::UtcTime(utc))
        } else if let Some(generalized) = cons
            .take_opt_primitive_if(Tag::GENERALIZED_TIME, |prim| {
                GeneralizedTime::from_primitive_no_fractional_or_timezone_offsets(prim)
            })?
        {
            Ok(Self::GeneralizedTime(generalized))
        } else {
            Err(cons.content_err("invalid Time value"))
        }
    }
}

impl From<Time> for chrono::DateTime<chrono::Utc> {
    fn from(t: Time) -> Self {
        match t {
            Time::UtcTime(utc) => utc.to_datetime(),
            Time::GeneralizedTime(gt) => gt.into(),
        }
    }
}

pub(crate) type AttributeCertificateV2 = AttributeCertificate;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut result = vec![tag];

        match body.len() {
            n if n < 128 => result.push(n as u8),
            n if n < 256 => result.extend([0x81, n as u8]),
            n if n < 65_536 => result.extend([0x82, (n >> 8) as u8, n as u8]),
            n => result.extend([0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]),
        }

        result.extend(body);
        result
    }

    #[test]
    fn cms_time_choices_decode_and_reject_invalid_formats() {
        for (tag, time, expected) in [
            (0x17, b"200101000000Z".as_slice(), 1_577_836_800),
            (0x18, b"20200101000000Z".as_slice(), 1_577_836_800),
        ] {
            let der = tlv(tag, time);
            let decoded = Constructed::decode(der.as_slice(), Mode::Der, Time::take_from).unwrap();
            let dt: chrono::DateTime<chrono::Utc> = decoded.into();
            assert_eq!(dt.timestamp(), expected);
        }

        for (tag, time) in [
            (0x17, b"200132000000Z".as_slice()),
            (0x18, b"20200101000000.1Z".as_slice()),
            (0x04, b"20200101000000Z".as_slice()),
        ] {
            let der = tlv(tag, time);
            assert!(Constructed::decode(der.as_slice(), Mode::Der, Time::take_from).is_err());
        }
    }

    #[test]
    fn cms_versions_roundtrip_and_unknown_versions_are_rejected() {
        for version in [
            CmsVersion::V0,
            CmsVersion::V1,
            CmsVersion::V2,
            CmsVersion::V3,
            CmsVersion::V4,
            CmsVersion::V5,
        ] {
            let mut der = Vec::new();
            version.encode().write_encoded(Mode::Der, &mut der).unwrap();

            assert_eq!(
                Constructed::decode(der.as_slice(), Mode::Der, CmsVersion::take_from).unwrap(),
                version
            );
        }

        for bad in [6, 255] {
            assert!(
                Constructed::decode([2, 1, bad].as_slice(), Mode::Der, CmsVersion::take_from)
                    .is_err()
            );
        }
    }

    #[test]
    fn cached_signed_attributes_reconstruct_set_lengths_without_touching_content() {
        let algorithm = [0x30, 0x0b, 6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1];

        for size in [0, 90, 128, 256, 65_536] {
            let attribute = tlv(
                0x30,
                &[
                    [6, 3, 0x2a, 3, 4].as_slice(),
                    &tlv(0x31, &tlv(4, &vec![0xab; size])),
                ]
                .concat(),
            );

            let der = tlv(
                0x30,
                &[
                    [2, 1, 1, 0x30, 5, 0x30, 0, 2, 1, 1].as_slice(),
                    &algorithm,
                    &tlv(0xa0, &attribute),
                    &algorithm,
                    &[4, 1, 0],
                    &tlv(0xa1, &attribute),
                ]
                .concat(),
            );

            let signer = Constructed::decode(der.as_slice(), Mode::Der, SignerInfo::take_opt_from)
                .unwrap()
                .unwrap();

            assert_eq!(signer.signed_attributes.as_ref().unwrap().len(), 1);
            assert_eq!(signer.unsigned_attributes.as_ref().unwrap().len(), 1);

            assert_eq!(
                signer.signed_attributes_digested_content().unwrap(),
                Some(tlv(0x31, &attribute))
            );

            assert_eq!(signer.signature.to_bytes().as_ref(), &[0]);
        }
    }

    #[test]
    fn unsupported_legacy_certificate_choices_fail_without_panicking() {
        // These legacy CMS choices have explicit unimplemented parsers;
        // the RFC 3161 engine uses rasn_cms instead.
        for tag in [0xa0, 0xa1, 0xa2, 0xa3] {
            let der = tlv(tag, &[0x30, 0]);

            assert!(Constructed::decode(
                der.as_slice(),
                Mode::Der,
                CertificateChoices::take_opt_from
            )
            .is_err());
        }
    }
}
