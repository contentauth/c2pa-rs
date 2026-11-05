// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Legacy CMS signed-data codecs retained for SDK compatibility and codec tests.
//!
//! [RFC 5652]: https://datatracker.ietf.org/doc/html/rfc5652
//!
//! The types defined in this module are intended to be extremely low-level and
//! only to be used for (de)serialization. See types outside the `asn1` module
//! tree for higher-level functionality.
//!
//! Certificate structures are captured opaquely; these codecs do not perform
//! certificate validation.

use std::{
    fmt::{Debug, Formatter},
    io::Write,
    ops::{Deref, DerefMut},
};

#[cfg(test)]
use bcder::decode::Primitive;
use bcder::{
    decode::{Constructed, DecodeError, Source},
    encode,
    encode::{PrimitiveContent, Values},
    Captured, Integer, Mode, OctetString, Oid, Tag,
};
#[cfg(test)]
use der::Decode;

use super::ContentType;
#[cfg(test)]
use crate::asn1::GeneralizedTime;
use crate::asn1::{rfc3281::AttributeCertificate, AlgorithmIdentifier};

// Retain local bcder-compatible types from the SDK's legacy CMS codec.

/// UTC time compatible with `bcder`, parsed using the `der` crate.
#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct UtcTime {
    // Store the der crate's time type, which handles the year 2000 correctly.
    der_time: der::asn1::UtcTime,

    // Cache the DER encoding for bcder compatibility.
    der_bytes: Vec<u8>,
}

#[cfg(test)]
impl PartialEq for UtcTime {
    fn eq(&self, other: &Self) -> bool {
        self.der_time == other.der_time
    }
}

#[cfg(test)]
impl Eq for UtcTime {}

#[cfg(test)]
impl UtcTime {
    pub(crate) fn from_primitive<S: Source>(
        prim: &mut Primitive<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        // Get the raw bytes (without tag/length).
        let bytes = prim.take_all()?;

        // Reconstruct DER encoding using helper (tag 0x17 = UTC_TIME).
        let der_bytes = crate::asn1::reconstruct_der_bytes(0x17, bytes.as_ref())
            .map_err(|_| DecodeError::content("failed to reconstruct DER bytes", prim.pos()))?;

        // Parse with the der crate to validate the time format.
        let der_time = der::asn1::UtcTime::from_der(&der_bytes)
            .map_err(|_| DecodeError::content("invalid UtcTime", prim.pos()))?;

        Ok(UtcTime {
            der_time,
            der_bytes,
        })
    }

    /// Convert to `chrono::DateTime`.
    pub(crate) fn to_datetime(&self) -> chrono::DateTime<chrono::Utc> {
        // Convert der's time to SystemTime, then to chrono.
        let system_time = self.der_time.to_system_time();
        system_time.into()
    }
}

#[cfg(test)]
impl Values for UtcTime {
    fn encoded_len(&self, _mode: Mode) -> usize {
        self.der_bytes.len()
    }

    fn write_encoded<W: Write>(&self, _mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        target.write_all(&self.der_bytes)
    }
}

/// Opaque distinguished name captured in its DER encoding.
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

/// Opaque certificate captured in its DER encoding.
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

/// Attribute with type and values fields.
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

/// Opaque certificate list captured in its DER encoding.
#[derive(Clone, Debug)]
pub(crate) struct CertificateList(Captured);

impl PartialEq for CertificateList {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for CertificateList {}

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
    /// Decode CMS `SignedData` without verifying its signatures.
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

/// Signer information entries.
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

/// Encapsulated content information.
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

    /// Raw bytes backing the signed attributes.
    ///
    /// Does not include the constructed tag or length bytes.
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
            // rest of the structure is BER encoded. Buffer the data so we can
            // feed it into a new decoder.
            let der = cons.capture_all()?;

            // The raw data constituting the signed
            // attributes is also digested and used for content/signature
            // verification. Because our DER serialization may not round trip
            // losslessly, we retain a copy of these bytes so they may be
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

    /// Obtain the signed-attribute content to be digested.
    ///
    /// Preparing the content for the digest calculation requires special handling.
    /// From RFC 5652:
    ///
    /// > The result of the message digest calculation process depends on
    /// > whether the `signedAttrs` field is present. When the field is absent,
    /// > the result is just the message digest of the content as described
    /// > above. When the field is present, however, the result is the message
    /// > digest of the complete DER encoding of the `SignedAttrs` value
    /// > contained in the `signedAttrs` field. Since the `SignedAttrs` value,
    /// > when present, must contain the content-type and the message-digest
    /// > attributes, those values are indirectly included in the result. The
    /// > content-type attribute MUST NOT be included in a countersignature
    /// > unsigned attribute as defined in Section 11.4. A separate encoding
    /// > of the `signedAttrs` field is performed for message digest calculation.
    /// > The `IMPLICIT [0]` tag in the `signedAttrs` is not used for the DER
    /// > encoding, rather an `EXPLICIT SET OF` tag is used. That is, the DER
    /// > encoding of the `EXPLICIT SET OF` tag, rather than of the `IMPLICIT [0]`
    /// > tag, MUST be included in the message digest calculation along with
    /// > the length and content octets of the `SignedAttributes` value.
    ///
    /// A few things to note here:
    ///
    /// * Encode all `SignedAttributes` values using DER, not BER.
    /// * The `SignedAttributes` tag must use `EXPLICIT SET OF` instead of
    ///   `IMPLICIT [0]`, so default encoding is not appropriate.
    /// * If this instance was parsed, retain the raw `SignedAttributes` bytes
    ///   to ensure a lossless copy.
    pub fn signed_attributes_digested_content(&self) -> Result<Option<Vec<u8>>, std::io::Error> {
        if let Some(signed_attributes) = &self.signed_attributes {
            if let Some(existing_data) = &self.signed_attributes_data {
                // Reserve eight extra bytes for the tag and length.
                let mut buffer = Vec::with_capacity(existing_data.len() + 8);
                // EXPLICIT SET OF.
                buffer.write_all(&[0x31])?;

                // The bcder crate does not export a length encoder, so encode it manually.
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
                // No original copy is present; serialize the data structures.
                // Sort the attributes first because
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
/// ```
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
    /// [`SignerInfo::signed_attributes_digested_content`].
    pub(crate) fn as_sorted(&self) -> Result<Self, std::io::Error> {
        // All elements of the set have the same type, so sorting is based on encoded
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
    // SignedAttributes are always written using DER encoding.
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

type SubjectKeyIdentifier = OctetString;

pub(crate) type SignatureAlgorithmIdentifier = AlgorithmIdentifier;

/// Revocation information choices.
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

/// Revocation information choice.
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

/// Other revocation information format.
///
/// ```ASN.1
/// OtherRevocationInfoFormat ::= SEQUENCE {
///   otherRevInfoFormat OBJECT IDENTIFIER,
///   otherRevInfo ANY DEFINED BY otherRevInfoFormat }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OtherRevocationInfoFormat {
    pub(crate) other_rev_info_info_format: Oid,

    // TODO: Support ASN.1 ANY values.
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

        // TODO: The first two choices need parsers for an already-entered SEQUENCE.
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

    // TODO: Support ASN.1 ANY values.
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

    #[cfg(test)]
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

/// CMS time value.
///
/// ```ASN.1
/// Time ::= CHOICE {
///   utcTime UTCTime,
///   generalizedTime GeneralizedTime }
/// ```
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Time {
    UtcTime(UtcTime),
    GeneralizedTime(GeneralizedTime),
}

#[cfg(test)]
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

#[cfg(test)]
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
    fn signed_data_decodes_a_minimal_unverified_envelope() {
        let der = tlv(
            0x30,
            &[2, 1, 1, 0x31, 0, 0x30, 5, 6, 3, 0x2a, 3, 4, 0x31, 0],
        );

        let decoded =
            Constructed::decode(der.as_slice(), Mode::Der, SignedData::take_from).unwrap();

        assert_eq!(decoded.version, CmsVersion::V1);
        assert!(decoded.digest_algorithms.is_empty());
        assert!(decoded.signer_infos.is_empty());
        assert!(decoded.certificates.is_none());
        assert!(decoded.crls.is_none());
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
