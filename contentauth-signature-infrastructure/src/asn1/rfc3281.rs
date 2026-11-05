// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! ASN.1 types defined by [RFC 3281].
//!
//! [RFC 3281]: https://datatracker.ietf.org/doc/html/rfc3281

use bcder::{
    decode::{Constructed, DecodeError, Source},
    BitString, Captured, Oid,
};

use super::{AlgorithmIdentifier, Extensions, GeneralizedTime};

// Define opaque types for RFC 3281 that are not currently parsed.
// Since AttributeCertificateInfo::take_from is not implemented, these are just
// opaque wrappers around Captured for type safety.

/// General names (opaque; not parsed).
#[derive(Clone, Debug)]
pub(crate) struct GeneralNames(Captured);

impl PartialEq for GeneralNames {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for GeneralNames {}

/// Certificate serial number (opaque; not parsed).
#[derive(Clone, Debug)]
pub(crate) struct CertificateSerialNumber(Captured);

impl PartialEq for CertificateSerialNumber {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for CertificateSerialNumber {}

/// Unique identifier (opaque; not parsed).
#[derive(Clone, Debug)]
pub(crate) struct UniqueIdentifier(Captured);

impl PartialEq for UniqueIdentifier {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for UniqueIdentifier {}

/// Attribute certificate.
///
/// ```ASN.1
/// AttributeCertificate ::= SEQUENCE {
///   acinfo               AttributeCertificateInfo,
///   signatureAlgorithm   AlgorithmIdentifier,
///   signatureValue       BIT STRING
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AttributeCertificate {
    /// Attribute certificate contents covered by the signature.
    pub(crate) ac_info: AttributeCertificateInfo,

    /// Algorithm used to sign the attribute certificate.
    pub(crate) signature_algorithm: AlgorithmIdentifier,

    /// Signature over the attribute certificate information.
    pub(crate) signature_value: BitString,
}

impl AttributeCertificate {
    /// Decode an attribute certificate; its information parser is not implemented.
    ///
    /// Currently returns a decoding error when it reaches `ac_info`.
    pub(crate) fn take_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let ac_info = AttributeCertificateInfo::take_from(cons)?;
            let signature_algorithm = AlgorithmIdentifier::take_from(cons)?;
            let signature_value = BitString::take_from(cons)?;

            Ok(Self {
                ac_info,
                signature_algorithm,
                signature_value,
            })
        })
    }
}

/// Attribute certificate information.
///
/// ```ASN.1
/// AttributeCertificateInfo ::= SEQUENCE {
///   version              AttCertVersion -- version is v2,
///   holder               Holder,
///   issuer               AttCertIssuer,
///   signature            AlgorithmIdentifier,
///   serialNumber         CertificateSerialNumber,
///   attrCertValidityPeriod   AttCertValidityPeriod,
///   attributes           SEQUENCE OF Attribute,
///   issuerUniqueID       UniqueIdentifier OPTIONAL,
///   extensions           Extensions OPTIONAL
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AttributeCertificateInfo {
    /// Attribute certificate version.
    pub(crate) version: AttCertVersion,

    /// Entity to which the attributes apply.
    pub(crate) holder: Holder,

    /// Authority issuing the attribute certificate.
    pub(crate) issuer: AttCertIssuer,

    /// Algorithm used to sign this information.
    pub(crate) signature: AlgorithmIdentifier,

    /// Serial number assigned by the issuer.
    pub(crate) serial_number: CertificateSerialNumber,

    /// Interval during which the attribute certificate is valid.
    pub(crate) attr_cert_validity_period: AttCertValidityPeriod,

    /// Attributes certified for the holder.
    pub(crate) attributes: Vec<Attribute>,

    /// Optional unique identifier of the issuer.
    pub(crate) issuer_unique_ud: Option<UniqueIdentifier>,

    /// Optional attribute certificate extensions.
    pub(crate) extensions: Option<Extensions>,
}

impl AttributeCertificateInfo {
    /// Return a decoding error because attribute certificate information is unsupported.
    pub(crate) fn take_from<S: Source>(
        cons: &Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        Err(cons.content_err("AttributeCertificateInfo parsing not implemented"))
    }
}

/// Supported attribute certificate version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(unused)]
pub(crate) enum AttCertVersion {
    /// Version 2, represented by ASN.1 integer 1.
    V2 = 1,
}

/// Certificate holder.
///
/// ```ASN.1
/// Holder ::= SEQUENCE {
///   baseCertificateID   [0] IssuerSerial OPTIONAL,
///     -- the issuer and serial number of
///     -- the holder's Public Key Certificate
///   entityName          [1] GeneralNames OPTIONAL,
///     -- the name of the claimant or role
///   objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
///     -- used to directly authenticate the holder,
///     -- for example, an executable
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Holder {
    /// Optional issuer and serial number of the holder's certificate.
    pub(crate) base_certificate_id: Option<IssuerSerial>,

    /// Optional names identifying the holder.
    pub(crate) entity_name: Option<GeneralNames>,

    /// Optional digest identifying an object associated with the holder.
    pub(crate) object_digest_info: Option<ObjectDigestInfo>,
}

/// Kind of object identified by an attribute certificate's digest.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(unused)]
pub(crate) enum DigestedObjectType {
    /// The holder's public key.
    PublicKey = 0,

    /// The holder's public-key certificate.
    PublicKeyCert = 1,

    /// Another object type identified by an OID.
    OtherObjectTypes = 2,
}

/// Object digest information.
///
/// ```ASN.1
/// ObjectDigestInfo ::= SEQUENCE {
///   digestedObjectType  ENUMERATED {
///     publicKey            (0),
///     publicKeyCert        (1),
///     otherObjectTypes     (2) },
///       -- otherObjectTypes MUST NOT
///       -- be used in this profile
///   otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
///   digestAlgorithm     AlgorithmIdentifier,
///   objectDigest        BIT STRING
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObjectDigestInfo {
    /// Kind of object whose digest is carried here.
    pub(crate) digested_object_type: DigestedObjectType,

    /// Object type OID for the `OtherObjectTypes` choice.
    pub(crate) other_object_type_id: Oid,

    /// Algorithm used to compute the object digest.
    pub(crate) digest_algorithm: AlgorithmIdentifier,

    /// Digest identifying the object.
    pub(crate) object_digest: BitString,
}

/// Attribute certificate issuer.
///
/// ```ASN.1
/// AttCertIssuer ::= CHOICE {
///   v1Form   GeneralNames,  -- MUST NOT be used in this
///                           -- profile
///   v2Form   [0] V2Form     -- v2 only
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(unused)]
pub(crate) enum AttCertIssuer {
    /// Legacy issuer naming form, not permitted by the RFC 3281 profile.
    V1Form(GeneralNames),

    /// Version 2 issuer naming form.
    V2Form(Box<V2Form>),
}

/// Version 2 issuer naming form.
///
/// ```ASN.1
/// V2Form ::= SEQUENCE {
///   issuerName            GeneralNames  OPTIONAL,
///   baseCertificateID     [0] IssuerSerial  OPTIONAL,
///   objectDigestInfo      [1] ObjectDigestInfo  OPTIONAL
///     -- issuerName MUST be present in this profile
///     -- baseCertificateID and objectDigestInfo MUST NOT
///     -- be present in this profile
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct V2Form {
    /// Optional issuer names; required by the RFC 3281 profile.
    pub(crate) issuer_name: Option<GeneralNames>,

    /// Optional issuer certificate reference, excluded by the RFC 3281 profile.
    pub(crate) base_certificate_id: Option<IssuerSerial>,

    /// Optional issuer object digest, excluded by the RFC 3281 profile.
    pub(crate) object_digest_info: Option<ObjectDigestInfo>,
}

/// Issuer serial.
///
/// ```ASN.1
/// IssuerSerial  ::=  SEQUENCE {
///   issuer         GeneralNames,
///   serial         CertificateSerialNumber,
///   issuerUID      UniqueIdentifier OPTIONAL
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IssuerSerial {
    /// Names of the certificate issuer.
    pub(crate) issuer: GeneralNames,

    /// Certificate serial number assigned by that issuer.
    pub(crate) serial: CertificateSerialNumber,

    /// Optional issuer unique identifier.
    pub(crate) issuer_uid: Option<UniqueIdentifier>,
}

/// Attribute certificate validity period.
///
/// ```ASN.1
/// AttCertValidityPeriod  ::= SEQUENCE {
///   notBeforeTime  GeneralizedTime,
///   notAfterTime   GeneralizedTime
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AttCertValidityPeriod {
    /// Earliest instant at which the attribute certificate is valid.
    pub(crate) not_before_time: GeneralizedTime,

    /// Latest instant at which the attribute certificate is valid.
    pub(crate) not_after_time: GeneralizedTime,
}

/// Attribute.
///
/// ```ASN.1
/// Attribute ::= SEQUENCE {
///   type      AttributeType,
///   values    SET OF AttributeValue
///     -- at least one value is required
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Attribute {
    /// Object identifier selecting the attribute's syntax.
    pub(crate) typ: AttributeType,

    /// Values of the attribute in this codec's placeholder representation.
    pub(crate) values: Vec<AttributeValue>,
}

/// Object identifier selecting an attribute's syntax.
pub(crate) type AttributeType = Oid;

// TODO: Support ASN.1 ANY values.
/// Placeholder for an attribute value whose ASN.1 `ANY` syntax is not implemented.
pub(crate) type AttributeValue = Option<()>;
