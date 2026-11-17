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

//! Deterministic, certificate-backed COSE Sign1 verification.
//!
//! Parsing does not authenticate a payload, certificate chain, or header. A valid
//! signature establishes only possession of the signing certificate's key, not
//! certificate issuance, profile validity, trust, time, or application acceptance.
//! In particular, unprotected headers (including timestamps and revocation data)
//! are never authenticated by Sign1 verification. Hosts select header policy and
//! retain all C2PA/CAWG orchestration and reporting. This is not a signing framework
//! or a general-purpose COSE environment.
//!
//! ```rust
//! use contentauth_pki::cose::{CertificateHeaderPolicy, ParsedSign1, Payload, VerificationError};
//!
//! fn check_signature(encoded: &[u8], payload: &[u8]) -> Result<(), VerificationError> {
//!     let parsed = ParsedSign1::from_tagged_slice(encoded)?;
//!     let verified = parsed.verify_signature(
//!         Payload::Detached(payload),
//!         b"",
//!         CertificateHeaderPolicy::C2pa,
//!     )?;
//!
//!     // Apply host-selected role, certificate profile, chain/trust, time, and
//!     // revocation policy before accepting this payload for any application.
//!     let _ = (verified.payload(), verified.signer_certificate());
//!     Ok(())
//! }
//! ```

use c2pa_raw_crypto::{
    ec_utils::parse_ec_der_sig, validator_for_signing_alg, RawSignatureValidationError, SigningAlg,
};
use coset::{
    cbor::value::Value,
    iana::{self, Algorithm, EnumI64},
    CoseSign1, Label, RegisteredLabelWithPrivate, TaggedCborSerializable,
};
use thiserror::Error;
use x509_parser::{der_parser::oid, oid_registry::Oid, x509::AlgorithmIdentifier};

use crate::x509::ParsedCertificate;

/// An explicit host choice of certificate-header interpretation.
///
/// There is deliberately no default or configurable general-purpose COSE policy.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum CertificateHeaderPolicy {
    /// Preserve C2PA's existing x5chain interpretation, including legacy forms.
    ///
    /// Integer label 33 wins over text `x5chain`, in either header. The same label
    /// in both headers is rejected before decoding, even if malformed. A value
    /// must be a byte string or a nonempty array containing only byte strings.
    /// This decodes certificate bytes; it does not validate their DER or chain.
    C2pa,
}

/// Payload selection for signature verification.
#[derive(Clone, Copy, Debug)]
pub enum Payload<'a> {
    /// Verify the payload carried by Sign1; a missing payload is an error.
    Embedded,

    /// Verify exactly these bytes, overriding any embedded payload.
    ///
    /// This preserves the SDK's detached-payload behavior, including signatures
    /// whose encoded payload is not null.
    Detached(&'a [u8]),
}

/// A parsing or cryptographic failure, without application reporting or policy.
///
/// Additional failure categories may be introduced as the verifier evolves.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerificationError {
    /// Tagged Sign1 or its CBOR headers could not be decoded.
    #[error("error while parsing CBOR ({0})")]
    CborParsingError(String),

    /// The protected algorithm is missing or unsupported.
    #[error("unsupported signing algorithm")]
    UnsupportedSigningAlgorithm,

    /// The selected certificate header is absent or malformed.
    #[error("missing signing certificate chain")]
    MissingSigningCertificateChain,

    /// The same certificate label occurs in both headers.
    #[error("multiple signing certificate chains detected")]
    MultipleSigningCertificateChains,

    /// Embedded verification was requested for a detached Sign1.
    #[error("missing embedded payload")]
    MissingPayload,

    /// An EC signature uses DER rather than the accepted P1363 encoding.
    #[error("could not parse ECDSA signature")]
    InvalidEcdsaSignature,

    /// The selected signing certificate could not be parsed.
    #[error("invalid X509 certificate")]
    InvalidCertificate,

    /// The signing certificate's key type or EC curve does not match the algorithm.
    #[error("certificate key algorithm does not match COSE signing algorithm")]
    IncompatibleCertificateKey,

    /// The existing raw validator rejected the signature or its inputs.
    #[error(transparent)]
    RawSignatureValidationError(#[from] RawSignatureValidationError),
}

/// An opaque decoded Sign1 carrying no authenticity or acceptance guarantee.
pub struct ParsedSign1 {
    pub(crate) sign1: CoseSign1,
}

impl ParsedSign1 {
    /// Decode a tagged Sign1, preserving the original protected-header bytes.
    ///
    /// An untagged value is rejected. Algorithm, certificate, signature, and
    /// application-policy checks are deferred; successful parsing is not validity.
    pub fn from_tagged_slice(bytes: &[u8]) -> Result<Self, VerificationError> {
        Ok(Self {
            sign1: CoseSign1::from_tagged_slice(bytes)
                .map_err(|error| VerificationError::CborParsingError(error.to_string()))?,
        })
    }

    /// Original protected-header encoding, before any signature authentication.
    pub fn protected_header_bytes(&self) -> &[u8] {
        self.sign1.protected.original_data.as_deref().unwrap_or(&[])
    }

    /// Decoded embedded payload, without any authenticity guarantee.
    pub fn embedded_payload(&self) -> Option<&[u8]> {
        self.sign1.payload.as_deref()
    }

    /// Decode the protected algorithm, including the SDK's accepted legacy labels.
    pub fn signing_algorithm(&self) -> Result<SigningAlg, VerificationError> {
        signing_algorithm(&self.sign1)
    }

    /// Decode the selected certificate bytes in leaf-first header order.
    ///
    /// These borrowed bytes are unverified, possibly unprotected metadata. No
    /// certificate parsing, issuance, profile, or trust check is performed.
    pub fn certificate_chain(
        &self,
        policy: CertificateHeaderPolicy,
    ) -> Result<Vec<&[u8]>, VerificationError> {
        certificate_chain(&self.sign1, policy)
    }

    /// Verify exactly the selected payload and external AAD with the header's leaf.
    ///
    /// Original protected bytes are used, not a re-encoded header. This does not
    /// authenticate unprotected headers, validate certificate issuance or chain
    /// order, or establish profile validity, trust, or timestamp/OCSP acceptance.
    pub fn verify_signature<'a>(
        &'a self,
        payload: Payload<'a>,
        external_aad: &[u8],
        policy: CertificateHeaderPolicy,
    ) -> Result<SignatureVerifiedPayload<'a>, VerificationError> {
        let payload = match payload {
            Payload::Embedded => self
                .embedded_payload()
                .ok_or(VerificationError::MissingPayload)?,
            Payload::Detached(payload) => payload,
        };

        verify_signature(&self.sign1, payload, external_aad, policy)
    }
}

/// A payload authenticated under the selected certificate's public key only.
///
/// The certificate is not thereby profile-valid, issued by its claimed issuer,
/// or trusted. Unprotected metadata remains exclusively on the parsed side of
/// the boundary, accessible to the SDK through its compatibility adapter.
pub struct SignatureVerifiedPayload<'a> {
    payload: &'a [u8],
    algorithm: SigningAlg,
    signer_certificate: ParsedCertificate<'a>,
}

impl<'a> SignatureVerifiedPayload<'a> {
    /// Exact payload bytes used in the successful signature check.
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Protected algorithm used in the successful signature check.
    pub fn signing_algorithm(&self) -> SigningAlg {
        self.algorithm
    }

    /// Certificate whose public key verified the signature, not a trust verdict.
    pub fn signer_certificate(&self) -> &ParsedCertificate<'a> {
        &self.signer_certificate
    }
}

pub(crate) fn signing_algorithm(sign1: &CoseSign1) -> Result<SigningAlg, VerificationError> {
    let Some(ref alg) = sign1.protected.header.alg else {
        return Err(VerificationError::UnsupportedSigningAlgorithm);
    };

    match alg {
        RegisteredLabelWithPrivate::PrivateUse(a) => match a {
            -39 => Ok(SigningAlg::Ps512),
            -38 => Ok(SigningAlg::Ps384),
            -37 => Ok(SigningAlg::Ps256),
            -36 => Ok(SigningAlg::Es512),
            -35 => Ok(SigningAlg::Es384),
            -7 => Ok(SigningAlg::Es256),
            -8 => Ok(SigningAlg::Ed25519),
            _ => Err(VerificationError::UnsupportedSigningAlgorithm),
        },

        RegisteredLabelWithPrivate::Assigned(a) => match a {
            Algorithm::PS512 => Ok(SigningAlg::Ps512),
            Algorithm::PS384 => Ok(SigningAlg::Ps384),
            Algorithm::PS256 => Ok(SigningAlg::Ps256),
            Algorithm::ES512 => Ok(SigningAlg::Es512),
            Algorithm::ES384 => Ok(SigningAlg::Es384),
            Algorithm::ES256 => Ok(SigningAlg::Es256),
            Algorithm::EdDSA => Ok(SigningAlg::Ed25519),
            _ => Err(VerificationError::UnsupportedSigningAlgorithm),
        },

        _ => Err(VerificationError::UnsupportedSigningAlgorithm),
    }
}

pub(crate) fn certificate_chain(
    sign1: &CoseSign1,
    policy: CertificateHeaderPolicy,
) -> Result<Vec<&[u8]>, VerificationError> {
    let CertificateHeaderPolicy::C2pa = policy;
    let (protected_integer, protected_text) = x5chain_header_values(&sign1.protected.header);
    let (unprotected_integer, unprotected_text) = x5chain_header_values(&sign1.unprotected);

    if (protected_integer.is_some() && unprotected_integer.is_some())
        || (protected_text.is_some() && unprotected_text.is_some())
    {
        return Err(VerificationError::MultipleSigningCertificateChains);
    }

    let value = protected_integer
        .or(unprotected_integer)
        .or(protected_text)
        .or(unprotected_text)
        .ok_or(VerificationError::MissingSigningCertificateChain)?;

    match value {
        Value::Array(values) if !values.is_empty() => values
            .iter()
            .map(|value| match value {
                Value::Bytes(bytes) => Ok(bytes.as_slice()),
                _ => Err(VerificationError::MissingSigningCertificateChain),
            })
            .collect(),

        Value::Bytes(bytes) => Ok(vec![bytes.as_slice()]),

        _ => Err(VerificationError::MissingSigningCertificateChain),
    }
}

fn x5chain_header_values(header: &coset::Header) -> (Option<&Value>, Option<&Value>) {
    let integer = header.rest.iter().find_map(|(label, value)| {
        (*label == Label::Int(iana::HeaderParameter::X5Chain.to_i64())).then_some(value)
    });
    let text = header.rest.iter().find_map(|(label, value)| {
        matches!(label, Label::Text(text) if text == "x5chain").then_some(value)
    });

    (integer, text)
}

pub(crate) fn check_signature_encoding(
    sign1: &CoseSign1,
    alg: SigningAlg,
) -> Result<(), VerificationError> {
    if matches!(
        alg,
        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512
    ) && parse_ec_der_sig(&sign1.signature).is_some()
    {
        return Err(VerificationError::InvalidEcdsaSignature);
    }

    Ok(())
}

pub(crate) fn verify_signature<'a>(
    sign1: &'a CoseSign1,
    payload: &'a [u8],
    external_aad: &[u8],
    policy: CertificateHeaderPolicy,
) -> Result<SignatureVerifiedPayload<'a>, VerificationError> {
    let algorithm = signing_algorithm(sign1)?;
    check_signature_encoding(sign1, algorithm)?;

    let certificates = certificate_chain(sign1, policy)?;
    let certificate = ParsedCertificate::from_der(certificates[0])
        .map_err(|_| VerificationError::InvalidCertificate)?;
    let public_key = certificate.parsed().public_key();

    if !spki_matches_signing_alg(algorithm, &public_key.algorithm) {
        return Err(VerificationError::IncompatibleCertificateKey);
    }

    let validator = validator_for_signing_alg(algorithm)
        .ok_or(VerificationError::UnsupportedSigningAlgorithm)?;
    let tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        sign1.protected.clone(),
        None,
        external_aad,
        payload,
    );

    validator.validate(&sign1.signature, &tbs, public_key.raw)?;

    Ok(SignatureVerifiedPayload {
        payload,
        algorithm,
        signer_certificate: certificate,
    })
}

const EC_PUBLICKEY_OID: Oid<'static> = oid!(1.2.840 .10045 .2 .1);
const RSA_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .1);
const RSASSA_PSS_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .10);
const ED25519_OID: Oid<'static> = oid!(1.3.101 .112);
const PRIME256V1_OID: Oid<'static> = oid!(1.2.840 .10045 .3 .1 .7);
const SECP384R1_OID: Oid<'static> = oid!(1.3.132 .0 .34);
const SECP521R1_OID: Oid<'static> = oid!(1.3.132 .0 .35);

fn spki_matches_signing_alg(alg: SigningAlg, spki: &AlgorithmIdentifier) -> bool {
    let key_alg = &spki.algorithm;
    let ec_named_curve_is = |curve: &Oid| {
        *key_alg == EC_PUBLICKEY_OID
            && spki
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .is_some_and(|c| c == *curve)
    };

    match alg {
        SigningAlg::Es256 => ec_named_curve_is(&PRIME256V1_OID),
        SigningAlg::Es384 => ec_named_curve_is(&SECP384R1_OID),
        SigningAlg::Es512 => ec_named_curve_is(&SECP521R1_OID),
        SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512 => {
            *key_alg == RSA_OID || *key_alg == RSASSA_PSS_OID
        }

        SigningAlg::Ed25519 => *key_alg == ED25519_OID,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use c2pa_raw_crypto::signer_from_private_key;
    use coset::{CoseSign1Builder, HeaderBuilder};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const POLICY: CertificateHeaderPolicy = CertificateHeaderPolicy::C2pa;
    const ES256: &[u8] = include_bytes!("../../sdk/tests/fixtures/crypto/raw_signature/es256.pub");
    const ES384: &[u8] = include_bytes!("../../sdk/tests/fixtures/crypto/raw_signature/es384.pub");
    const ES512: &[u8] = include_bytes!("../../sdk/tests/fixtures/crypto/raw_signature/es512.pub");
    const PS256: &[u8] = include_bytes!("../../sdk/tests/fixtures/crypto/raw_signature/ps256.pub");
    const PS384: &[u8] = include_bytes!("../../sdk/tests/fixtures/crypto/raw_signature/ps384.pub");
    const PS512: &[u8] = include_bytes!("../../sdk/tests/fixtures/crypto/raw_signature/ps512.pub");
    const ED25519: &[u8] =
        include_bytes!("../../sdk/tests/fixtures/crypto/raw_signature/ed25519.pub");
    const ED448: &[u8] = include_bytes!("../../sdk/tests/fixtures/crypto/raw_signature/ed448.pub");
    const ES256_KEY: &[u8] =
        include_bytes!("../../sdk/tests/fixtures/crypto/raw_signature/es256.priv");

    fn certificate(pem_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(pem::parse(pem_bytes)?.into_contents())
    }

    fn signed(
        alg: SigningAlg,
        label: Algorithm,
        cert: &[u8],
        key: &[u8],
    ) -> Result<CoseSign1, Box<dyn std::error::Error>> {
        let mut sign1 = CoseSign1Builder::new()
            .protected(HeaderBuilder::new().algorithm(label).build())
            .unprotected(
                HeaderBuilder::new()
                    .value(33, Value::Bytes(certificate(cert)?))
                    .build(),
            )
            .payload(b"payload".to_vec())
            .build();
        sign1.signature = signer_from_private_key(key, alg)?.sign(&sign1.tbs_data(b"aad"))?;

        Ok(sign1)
    }

    #[test]
    fn all_supported_algorithms_verify_and_bind_payload_and_aad() -> TestResult {
        for (alg, label, cert, key) in [
            (SigningAlg::Es256, Algorithm::ES256, ES256, ES256_KEY),
            (
                SigningAlg::Es384,
                Algorithm::ES384,
                ES384,
                include_bytes!("../../sdk/tests/fixtures/crypto/raw_signature/es384.priv")
                    .as_slice(),
            ),
            (
                SigningAlg::Es512,
                Algorithm::ES512,
                ES512,
                include_bytes!("../../sdk/tests/fixtures/crypto/raw_signature/es512.priv")
                    .as_slice(),
            ),
            (
                SigningAlg::Ps256,
                Algorithm::PS256,
                PS256,
                include_bytes!("../../sdk/tests/fixtures/crypto/raw_signature/ps256.priv")
                    .as_slice(),
            ),
            (
                SigningAlg::Ps384,
                Algorithm::PS384,
                PS384,
                include_bytes!("../../sdk/tests/fixtures/crypto/raw_signature/ps384.priv")
                    .as_slice(),
            ),
            (
                SigningAlg::Ps512,
                Algorithm::PS512,
                PS512,
                include_bytes!("../../sdk/tests/fixtures/crypto/raw_signature/ps512.priv")
                    .as_slice(),
            ),
            (
                SigningAlg::Ed25519,
                Algorithm::EdDSA,
                ED25519,
                include_bytes!("../../sdk/tests/fixtures/crypto/raw_signature/ed25519.priv")
                    .as_slice(),
            ),
        ] {
            let sign1 = signed(alg, label, cert, key)?;
            let bytes = sign1.clone().to_tagged_vec()?;
            let parsed = ParsedSign1::from_tagged_slice(&bytes)?;
            let verified = parsed.verify_signature(Payload::Embedded, b"aad", POLICY)?;
            assert_eq!(verified.payload(), b"payload");
            assert_eq!(verified.signing_algorithm(), alg);
            assert_eq!(
                verified.signer_certificate().certificate_der(),
                certificate(cert)?
            );
            assert!(matches!(
                parsed.verify_signature(Payload::Detached(b"changed"), b"aad", POLICY),
                Err(VerificationError::RawSignatureValidationError(
                    RawSignatureValidationError::SignatureMismatch
                ))
            ));
            assert!(matches!(
                parsed.verify_signature(Payload::Embedded, b"changed", POLICY),
                Err(VerificationError::RawSignatureValidationError(
                    RawSignatureValidationError::SignatureMismatch
                ))
            ));

            let mut tampered = sign1;
            tampered.signature[0] ^= 1;
            let parsed = ParsedSign1::from_tagged_slice(&tampered.to_tagged_vec()?)?;
            assert!(parsed
                .verify_signature(Payload::Embedded, b"aad", POLICY)
                .is_err());
        }

        Ok(())
    }

    #[test]
    fn exact_protected_encoding_and_detached_override_are_preserved() -> TestResult {
        let mut sign1 = signed(SigningAlg::Es256, Algorithm::ES256, ES256, ES256_KEY)?;
        // Deliberately non-minimal integer encodings: {1: -7}.
        let protected = vec![0xa1, 0x18, 0x01, 0x38, 0x06];
        sign1.protected.original_data = Some(protected.clone());
        let mut tbs = b"\x84\x6aSignature1\x45".to_vec();
        tbs.extend_from_slice(&protected);
        tbs.extend_from_slice(b"\x43aad\x47payload");
        sign1.signature = signer_from_private_key(ES256_KEY, SigningAlg::Es256)?.sign(&tbs)?;

        for embedded in [Some(b"not the signed payload".to_vec()), None] {
            sign1.payload = embedded;
            let bytes = sign1.clone().to_tagged_vec()?;
            let parsed = ParsedSign1::from_tagged_slice(&bytes)?;
            assert_eq!(parsed.protected_header_bytes(), protected);
            assert!(parsed
                .verify_signature(Payload::Embedded, b"aad", POLICY)
                .is_err());
            if parsed.embedded_payload().is_none() {
                assert!(matches!(
                    parsed.verify_signature(Payload::Embedded, b"aad", POLICY),
                    Err(VerificationError::MissingPayload)
                ));
            }
            assert_eq!(
                parsed
                    .verify_signature(Payload::Detached(b"payload"), b"aad", POLICY)?
                    .payload(),
                b"payload"
            );
        }

        sign1.protected.original_data = None;
        sign1.payload = Some(b"payload".to_vec());
        let parsed = ParsedSign1::from_tagged_slice(&sign1.to_tagged_vec()?)?;
        assert!(parsed
            .verify_signature(Payload::Embedded, b"aad", POLICY)
            .is_err());

        Ok(())
    }

    #[test]
    fn parsing_and_unprotected_claims_do_not_establish_authenticity() -> TestResult {
        let mut sign1 = signed(SigningAlg::Es256, Algorithm::ES256, ES256, ES256_KEY)?;
        sign1.unprotected.rest.push((
            Label::Text("sigTst2".into()),
            Value::Text("unverified timestamp".into()),
        ));
        let encoded = sign1.clone().to_tagged_vec()?;
        assert!(ParsedSign1::from_tagged_slice(&encoded[1..]).is_err());
        assert!(ParsedSign1::from_tagged_slice(b"not CBOR").is_err());

        let parsed = ParsedSign1::from_tagged_slice(&encoded)?;
        assert!(parsed
            .verify_signature(Payload::Embedded, b"aad", POLICY)
            .is_ok());

        sign1.unprotected.rest[0].1 = Value::Bytes(vec![]);
        let parsed = ParsedSign1::from_tagged_slice(&sign1.clone().to_tagged_vec()?)?;
        assert_eq!(parsed.certificate_chain(POLICY)?, vec![b"".as_slice()]);
        assert!(matches!(
            parsed.verify_signature(Payload::Embedded, b"aad", POLICY),
            Err(VerificationError::InvalidCertificate)
        ));

        sign1.unprotected.rest.remove(0);
        let parsed = ParsedSign1::from_tagged_slice(&sign1.clone().to_tagged_vec()?)?;
        assert!(matches!(
            parsed.verify_signature(Payload::Embedded, b"aad", POLICY),
            Err(VerificationError::MissingSigningCertificateChain)
        ));

        sign1
            .unprotected
            .rest
            .insert(0, (Label::Int(33), Value::Bytes(certificate(ES256)?)));
        sign1.signature.clear();
        let parsed = ParsedSign1::from_tagged_slice(&sign1.to_tagged_vec()?)?;
        assert_eq!(parsed.embedded_payload(), Some(b"payload".as_slice()));
        assert_eq!(parsed.certificate_chain(POLICY)?.len(), 1);
        assert!(parsed
            .verify_signature(Payload::Embedded, b"aad", POLICY)
            .is_err());

        Ok(())
    }

    #[test]
    fn protected_algorithm_and_encoding_failures_remain_distinct() -> TestResult {
        for (label, expected) in [
            (Algorithm::PS512, SigningAlg::Ps512),
            (Algorithm::PS384, SigningAlg::Ps384),
            (Algorithm::PS256, SigningAlg::Ps256),
            (Algorithm::ES512, SigningAlg::Es512),
            (Algorithm::ES384, SigningAlg::Es384),
            (Algorithm::ES256, SigningAlg::Es256),
            (Algorithm::EdDSA, SigningAlg::Ed25519),
        ] {
            for label in [
                RegisteredLabelWithPrivate::Assigned(label),
                RegisteredLabelWithPrivate::PrivateUse(label.to_i64()),
            ] {
                let mut sign1 = CoseSign1::default();
                sign1.protected.header.alg = Some(label);
                assert_eq!(signing_algorithm(&sign1)?, expected);
            }
        }

        for label in [
            None,
            Some(RegisteredLabelWithPrivate::Assigned(Algorithm::A128GCM)),
            Some(RegisteredLabelWithPrivate::PrivateUse(-65537)),
            Some(RegisteredLabelWithPrivate::Text("ES256".into())),
        ] {
            let mut sign1 = CoseSign1::default();
            sign1.unprotected.alg = Some(RegisteredLabelWithPrivate::Assigned(Algorithm::ES256));
            sign1.protected.header.alg = label;
            assert!(matches!(
                signing_algorithm(&sign1),
                Err(VerificationError::UnsupportedSigningAlgorithm)
            ));
        }

        let mut sign1 = signed(SigningAlg::Es256, Algorithm::ES256, ES256, ES256_KEY)?;
        sign1.signature = vec![0x30, 6, 2, 1, 1, 2, 1, 2];
        let parsed = ParsedSign1::from_tagged_slice(&sign1.to_tagged_vec()?)?;
        assert!(matches!(
            parsed.verify_signature(Payload::Embedded, b"aad", POLICY),
            Err(VerificationError::InvalidEcdsaSignature)
        ));

        Ok(())
    }

    fn key_matches(cert_pem: &[u8], alg: SigningAlg) -> Result<bool, Box<dyn std::error::Error>> {
        let der = certificate(cert_pem)?;
        let cert = ParsedCertificate::from_der(&der)?;

        Ok(spki_matches_signing_alg(
            alg,
            &cert.parsed().public_key().algorithm,
        ))
    }

    #[test]
    fn matching_keys_accepted() -> TestResult {
        for (cert, alg) in [
            (ED25519, SigningAlg::Ed25519),
            (ES256, SigningAlg::Es256),
            (ES384, SigningAlg::Es384),
            (ES512, SigningAlg::Es512),
            (PS256, SigningAlg::Ps256),
            (PS384, SigningAlg::Ps384),
            (PS512, SigningAlg::Ps512),
        ] {
            assert!(key_matches(cert, alg)?);
        }

        Ok(())
    }

    #[test]
    fn wrong_key_type_and_ec_curve_rejected() -> TestResult {
        for (cert, alg) in [
            (ED448, SigningAlg::Ed25519),
            (ES256, SigningAlg::Ed25519),
            (ED25519, SigningAlg::Es256),
            (PS256, SigningAlg::Es256),
            (ES256, SigningAlg::Ps256),
            (PS256, SigningAlg::Ed25519),
            (ES256, SigningAlg::Es384),
            (ES256, SigningAlg::Es512),
            (ES384, SigningAlg::Es256),
            (ES512, SigningAlg::Es256),
        ] {
            assert!(!key_matches(cert, alg)?);
        }

        let mut sign1 = signed(SigningAlg::Es256, Algorithm::ES256, ES256, ES256_KEY)?;
        sign1.unprotected.rest[0].1 = Value::Bytes(certificate(ES384)?);
        let parsed = ParsedSign1::from_tagged_slice(&sign1.to_tagged_vec()?)?;
        assert!(matches!(
            parsed.verify_signature(Payload::Embedded, b"aad", POLICY),
            Err(VerificationError::IncompatibleCertificateKey)
        ));

        Ok(())
    }

    #[test]
    fn header_policy_preserves_legacy_forms_and_strict_chain_decoding() -> TestResult {
        for label in [Label::Int(33), Label::Text("x5chain".into())] {
            for protected in [true, false] {
                for value in [
                    Value::Bytes(vec![]),
                    Value::Bytes(vec![1]),
                    Value::Array(vec![Value::Bytes(vec![1]), Value::Bytes(vec![2])]),
                ] {
                    let mut sign1 = CoseSign1::default();
                    let header = if protected {
                        &mut sign1.protected.header
                    } else {
                        &mut sign1.unprotected
                    };
                    header.rest.push((label.clone(), value));
                    assert!(certificate_chain(&sign1, POLICY).is_ok());

                    for duplicate in [Value::Null, Value::Array(vec![])] {
                        let mut duplicate_sign1 = sign1.clone();
                        let other = if protected {
                            &mut duplicate_sign1.unprotected
                        } else {
                            &mut duplicate_sign1.protected.header
                        };
                        other.rest.push((label.clone(), duplicate));
                        assert!(matches!(
                            certificate_chain(&duplicate_sign1, POLICY),
                            Err(VerificationError::MultipleSigningCertificateChains)
                        ));
                    }
                }

                for value in [
                    Value::Null,
                    Value::Array(vec![]),
                    Value::Array(vec![Value::Null, Value::Bytes(vec![1])]),
                    Value::Array(vec![Value::Bytes(vec![1]), Value::Null]),
                ] {
                    let mut sign1 = CoseSign1::default();
                    let header = if protected {
                        &mut sign1.protected.header
                    } else {
                        &mut sign1.unprotected
                    };
                    header.rest.push((label.clone(), value));
                    assert!(matches!(
                        certificate_chain(&sign1, POLICY),
                        Err(VerificationError::MissingSigningCertificateChain)
                    ));
                }
            }
        }

        for integer_protected in [true, false] {
            for text_protected in [true, false] {
                for integer_value in [Value::Null, Value::Bytes(vec![1])] {
                    let mut sign1 = CoseSign1::default();

                    for (protected, label, value) in [
                        (
                            text_protected,
                            Label::Text("x5chain".into()),
                            Value::Bytes(vec![2]),
                        ),
                        (integer_protected, Label::Int(33), integer_value.clone()),
                    ] {
                        let header = if protected {
                            &mut sign1.protected.header
                        } else {
                            &mut sign1.unprotected
                        };
                        header.rest.push((label, value));
                    }

                    if integer_value == Value::Null {
                        assert!(matches!(
                            certificate_chain(&sign1, POLICY),
                            Err(VerificationError::MissingSigningCertificateChain)
                        ));
                    } else {
                        assert_eq!(certificate_chain(&sign1, POLICY)?, vec![[1].as_slice()]);
                    }
                }
            }
        }

        Ok(())
    }
}
