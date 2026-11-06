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

//! Regression coverage for timestamp RSA-PSS profiles and strict SKI lookup.

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

trait Required<T> {
    fn required(self) -> TestResult<T>;
}

impl<T, E: std::fmt::Debug> Required<T> for Result<T, E> {
    fn required(self) -> TestResult<T> {
        self.map_err(|error| std::io::Error::other(format!("{error:?}")).into())
    }
}

impl<T> Required<T> for Option<T> {
    fn required(self) -> TestResult<T> {
        self.ok_or_else(|| std::io::Error::other("missing timestamp fixture value").into())
    }
}

const DATA: &[u8] = b"RSA timestamp regression";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const SHA384: &str = "2.16.840.1.101.3.4.2.2";
const SHA512: &str = "2.16.840.1.101.3.4.2.3";
const PS256: &[u8] = include_bytes!("../../../tests/fixtures/time_stamp/ps256.tst");
const PS384: &[u8] = include_bytes!("../../../tests/fixtures/time_stamp/ps384.tst");
const PS512: &[u8] = include_bytes!("../../../tests/fixtures/time_stamp/ps512.tst");
const PKCS1: &[u8] = include_bytes!("../../../tests/fixtures/time_stamp/rsa-pkcs1.tst");

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    let length = body.len();

    if length < 128 {
        output.push(length as u8);
    } else if length < 256 {
        output.extend([0x81, length as u8]);
    } else {
        output.extend([0x82, (length >> 8) as u8, length as u8]);
    }

    output.extend(body);
    output
}

fn algorithm(oid: &str, parameters: Option<Vec<u8>>) -> TestResult<rasn_pkix::AlgorithmIdentifier> {
    Ok(rasn_pkix::AlgorithmIdentifier {
        algorithm: types::ObjectIdentifier::new_unchecked(
            oid.split('.')
                .map(str::parse)
                .collect::<Result<Vec<_>, _>>()?
                .into(),
        ),
        parameters: parameters.map(types::Any::new),
    })
}

fn hash_algorithm(hash: &str) -> TestResult<Vec<u8>> {
    Ok(rasn::der::encode(&algorithm(hash, Some(vec![5, 0]))?)?)
}

fn pss(hash: &str, mgf_hash: &str, salt: u8, trailer: Option<u8>) -> TestResult<Vec<u8>> {
    let mut fields = tlv(0xa0, &hash_algorithm(hash)?);

    fields.extend(tlv(
        0xa1,
        &rasn::der::encode(&algorithm(MGF1, Some(hash_algorithm(mgf_hash)?))?)?,
    ));

    fields.extend(tlv(0xa2, &tlv(2, &[salt])));

    if let Some(trailer) = trailer {
        fields.extend(tlv(0xa3, &tlv(2, &[trailer])));
    }

    Ok(tlv(0x30, &fields))
}

fn decode(token: &[u8]) -> TestResult<rasn_cms::SignedData> {
    signed_data_from_time_stamp_response(token)?.required()
}

fn encode(sd: &rasn_cms::SignedData) -> TestResult<Vec<u8>> {
    let mut content: rasn_cms::ContentInfo = rasn::der::decode(PS256)?;
    content.content = types::Any::new(rasn::der::encode(sd)?);

    Ok(rasn::der::encode(&content)?)
}

fn certificate(sd: &rasn_cms::SignedData) -> TestResult<&rasn_pkix::Certificate> {
    sd.certificates
        .as_ref()
        .required()?
        .to_vec()
        .into_iter()
        .find_map(|choice| match choice {
            CertificateChoices::Certificate(cert) => Some(cert.as_ref()),
            _ => None,
        })
        .required()
}

fn change_certificate(
    sd: &mut rasn_cms::SignedData,
    change: impl FnOnce(&mut rasn_pkix::Certificate) -> TestResult,
) -> TestResult {
    let mut cert = certificate(sd)?.clone();
    change(&mut cert)?;
    sd.certificates = Some(vec![CertificateChoices::Certificate(Box::new(cert))].into());

    Ok(())
}

fn verify(token: &[u8]) -> Result<(), VerificationError> {
    let parsed = ParsedTimestamp::parse(token)?;

    let signed = parsed.verify_signatures().next().ok_or_else(|| {
        VerificationError::new(
            VerificationStage::SignerIdentifier,
            VerificationErrorKind::NoMatchingCertificate,
            "fixture has no signer",
        )
    })??;

    signed.verify_message_imprint(DATA)?;

    Ok(())
}

#[test]
fn rsa_pss_profiles_with_rsa_encryption_spki_and_legacy_pkcs1_verify() -> TestResult {
    for token in [PS256, PS384, PS512, PKCS1] {
        let sd = decode(token)?;

        assert_eq!(
            certificate(&sd)?
                .tbs_certificate
                .subject_public_key_info
                .algorithm
                .algorithm
                .to_string(),
            RSA_ENCRYPTION
        );

        verify(token)?;

        if token != PKCS1 {
            let signer = sd.signer_infos.to_vec()[0];
            let key = &certificate(&sd)?.tbs_certificate.subject_public_key_info;

            let tbs = signed_attributes_digested_content(signer)
                .required()?
                .required()?;

            let signature = OctetString::new(bytes::Bytes::copy_from_slice(&signer.signature));

            assert!(
                validate_timestamp_sig(
                    &bcder::Oid::from_str(RSA_ENCRYPTION).required()?,
                    &bcder::Oid::from_str(&signer.digest_algorithm.algorithm.to_string())
                        .required()?,
                    &signature,
                    &tbs,
                    &rasn::der::encode(key).required()?,
                )
                .is_err(),
                "the previous SPKI-based selection must reproduce the failure"
            );
        }
    }

    Ok(())
}

#[test]
fn legacy_rsa_signature_oids_preserve_pkcs1_and_require_matching_digest() -> TestResult {
    let mut sd = decode(PKCS1)?;
    let mut signer = sd.signer_infos.to_vec()[0].clone();

    let key = &certificate(&sd)?
        .tbs_certificate
        .subject_public_key_info
        .algorithm;

    for (signature, hash) in [
        ("1.2.840.113549.1.1.5", "1.3.14.3.2.26"),
        ("1.2.840.113549.1.1.11", SHA256),
        ("1.2.840.113549.1.1.12", SHA384),
        ("1.2.840.113549.1.1.13", SHA512),
    ] {
        signer.signature_algorithm = algorithm(signature, Some(vec![5, 0]))?;
        signer.digest_algorithm = algorithm(hash, None)?;

        assert_eq!(
            timestamp_signature_algorithm(&signer, key)
                .required()?
                .to_string(),
            RSA_ENCRYPTION
        );

        signer.digest_algorithm = algorithm("1.2.3.4", None)?;

        assert!(timestamp_signature_algorithm(&signer, key).is_err());
    }

    signer.signature_algorithm = algorithm("1.2.840.113549.1.1.11", Some(vec![5, 0]))?;
    signer.digest_algorithm = algorithm(SHA256, None)?;
    sd.signer_infos = vec![signer].into();
    verify(&encode(&sd)?)?;

    Ok(())
}

#[test]
fn pss_signature_parameters_are_required_and_strictly_parsed() -> TestResult {
    let sd = decode(PS256)?;
    let mut signer = sd.signer_infos.to_vec()[0].clone();

    let key = &certificate(&sd)?
        .tbs_certificate
        .subject_public_key_info
        .algorithm;

    signer.signature_algorithm.parameters = None;

    assert!(matches!(
        timestamp_signature_algorithm(&signer, key),
        Err(VerificationErrorKind::DecodeError(_))
    ));

    for parameters in [
        vec![5, 0],
        vec![4, 0],
        vec![0x30, 1, 0],
        tlv(0x30, &tlv(0xa4, &tlv(2, &[1]))),
        tlv(0x30, &tlv(0x82, &[32])),
        tlv(0x30, &tlv(0xa2, &tlv(2, &[0xff]))),
        tlv(0x30, &tlv(0xa2, &tlv(2, &[]))),
        tlv(0x30, &tlv(0xa2, &tlv(2, &[0, 32]))),
        tlv(0x30, &tlv(0xa2, &tlv(2, &[1, 0, 0, 0, 0, 0, 0, 0, 0]))),
        tlv(
            0x30,
            &tlv(
                0xa0,
                &rasn::der::encode(&algorithm(SHA256, Some(vec![4, 0]))?).required()?,
            ),
        ),
        tlv(0x30, &tlv(0xa2, &[2, 1, 32, 5, 0])),
        tlv(
            0x30,
            &[
                tlv(0xa0, &hash_algorithm(SHA256)?),
                tlv(0xa0, &hash_algorithm(SHA256)?),
            ]
            .concat(),
        ),
        tlv(
            0x30,
            &[
                tlv(0xa2, &tlv(2, &[32])),
                tlv(0xa0, &hash_algorithm(SHA256)?),
            ]
            .concat(),
        ),
        [pss(SHA256, SHA256, 32, None)?, vec![5, 0]].concat(),
        tlv(
            0x30,
            &tlv(
                0xa1,
                &rasn::der::encode(&algorithm(MGF1, None)?).required()?,
            ),
        ),
    ] {
        signer.signature_algorithm.parameters = Some(types::Any::new(parameters.clone()));

        assert!(
            matches!(
                timestamp_signature_algorithm(&signer, key),
                Err(VerificationErrorKind::DecodeError(_))
            ),
            "{parameters:02x?}"
        );
    }

    Ok(())
}

#[test]
fn pss_profiles_reject_unsupported_and_inconsistent_parameters() -> TestResult {
    let mut sd = decode(PS256)?;
    let mut signer = sd.signer_infos.to_vec()[0].clone();

    for parameters in [
        vec![0x30, 0],
        pss("1.3.14.3.2.26", "1.3.14.3.2.26", 20, None)?,
        pss("2.16.840.1.101.3.4.2.4", "2.16.840.1.101.3.4.2.4", 28, None)?,
        pss(SHA384, SHA384, 48, None)?,
        pss(SHA256, SHA384, 32, None)?,
        pss(SHA256, SHA256, 0, None)?,
        pss(SHA256, SHA256, 33, None)?,
        pss(SHA256, SHA256, 32, Some(2))?,
        tlv(0x30, &tlv(0xa0, &hash_algorithm(SHA256)?)),
        tlv(
            0x30,
            &[
                tlv(0xa0, &hash_algorithm(SHA256)?),
                tlv(
                    0xa1,
                    &rasn::der::encode(&algorithm("1.2.3.4", Some(hash_algorithm(SHA256)?))?)
                        .required()?,
                ),
                tlv(0xa2, &tlv(2, &[32])),
            ]
            .concat(),
        ),
    ] {
        signer.signature_algorithm.parameters = Some(types::Any::new(parameters.clone()));

        assert!(
            matches!(
                timestamp_signature_algorithm(
                    &signer,
                    &certificate(&sd)?
                        .tbs_certificate
                        .subject_public_key_info
                        .algorithm
                ),
                Err(VerificationErrorKind::UnsupportedAlgorithm)
            ),
            "{parameters:02x?}"
        );

        sd.signer_infos = vec![signer.clone()].into();
        let error = verify(&encode(&sd)?).err().required()?;

        assert_eq!(error.stage, VerificationStage::SignatureAlgorithm);
        assert_eq!(error.kind, VerificationErrorKind::UnsupportedAlgorithm);
    }

    Ok(())
}

#[test]
fn pss_parameter_defaults_and_null_or_absent_hash_parameters() -> TestResult {
    for (hash, salt) in [(SHA256, 32), (SHA384, 48), (SHA512, 64)] {
        let sd = decode(PS256)?;

        let key = &certificate(&sd)?
            .tbs_certificate
            .subject_public_key_info
            .algorithm;

        let mut signer = sd.signer_infos.to_vec()[0].clone();

        signer.digest_algorithm = algorithm(hash, None)?;
        signer.signature_algorithm = algorithm(RSA_PSS, Some(pss(hash, hash, salt, None)?))?;

        assert!(timestamp_signature_algorithm(&signer, key).is_ok());

        let hash_der = rasn::der::encode(&algorithm(hash, None)?).required()?;

        let fields = [
            tlv(0xa0, &hash_der),
            tlv(
                0xa1,
                &rasn::der::encode(&algorithm(MGF1, Some(hash_der))?).required()?,
            ),
            tlv(0xa2, &tlv(2, &[salt])),
        ]
        .concat();
        signer.signature_algorithm.parameters = Some(types::Any::new(tlv(0x30, &fields)));

        assert!(timestamp_signature_algorithm(&signer, key).is_ok());
    }

    let defaults = pss_parameters(&types::Any::new(vec![0x30, 0])).required()?;

    assert_eq!(defaults.hash, "1.3.14.3.2.26");
    assert_eq!(defaults.mgf_hash, "1.3.14.3.2.26");
    assert_eq!(defaults.salt_length, 20);
    assert_eq!(defaults.trailer, 1);

    Ok(())
}

#[test]
fn pss_actual_salt_must_match_the_declared_profile() -> TestResult {
    for token in [
        include_bytes!("../../../tests/fixtures/time_stamp/ps256-salt0.tst").as_slice(),
        include_bytes!("../../../tests/fixtures/time_stamp/ps256-saltmax.tst").as_slice(),
    ] {
        let error = verify(token).err().required()?;

        assert_eq!(error.stage, VerificationStage::SignatureAlgorithm);
        assert_eq!(error.kind, VerificationErrorKind::UnsupportedAlgorithm);

        let mut sd = decode(token)?;
        let mut signer = sd.signer_infos.to_vec()[0].clone();
        signer.signature_algorithm = algorithm(RSA_PSS, Some(pss(SHA256, SHA256, 32, None)?))?;
        sd.signer_infos = vec![signer].into();
        let error = verify(&encode(&sd)?).err().required()?;

        assert_eq!(error.stage, VerificationStage::Signature);
        assert_eq!(error.kind, VerificationErrorKind::SignatureMismatch);
    }

    Ok(())
}

#[test]
fn pss_actual_hash_must_match_the_declared_profile() -> TestResult {
    let sd = decode(PS384)?;
    let mut signer = sd.signer_infos.to_vec()[0].clone();
    signer.digest_algorithm = algorithm(SHA256, None)?;
    signer.signature_algorithm = algorithm(RSA_PSS, Some(pss(SHA256, SHA256, 32, None)?))?;
    let key = &certificate(&sd)?.tbs_certificate.subject_public_key_info;
    let signature_algorithm = timestamp_signature_algorithm(&signer, &key.algorithm).required()?;

    let tbs = signed_attributes_digested_content(&signer)
        .required()?
        .required()?;

    let signature = OctetString::new(bytes::Bytes::copy_from_slice(&signer.signature));

    assert!(validate_timestamp_sig(
        &signature_algorithm,
        &bcder::Oid::from_str(SHA256).required()?,
        &signature,
        &tbs,
        &rasn::der::encode(key).required()?,
    )
    .is_err());

    Ok(())
}

#[test]
fn pss_spki_restrictions_and_key_compatibility() -> TestResult {
    let sd = decode(PS256)?;
    let signer = sd.signer_infos.to_vec()[0].clone();

    for parameters in [
        None,
        Some(pss(SHA256, SHA256, 32, None)?),
        Some(pss(SHA256, SHA256, 20, None)?),
    ] {
        let key = algorithm(RSA_PSS, parameters.clone())?;

        assert!(timestamp_signature_algorithm(&signer, &key).is_ok());

        let mut changed = sd.clone();

        change_certificate(&mut changed, |cert| {
            cert.tbs_certificate.subject_public_key_info.algorithm = key;

            Ok(())
        })?;

        verify(&encode(&changed)?)?;
    }

    for parameters in [
        vec![0x30, 0],
        pss(SHA384, SHA384, 48, None)?,
        pss(SHA256, SHA384, 32, None)?,
        pss(SHA256, SHA256, 33, None)?,
        pss(SHA256, SHA256, 32, Some(2))?,
        vec![5, 0],
    ] {
        assert!(
            timestamp_signature_algorithm(&signer, &algorithm(RSA_PSS, Some(parameters))?).is_err()
        );
    }

    for incompatible in [EC_PUBLIC_KEY, "1.3.101.112"] {
        assert!(timestamp_signature_algorithm(&signer, &algorithm(incompatible, None)?).is_err());
    }

    let legacy = decode(PKCS1)?;

    assert!(timestamp_signature_algorithm(
        legacy.signer_infos.to_vec()[0],
        &algorithm(RSA_PSS, None)?,
    )
    .is_err());

    Ok(())
}

#[test]
fn both_signer_lookup_sites_accept_ski_and_preserve_issuer_serial() -> TestResult {
    let mut sd = decode(PS256)?;

    let expected = signer_certificate_from_token(PS256)
        .required()?
        .required()?;

    verify(PS256)?;

    let extension = certificate(&sd)?
        .tbs_certificate
        .extensions
        .as_ref()
        .required()?
        .iter()
        .find(|extension| {
            extension.extn_id
                == Oid::JOINT_ISO_ITU_T_DS_CERTIFICATE_EXTENSION_SUBJECT_KEY_IDENTIFIER
        })
        .required()?
        .extn_value
        .clone();

    let identifier = rasn::der::decode::<types::OctetString>(&extension).required()?;

    let mut signer = sd.signer_infos.to_vec()[0].clone();
    signer.version = 3.into();
    signer.sid = SignerIdentifier::SubjectKeyIdentifier(identifier.clone());
    sd.signer_infos = vec![signer.clone()].into();
    let token = encode(&sd)?;

    assert_eq!(
        signer_certificate_from_token(&token).required()?,
        Some(expected)
    );

    verify(&token)?;

    for value in [
        None,
        Some(vec![4, 1, 0]),
        Some(identifier.to_vec()),
        Some(vec![4, 20, 1]),
        Some(vec![5, 0]),
        Some([extension.to_vec(), vec![5, 0]].concat()),
    ] {
        let mut changed = sd.clone();

        change_certificate(&mut changed, |cert| {
            let extensions = cert.tbs_certificate.extensions.as_mut().required()?;

            if let Some(value) = value {
                let extension = extensions
                    .iter_mut()
                    .find(|extension| {
                        extension.extn_id
                            == Oid::JOINT_ISO_ITU_T_DS_CERTIFICATE_EXTENSION_SUBJECT_KEY_IDENTIFIER
                    })
                    .required()?;

                extension.extn_value = value.into();
            } else {
                extensions.retain(|extension| {
                    extension.extn_id
                        != Oid::JOINT_ISO_ITU_T_DS_CERTIFICATE_EXTENSION_SUBJECT_KEY_IDENTIFIER
                });
            }

            Ok(())
        })?;

        let token = encode(&changed)?;

        assert!(signer_certificate_from_token(&token).required()?.is_none());

        let error = verify(&token).err().required()?;

        assert_eq!(error.stage, VerificationStage::SignerIdentifier);
        assert_eq!(error.kind, VerificationErrorKind::NoMatchingCertificate);
    }

    signer.sid = SignerIdentifier::SubjectKeyIdentifier(extension);
    sd.signer_infos = vec![signer].into();
    let token = encode(&sd)?;

    assert!(signer_certificate_from_token(&token).required()?.is_none());

    let error = verify(&token).err().required()?;

    assert_eq!(error.stage, VerificationStage::SignerIdentifier);
    assert_eq!(error.kind, VerificationErrorKind::NoMatchingCertificate);

    Ok(())
}

#[test]
fn valid_signature_does_not_establish_message_imprint() -> TestResult {
    let parsed = ParsedTimestamp::parse(PS256)?;
    let signed = parsed.verify_signatures().next().required()??;

    let error = signed
        .verify_message_imprint(b"not the timestamped message")
        .err()
        .required()?;

    assert_eq!(error.stage, VerificationStage::MessageImprint);

    assert_eq!(error.kind, VerificationErrorKind::InvalidData);

    Ok(())
}

#[test]
fn valid_timestamp_cryptography_does_not_validate_certificate_signature_or_profile() -> TestResult {
    let mut sd = decode(PS256)?;

    change_certificate(&mut sd, |cert| {
        cert.signature_value.fill(false);
        cert.tbs_certificate.extensions = None;

        Ok(())
    })?;

    // Issuer/serial lookup and CMS cryptography do not validate the certificate.
    verify(&encode(&sd)?)?;

    Ok(())
}
