// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License, Version 2.0
// (http://www.apache.org/licenses/LICENSE-2.0) or the MIT license
// (http://opensource.org/licenses/MIT), at your option.
// Unless required by applicable law or agreed to in writing, this file
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
// OF ANY KIND, either express or implied. See the LICENSE-MIT and
// LICENSE-APACHE files for the specific language governing permissions
// and limitations under each license.

//! Regression coverage for timestamp RSA-PSS profiles and SKI signer lookup.

#![allow(clippy::unwrap_used)]

use super::*;

const DATA: &[u8] = b"RSA timestamp regression";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const SHA384: &str = "2.16.840.1.101.3.4.2.2";
const SHA512: &str = "2.16.840.1.101.3.4.2.3";
const PS256: &[u8] = include_bytes!("../../../tests/fixtures/crypto/time_stamp/ps256.tst");
const PS384: &[u8] = include_bytes!("../../../tests/fixtures/crypto/time_stamp/ps384.tst");
const PS512: &[u8] = include_bytes!("../../../tests/fixtures/crypto/time_stamp/ps512.tst");
const PKCS1: &[u8] = include_bytes!("../../../tests/fixtures/crypto/time_stamp/rsa-pkcs1.tst");

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

fn algorithm(oid: &str, parameters: Option<Vec<u8>>) -> rasn_pkix::AlgorithmIdentifier {
    rasn_pkix::AlgorithmIdentifier {
        algorithm: types::ObjectIdentifier::new_unchecked(
            oid.split('.')
                .map(|part| part.parse().unwrap())
                .collect::<Vec<_>>()
                .into(),
        ),
        parameters: parameters.map(types::Any::new),
    }
}

fn hash_algorithm(hash: &str) -> Vec<u8> {
    rasn::der::encode(&algorithm(hash, Some(vec![5, 0]))).unwrap()
}

fn pss(hash: &str, mgf_hash: &str, salt: u8, trailer: Option<u8>) -> Vec<u8> {
    let mut fields = tlv(0xa0, &hash_algorithm(hash));
    fields.extend(tlv(
        0xa1,
        &rasn::der::encode(&algorithm(MGF1, Some(hash_algorithm(mgf_hash)))).unwrap(),
    ));
    fields.extend(tlv(0xa2, &tlv(2, &[salt])));

    if let Some(trailer) = trailer {
        fields.extend(tlv(0xa3, &tlv(2, &[trailer])));
    }

    tlv(0x30, &fields)
}

fn decode(token: &[u8]) -> rasn_cms::SignedData {
    signed_data_from_time_stamp_response(token)
        .unwrap()
        .unwrap()
}

fn encode(sd: &rasn_cms::SignedData) -> Vec<u8> {
    let mut content: rasn_cms::ContentInfo = rasn::der::decode(PS256).unwrap();
    content.content = types::Any::new(rasn::der::encode(sd).unwrap());
    rasn::der::encode(&content).unwrap()
}

fn certificate(sd: &rasn_cms::SignedData) -> &rasn_pkix::Certificate {
    sd.certificates
        .as_ref()
        .unwrap()
        .to_vec()
        .into_iter()
        .find_map(|choice| match choice {
            CertificateChoices::Certificate(cert) => Some(cert.as_ref()),
            _ => None,
        })
        .unwrap()
}

fn change_certificate(
    sd: &mut rasn_cms::SignedData,
    change: impl FnOnce(&mut rasn_pkix::Certificate),
) {
    let mut cert = certificate(sd).clone();
    change(&mut cert);
    sd.certificates = Some(vec![CertificateChoices::Certificate(Box::new(cert))].into());
}

fn verify(token: &[u8]) -> (Result<TstInfo, TimeStampError>, StatusTracker) {
    let mut log = StatusTracker::default();
    let result = verify_time_stamp(
        token,
        DATA,
        &CertificateTrustPolicy::default(),
        &mut log,
        false,
    );
    (result, log)
}

#[test]
fn rsa_pss_profiles_with_rsa_encryption_spki_and_legacy_pkcs1_verify() {
    for token in [PS256, PS384, PS512, PKCS1] {
        let sd = decode(token);
        assert_eq!(
            certificate(&sd)
                .tbs_certificate
                .subject_public_key_info
                .algorithm
                .algorithm
                .to_string(),
            RSA_ENCRYPTION
        );
        let (result, log) = verify(token);
        assert!(result.is_ok(), "{result:?}: {log:?}");
        assert!(log.has_status(TIMESTAMP_VALIDATED));
        assert!(log.has_status(TIMESTAMP_TRUSTED));
        assert!(!log.has_status(TIMESTAMP_UNTRUSTED));

        if token != PKCS1 {
            let signer = sd.signer_infos.to_vec()[0];
            let key = &certificate(&sd).tbs_certificate.subject_public_key_info;
            let tbs = signed_attributes_digested_content(signer).unwrap().unwrap();
            let signature = OctetString::new(bytes::Bytes::copy_from_slice(&signer.signature));
            assert!(
                validate_timestamp_sig(
                    &bcder::Oid::from_str(RSA_ENCRYPTION).unwrap(),
                    &bcder::Oid::from_str(&signer.digest_algorithm.algorithm.to_string()).unwrap(),
                    &signature,
                    &tbs,
                    &rasn::der::encode(key).unwrap(),
                )
                .is_err(),
                "the previous SPKI-based selection must reproduce the failure"
            );
        }
    }
}

#[test]
fn rsa_profiles_and_ski_signers_reach_normal_tsa_trust_validation() {
    for token in [PS256, PS384, PS512, PKCS1] {
        let mut sd = decode(token);
        let cert_der = tsa_signer_cert_der_from_token(token).unwrap().unwrap();
        let pem = pem::encode(&pem::Pem::new("CERTIFICATE", cert_der));
        let mut policy = CertificateTrustPolicy::new();
        policy
            .add_trust_anchors(pem.as_bytes(), "test:tsa", TrustAnchorType::TSA, None)
            .unwrap();

        for ski in [false, true] {
            if ski {
                let extension = certificate(&sd)
                    .tbs_certificate
                    .extensions
                    .as_ref()
                    .unwrap()
                    .iter()
                    .find(|extension| {
                        extension.extn_id
                            == Oid::JOINT_ISO_ITU_T_DS_CERTIFICATE_EXTENSION_SUBJECT_KEY_IDENTIFIER
                    })
                    .unwrap();
                let mut signer = sd.signer_infos.to_vec()[0].clone();
                signer.version = 3.into();
                signer.sid = SignerIdentifier::SubjectKeyIdentifier(
                    rasn::der::decode(&extension.extn_value).unwrap(),
                );
                sd.signer_infos = vec![signer].into();
            }

            let mut log = StatusTracker::default();
            let result = verify_time_stamp(&encode(&sd), DATA, &policy, &mut log, true);
            assert!(result.is_ok(), "{result:?}: {log:?}");
            assert!(log.has_status(TIMESTAMP_VALIDATED));
            assert!(log.has_status(TIMESTAMP_TRUSTED));
            assert!(!log.has_status(TIMESTAMP_UNTRUSTED));
        }
    }
}

#[test]
fn legacy_rsa_signature_oids_preserve_pkcs1_and_require_matching_digest() {
    let mut sd = decode(PKCS1);
    let mut signer = sd.signer_infos.to_vec()[0].clone();
    let key = &certificate(&sd)
        .tbs_certificate
        .subject_public_key_info
        .algorithm;

    for (signature, hash) in [
        ("1.2.840.113549.1.1.5", "1.3.14.3.2.26"),
        ("1.2.840.113549.1.1.11", SHA256),
        ("1.2.840.113549.1.1.12", SHA384),
        ("1.2.840.113549.1.1.13", SHA512),
    ] {
        signer.signature_algorithm = algorithm(signature, Some(vec![5, 0]));
        signer.digest_algorithm = algorithm(hash, None);
        assert_eq!(
            timestamp_signature_algorithm(&signer, key)
                .unwrap()
                .to_string(),
            RSA_ENCRYPTION
        );
        signer.digest_algorithm = algorithm("1.2.3.4", None);
        assert!(timestamp_signature_algorithm(&signer, key).is_err());
    }

    signer.signature_algorithm = algorithm("1.2.840.113549.1.1.11", Some(vec![5, 0]));
    signer.digest_algorithm = algorithm(SHA256, None);
    sd.signer_infos = vec![signer].into();
    assert!(verify(&encode(&sd)).0.is_ok());
}

#[test]
fn pss_signature_parameters_are_required_and_strictly_parsed() {
    let sd = decode(PS256);
    let mut signer = sd.signer_infos.to_vec()[0].clone();
    let key = &certificate(&sd)
        .tbs_certificate
        .subject_public_key_info
        .algorithm;
    signer.signature_algorithm.parameters = None;
    assert!(matches!(
        timestamp_signature_algorithm(&signer, key),
        Err(TimeStampError::DecodeError(_))
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
                &rasn::der::encode(&algorithm(SHA256, Some(vec![4, 0]))).unwrap(),
            ),
        ),
        tlv(0x30, &tlv(0xa2, &[2, 1, 32, 5, 0])),
        tlv(
            0x30,
            &[
                tlv(0xa0, &hash_algorithm(SHA256)),
                tlv(0xa0, &hash_algorithm(SHA256)),
            ]
            .concat(),
        ),
        tlv(
            0x30,
            &[
                tlv(0xa2, &tlv(2, &[32])),
                tlv(0xa0, &hash_algorithm(SHA256)),
            ]
            .concat(),
        ),
        [pss(SHA256, SHA256, 32, None), vec![5, 0]].concat(),
        tlv(
            0x30,
            &tlv(0xa1, &rasn::der::encode(&algorithm(MGF1, None)).unwrap()),
        ),
    ] {
        signer.signature_algorithm.parameters = Some(types::Any::new(parameters.clone()));
        assert!(
            matches!(
                timestamp_signature_algorithm(&signer, key),
                Err(TimeStampError::DecodeError(_))
            ),
            "{parameters:02x?}"
        );
    }
}

#[test]
fn pss_profiles_reject_unsupported_and_inconsistent_parameters() {
    let mut sd = decode(PS256);
    let mut signer = sd.signer_infos.to_vec()[0].clone();

    for parameters in [
        vec![0x30, 0],
        pss("1.3.14.3.2.26", "1.3.14.3.2.26", 20, None),
        pss("2.16.840.1.101.3.4.2.4", "2.16.840.1.101.3.4.2.4", 28, None),
        pss(SHA384, SHA384, 48, None),
        pss(SHA256, SHA384, 32, None),
        pss(SHA256, SHA256, 0, None),
        pss(SHA256, SHA256, 33, None),
        pss(SHA256, SHA256, 32, Some(2)),
        tlv(0x30, &tlv(0xa0, &hash_algorithm(SHA256))),
        tlv(
            0x30,
            &[
                tlv(0xa0, &hash_algorithm(SHA256)),
                tlv(
                    0xa1,
                    &rasn::der::encode(&algorithm("1.2.3.4", Some(hash_algorithm(SHA256))))
                        .unwrap(),
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
                    &certificate(&sd)
                        .tbs_certificate
                        .subject_public_key_info
                        .algorithm
                ),
                Err(TimeStampError::UnsupportedAlgorithm)
            ),
            "{parameters:02x?}"
        );
        sd.signer_infos = vec![signer.clone()].into();
        let (result, log) = verify(&encode(&sd));
        assert!(result.is_err(), "{parameters:02x?}");
        assert!(log.has_status(TIMESTAMP_MALFORMED));
        assert!(!log.has_status(TIMESTAMP_TRUSTED));
    }
}

#[test]
fn pss_parameter_defaults_and_null_or_absent_hash_parameters() {
    for (hash, salt) in [(SHA256, 32), (SHA384, 48), (SHA512, 64)] {
        let sd = decode(PS256);
        let key = &certificate(&sd)
            .tbs_certificate
            .subject_public_key_info
            .algorithm;
        let mut signer = sd.signer_infos.to_vec()[0].clone();
        signer.digest_algorithm = algorithm(hash, None);
        signer.signature_algorithm = algorithm(RSA_PSS, Some(pss(hash, hash, salt, None)));
        assert!(timestamp_signature_algorithm(&signer, key).is_ok());

        let hash_der = rasn::der::encode(&algorithm(hash, None)).unwrap();
        let fields = [
            tlv(0xa0, &hash_der),
            tlv(
                0xa1,
                &rasn::der::encode(&algorithm(MGF1, Some(hash_der))).unwrap(),
            ),
            tlv(0xa2, &tlv(2, &[salt])),
        ]
        .concat();
        signer.signature_algorithm.parameters = Some(types::Any::new(tlv(0x30, &fields)));
        assert!(timestamp_signature_algorithm(&signer, key).is_ok());
    }

    let defaults = pss_parameters(&types::Any::new(vec![0x30, 0])).unwrap();
    assert_eq!(defaults.hash, "1.3.14.3.2.26");
    assert_eq!(defaults.mgf_hash, "1.3.14.3.2.26");
    assert_eq!(defaults.salt_length, 20);
    assert_eq!(defaults.trailer, 1);
}

#[test]
fn pss_actual_salt_must_match_the_declared_profile() {
    for token in [
        include_bytes!("../../../tests/fixtures/crypto/time_stamp/ps256-salt0.tst").as_slice(),
        include_bytes!("../../../tests/fixtures/crypto/time_stamp/ps256-saltmax.tst").as_slice(),
    ] {
        assert!(verify(token).0.is_err());
        let mut sd = decode(token);
        let mut signer = sd.signer_infos.to_vec()[0].clone();
        signer.signature_algorithm = algorithm(RSA_PSS, Some(pss(SHA256, SHA256, 32, None)));
        sd.signer_infos = vec![signer].into();
        let (result, log) = verify(&encode(&sd));
        assert!(matches!(result, Err(TimeStampError::Untrusted)));
        assert!(log.has_status(TIMESTAMP_UNTRUSTED));
        assert!(!log.has_status(TIMESTAMP_TRUSTED));
    }
}

#[test]
fn pss_actual_hash_must_match_the_declared_profile() {
    let sd = decode(PS384);
    let mut signer = sd.signer_infos.to_vec()[0].clone();
    signer.digest_algorithm = algorithm(SHA256, None);
    signer.signature_algorithm = algorithm(RSA_PSS, Some(pss(SHA256, SHA256, 32, None)));
    let key = &certificate(&sd).tbs_certificate.subject_public_key_info;
    let signature_algorithm = timestamp_signature_algorithm(&signer, &key.algorithm).unwrap();
    let tbs = signed_attributes_digested_content(&signer)
        .unwrap()
        .unwrap();
    let signature = OctetString::new(bytes::Bytes::copy_from_slice(&signer.signature));
    assert!(validate_timestamp_sig(
        &signature_algorithm,
        &bcder::Oid::from_str(SHA256).unwrap(),
        &signature,
        &tbs,
        &rasn::der::encode(key).unwrap(),
    )
    .is_err());
}

#[test]
fn pss_spki_restrictions_and_key_compatibility() {
    let sd = decode(PS256);
    let signer = sd.signer_infos.to_vec()[0].clone();

    for parameters in [
        None,
        Some(pss(SHA256, SHA256, 32, None)),
        Some(pss(SHA256, SHA256, 20, None)),
    ] {
        let key = algorithm(RSA_PSS, parameters.clone());
        assert!(timestamp_signature_algorithm(&signer, &key).is_ok());
        let mut changed = sd.clone();
        change_certificate(&mut changed, |cert| {
            cert.tbs_certificate.subject_public_key_info.algorithm = key;
        });
        let (result, log) = verify(&encode(&changed));
        assert!(result.is_ok(), "{parameters:02x?}: {result:?}: {log:?}");
    }

    for parameters in [
        vec![0x30, 0],
        pss(SHA384, SHA384, 48, None),
        pss(SHA256, SHA384, 32, None),
        pss(SHA256, SHA256, 33, None),
        pss(SHA256, SHA256, 32, Some(2)),
        vec![5, 0],
    ] {
        assert!(
            timestamp_signature_algorithm(&signer, &algorithm(RSA_PSS, Some(parameters))).is_err()
        );
    }

    for incompatible in [EC_PUBLIC_KEY, "1.3.101.112"] {
        assert!(timestamp_signature_algorithm(&signer, &algorithm(incompatible, None)).is_err());
    }

    let legacy = decode(PKCS1);
    assert!(timestamp_signature_algorithm(
        legacy.signer_infos.to_vec()[0],
        &algorithm(RSA_PSS, None),
    )
    .is_err());
}

#[test]
fn both_signer_lookup_sites_accept_ski_and_preserve_issuer_serial() {
    let mut sd = decode(PS256);
    let expected = tsa_signer_cert_der_from_token(PS256).unwrap().unwrap();
    assert!(verify(PS256).0.is_ok());
    let extension = certificate(&sd)
        .tbs_certificate
        .extensions
        .as_ref()
        .unwrap()
        .iter()
        .find(|extension| {
            extension.extn_id
                == Oid::JOINT_ISO_ITU_T_DS_CERTIFICATE_EXTENSION_SUBJECT_KEY_IDENTIFIER
        })
        .unwrap()
        .extn_value
        .clone();
    let identifier = rasn::der::decode::<types::OctetString>(&extension).unwrap();
    let mut signer = sd.signer_infos.to_vec()[0].clone();
    signer.version = 3.into();
    signer.sid = SignerIdentifier::SubjectKeyIdentifier(identifier.clone());
    sd.signer_infos = vec![signer.clone()].into();
    let token = encode(&sd);
    assert_eq!(
        tsa_signer_cert_der_from_token(&token).unwrap(),
        Some(expected)
    );
    let (result, log) = verify(&token);
    assert!(result.is_ok(), "{result:?}: {log:?}");
    assert!(log.has_status(TIMESTAMP_VALIDATED));

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
            let extensions = cert.tbs_certificate.extensions.as_mut().unwrap();
            if let Some(value) = value {
                let extension = extensions
                    .iter_mut()
                    .find(|extension| {
                        extension.extn_id
                            == Oid::JOINT_ISO_ITU_T_DS_CERTIFICATE_EXTENSION_SUBJECT_KEY_IDENTIFIER
                    })
                    .unwrap();
                extension.extn_value = value.into();
            } else {
                extensions.retain(|extension| {
                    extension.extn_id
                        != Oid::JOINT_ISO_ITU_T_DS_CERTIFICATE_EXTENSION_SUBJECT_KEY_IDENTIFIER
                });
            }
        });
        let token = encode(&changed);
        assert!(tsa_signer_cert_der_from_token(&token).unwrap().is_none());
        assert!(matches!(verify(&token).0, Err(TimeStampError::InvalidData)));
    }

    signer.sid = SignerIdentifier::SubjectKeyIdentifier(extension);
    sd.signer_infos = vec![signer].into();
    let token = encode(&sd);
    assert!(tsa_signer_cert_der_from_token(&token).unwrap().is_none());
    assert!(matches!(verify(&token).0, Err(TimeStampError::InvalidData)));
}
