// Copyright 2022 Adobe. All rights reserved.
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

use async_generic::async_generic;
use c2pa_raw_crypto::SigningAlg;
use coset::{
    cbor::value::Value,
    iana::{self, Algorithm, EnumI64},
    CoseSign1, Label, RegisteredLabelWithPrivate, TaggedCborSerializable,
};

use crate::{
    crypto::cose::{
        validate_cose_tst_info, validate_cose_tst_info_async, CertificateTrustPolicy, CoseError,
    },
    log_item,
    status_tracker::StatusTracker,
    validation_results::validation_codes::CLAIM_SIGNATURE_MISMATCH,
};

/// Parse a byte slice as a COSE Sign1 data structure.
///
/// Log errors that might occur to the provided [`StatusTracker`].
pub fn parse_cose_sign1(
    cose_bytes: &[u8],
    data: &[u8],
    validation_log: &mut StatusTracker,
) -> Result<CoseSign1, CoseError> {
    let mut sign1 = <coset::CoseSign1 as TaggedCborSerializable>::from_tagged_slice(cose_bytes)
        .map_err(|coset_error| {
            log_item!(
                "Cose_Sign1",
                "could not parse signature",
                "parse_cose_sign1"
            )
            .validation_status(CLAIM_SIGNATURE_MISMATCH)
            .failure_no_throw(
                validation_log,
                CoseError::CborParsingError(coset_error.to_string()),
            );

            CoseError::CborParsingError(coset_error.to_string())
        })?;

    // Temporarily restore the payload into the signature for verification check.
    sign1.payload = Some(data.to_vec());

    Ok(sign1)
}

/// TO DO: Documentation for this function.
pub fn signing_alg_from_sign1(sign1: &coset::CoseSign1) -> Result<SigningAlg, CoseError> {
    let Some(ref alg) = sign1.protected.header.alg else {
        return Err(CoseError::UnsupportedSigningAlgorithm);
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
            _ => Err(CoseError::UnsupportedSigningAlgorithm),
        },

        RegisteredLabelWithPrivate::Assigned(a) => match a {
            Algorithm::PS512 => Ok(SigningAlg::Ps512),
            Algorithm::PS384 => Ok(SigningAlg::Ps384),
            Algorithm::PS256 => Ok(SigningAlg::Ps256),
            Algorithm::ES512 => Ok(SigningAlg::Es512),
            Algorithm::ES384 => Ok(SigningAlg::Es384),
            Algorithm::ES256 => Ok(SigningAlg::Es256),
            Algorithm::EdDSA => Ok(SigningAlg::Ed25519),
            _ => Err(CoseError::UnsupportedSigningAlgorithm),
        },

        _ => Err(CoseError::UnsupportedSigningAlgorithm),
    }
}

/// TO DO: Documentation for this function.
pub fn cert_chain_from_sign1(sign1: &coset::CoseSign1) -> Result<Vec<Vec<u8>>, CoseError> {
    // Check the protected header first.
    let Some(value) = sign1
        .protected
        .header
        .rest
        .iter()
        .find_map(|x: &(Label, Value)| is_x5chain_label(&x.0).then(|| x.1.clone()))
    else {
        // Not there: Also try unprotected header. (This was permitted in older versions
        // of C2PA.)
        return get_unprotected_header_certs(sign1);
    };

    // Certs may be in protected or unprotected header, but not both. Check for the
    // label itself, so a malformed chain in the unprotected header is not ignored.
    if sign1
        .unprotected
        .rest
        .iter()
        .any(|x: &(Label, Value)| is_x5chain_label(&x.0))
    {
        return Err(CoseError::MultipleSigningCertificateChains);
    }

    cert_chain_from_cbor_value(value)
}

/// The x5chain header may use its text label or its IANA integer label (33).
fn is_x5chain_label(label: &Label) -> bool {
    *label == Label::Text("x5chain".to_string())
        || *label == Label::Int(iana::HeaderParameter::X5Chain.to_i64())
}

fn get_unprotected_header_certs(sign1: &coset::CoseSign1) -> Result<Vec<Vec<u8>>, CoseError> {
    let Some(value) = sign1
        .unprotected
        .rest
        .iter()
        .find_map(|x: &(Label, Value)| is_x5chain_label(&x.0).then(|| x.1.clone()))
    else {
        return Err(CoseError::MissingSigningCertificateChain);
    };

    cert_chain_from_cbor_value(value)
}

fn cert_chain_from_cbor_value(value: Value) -> Result<Vec<Vec<u8>>, CoseError> {
    match value {
        Value::Array(cert_chain) => {
            // Every entry must be a certificate. Skipping a malformed entry would
            // promote the next certificate to signing certificate.
            let certs = cert_chain
                .into_iter()
                .map(|c| match c {
                    Value::Bytes(der_bytes) => Ok(der_bytes),
                    _ => Err(CoseError::MissingSigningCertificateChain),
                })
                .collect::<Result<Vec<Vec<u8>>, CoseError>>()?;

            if certs.is_empty() {
                Err(CoseError::MissingSigningCertificateChain)
            } else {
                Ok(certs)
            }
        }

        Value::Bytes(ref der_bytes) => Ok(vec![der_bytes.clone()]),

        _ => Err(CoseError::MissingSigningCertificateChain),
    }
}

/// Return the time of signing for this signature.
///
/// Should not be used for certificate validation.
#[async_generic]
pub fn signing_time_from_sign1(
    sign1: &coset::CoseSign1,
    data: &[u8],
    verify_trust: bool,
) -> Option<chrono::DateTime<chrono::Utc>> {
    // get timestamp info if available

    let mut local_log = StatusTracker::default();
    // allow timestamp reading by using passthrough certificate check
    let local_ctp = CertificateTrustPolicy::passthrough();

    let time_stamp_info = if _sync {
        validate_cose_tst_info(sign1, data, &local_ctp, &mut local_log, verify_trust)
    } else {
        validate_cose_tst_info_async(sign1, data, &local_ctp, &mut local_log, verify_trust).await
    };

    if let Ok(tst_info) = time_stamp_info {
        Some(tst_info.gen_time.into())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use coset::{CoseSign1Builder, HeaderBuilder};
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    #[test]
    fn algorithms_accept_assigned_and_legacy_private_labels_only() {
        for (assigned, private, expected) in [
            (Algorithm::PS512, -39, SigningAlg::Ps512),
            (Algorithm::PS384, -38, SigningAlg::Ps384),
            (Algorithm::PS256, -37, SigningAlg::Ps256),
            (Algorithm::ES512, -36, SigningAlg::Es512),
            (Algorithm::ES384, -35, SigningAlg::Es384),
            (Algorithm::ES256, -7, SigningAlg::Es256),
            (Algorithm::EdDSA, -8, SigningAlg::Ed25519),
        ] {
            for label in [
                RegisteredLabelWithPrivate::Assigned(assigned),
                RegisteredLabelWithPrivate::PrivateUse(private),
            ] {
                let mut sign1 = CoseSign1::default();
                sign1.protected.header.alg = Some(label);
                assert_eq!(signing_alg_from_sign1(&sign1).unwrap(), expected);
            }
        }

        for alg in [
            None,
            Some(RegisteredLabelWithPrivate::Assigned(Algorithm::A128GCM)),
            Some(RegisteredLabelWithPrivate::PrivateUse(-65537)),
            Some(RegisteredLabelWithPrivate::Text("ES256".into())),
        ] {
            let mut sign1 = CoseSign1::default();
            sign1.protected.header.alg = alg;
            assert!(matches!(
                signing_alg_from_sign1(&sign1),
                Err(CoseError::UnsupportedSigningAlgorithm)
            ));
        }
    }

    #[test]
    fn certificate_chain_header_locations_and_value_shapes() {
        let cert = vec![1, 2, 3];
        let chain = vec![cert.clone(), vec![4, 5]];
        for label in [
            Label::Text("x5chain".into()),
            Label::Int(iana::HeaderParameter::X5Chain.to_i64()),
        ] {
            for (value, expected) in [
                (Value::Bytes(cert.clone()), vec![cert.clone()]),
                (
                    Value::Array(chain.iter().cloned().map(Value::Bytes).collect()),
                    chain.clone(),
                ),
            ] {
                let mut sign1 = CoseSign1::default();
                sign1.protected.header.rest.push((label.clone(), value));
                assert_eq!(cert_chain_from_sign1(&sign1).unwrap(), expected);
            }
        }

        let mut legacy = CoseSign1::default();
        legacy
            .unprotected
            .rest
            .push((Label::Text("x5chain".into()), Value::Bytes(cert.clone())));
        assert_eq!(cert_chain_from_sign1(&legacy).unwrap(), vec![cert.clone()]);
        legacy.protected.header.rest.push((
            Label::Int(iana::HeaderParameter::X5Chain.to_i64()),
            Value::Bytes(cert),
        ));
        assert!(matches!(
            cert_chain_from_sign1(&legacy),
            Err(CoseError::MultipleSigningCertificateChains)
        ));
    }

    #[test]
    fn absent_and_malformed_chains_are_not_certificates() {
        assert!(matches!(
            cert_chain_from_sign1(&CoseSign1::default()),
            Err(CoseError::MissingSigningCertificateChain)
        ));
        for value in [
            Value::Null,
            Value::Array(vec![]),
            Value::Array(vec![Value::Null]),
            // A non-certificate entry would promote the next one to signing certificate.
            Value::Array(vec![Value::Null, Value::Bytes(vec![1])]),
        ] {
            assert!(matches!(
                cert_chain_from_cbor_value(value),
                Err(CoseError::MissingSigningCertificateChain)
            ));
        }

        let mut sign1 = CoseSign1::default();
        sign1.unprotected.rest.push((
            Label::Int(iana::HeaderParameter::X5Chain.to_i64()),
            Value::Bytes(vec![1]),
        ));
        // Either label is recognized in legacy unprotected headers.
        assert_eq!(cert_chain_from_sign1(&sign1).unwrap(), vec![vec![1]]);
    }

    #[test]
    fn parsing_requires_a_tag_and_restores_the_supplied_payload() {
        let original = CoseSign1 {
            payload: Some(b"embedded".to_vec()),
            signature: vec![1, 2],
            ..Default::default()
        };

        let encoded = original.to_tagged_vec().unwrap();
        let mut log = StatusTracker::default();
        let parsed = parse_cose_sign1(&encoded, b"detached", &mut log).unwrap();
        assert_eq!(parsed.payload.as_deref(), Some(b"detached".as_slice()));
        assert_eq!(parsed.signature, vec![1, 2]);
        assert!(log.logged_items().is_empty());
        for bad in [b"not CBOR".as_slice(), &encoded[1..]] {
            let mut log = StatusTracker::default();
            assert!(matches!(
                parse_cose_sign1(bad, b"", &mut log),
                Err(CoseError::CborParsingError(_))
            ));
            assert!(log.has_status(CLAIM_SIGNATURE_MISMATCH));
        }
    }

    #[c2pa_macros::c2pa_test_async]
    async fn missing_timestamp_has_no_signing_time_in_either_api() {
        let sign1 = CoseSign1::default();
        assert!(signing_time_from_sign1(&sign1, b"", false).is_none());
        assert!(signing_time_from_sign1_async(&sign1, b"", false)
            .await
            .is_none());
    }

    const X5CHAIN: i64 = iana::HeaderParameter::X5Chain as i64;

    fn chain(certs: &[&[u8]]) -> Value {
        Value::Array(certs.iter().map(|c| Value::Bytes(c.to_vec())).collect())
    }

    #[test]
    fn unprotected_x5chain_integer_label_is_found() {
        let sign1 = CoseSign1Builder::new()
            .unprotected(
                HeaderBuilder::new()
                    .value(X5CHAIN, chain(&[b"leaf"]))
                    .build(),
            )
            .build();

        assert_eq!(
            cert_chain_from_sign1(&sign1).unwrap(),
            vec![b"leaf".to_vec()]
        );
    }

    #[test]
    fn x5chain_in_both_headers_is_rejected_for_either_label() {
        for unprotected in [
            HeaderBuilder::new().value(X5CHAIN, chain(&[b"other"])),
            HeaderBuilder::new().text_value("x5chain".to_string(), chain(&[b"other"])),
            // A malformed chain must not let the check pass.
            HeaderBuilder::new().value(X5CHAIN, Value::Text("not a chain".to_string())),
        ] {
            let sign1 = CoseSign1Builder::new()
                .protected(
                    HeaderBuilder::new()
                        .value(X5CHAIN, chain(&[b"leaf"]))
                        .build(),
                )
                .unprotected(unprotected.build())
                .build();

            assert!(matches!(
                cert_chain_from_sign1(&sign1),
                Err(CoseError::MultipleSigningCertificateChains)
            ));
        }
    }

    #[test]
    fn x5chain_with_a_non_certificate_entry_is_rejected() {
        let entries = Value::Array(vec![
            Value::Text("not a certificate".to_string()),
            Value::Bytes(b"intermediate".to_vec()),
        ]);
        let sign1 = CoseSign1Builder::new()
            .protected(HeaderBuilder::new().value(X5CHAIN, entries).build())
            .build();

        assert!(matches!(
            cert_chain_from_sign1(&sign1),
            Err(CoseError::MissingSigningCertificateChain)
        ));
    }

    #[test]
    fn well_formed_x5chain_is_accepted() {
        let sign1 = CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .value(X5CHAIN, chain(&[b"leaf", b"intermediate"]))
                    .build(),
            )
            .build();

        assert_eq!(
            cert_chain_from_sign1(&sign1).unwrap(),
            vec![b"leaf".to_vec(), b"intermediate".to_vec()]
        );
    }
}
