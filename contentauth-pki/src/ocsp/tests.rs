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

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GOOD: &[u8] = include_bytes!("../../../sdk/tests/fixtures/crypto/ocsp/response_good.der");

fn chain() -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    Ok(pem::parse_many(include_bytes!(
        "../../../sdk/tests/fixtures/crypto/ocsp/ocsp_chain.pem"
    ))?
    .into_iter()
    .map(|pem| pem.into_contents())
    .collect())
}

#[test]
fn parsed_claims_and_authenticated_bound_facts_are_distinct() -> TestResult {
    let parsed = ParsedOcspResponse::from_der(GOOD)?;
    assert_eq!(parsed.response_der(), GOOD);
    assert_eq!(
        parsed
            .claimed_responses()
            .next()
            .ok_or("missing claim")?
            .status()?,
        ClaimedStatus::Good
    );

    let signing_chain = chain()?;
    let verified = parsed.verify_signature(&signing_chain)?;
    assert_eq!(verified.response_der(), GOOD);
    assert!(!verified.responder_certificates().is_empty());

    let response = verified
        .responses_for_certificate(&signing_chain)
        .next()
        .ok_or("missing bound claim")?;
    assert_eq!(response.claims().status()?, ClaimedStatus::Good);
    assert!(!response.claims().certificate_serial_number().is_empty());
    assert!(response.claims().this_update()? <= verified.produced_at());
    assert_eq!(response.claims().next_update()?, None);
    assert_eq!(verified.responses_for_certificate(&[]).count(), 0);
    assert_eq!(
        verified
            .responses_for_certificate(&signing_chain[..1])
            .count(),
        0
    );

    // A parsed Good claim cannot manufacture signature-verified evidence.
    let mut damaged = ParsedOcspResponse::from_der(GOOD)?;
    damaged.basic.signature = rasn::types::BitString::from_vec(vec![0; 64]);
    assert!(matches!(
        damaged.verify_signature(&signing_chain),
        Err(VerificationError::UnauthenticatedResponse)
    ));

    Ok(())
}

#[test]
fn cert_id_requires_serial_both_issuer_hashes_and_supported_algorithm() -> TestResult {
    let chain = chain()?;
    let parsed = ParsedOcspResponse::from_der(GOOD)?;
    let original = parsed.basic.tbs_response_data.responses[0].cert_id.clone();
    assert!(cert_id_matches_signer(&original, &chain));

    for invalid_chain in [
        vec![],
        chain[..1].to_vec(),
        vec![vec![0], chain[1].clone()],
        vec![chain[0].clone(), vec![0]],
    ] {
        assert!(!cert_id_matches_signer(&original, &invalid_chain));
    }

    let mut wrong_serial = original.clone();
    wrong_serial.serial_number = 0.into();
    let mut wrong_name = original.clone();
    wrong_name.issuer_name_hash = vec![0; 20].into();
    let mut wrong_key = original.clone();
    wrong_key.issuer_key_hash = vec![0; 20].into();
    let mut unsupported = original.clone();
    unsupported.hash_algorithm.algorithm =
        rasn::types::ObjectIdentifier::new_unchecked(vec![1, 2, 3, 4].into());

    for invalid in [wrong_serial, wrong_name, wrong_key, unsupported] {
        assert!(!cert_id_matches_signer(&invalid, &chain));
    }

    let issuer: Certificate = rasn::der::decode(&chain[1])?;
    let mut sha256 = original;
    sha256.hash_algorithm.algorithm =
        rasn::types::ObjectIdentifier::new_unchecked(vec![2, 16, 840, 1, 101, 3, 4, 2, 1].into());
    sha256.issuer_name_hash =
        sha2::Sha256::digest(rasn::der::encode(&issuer.tbs_certificate.subject)?)
            .to_vec()
            .into();
    sha256.issuer_key_hash = sha2::Sha256::digest(
        issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_raw_slice(),
    )
    .to_vec()
    .into();
    assert!(cert_id_matches_signer(&sha256, &chain));

    Ok(())
}

#[test]
fn malformed_and_unsupported_inputs_remain_typed() -> TestResult {
    assert!(matches!(
        ParsedOcspResponse::from_der(b"not DER"),
        Err(ParseError::MalformedResponse)
    ));

    let mut response: rasn_ocsp::OcspResponse = rasn::der::decode(GOOD)?;
    response.status = OcspResponseStatus::Unauthorized;
    assert!(matches!(
        ParsedOcspResponse::from_der(&rasn::der::encode(&response)?),
        Err(ParseError::UnsuccessfulResponse)
    ));
    response.status = OcspResponseStatus::Successful;
    response.bytes = None;
    assert!(matches!(
        ParsedOcspResponse::from_der(&rasn::der::encode(&response)?),
        Err(ParseError::MissingResponse)
    ));

    let mut response: rasn_ocsp::OcspResponse = rasn::der::decode(GOOD)?;
    let bytes = response.bytes.as_mut().ok_or("missing basic response")?;
    let mut basic: BasicOcspResponse = rasn::der::decode(&bytes.response)?;
    basic.signature_algorithm.algorithm =
        rasn::types::ObjectIdentifier::new_unchecked(vec![1, 2, 3, 4].into());
    bytes.response = rasn::der::encode(&basic)?.into();

    assert!(matches!(
        ParsedOcspResponse::from_der(&rasn::der::encode(&response)?),
        Err(ParseError::UnsupportedAlgorithm)
    ));

    let unsupported = "1.2.3.4".parse::<bcder::Oid>()?;
    assert_eq!(
        validate_ocsp_sig(
            &unsupported,
            &unsupported,
            &bcder::OctetString::new(bytes::Bytes::new()),
            b"data",
            b"key",
        ),
        Err(RawSignatureValidationError::UnsupportedAlgorithm)
    );

    Ok(())
}

#[test]
fn status_time_errors_are_lazy_and_do_not_become_good_claims() -> TestResult {
    let mut parsed = ParsedOcspResponse::from_der(GOOD)?;
    let fractional = DateTime::parse_from_rfc3339("2025-03-08T00:00:00.500Z")?;
    parsed.basic.tbs_response_data.responses[0].this_update = fractional;

    let claim = parsed.claimed_responses().next().ok_or("missing claim")?;
    assert_eq!(claim.this_update(), Err(InvalidStatusTime));
    assert_eq!(claim.status()?, ClaimedStatus::Good);

    parsed.basic.tbs_response_data.responses[0].cert_status =
        CertStatus::Revoked(rasn_ocsp::RevokedInfo {
            revocation_time: fractional,
            revocation_reason: None,
        });

    assert_eq!(
        parsed
            .claimed_responses()
            .next()
            .ok_or("missing claim")?
            .status(),
        Err(InvalidStatusTime)
    );

    Ok(())
}

#[test]
fn signature_algorithm_hash_mapping_preserves_compatibility() -> TestResult {
    for (signature, digest) in [
        ("1.2.840.10045.4.3.2", "2.16.840.1.101.3.4.2.1"),
        ("1.2.840.10045.4.3.3", "2.16.840.1.101.3.4.2.2"),
        ("1.2.840.10045.4.3.4", "2.16.840.1.101.3.4.2.3"),
        ("1.2.840.113549.1.1.11", "2.16.840.1.101.3.4.2.1"),
        ("1.2.840.113549.1.1.12", "2.16.840.1.101.3.4.2.2"),
        ("1.2.840.113549.1.1.13", "2.16.840.1.101.3.4.2.3"),
        ("1.3.101.112", "2.16.840.1.101.3.4.2.3"),
    ] {
        let oid = rasn::types::ObjectIdentifier::new_unchecked(
            signature
                .split('.')
                .map(str::parse)
                .collect::<Result<Vec<u32>, _>>()?
                .into(),
        );
        assert_eq!(
            hash_alg_for_sig_alg(&oid)
                .ok_or("missing algorithm")?
                .to_string(),
            digest
        );
    }

    Ok(())
}
