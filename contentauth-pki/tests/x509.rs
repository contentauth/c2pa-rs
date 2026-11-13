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

use std::collections::HashSet;

use contentauth_pki::x509::{
    chain::{validate_chain_to_anchors, verify_chain_signatures, ChainError},
    profile::{check_disallowed_ekus, check_profile, CertificateProfileError, ProfilePolicy},
};
use rasn::types;
use rasn_pkix::Certificate;
use x509_parser::prelude::*;

fn certificates() -> Vec<Vec<u8>> {
    ::pem::parse_many(include_bytes!("fixtures/certs/ed25519.pub"))
        .unwrap()
        .into_iter()
        .map(|pem| pem.into_contents())
        .collect()
}

fn policy<'a>(allowed: &'a HashSet<String>, required: &'a HashSet<String>) -> ProfilePolicy<'a> {
    ProfilePolicy {
        allowed_ekus: allowed,
        mandatory_ekus: required,
        allow_email_protection_when_empty: true,
        allow_specialty_purposes: true,
        end_entity: true,
    }
}

fn signing_time(der: &[u8]) -> i64 {
    X509Certificate::from_der(der)
        .unwrap()
        .1
        .validity()
        .not_before
        .timestamp()
}

fn with_ekus(der: &[u8], purposes: &[&[u32]]) -> Vec<u8> {
    let mut certificate: Certificate = rasn::der::decode(der).unwrap();
    let eku_oid = types::ObjectIdentifier::new(vec![2, 5, 29, 37]).unwrap();

    let purposes: Vec<_> = purposes
        .iter()
        .map(|oid| types::ObjectIdentifier::new(oid.to_vec()).unwrap())
        .collect();

    certificate
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|extension| extension.extn_id == eku_oid)
        .unwrap()
        .extn_value = rasn::der::encode(&purposes).unwrap().into();

    rasn::der::encode(&certificate).unwrap()
}

#[test]
fn certificate_signatures_cover_existing_key_families() {
    for pem in [
        include_bytes!("fixtures/certs/ed25519.pub").as_slice(),
        include_bytes!("fixtures/certs/es256.pub").as_slice(),
        include_bytes!("fixtures/certs/es384.pub").as_slice(),
        include_bytes!("fixtures/certs/es512.pub").as_slice(),
        include_bytes!("fixtures/certs/ps256.pub").as_slice(),
        include_bytes!("fixtures/certs/rs256.pub").as_slice(),
    ] {
        let chain: Vec<_> = ::pem::parse_many(pem)
            .unwrap()
            .into_iter()
            .map(|pem| pem.into_contents())
            .collect();

        assert!(verify_chain_signatures(&chain).is_ok());
    }
}

#[test]
fn signature_profile_and_anchor_association_are_independent() {
    let mut chain = certificates();
    let empty = HashSet::new();
    let policy = policy(&empty, &empty);
    let time = signing_time(&chain[0]);
    let anchors = vec![chain.last().unwrap().clone()];

    assert!(verify_chain_signatures(&chain).is_ok());
    assert!(check_profile(&chain[0], &policy, time).is_ok());

    let association = validate_chain_to_anchors(&chain, &chain[0], &anchors, time).unwrap();

    assert_eq!(association.anchors(), anchors);

    // The same valid signatures establish no association with an unrelated set.
    let other = ::pem::parse(include_bytes!("fixtures/certs/ca_authorization_root.pub"))
        .unwrap()
        .into_contents();

    assert_eq!(
        validate_chain_to_anchors(&chain, &chain[0], &[other], time).unwrap_err(),
        ChainError::NoAnchorAssociation,
    );

    let expired = X509Certificate::from_der(&chain[0])
        .unwrap()
        .1
        .validity()
        .not_after
        .timestamp()
        + 1;

    assert_eq!(
        check_profile(&chain[0], &policy, expired).unwrap_err().kind,
        CertificateProfileError::CertificateNotValidAtTime,
    );

    assert!(verify_chain_signatures(&chain).is_ok());

    *chain[0].last_mut().unwrap() ^= 1;
    assert!(check_profile(&chain[0], &policy, time).is_ok());

    assert_eq!(
        verify_chain_signatures(&chain).unwrap_err(),
        ChainError::SignatureMismatch,
    );

    assert!(validate_chain_to_anchors(&chain, &chain[0], &anchors, time).is_err());
}

#[test]
fn explicit_role_constraints_do_not_redefine_identity_compatibility() {
    let chain = certificates();
    let time = signing_time(&chain[0]);
    let empty = HashSet::new();
    let timestamp = "1.3.6.1.5.5.7.3.8";
    let ocsp = "1.3.6.1.5.5.7.3.9";
    let email = "1.3.6.1.5.5.7.3.4";

    for (oid, purpose) in [
        (&[1, 3, 6, 1, 5, 5, 7, 3, 8][..], timestamp),
        (&[1, 3, 6, 1, 5, 5, 7, 3, 9][..], ocsp),
    ] {
        let certificate = with_ekus(&chain[0], &[oid]);
        let required = HashSet::from([purpose.to_string()]);
        let specialty = policy(&empty, &required);

        assert!(check_profile(&certificate, &specialty, time).is_ok());

        let other_required = HashSet::from([email.to_string()]);

        assert_eq!(
            check_profile(&certificate, &policy(&empty, &other_required), time)
                .unwrap_err()
                .kind,
            CertificateProfileError::InvalidEku,
        );

        assert_eq!(
            check_disallowed_ekus(&certificate, &[timestamp, ocsp]),
            Err(CertificateProfileError::InvalidEku),
        );

        // The host's identity role deliberately does not add claim exclusions.
        assert!(check_profile(&certificate, &policy(&empty, &empty), time).is_ok());
    }
}

#[test]
fn host_eku_inputs_preserve_empty_explicit_alternate_and_mixed_rules() {
    let chain = certificates();
    let time = signing_time(&chain[0]);
    let empty = HashSet::new();
    let email = with_ekus(&chain[0], &[&[1, 3, 6, 1, 5, 5, 7, 3, 4]]);

    assert!(check_profile(&email, &policy(&empty, &empty), time).is_ok());

    let alternate_oid = "1.3.6.1.4.1.62558.2.1".to_string();
    let explicit = HashSet::from([alternate_oid]);

    assert!(check_profile(&email, &policy(&explicit, &empty), time).is_err());

    let alternate = with_ekus(&chain[0], &[&[1, 3, 6, 1, 4, 1, 62558, 2, 1]]);

    assert!(check_profile(&alternate, &policy(&explicit, &empty), time).is_ok());

    let additive = HashSet::from([
        "1.3.6.1.5.5.7.3.4".to_string(),
        "1.3.6.1.4.1.62558.2.1".to_string(),
    ]);

    assert!(check_profile(&email, &policy(&additive, &empty), time).is_ok());
    assert!(check_profile(&alternate, &policy(&additive, &empty), time).is_ok());

    let all_required = additive.clone();

    assert_eq!(
        check_profile(&alternate, &policy(&additive, &all_required), time)
            .unwrap_err()
            .kind,
        CertificateProfileError::InvalidEku,
    );

    let both = with_ekus(
        &chain[0],
        &[
            &[1, 3, 6, 1, 5, 5, 7, 3, 4],
            &[1, 3, 6, 1, 4, 1, 62558, 2, 1],
        ],
    );

    assert!(check_profile(&both, &policy(&additive, &all_required), time).is_ok());

    for purposes in [
        vec![&[2, 5, 29, 37, 0][..]],
        vec![
            &[1, 3, 6, 1, 5, 5, 7, 3, 8][..],
            &[1, 3, 6, 1, 5, 5, 7, 3, 4],
        ],
        vec![
            &[1, 3, 6, 1, 5, 5, 7, 3, 8][..],
            &[1, 3, 6, 1, 5, 5, 7, 3, 9],
        ],
    ] {
        let certificate = with_ekus(&chain[0], &purposes);

        assert!(check_profile(&certificate, &policy(&additive, &empty), time).is_err());
    }
}
