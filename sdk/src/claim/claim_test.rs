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

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(deprecated)]

use serde_json::{json, Value};

use super::{
    claim_core::{GH_FULL_VERSION_LIST, SPEC_VERSION_F},
    claim_verify::LEGACY_WATERMARKED_ACTION,
};
use crate::{
    assertion::{Assertion, AssertionBase, AssertionData},
    assertions::{self, c2pa_action, Action, Actions, Ingredient, Relationship},
    claim::{AssertionStoreJsonFormat, Claim, ClaimAssertionType},
    context::Context,
    error::{Error, Result},
    hashed_uri::HashedUri,
    jumbf::labels::to_assertion_uri,
    resource_store::UriOrResource,
    settings::Settings,
    status_tracker::{ErrorBehavior, StatusTracker},
    store::StoreValidationInfo,
    utils::test::create_test_claim,
    validation_status, ClaimGeneratorInfo, DigitalSourceType,
};

#[test]
fn test_build_claim() {
    // Create a new claim.
    let mut claim = create_test_claim().expect("create test claim");

    // Add a redaction.
    // claim.redact_assertion("as_tp_1/c2pa.location.precise");

    // Build claim checking rules.
    claim.build().expect("bad claim");

    // Test round-tripping of binary.
    let orig_binary = claim.data().expect("failure returning data");
    let restored_claim =
        Claim::from_data("as_adbe_1", &orig_binary).expect("could not restore from binary");
    let restored_binary = restored_claim.data().expect("failure returning data");

    assert_eq!(orig_binary, restored_binary);
    println!("Restored Claim: {restored_claim:?}");

    // NOTE: I added a separate mirror of original data because a third-party's
    // JSON serialization could differ from our re-serialization of that same data.
    // When reading claims from assets and verifying signatures of those claims,
    // we need the exact original bytes of the signed JSON or the signature verification
    // will fail.
    assert_eq!(orig_binary, restored_claim.original_bytes.unwrap());

    // JSON examples
    let json_str = claim
        .to_json(AssertionStoreJsonFormat::OrderedList, true)
        .expect("could not generate json");

    println!("Claim: {json_str}");
}

#[test]
fn test_build_claim_generator_hints() {
    // Create a new claim.
    let mut claim = create_test_claim().expect("create test claim");

    claim.add_claim_generator_hint(
        GH_FULL_VERSION_LIST,
        Value::String(r#""user app";v="2.3.4""#.to_string()),
    );
    claim.add_claim_generator_hint(
        GH_FULL_VERSION_LIST,
        Value::String(r#""some toolkit";v="1.0.0""#.to_string()),
    );

    let expected_value = r#""user app";v="2.3.4", "some toolkit";v="1.0.0""#;

    let cg_map = claim.get_claim_generator_hint_map().unwrap();
    let value = &cg_map[GH_FULL_VERSION_LIST];

    assert_eq!(expected_value, value.as_str().unwrap());
}

#[test]
fn test_build_claim_generator_info() {
    // Create a new claim.
    let mut claim = create_test_claim().expect("create test claim");

    let mut info = ClaimGeneratorInfo::new("test app");
    info.version = Some("2.3.4".to_string());
    info.icon = Some(UriOrResource::HashedUri(HashedUri::new(
        "self#jumbf=c2pa.databoxes.data_box".to_string(),
        None,
        b"hashed",
    )));
    info.insert("something", "else");

    claim.add_claim_generator_info(info);

    let cgi = claim.claim_generator_info().unwrap();

    assert_eq!(&cgi[0].name, "test app");
    assert_eq!(cgi[0].version.as_deref(), Some("2.3.4"));
    if let UriOrResource::HashedUri(r) = cgi[1].icon.as_ref().unwrap() {
        assert_eq!(r.hash(), b"hashed");
    }
}

#[test]
fn test_new_with_user_guid() {
    // good v1
    Claim::new_with_user_guid(
        "claim_generator",
        "acme:urn:uuid:3fad1ead-8ed5-44d0-873b-ea5f58adea82",
        1,
    )
    .unwrap();

    // good v2
    Claim::new_with_user_guid(
        "claim_generator",
        "urn:c2pa:3fad1ead-8ed5-44d0-873b-ea5f58adea82:acme",
        2,
    )
    .unwrap();

    // feature incompatible
    let c2 = Claim::new_with_user_guid(
        "claim_generator",
        "urn:c2pa:3fad1ead-8ed5-44d0-873b-ea5f58adea82:acme",
        1,
    );
    assert!(c2.is_err());

    // version incompatible
    let c3 = Claim::new_with_user_guid(
        "claim_generator",
        "acme:urn:uuid:3fad1ead-8ed5-44d0-873b-ea5f58adea82",
        2,
    );
    assert!(c3.is_err());

    // malformed
    let c4 = Claim::new_with_user_guid(
        "claim_generator",
        "urn:c2pa:3fad1ead-8ed5-44d0-873b-ea5f58adea82:acme",
        1,
    );
    assert!(c4.is_err());

    // bad v2
    let c5 = Claim::new_with_user_guid(
        "claim_generator",
        "urn:blahblah:3fad1ead-8ed5-44d0-873b-ea5f58adea82:acme",
        2,
    );
    assert!(c5.is_err());
}

#[test]
fn test_add_assertion_variants() -> Result<()> {
    let mut claim = crate::utils::test::create_min_test_claim()?;

    const MY_METADATA: &str = "my.metadata";
    let data = json!({
    "@context" : {
        "dc" : "http://purl.org/dc/elements/1.1/"
    },
    "dc:created": "2025 August 13",
    "dc:creator": [
         "John Doe"
    ]
    })
    .to_string();

    let metadata = assertions::Metadata::new(MY_METADATA, &data)?;

    // add first time
    claim.add_assertion(&metadata)?;

    // add second time should create instance label
    claim.add_assertion(&metadata)?;

    // add third time should create instance label
    claim.add_assertion(&metadata)?;

    // check that we have three instances now
    let instances = claim.count_instances(MY_METADATA);
    assert_eq!(instances, 3);

    // check that we can retrieve each one
    for i in 0..instances {
        let ca = claim
            .get_claim_assertion(MY_METADATA, i)
            .expect("should find assertion");
        assert_eq!(ca.instance(), i);
        assert_eq!(ca.label_raw(), MY_METADATA);
        assert_eq!(ca.assertion().label(), MY_METADATA);
        assert_eq!(ca.assertion_type(), ClaimAssertionType::Gathered);
        //assert_eq!(ca.assertion().decode_data(), AssertionData::Cbor(vec![1, 2, 3, 4]));
    }

    Ok(())
}

/// When a claim has two assertions whose labels share a prefix
/// (e.g. `c2pa.thumbnail.ingredient` and `c2pa.thumbnail.ingredient__1`),
/// redacting the `__1` URI must remove only the `__1` instance and leave
/// the base instance intact, not vice-versa.
#[test]
fn test_redact_assertion_exact_label_match_with_shared_prefix() {
    use crate::{
        assertions::{labels, EmbeddedData},
        jumbf::labels::to_assertion_uri,
    };

    let mut claim = Claim::new("unit test", Some("test"), 2);

    // Add two ingredient thumbnails — the second gets the `__1` suffix.
    let thumb0 = EmbeddedData::new(labels::INGREDIENT_THUMBNAIL, "image/jpeg", vec![0u8; 4]);
    let thumb1 = EmbeddedData::new(labels::INGREDIENT_THUMBNAIL, "image/jpeg", vec![1u8; 4]);
    claim.add_assertion(&thumb0).expect("add thumb0");
    claim.add_assertion(&thumb1).expect("add thumb1");

    // Both labels must be here
    assert!(
        claim
            .get_assertion(labels::INGREDIENT_THUMBNAIL, 0)
            .is_some(),
        "instance 0 should exist"
    );
    assert!(
        claim
            .get_assertion(labels::INGREDIENT_THUMBNAIL, 1)
            .is_some(),
        "instance 1 should exist"
    );

    let manifest_label = claim.label();
    let uri_base = to_assertion_uri(manifest_label, labels::INGREDIENT_THUMBNAIL);
    let uri_instance1 = to_assertion_uri(
        manifest_label,
        &format!("{}__1", labels::INGREDIENT_THUMBNAIL),
    );

    // Order is important here, first redact the __1 URI
    claim
        .redact_assertion(&uri_instance1)
        .expect("redact instance 1 should succeed");

    // The URI without the __1 (base) should still be here
    assert!(
        claim
            .get_assertion(labels::INGREDIENT_THUMBNAIL, 0)
            .is_some(),
        "instance 0 must still exist after redacting instance 1"
    );

    // Now redact the base
    claim
        .redact_assertion(&uri_base)
        .expect("redact base instance should succeed");

    // Both URIs must be gone now
    assert!(
        claim
            .get_assertion(labels::INGREDIENT_THUMBNAIL, 0)
            .is_none(),
        "instance 0 should be gone"
    );
    assert!(
        claim
            .get_assertion(labels::INGREDIENT_THUMBNAIL, 1)
            .is_none(),
        "instance 1 should be gone"
    );
}

#[test]
fn test_redact_databox_exact_label_match_with_shared_prefix() {
    let mut claim = Claim::new("unit test", Some("test"), 2);

    // Add two databoxes to force multiple URIs
    let uri0 = claim
        .add_databox("application/octet-stream", vec![0u8; 4], None)
        .expect("add databox 0");
    let uri1 = claim
        .add_databox("application/octet-stream", vec![1u8; 4], None)
        .expect("add databox 1");

    let has_databox = |claim: &Claim, uri: &HashedUri| {
        claim.databoxes().iter().any(|(x, _d)| x.url() == uri.url())
    };

    assert!(has_databox(&claim, &uri0), "databox 0 should exist");
    assert!(has_databox(&claim, &uri1), "databox 1 should exist");

    // Check labels
    assert!(
        uri0.url().ends_with("/c2pa.data"),
        "expected databox 0 to be labeled `c2pa.data`, got {}",
        uri0.url()
    );
    assert!(
        uri1.url().ends_with("/c2pa.data__1"),
        "expected databox 1 to be labeled `c2pa.data__1`, got {}",
        uri1.url()
    );

    // Order is important here in our test.
    // redact the `__1` URI first, to make sure we exact-match.
    claim
        .redact_assertion(&uri1.url())
        .expect("redact databox 1 should succeed");

    assert!(
        has_databox(&claim, &uri0),
        "databox 0 must still exist after redacting databox 1"
    );
    assert!(!has_databox(&claim, &uri1), "databox 1 should be gone");

    // Now redact the base (which should be still here, since the other exact-matched).
    claim
        .redact_assertion(&uri0.url())
        .expect("redact databox 0 should succeed");

    assert!(!has_databox(&claim, &uri0), "databox 0 should be gone");
    assert!(!has_databox(&claim, &uri1), "databox 1 should be gone");
}

#[test]
fn test_redact_databox_from_other_manifest_returns_not_found() {
    use crate::jumbf::labels::to_databox_uri;

    let mut claim = Claim::new("unit test", Some("test"), 2);

    let uri0 = claim
        .add_databox("application/octet-stream", vec![0u8; 4], None)
        .expect("add databox 0");

    let foreign_uri = to_databox_uri("urn:uuid:00000000-0000-0000-0000-000000000000", "c2pa.data");
    assert_ne!(foreign_uri, uri0.url(), "test setup: URIs must differ");

    let result = claim.redact_assertion(&foreign_uri);
    assert!(
        matches!(result, Err(Error::AssertionRedactionNotFound)),
        "cross-manifest redaction should fail, got {result:?}"
    );

    assert!(
        claim
            .databoxes()
            .iter()
            .any(|(x, _d)| x.url() == uri0.url()),
        "databox 0 should have survived a redaction targeting another manifest"
    );
}

#[test]
fn test_redact_assertion_instance_labels_are_exact() {
    use crate::{assertions::UserCbor, jumbf::labels::to_assertion_uri};

    const LABEL: &str = "com.example.a";

    let mut claim = Claim::new("unit test", Some("test"), 2);
    for n in 0..3 {
        claim
            .add_assertion(&UserCbor::new(
                LABEL,
                c2pa_cbor::to_vec(&format!("payload {n}")).unwrap(),
            ))
            .expect("add assertion");
    }

    let stored = |claim: &Claim| -> Vec<String> {
        claim
            .claim_assertion_store()
            .iter()
            .map(|x| Claim::label_with_instance(&x.label_raw(), x.instance()))
            .collect()
    };

    assert_eq!(
        stored(&claim),
        vec!["com.example.a", "com.example.a__1", "com.example.a__2"],
        "test setup: three instances of the same label"
    );

    // Redact `__2` first: the `__1` and base labels share its prefix and must survive.
    claim
        .redact_assertion(&to_assertion_uri(claim.label(), "com.example.a__2"))
        .expect("redact instance 2");
    assert_eq!(
        stored(&claim),
        vec!["com.example.a", "com.example.a__1"],
        "only instance 2 should have been removed"
    );

    claim
        .redact_assertion(&to_assertion_uri(claim.label(), "com.example.a__1"))
        .expect("redact instance 1");
    assert_eq!(
        stored(&claim),
        vec!["com.example.a"],
        "only instance 1 should have been removed"
    );

    claim
        .redact_assertion(&to_assertion_uri(claim.label(), LABEL))
        .expect("redact base instance");
    assert!(claim.claim_assertion_store().is_empty());
}

/// `com.example.meta` is a prefix of `com.example.metadata` but is not the same
/// assertion, so redacting it must not match.
#[test]
fn test_redact_assertion_prefix_is_not_a_match() {
    use crate::{assertions::UserCbor, jumbf::labels::to_assertion_uri};

    let mut claim = Claim::new("unit test", Some("test"), 2);
    claim
        .add_assertion(&UserCbor::new(
            "com.example.metadata",
            c2pa_cbor::to_vec(&"payload").unwrap(),
        ))
        .expect("add assertion");

    let uri = to_assertion_uri(claim.label(), "com.example.meta");
    let result = claim.redact_assertion(&uri);
    assert!(
        matches!(result, Err(Error::AssertionRedactionNotFound)),
        "a prefix of a stored label must not match, got {result:?}"
    );
    assert_eq!(
        claim.claim_assertion_store().len(),
        1,
        "the assertion must survive a non-matching redaction"
    );
}

#[test]
fn test_redact_assertion_suffix_label_is_not_a_match() {
    use crate::{assertions::UserCbor, jumbf::labels::to_assertion_uri};

    let mut claim = Claim::new("unit test", Some("test"), 2);
    for label in ["example.a", "org.example.a"] {
        claim
            .add_assertion(&UserCbor::new(
                label,
                c2pa_cbor::to_vec(&"payload").unwrap(),
            ))
            .expect("add assertion");
    }

    claim
        .redact_assertion(&to_assertion_uri(claim.label(), "org.example.a"))
        .expect("redact org.example.a");

    let remaining: Vec<String> = claim
        .claim_assertion_store()
        .iter()
        .map(|x| Claim::label_with_instance(&x.label_raw(), x.instance()))
        .collect();
    assert_eq!(
        remaining,
        vec!["example.a"],
        "redacting `org.example.a` must not remove the `example.a` assertion"
    );
}

/// Verify comparison conditions.
#[test]
fn test_redact_assertion_label_from_link_round_trip() {
    for label in [
        "com.example.a",
        "com.example.a__1",
        "c2pa.thumbnail.ingredient__3.jpeg",
        "c2pa.thumbnail.claim.jpeg__1",
        "stds.schema-org.CreativeWork__2",
        "c2pa.data",
        "c2pa.data__1",
    ] {
        let (parsed, instance) = Claim::assertion_label_from_link(label);
        assert_eq!(
            Claim::label_with_instance(&parsed, instance),
            label,
            "label normalization must round-trip for {label}"
        );
    }
}

fn make_soft_binding(alg: Option<&str>) -> assertions::SoftBinding {
    use crate::assertions::{SoftBindingBlock, SoftBindingScope};
    let mut sb = assertions::SoftBinding::default();
    sb.alg = alg.map(str::to_string);
    sb.blocks = vec![SoftBindingBlock {
        scope: SoftBindingScope::default(),
        value: "abc123".as_bytes().to_vec(),
    }];
    sb
}

#[test]
fn test_verify_soft_binding_alg_valid() {
    let settings = Settings::new()
        .with_json(
            r#"
            {
                "soft_binding": {
                    "soft_binding_algorithms": ["com.adobe.trustmark.Q", "com.adobe.trustmark.C", "com.digimarc.validate.1"]
                }
            }
        "#,
        )
        .unwrap();

    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut claim = create_test_claim().expect("create test claim");

    claim
        .add_assertion(&make_soft_binding(Some("com.digimarc.validate.1")))
        .expect("add soft binding");

    assert!(
        Claim::verify_soft_binding_alg(
            &claim,
            settings
                .soft_binding
                .soft_binding_algorithms
                .as_deref()
                .unwrap_or(&[]),
            &mut validation_log
        )
        .is_ok(),
        "known algorithm should pass"
    );
    assert!(validation_log.logged_items().is_empty());
}

#[test]
#[ignore = "validation disabled for C2PA 2.4 forward"]
fn test_verify_soft_binding_alg_unknown() {
    let settings = Settings::new()
        .with_json(
            r#"
            {
                "soft_binding": {
                    "soft_binding_algorithms": ["com.adobe.trustmark.Q", "com.adobe.trustmark.C", "com.digimarc.validate.1"]
                }
            }
        "#,
        )
        .unwrap();

    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut claim = create_test_claim().expect("create test claim");

    claim
        .add_assertion(&make_soft_binding(Some("com.unknown.watermark.99")))
        .expect("add soft binding");

    let result = Claim::verify_soft_binding_alg(
        &claim,
        settings
            .soft_binding
            .soft_binding_algorithms
            .as_deref()
            .unwrap_or(&[]),
        &mut validation_log,
    );
    assert!(result.is_err(), "unknown algorithm should fail");
    assert!(
        validation_log
            .logged_items()
            .iter()
            .any(|item| item.validation_status.as_deref()
                == Some(validation_status::ALGORITHM_UNSUPPORTED)),
        "should log ALGORITHM_UNSUPPORTED"
    );
}

#[test]
#[ignore = "validation disabled for C2PA 2.4 forward"]
fn test_verify_soft_binding_alg_missing_alg() {
    let settings = Settings::new()
        .with_json(
            r#"
            {
                "soft_binding": {
                    "soft_binding_algorithms": ["com.adobe.trustmark.Q", "com.adobe.trustmark.C", "com.digimarc.validate.1"]
                }
            }
        "#,
        )
        .unwrap();

    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut claim = create_test_claim().expect("create test claim");

    // No alg on assertion, no alg_soft on claim
    claim
        .add_assertion(&make_soft_binding(None))
        .expect("add soft binding");

    let result = Claim::verify_soft_binding_alg(
        &claim,
        settings
            .soft_binding
            .soft_binding_algorithms
            .as_deref()
            .unwrap_or(&[]),
        &mut validation_log,
    );
    assert!(result.is_err(), "missing algorithm should fail");
    assert!(
        validation_log
            .logged_items()
            .iter()
            .any(|item| item.validation_status.as_deref()
                == Some(validation_status::CLAIM_MALFORMED)),
        "should log CLAIM_MALFORMED"
    );
}

#[test]
fn test_verify_soft_binding_alg_fallback_to_alg_soft() {
    let settings = Settings::new()
        .with_json(
            r#"
            {
                "soft_binding": {
                    "soft_binding_algorithms": ["io.iscc.v0"]
                }
            }
        "#,
        )
        .unwrap();

    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut claim = create_test_claim().expect("create test claim");

    // No alg on assertion, but claim-level alg_soft is a known algorithm
    claim.alg_soft = Some("io.iscc.v0".to_string());
    claim
        .add_assertion(&make_soft_binding(None))
        .expect("add soft binding");

    assert!(
        Claim::verify_soft_binding_alg(
            &claim,
            settings
                .soft_binding
                .soft_binding_algorithms
                .as_deref()
                .unwrap_or(&[]),
            &mut validation_log
        )
        .is_ok(),
        "valid alg_soft fallback should pass"
    );
    assert!(validation_log.logged_items().is_empty());
}

#[test]
#[ignore = "validation disabled for C2PA 2.4 forward"]
fn test_verify_soft_binding_alg_undecodable_does_not_abort() {
    // A soft binding assertion that isn't valid CBOR-encoded SoftBinding data
    // (e.g. reusing the c2pa.soft-binding label for a JSON payload) should be
    // logged as a claim.malformed failure, not abort the whole verification.
    struct MalformedSoftBinding;

    impl AssertionBase for MalformedSoftBinding {
        const LABEL: &'static str = assertions::SoftBinding::LABEL;

        fn to_assertion(&self) -> Result<Assertion> {
            Ok(Assertion::new(
                Self::LABEL,
                None,
                AssertionData::Json(r#"{"alg":"com.example.sha256","value":"abc123"}"#.to_string()),
            )
            .set_content_type("application/json"))
        }

        fn from_assertion(_assertion: &Assertion) -> Result<Self> {
            unimplemented!("not needed for this test")
        }
    }

    let settings = Settings::new()
        .with_json(
            r#"
            {
                "soft_binding": {
                    "soft_binding_algorithms": ["com.example.sha256"]
                }
            }
        "#,
        )
        .unwrap();

    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut claim = create_test_claim().expect("create test claim");

    claim
        .add_assertion(&MalformedSoftBinding)
        .expect("add malformed soft binding");

    assert!(
        Claim::verify_soft_binding_alg(
            &claim,
            settings
                .soft_binding
                .soft_binding_algorithms
                .as_deref()
                .unwrap_or(&[]),
            &mut validation_log
        )
        .is_ok(),
        "an undecodable soft binding assertion should not abort verification"
    );
    assert!(
        validation_log
            .logged_items()
            .iter()
            .any(|item| item.validation_status.as_deref()
                == Some(validation_status::CLAIM_MALFORMED)),
        "should log CLAIM_MALFORMED for the undecodable assertion"
    );
}

#[test]
#[ignore = "validation disabled for C2PA 2.4 forward"]
fn test_verify_soft_binding_alg_continues_past_malformed_assertion() {
    // A claim with three c2pa.soft-binding assertions: the first undecodable,
    // the second valid, and the third using an unsupported algorithm. Skipping
    // past the first (undecodable, non-fatal) must not skip evaluation of the
    // second and third -- the unsupported algorithm in the third must still be
    // caught and reported as a fatal error.
    struct MalformedSoftBinding;

    impl AssertionBase for MalformedSoftBinding {
        const LABEL: &'static str = assertions::SoftBinding::LABEL;

        fn to_assertion(&self) -> Result<Assertion> {
            Ok(Assertion::new(
                Self::LABEL,
                None,
                AssertionData::Json(r#"{"alg":"com.example.sha256","value":"abc123"}"#.to_string()),
            )
            .set_content_type("application/json"))
        }

        fn from_assertion(_assertion: &Assertion) -> Result<Self> {
            unimplemented!("not needed for this test")
        }
    }

    let settings = Settings::new()
        .with_json(
            r#"
            {
                "soft_binding": {
                    "soft_binding_algorithms": ["com.example.sha256"]
                }
            }
        "#,
        )
        .unwrap();

    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut claim = create_test_claim().expect("create test claim");

    claim
        .add_assertion(&MalformedSoftBinding)
        .expect("add malformed soft binding");
    claim
        .add_assertion(&make_soft_binding(Some("com.example.sha256")))
        .expect("add valid soft binding");
    claim
        .add_assertion(&make_soft_binding(Some("com.unknown.watermark.99")))
        .expect("add soft binding with unsupported algorithm");

    let result = Claim::verify_soft_binding_alg(
        &claim,
        settings
            .soft_binding
            .soft_binding_algorithms
            .as_deref()
            .unwrap_or(&[]),
        &mut validation_log,
    );
    assert!(
        result.is_err(),
        "the unsupported algorithm on the third assertion must still be fatal"
    );
    assert!(
        validation_log
            .logged_items()
            .iter()
            .any(|item| item.validation_status.as_deref()
                == Some(validation_status::CLAIM_MALFORMED)),
        "should log CLAIM_MALFORMED for the first, undecodable assertion"
    );
    assert!(
        validation_log
            .logged_items()
            .iter()
            .any(|item| item.validation_status.as_deref()
                == Some(validation_status::ALGORITHM_UNSUPPORTED)),
        "should still reach and log ALGORITHM_UNSUPPORTED for the third assertion"
    );
}

#[test]
fn test_verify_claim_generator_info_valid() {
    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let claim = create_test_claim().expect("create test claim");

    // create_test_claim adds a ClaimGeneratorInfo with name "test app"
    assert!(
        Claim::verify_claim_generator_info(&claim, &mut validation_log).is_ok(),
        "valid claim_generator_info should pass"
    );
    assert!(
        validation_log.logged_items().is_empty(),
        "no errors should be logged for a valid claim"
    );
}

#[test]
fn test_verify_claim_generator_info_missing() {
    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    // Build a v2 claim without adding any claim_generator_info
    let mut claim = Claim::new("test", Some("test"), 2);
    claim.claim_generator_info = None;

    let result = Claim::verify_claim_generator_info(&claim, &mut validation_log);
    assert!(result.is_err(), "missing claim_generator_info should fail");
    assert!(
        validation_log
            .logged_items()
            .iter()
            .any(|item| item.validation_status.as_deref()
                == Some(validation_status::CLAIM_MALFORMED)),
        "should log CLAIM_MALFORMED"
    );
}

#[test]
fn test_verify_claim_generator_info_empty_name() {
    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut claim = Claim::new("test", Some("test"), 2);
    claim.add_claim_generator_info(ClaimGeneratorInfo::new(""));

    let result = Claim::verify_claim_generator_info(&claim, &mut validation_log);
    assert!(result.is_err(), "empty name should fail");
    assert!(
        validation_log
            .logged_items()
            .iter()
            .any(|item| item.validation_status.as_deref()
                == Some(validation_status::CLAIM_MALFORMED)),
        "should log CLAIM_MALFORMED"
    );
}

#[test]
fn test_spec_version_from_claim_generator_info() {
    let mut claim = Claim::new("test", Some("test"), 2);
    let mut cgi = ClaimGeneratorInfo::new("test app");
    cgi.set_spec_version("2.4.0");
    claim.add_claim_generator_info(cgi);

    assert_eq!(claim.spec_version().map(|s| s.as_str()), Some("2.4.0"));
}

#[test]
fn test_spec_version_in_claim_generator_info_round_trips() {
    let mut claim = Claim::new("test", Some("test"), 2);
    let mut cgi = ClaimGeneratorInfo::new("test app");
    cgi.set_spec_version("2.4.0");
    claim.add_claim_generator_info(cgi);

    let data = claim.data().unwrap();
    let decoded = Claim::from_data("test", &data).unwrap();
    assert_eq!(decoded.spec_version().map(|s| s.as_str()), Some("2.4.0"));

    let value: c2pa_cbor::Value = c2pa_cbor::from_slice(&data).unwrap();
    assert!(matches!(
        &value,
        c2pa_cbor::Value::Map(map) if !map
            .keys()
            .any(|k| matches!(k, c2pa_cbor::Value::Text(t) if t == SPEC_VERSION_F))
    ));
}

#[test]
fn test_spec_version_none_when_not_set_in_claim_generator_info() {
    let mut claim = Claim::new("test", Some("test"), 2);
    claim.add_claim_generator_info(ClaimGeneratorInfo::new("test app"));

    assert_eq!(claim.spec_version(), None);
}

fn make_cloud_data(label: &str) -> assertions::CloudData {
    assertions::CloudData::new(
        label,
        1024,
        assertions::HashedExtUri::new(
            "https://example.com/data",
            "sha256",
            vec![0xde, 0xad, 0xbe, 0xef],
        ),
    )
}

fn make_external_reference(url: &str) -> assertions::ExternalReference {
    assertions::ExternalReference::new_hashed(url, "sha256", vec![0xde, 0xad, 0xbe, 0xef])
}

#[test]
fn test_verify_external_reference_valid() {
    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut claim = create_test_claim().expect("create test claim");

    claim
        .add_assertion(&make_external_reference("https://example.com/ext.json"))
        .expect("add external reference");

    assert!(
        Claim::verify_external_reference(&claim, &mut validation_log).is_ok(),
        "valid external-reference assertion should pass"
    );
    assert!(validation_log.logged_items().is_empty());
}

#[test]
fn test_verify_external_reference_rejects_malformed() {
    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut claim = create_test_claim().expect("create test claim");

    let bad = assertions::ExternalReference {
        location: assertions::ExternalReferenceLocation::Hashed(assertions::HashedExtUri {
            url: "   ".to_owned(),
            alg: String::new(),
            hash: vec![],
            data_types: None,
        }),
        label: None,
        description: None,
        metadata: None,
    };
    claim
        .add_assertion(&bad)
        .expect("add malformed external reference");

    Claim::verify_external_reference(&claim, &mut validation_log).unwrap();

    assert!(
        validation_log
            .logged_items()
            .iter()
            .any(|item| item.validation_status.as_deref()
                == Some(validation_status::ASSERTION_EXTERNAL_REFERENCE_MALFORMED)),
        "should log ASSERTION_EXTERNAL_REFERENCE_MALFORMED"
    );
}

#[test]
fn test_verify_cloud_data_valid() {
    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut claim = create_test_claim().expect("create test claim");

    // A fully-specified cloud-data assertion referencing a non-forbidden type.
    claim
        .add_assertion(&make_cloud_data("c2pa.metadata"))
        .expect("add cloud data");

    assert!(
        Claim::verify_cloud_data(&claim, &mut validation_log).is_ok(),
        "valid cloud-data assertion should pass"
    );
    assert!(validation_log.logged_items().is_empty());
}

#[test]
fn test_verify_cloud_data_zero_size_rejected() {
    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut claim = create_test_claim().expect("create test claim");

    // size must be >= 1 per spec (size-type = int .ge 1).
    let cd = assertions::CloudData::new(
        "c2pa.metadata",
        0,
        assertions::HashedExtUri::new(
            "https://example.com/data",
            "sha256",
            vec![0xde, 0xad, 0xbe, 0xef],
        ),
    );
    claim.add_assertion(&cd).expect("add cloud data");

    Claim::verify_cloud_data(&claim, &mut validation_log).unwrap();

    assert!(
        validation_log
            .logged_items()
            .iter()
            .any(|item| item.validation_status.as_deref()
                == Some(validation_status::ASSERTION_CLOUD_DATA_MALFORMED)),
        "should log ASSERTION_CLOUD_DATA_MALFORMED"
    );
}

// Builds a v2 claim whose created assertions contain a valid c2pa.created
// action followed by the given c2pa.translated action, runs verify_actions,
// and returns the validation log for status-code checks.
fn verify_translated_action(translated: Action) -> StatusTracker {
    use crate::assertions::DigitalSourceType;

    // A valid first action (created + digitalSourceType) keeps the claim
    // otherwise clean, so the only possible malformed status comes from the
    // c2pa.translated action under test.
    let mut claim = Claim::new("test", Some("test"), 2);
    let actions = Actions::new()
        .add_action(
            Action::new(c2pa_action::CREATED).set_source_type(DigitalSourceType::AlgorithmicMedia),
        )
        .add_action(translated);
    claim.add_assertion(&actions).expect("add actions");

    let svi = StoreValidationInfo::default();
    let settings = Settings::default();
    let mut validation_log =
        StatusTracker::with_error_behavior(ErrorBehavior::ContinueWhenPossible);
    Claim::verify_actions(&claim, &svi, &mut validation_log, &settings)
        .expect("verify_actions should not throw");
    validation_log
}

// Regression: per C2PA spec 18.15.4.7, a c2pa.translated action's parameters
// must contain sourceLanguage and targetLanguage. An action with empty
// parameters must be reported as assertion.action.malformed.
#[test]
fn test_verify_translated_action_missing_languages() {
    let log = verify_translated_action(Action::new(c2pa_action::TRANSLATED));
    assert!(
        log.has_status(validation_status::ASSERTION_ACTION_MALFORMED),
        "c2pa.translated without sourceLanguage/targetLanguage should be malformed"
    );
}

// A c2pa.translated action with only one of the two language codes is still
// malformed.
#[test]
fn test_verify_translated_action_partial_languages() {
    let translated = Action::new(c2pa_action::TRANSLATED)
        .set_parameter("source_language", "en-US")
        .expect("set source_language");
    let log = verify_translated_action(translated);
    assert!(
        log.has_status(validation_status::ASSERTION_ACTION_MALFORMED),
        "c2pa.translated with only sourceLanguage should be malformed"
    );
}

// Positive: a c2pa.translated action with both BCP-47 language codes present
// must not be reported as malformed.
#[test]
#[ignore = "validation disabled for C2PA 2.4 forward"]
fn test_verify_translated_action_with_languages_valid() {
    let translated = Action::new(c2pa_action::TRANSLATED)
        .set_parameter("source_language", "en-US")
        .expect("set source_language")
        .set_parameter("target_language", "fr-FR")
        .expect("set target_language");
    let log = verify_translated_action(translated);
    assert!(
        !log.has_status(validation_status::ASSERTION_ACTION_MALFORMED),
        "c2pa.translated with both languages should not be malformed"
    );
}

#[test]
fn test_verify_claim_generator_resource_ref_icons_rejected() {
    for version in [1, 2] {
        let mut claim = Claim::new("test", Some("test"), version);
        let info: ClaimGeneratorInfo = serde_json::from_value(json!({
            "name": "test",
            "icon": {"format": "image/png", "identifier": "icon.png"}
        }))
        .unwrap();
        claim.add_claim_generator_info(info);
        let mut validation_log =
            StatusTracker::with_error_behavior(ErrorBehavior::ContinueWhenPossible);
        Claim::verify_internal(
            &claim,
            &StoreValidationInfo::default(),
            Err(Error::CoseSignature),
            &mut validation_log,
            &Context::new(),
        )
        .unwrap();
        assert_eq!(
            hashed_uri_missing_location(&validation_log),
            Some(claim.to_claim_uri())
        );
    }
}

/// Returns the location reported for the first `hashedURI.missing` failure.
fn hashed_uri_missing_location(validation_log: &StatusTracker) -> Option<String> {
    validation_log
        .logged_items()
        .iter()
        .find(|item| {
            item.validation_status.as_deref() == Some(validation_status::HASHED_URI_MISSING)
        })
        .map(|item| item.label.to_string())
}

#[test]
fn test_verify_resource_ref_icons_rejected() {
    let icon = json!({"format": "image/png", "identifier": "icon.png"});
    let cases = [
        json!({"actions": [{"action": "c2pa.created", "softwareAgent": {"name": "test", "icon": icon}}]}),
        json!({"actions": [{"action": "c2pa.created"}], "softwareAgents": [{"name": "test", "icon": icon}]}),
        json!({"actions": [{"action": "c2pa.created"}], "templates": [{"action": "com.example.edit", "icon": icon}]}),
    ];
    for case in cases {
        let mut claim = Claim::new("test", Some("test"), 2);
        let actions: Actions = serde_json::from_value(case.clone()).unwrap();
        let actions_uri = claim.add_assertion(&actions).unwrap().url();
        let (actions_label, _) = Claim::assertion_label_from_link(&actions_uri);
        let expected_location = to_assertion_uri(claim.label(), &actions_label);
        for behavior in [
            ErrorBehavior::ContinueWhenPossible,
            ErrorBehavior::StopOnFirstError,
        ] {
            let stop_on_error = matches!(behavior, ErrorBehavior::StopOnFirstError);
            let mut validation_log = StatusTracker::with_error_behavior(behavior);
            let result = Claim::verify_actions(
                &claim,
                &StoreValidationInfo::default(),
                &mut validation_log,
                &Settings::default(),
            );
            assert_eq!(
                hashed_uri_missing_location(&validation_log).as_deref(),
                Some(expected_location.as_str()),
                "resource reference icon must be rejected at its actions assertion: {case}"
            );
            if stop_on_error {
                assert!(
                    matches!(result, Err(Error::ValidationRule(ref msg)) if msg.contains("icon.png"))
                );
            } else {
                assert!(result.is_ok());
            }
        }
    }
}

#[test]
fn test_verify_hashed_icons_and_resource_ref_after_databox() {
    let mut claim = Claim::new("test", Some("test"), 2);
    let embedded_icon = claim
        .add_assertion(&assertions::EmbeddedData::new(
            assertions::labels::ICON,
            "image/png",
            vec![1, 2, 3],
        ))
        .unwrap();
    let databox_icon = claim.add_databox("image/png", vec![1, 2, 3], None).unwrap();
    let mut actions_json = json!({
        "actions": [{
            "action": "c2pa.created",
            "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/algorithmicMedia",
            "softwareAgent": {"name": "test", "icon": embedded_icon}
        }],
        "softwareAgents": [{"name": "test", "icon": databox_icon}],
        "templates": [{"action": "com.example.edit", "icon": embedded_icon}]
    });
    for invalid in [false, true] {
        if invalid {
            actions_json["softwareAgents"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "name": "invalid",
                    "icon": {"format": "image/png", "identifier": "icon.png"}
                }));
        }
        let mut test_claim = claim.clone();
        let actions: Actions = serde_json::from_value(actions_json.clone()).unwrap();
        test_claim.add_assertion(&actions).unwrap();
        let mut validation_log =
            StatusTracker::with_error_behavior(ErrorBehavior::ContinueWhenPossible);
        Claim::verify_actions(
            &test_claim,
            &StoreValidationInfo::default(),
            &mut validation_log,
            &Settings::default(),
        )
        .unwrap();
        assert_eq!(
            validation_log.has_status(validation_status::HASHED_URI_MISSING),
            invalid
        );
        if !invalid {
            assert!(!validation_log.has_any_error(), "{validation_log:?}");
        }
    }
}

fn verify_related_assertions(claim: &mut Claim, related: Vec<HashedUri>) -> StatusTracker {
    let edited = Action::new(c2pa_action::EDITED)
        .set_parameter("relatedAssertions", related)
        .unwrap();
    let actions = Actions::new()
        .add_action(
            Action::new(c2pa_action::CREATED).set_source_type(DigitalSourceType::AlgorithmicMedia),
        )
        .add_action(edited);
    claim.add_assertion(&actions).unwrap();

    let svi = StoreValidationInfo::default();
    let settings = Settings::default();
    let mut validation_log =
        StatusTracker::with_error_behavior(ErrorBehavior::ContinueWhenPossible);
    Claim::verify_actions(claim, &svi, &mut validation_log, &settings).unwrap();

    validation_log
}

#[test]
fn test_verify_related_assertions_empty_rejected() {
    let mut claim = Claim::new("test", Some("test"), 2);
    let log = verify_related_assertions(&mut claim, vec![]);
    assert!(
        log.has_status(validation_status::ASSERTION_ACTION_MALFORMED),
        "empty relatedAssertions should be malformed"
    );
}

#[test]
fn test_verify_related_assertions_unresolvable_rejected() {
    let mut claim = Claim::new("test", Some("test"), 2);
    let uri = HashedUri::new(
        to_assertion_uri(claim.label(), "com.example.missing"),
        Some("sha256".to_string()),
        b"hash",
    );
    let log = verify_related_assertions(&mut claim, vec![uri]);
    assert!(
        log.has_status(validation_status::ASSERTION_ACTION_MALFORMED),
        "unresolvable relatedAssertions reference should be malformed"
    );
}

#[test]
fn test_verify_related_assertions_references_actions_rejected() {
    let mut claim = Claim::new("test", Some("test"), 2);
    let uri = HashedUri::new(
        to_assertion_uri(claim.label(), Actions::LABEL_VERSIONED),
        Some("sha256".to_string()),
        b"hash",
    );
    let log = verify_related_assertions(&mut claim, vec![uri]);
    assert!(
        log.has_status(validation_status::ASSERTION_ACTION_MALFORMED),
        "relatedAssertions referencing an actions assertion should be malformed"
    );
}

#[test]
fn test_verify_related_assertions_references_ingredient_rejected() {
    let mut claim = Claim::new("test", Some("test"), 2);
    let ingredient_uri = claim
        .add_assertion(&Ingredient::new_v3(Relationship::ComponentOf))
        .unwrap();
    let log = verify_related_assertions(&mut claim, vec![ingredient_uri]);
    assert!(
        log.has_status(validation_status::ASSERTION_ACTION_MALFORMED),
        "relatedAssertions referencing an ingredient assertion should be malformed"
    );
}

#[test]
fn test_verify_related_assertions_valid() {
    use crate::assertions::UserCbor;

    let mut claim = Claim::new("test", Some("test"), 2);
    let uri = claim
        .add_assertion(&UserCbor::new(
            "com.example.related",
            c2pa_cbor::to_vec(&"related payload").unwrap(),
        ))
        .unwrap();
    let log = verify_related_assertions(&mut claim, vec![uri]);
    assert!(
        !log.has_status(validation_status::ASSERTION_ACTION_MALFORMED),
        "relatedAssertions referencing an allowed assertion should not be malformed"
    );
}

#[test]
fn test_verify_actions_rejects_multiple_inception_actions_in_one_assertion() {
    use crate::assertions::DigitalSourceType;

    let mut claim = Claim::new("test", Some("test"), 2);
    let actions = Actions::new()
        .add_action(Action::new(c2pa_action::CREATED).set_source_type(DigitalSourceType::Empty))
        .add_action(Action::new(c2pa_action::OPENED));
    claim.add_assertion(&actions).expect("add actions");

    let svi = StoreValidationInfo::default();
    let settings = Settings::default();
    let mut validation_log =
        StatusTracker::with_error_behavior(ErrorBehavior::ContinueWhenPossible);

    Claim::verify_actions(&claim, &svi, &mut validation_log, &settings)
        .expect("verify_actions should not throw");

    assert!(
        validation_log.has_status(validation_status::ASSERTION_ACTION_MALFORMED),
        "an actions assertion containing more than one c2pa.created/c2pa.opened action should be malformed"
    );
}

#[test]
fn test_verify_actions_rejects_both_created_and_opened_actions() {
    use crate::assertions::DigitalSourceType;

    let mut claim = Claim::new("test", Some("test"), 2);
    let created_actions = Actions::new()
        .add_action(Action::new(c2pa_action::CREATED).set_source_type(DigitalSourceType::Empty));
    let opened_actions = Actions::new().add_action(Action::new(c2pa_action::OPENED));

    claim
        .add_assertion(&created_actions)
        .expect("add created actions");
    claim
        .add_assertion(&opened_actions)
        .expect("add opened actions");

    let svi = StoreValidationInfo::default();
    let settings = Settings::default();
    let mut validation_log =
        StatusTracker::with_error_behavior(ErrorBehavior::ContinueWhenPossible);

    Claim::verify_actions(&claim, &svi, &mut validation_log, &settings)
        .expect("verify_actions should not throw");

    assert!(
        validation_log.has_status(validation_status::ASSERTION_ACTION_MALFORMED),
        "a claim containing both c2pa.created and c2pa.opened actions should be malformed"
    );
}

// Builds a v2 claim whose actions assertion contains a valid c2pa.created
// action followed by the given watermark action, optionally adds a soft
// binding assertion, runs verify_actions, and returns the validation log.
fn verify_watermark_action(action: Action, with_soft_binding: bool) -> StatusTracker {
    use crate::assertions::DigitalSourceType;

    let mut claim = Claim::new("test", Some("test"), 2);
    let actions = Actions::new()
        .add_action(
            Action::new(c2pa_action::CREATED)
                .set_source_type(DigitalSourceType::TrainedAlgorithmicMedia),
        )
        .add_action(action);
    claim.add_assertion(&actions).expect("add actions");

    if with_soft_binding {
        claim
            .add_assertion(&make_soft_binding(Some("com.example.wm")))
            .expect("add soft binding");
    }

    let svi = StoreValidationInfo::default();
    let settings = Settings::default();
    let mut validation_log =
        StatusTracker::with_error_behavior(ErrorBehavior::ContinueWhenPossible);
    Claim::verify_actions(&claim, &svi, &mut validation_log, &settings)
        .expect("verify_actions should not throw");
    validation_log
}

#[test]
fn test_watermarked_action_without_soft_binding_logs_missing() {
    let log = verify_watermark_action(Action::new(LEGACY_WATERMARKED_ACTION), false);
    assert!(
        log.has_status(validation_status::ACTION_ASSERTION_SOFTBINDING_MISSING),
        "c2pa.watermarked without soft binding should log ACTION_ASSERTION_SOFTBINDING_MISSING"
    );
}

#[test]
fn test_watermarked_bound_action_without_soft_binding_logs_missing() {
    let log = verify_watermark_action(Action::new(c2pa_action::WATERMARKED_BOUND), false);
    assert!(
        log.has_status(validation_status::ACTION_ASSERTION_SOFTBINDING_MISSING),
        "c2pa.watermarked.bound without soft binding should log ACTION_ASSERTION_SOFTBINDING_MISSING"
    );
}

#[test]
fn test_watermarked_action_with_soft_binding_passes() {
    let log = verify_watermark_action(Action::new(LEGACY_WATERMARKED_ACTION), true);
    assert!(
        !log.has_status(validation_status::ACTION_ASSERTION_SOFTBINDING_MISSING),
        "c2pa.watermarked with soft binding present should not log ACTION_ASSERTION_SOFTBINDING_MISSING"
    );
}

#[test]
fn test_verify_cloud_data_hard_binding_rejected() {
    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut claim = create_test_claim().expect("create test claim");

    // Hard binding assertion referenced from cloud-data is forbidden.
    claim
        .add_assertion(&make_cloud_data(assertions::labels::DATA_HASH))
        .expect("add cloud data");

    Claim::verify_cloud_data(&claim, &mut validation_log).unwrap();

    assert!(
        validation_log
            .logged_items()
            .iter()
            .any(|item| item.validation_status.as_deref()
                == Some(validation_status::ASSERTION_CLOUD_DATA_HARD_BINDING)),
        "should log ASSERTION_CLOUD_DATA_HARD_BINDING"
    );
}

#[test]
fn test_verify_cloud_data_actions_in_update_manifest_rejected() {
    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut claim = create_test_claim().expect("create test claim");
    claim.set_update_manifest(true);

    claim
        .add_assertion(&make_cloud_data(assertions::labels::ACTIONS))
        .expect("add cloud data");

    Claim::verify_cloud_data(&claim, &mut validation_log).unwrap();

    assert!(
        validation_log
            .logged_items()
            .iter()
            .any(|item| item.validation_status.as_deref()
                == Some(validation_status::ASSERTION_CLOUD_DATA_ACTIONS)),
        "should log ASSERTION_CLOUD_DATA_ACTIONS"
    );
}

#[test]
fn test_update_manifest_with_claim_thumbnail_rejected() {
    let mut claim = create_test_claim().expect("create test claim");
    claim.set_update_manifest(true);
    claim
        .add_assertion(&assertions::EmbeddedData::new(
            assertions::labels::JPEG_CLAIM_THUMBNAIL,
            "image/jpeg",
            vec![0xff, 0xd8, 0xff],
        ))
        .expect("add claim thumbnail");

    let mut validation_log =
        StatusTracker::with_error_behavior(ErrorBehavior::ContinueWhenPossible);
    Claim::verify_internal(
        &claim,
        &StoreValidationInfo::default(),
        Err(Error::CoseSignature),
        &mut validation_log,
        &Context::new(),
    )
    .expect("verification should continue to report validation statuses");

    assert!(
        validation_log.has_status(validation_status::MANIFEST_UPDATE_INVALID),
        "an update manifest containing one claim thumbnail should be invalid"
    );
}

#[test]
fn test_verify_cloud_data_actions_in_non_update_manifest_not_allowed() {
    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let mut claim = create_test_claim().expect("create test claim");

    // Actions cloud-data is only forbidden in update manifests.
    claim
        .add_assertion(&make_cloud_data(assertions::labels::ACTIONS))
        .expect("add cloud data");

    Claim::verify_cloud_data(&claim, &mut validation_log).unwrap();

    assert!(
        validation_log.has_any_error(),
        "actions in cloud-data of a non-update manifest should fail"
    );
}
