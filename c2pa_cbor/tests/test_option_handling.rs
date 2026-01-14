// Copyright 2025 Adobe. All rights reserved.
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

// Tests for complex Option handling scenarios that may trigger indefinite-length encoding issues

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct NestedStruct {
    #[serde(skip_serializing_if = "Option::is_none")]
    optional_field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    another_optional: Option<Vec<String>>,
    required_field: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct ParentStruct {
    #[serde(skip_serializing_if = "Option::is_none")]
    nested: Option<NestedStruct>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Vec<String>>,
    title: String,
}

#[test]
fn test_nested_optional_round_trip() {
    // Create a structure with some None fields (mimics Actions assertion)
    let original = ParentStruct {
        nested: Some(NestedStruct {
            optional_field: None,
            another_optional: Some(vec!["value1".to_string()]),
            required_field: "required".to_string(),
        }),
        metadata: None,
        title: "Test".to_string(),
    };

    // Serialize to CBOR
    let cbor_bytes = c2pa_cbor::to_vec(&original).expect("serialize");
    println!("CBOR bytes: {:?}", cbor_bytes);

    // Deserialize back
    let deserialized: ParentStruct = c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize");

    assert_eq!(original, deserialized);
}

#[test]
fn test_map_with_skip_serializing_if() {
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct ActionLike {
        action: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        parameters: Option<HashMap<String, String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        software_agent: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct ActionsLike {
        actions: Vec<ActionLike>,
        #[serde(skip_serializing_if = "Option::is_none")]
        templates: Option<Vec<ActionLike>>,
    }

    let mut params = HashMap::new();
    params.insert("key1".to_string(), "value1".to_string());

    let actions = ActionsLike {
        actions: vec![
            ActionLike {
                action: "c2pa.created".to_string(),
                parameters: Some(params),
                software_agent: None,
            },
            ActionLike {
                action: "c2pa.opened".to_string(),
                parameters: None,
                software_agent: Some("TestApp".to_string()),
            },
        ],
        templates: None,
    };

    // This mimics what happens in the redaction test
    let cbor_bytes = c2pa_cbor::to_vec(&actions).expect("serialize");
    let deserialized: ActionsLike = c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize");

    assert_eq!(actions, deserialized);
}

#[test]
fn test_deeply_nested_options() {
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Level3 {
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Level2 {
        #[serde(skip_serializing_if = "Option::is_none")]
        level3: Option<Level3>,
        #[serde(skip_serializing_if = "Option::is_none")]
        other: Option<Vec<String>>,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Level1 {
        #[serde(skip_serializing_if = "Option::is_none")]
        level2: Option<Level2>,
        required: String,
    }

    let test = Level1 {
        level2: Some(Level2 {
            level3: Some(Level3 { data: None }),
            other: None,
        }),
        required: "test".to_string(),
    };

    let cbor_bytes = c2pa_cbor::to_vec(&test).expect("serialize");
    let deserialized: Level1 = c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize");

    assert_eq!(test, deserialized);
}

#[test]
fn test_all_none_options() {
    // Edge case: struct with all optional fields set to None
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct AllOptional {
        #[serde(skip_serializing_if = "Option::is_none")]
        field1: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        field2: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        field3: Option<HashMap<String, String>>,
    }

    let all_none = AllOptional {
        field1: None,
        field2: None,
        field3: None,
    };

    let cbor_bytes = c2pa_cbor::to_vec(&all_none).expect("serialize");
    let deserialized: AllOptional = c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize");

    assert_eq!(all_none, deserialized);
}

#[test]
fn test_option_in_vector() {
    // Test Option fields within a vector of structs
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Item {
        id: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tags: Option<Vec<String>>,
    }

    let items = vec![
        Item {
            id: 1,
            description: Some("First item".to_string()),
            tags: None,
        },
        Item {
            id: 2,
            description: None,
            tags: Some(vec!["tag1".to_string(), "tag2".to_string()]),
        },
        Item {
            id: 3,
            description: None,
            tags: None,
        },
    ];

    let cbor_bytes = c2pa_cbor::to_vec(&items).expect("serialize");
    let deserialized: Vec<Item> = c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize");

    assert_eq!(items, deserialized);
}

#[test]
fn test_option_hashmap_in_struct() {
    // Test Option<HashMap> which can be tricky with indefinite length
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct WithMap {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        properties: Option<HashMap<String, String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nested_maps: Option<HashMap<String, HashMap<String, String>>>,
    }

    let mut inner_map = HashMap::new();
    inner_map.insert("inner_key".to_string(), "inner_value".to_string());

    let mut nested = HashMap::new();
    nested.insert("outer_key".to_string(), inner_map);

    let with_maps = WithMap {
        name: "test".to_string(),
        properties: Some({
            let mut m = HashMap::new();
            m.insert("key1".to_string(), "value1".to_string());
            m.insert("key2".to_string(), "value2".to_string());
            m
        }),
        nested_maps: Some(nested),
    };

    let cbor_bytes = c2pa_cbor::to_vec(&with_maps).expect("serialize");
    let deserialized: WithMap = c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize");

    assert_eq!(with_maps, deserialized);
}

#[test]
fn test_mixed_some_none_pattern() {
    // Pattern that alternates Some/None - can expose field counting issues
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct MixedPattern {
        field1: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        opt1: Option<String>,
        field2: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        opt2: Option<String>,
        field3: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        opt3: Option<String>,
    }

    let mixed = MixedPattern {
        field1: "required1".to_string(),
        opt1: Some("optional1".to_string()),
        field2: "required2".to_string(),
        opt2: None,
        field3: "required3".to_string(),
        opt3: Some("optional3".to_string()),
    };

    let cbor_bytes = c2pa_cbor::to_vec(&mixed).expect("serialize");
    let deserialized: MixedPattern = c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize");

    assert_eq!(mixed, deserialized);
}

#[test]
fn test_newtype_backward_compatibility() {
    // Test that we can deserialize OLD format CBOR (without array wrapping)
    // This ensures backward compatibility with existing CBOR data

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Inner {
        #[serde(rename = "@context")]
        context: String,
        #[serde(rename = "@type")]
        type_name: String,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Wrapper(Inner);

    let inner = Inner {
        context: "http://schema.org/".to_string(),
        type_name: "CreativeWork".to_string(),
    };

    // Manually create OLD format CBOR: just the map directly (no array wrapping)
    // This simulates existing CBOR data created with the old serde_cbor behavior
    let old_format_cbor = c2pa_cbor::to_vec(&inner).expect("serialize inner directly");

    // Should be able to deserialize into the newtype wrapper
    let result: Result<Wrapper, _> = c2pa_cbor::from_slice(&old_format_cbor);
    assert!(
        result.is_ok(),
        "Should deserialize OLD format for backward compatibility"
    );

    let deserialized = result.unwrap();
    assert_eq!(deserialized.0, inner, "Inner value should match");
}

#[test]
fn test_option_with_flatten() {
    // Test #[serde(flatten)] with Option fields - known to cause indefinite-length issues
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct BaseFields {
        id: u32,
        name: String,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Extended {
        #[serde(flatten)]
        base: BaseFields,
        #[serde(skip_serializing_if = "Option::is_none")]
        extra: Option<String>,
    }

    let extended = Extended {
        base: BaseFields {
            id: 42,
            name: "test".to_string(),
        },
        extra: None,
    };

    let cbor_bytes = c2pa_cbor::to_vec(&extended).expect("serialize with flatten");
    let deserialized: Extended =
        c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize with flatten");

    assert_eq!(extended, deserialized);
}

#[test]
fn test_empty_collections_vs_none() {
    // Distinguish between None and empty collections
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct WithCollections {
        #[serde(skip_serializing_if = "Option::is_none")]
        vec_none: Option<Vec<String>>,
        vec_empty: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        map_none: Option<HashMap<String, String>>,
        map_empty: HashMap<String, String>,
    }

    let collections = WithCollections {
        vec_none: None,
        vec_empty: Vec::new(),
        map_none: None,
        map_empty: HashMap::new(),
    };

    let cbor_bytes = c2pa_cbor::to_vec(&collections).expect("serialize");
    let deserialized: WithCollections = c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize");

    assert_eq!(collections, deserialized);
}

#[test]
fn test_newtype_wrapper_around_map() {
    // Tests the fix for the CreativeWork issue: tuple struct wrapping a map-like structure.
    //
    // PROBLEM: serde's default behavior for newtype structs is to serialize them transparently
    // (just the inner value), but deserialize expects tuple format (1-element array).
    // This caused "invalid type: map, expected tuple struct CreativeWork" errors.
    //
    // SOLUTION: c2pa_cbor automatically wraps newtype structs in 1-element arrays during
    // serialization, maintaining tuple struct semantics and allowing proper round-trips.
    // Users can override with #[serde(transparent)] if they need transparent serialization.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct Inner {
        #[serde(rename = "@context")]
        context: String,
        #[serde(rename = "@type")]
        type_name: String,
        author: Option<String>,
    }

    // This is like CreativeWork(SchemaDotOrg) - will fail without transparent
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Wrapper(Inner);

    let inner = Inner {
        context: "http://schema.org/".to_string(),
        type_name: "CreativeWork".to_string(),
        author: Some("Alice".to_string()),
    };

    let wrapper = Wrapper(inner.clone());

    // Serialize to CBOR
    let cbor_bytes = c2pa_cbor::to_vec(&wrapper).expect("serialize newtype wrapper");
    println!("Newtype wrapper CBOR: {:?}", cbor_bytes);

    // With the fixed serializer, this should now work!
    // The newtype struct is serialized as a 1-element array containing the inner map
    let result: Result<Wrapper, _> = c2pa_cbor::from_slice(&cbor_bytes);
    assert!(result.is_ok(), "Should succeed with array wrapping");

    let deserialized = result.unwrap();
    assert_eq!(deserialized, wrapper, "Round-trip should preserve data");
}

#[test]
fn test_transparent_newtype() {
    // Test that #[serde(transparent)] fixes the tuple struct issue
    // This is the SOLUTION for CreativeWork
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    #[serde(transparent)] // <-- This fixes the issue!
    struct TransparentWrapper(HashMap<String, String>);

    let mut map = HashMap::new();
    map.insert("key1".to_string(), "value1".to_string());
    map.insert("key2".to_string(), "value2".to_string());

    let wrapper = TransparentWrapper(map.clone());

    let cbor_bytes = c2pa_cbor::to_vec(&wrapper).expect("serialize transparent wrapper");
    let deserialized: TransparentWrapper =
        c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize transparent wrapper");

    assert_eq!(wrapper, deserialized);
}

#[test]
fn test_transcode_from_json_with_flatten() {
    // Tests serde_transcode with #[serde(flatten)] which causes indefinite-length maps
    // This was causing "indefinite-length maps require manual encoding" errors
    use serde_json;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct WithFlatten {
        name: String,
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    }

    let json_str = r#"{"name":"test","param1":"value1","param2":42,"param3":true}"#;

    // Transcode from JSON to CBOR using ser::Serializer
    let buf: Vec<u8> = Vec::new();
    let mut from = serde_json::Deserializer::from_str(json_str);
    let mut to = c2pa_cbor::ser::Serializer::new(buf);

    serde_transcode::transcode(&mut from, &mut to).expect("transcode should work with flatten");

    let cbor_bytes = to.into_inner();

    // Verify it deserializes correctly
    let decoded: WithFlatten = c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize");
    assert_eq!(decoded.name, "test");
    assert_eq!(
        decoded.extra.get("param1").and_then(|v| v.as_str()),
        Some("value1")
    );
    assert_eq!(
        decoded.extra.get("param2").and_then(|v| v.as_i64()),
        Some(42)
    );
    assert_eq!(
        decoded.extra.get("param3").and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[test]
fn test_serialization_paths() {
    // Documents the two serialization paths: direct (fast) vs buffered (compatible)
    use std::collections::HashMap;

    // FAST PATH: Regular struct with known field count
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct FastPath {
        field1: String,
        field2: i32,
        field3: bool,
    }

    let fast = FastPath {
        field1: "test".to_string(),
        field2: 42,
        field3: true,
    };

    let cbor = c2pa_cbor::to_vec(&fast).expect("fast path serialization");
    let decoded: FastPath = c2pa_cbor::from_slice(&cbor).expect("deserialize");
    assert_eq!(fast, decoded);

    // BUFFERED PATH: Struct with #[serde(flatten)] causing unknown map size
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct BufferedPath {
        known_field: String,
        #[serde(flatten)]
        extra: HashMap<String, String>,
    }

    let mut extra = HashMap::new();
    extra.insert("dynamic1".to_string(), "value1".to_string());
    extra.insert("dynamic2".to_string(), "value2".to_string());

    let buffered = BufferedPath {
        known_field: "test".to_string(),
        extra,
    };

    let cbor = c2pa_cbor::to_vec(&buffered).expect("buffered path serialization");
    let decoded: BufferedPath = c2pa_cbor::from_slice(&cbor).expect("deserialize");
    assert_eq!(buffered, decoded);

    // Both produce valid definite-length CBOR (required for C2PA)
    // The difference is internal: fast path writes directly, buffered path collects first
}
