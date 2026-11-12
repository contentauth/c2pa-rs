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

//! The `C2PAAssetBinding` `termsOfUse` object and its correspondence with
//! `signer_payload`, as described in the CAWG identity 1.3 draft, “Binding to
//! C2PA asset.”

use base64::{prelude::BASE64_STANDARD, Engine};
use serde_json::{Map, Value};

use crate::identity::SignerPayload;

/// The `termsOfUse.type` that carries the C2PA asset binding.
pub(crate) const C2PA_ASSET_BINDING: &str = "C2PAAssetBinding";

/// Converts a `signer_payload` property name from snake_case to lowerCamelCase
/// as the draft requires: underscores are removed and the following ASCII
/// letter is capitalized; the first character stays lowercase; leading,
/// trailing and repeated underscores are discarded; non-alphabetic characters
/// are preserved.
pub(crate) fn snake_to_lower_camel(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper_next = false;
    for c in name.chars() {
        if c == '_' {
            // Leading underscores never capitalize the first character.
            upper_next = !out.is_empty();
        } else if upper_next {
            out.push(c.to_ascii_uppercase());
            upper_next = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// The JSON object that the aggregated `termsOfUse` binding must match for
/// `signer_payload`: the payload's JSON serialization without `sig_type`, with
/// byte strings as standard (not URL-safe) base 64 and property names in
/// lowerCamelCase.
pub(crate) fn expected_binding(signer_payload: &SignerPayload) -> Result<Value, String> {
    let mut cbor = Vec::new();
    c2pa_cbor::to_writer(&mut cbor, signer_payload).map_err(|e| e.to_string())?;
    let value: c2pa_cbor::Value = c2pa_cbor::from_slice(&cbor).map_err(|e| e.to_string())?;

    let mut json = cbor_to_binding_json(&value);
    if let Value::Object(ref mut map) = json {
        map.remove("sigType");
    }
    Ok(json)
}

fn cbor_to_binding_json(value: &c2pa_cbor::Value) -> Value {
    use c2pa_cbor::Value as Cbor;

    match value {
        Cbor::Null => Value::Null,
        Cbor::Bool(b) => Value::Bool(*b),
        Cbor::Integer(i) => Value::Number((*i).into()),
        Cbor::Float(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Cbor::Bytes(b) => Value::String(BASE64_STANDARD.encode(b)),
        Cbor::Text(s) => Value::String(s.clone()),
        Cbor::Array(a) => Value::Array(a.iter().map(cbor_to_binding_json).collect()),
        Cbor::Map(m) => {
            let mut obj = Map::new();
            for (k, v) in m {
                let key = match k {
                    Cbor::Text(s) => snake_to_lower_camel(s),
                    other => cbor_to_binding_json(other).to_string(),
                };
                obj.insert(key, cbor_to_binding_json(v));
            }
            Value::Object(obj)
        }
        Cbor::Tag(_, inner) => cbor_to_binding_json(inner),
    }
}

/// Aggregates `C2PAAssetBinding` `termsOfUse` objects as described in
/// “Credential binding data aggregation”: the outermost credential's object
/// comes first, then those of enveloped credentials in order.
///
/// `termsOfUse.type` is discarded. Array properties are concatenated, skipping
/// entries already present. Any other property must have the same value
/// everywhere it appears; the first conflicting property name is returned as
/// the error.
pub(crate) fn aggregate_terms_of_use<'a>(
    objects: impl IntoIterator<Item = &'a Map<String, Value>>,
) -> Result<Map<String, Value>, String> {
    let mut aggregated = Map::new();

    for object in objects {
        for (name, value) in object {
            if name == "type" {
                continue;
            }

            match (aggregated.get_mut(name), value) {
                (None, _) => {
                    aggregated.insert(name.clone(), value.clone());
                }
                (Some(Value::Array(existing)), Value::Array(more)) => {
                    for entry in more {
                        if !existing.contains(entry) {
                            existing.push(entry.clone());
                        }
                    }
                }
                (Some(existing), _) => {
                    if existing != value {
                        return Err(name.clone());
                    }
                }
            }
        }
    }

    Ok(aggregated)
}

/// Returns the `termsOfUse` entries of type `C2PAAssetBinding` from a
/// credential's `termsOfUse` property, which may be a single object or an
/// array of objects.
pub(crate) fn asset_bindings(terms_of_use: Option<&Value>) -> Vec<&Map<String, Value>> {
    let entries: Vec<&Value> = match terms_of_use {
        Some(Value::Array(entries)) => entries.iter().collect(),
        Some(entry) => vec![entry],
        None => Vec::new(),
    };

    entries
        .into_iter()
        .filter_map(Value::as_object)
        .filter(|o| o.get("type").and_then(Value::as_str) == Some(C2PA_ASSET_BINDING))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use serde_json::json;

    use super::*;
    use crate::HashedUri;

    #[test]
    fn snake_case_to_lower_camel_case() {
        assert_eq!(
            snake_to_lower_camel("referenced_assertions"),
            "referencedAssertions"
        );
        assert_eq!(snake_to_lower_camel("role"), "role");
        assert_eq!(
            snake_to_lower_camel("expected_partial_claim"),
            "expectedPartialClaim"
        );
        assert_eq!(snake_to_lower_camel("_leading"), "leading");
        assert_eq!(snake_to_lower_camel("trailing_"), "trailing");
        assert_eq!(snake_to_lower_camel("double__under"), "doubleUnder");
        assert_eq!(snake_to_lower_camel("v2_hash"), "v2Hash");
        assert_eq!(snake_to_lower_camel("alg"), "alg");
    }

    #[test]
    fn expected_binding_from_signer_payload() {
        let signer_payload = SignerPayload {
            referenced_assertions: vec![HashedUri::new(
                "self#jumbf=c2pa.assertions/c2pa.hash.data".to_owned(),
                Some("sha256".to_owned()),
                &[0xfb, 0xff, 0x01],
            )],
            sig_type: "cawg.verifiable_credential_binding".to_owned(),
            roles: vec!["cawg.creator".to_owned()],
        };

        assert_eq!(
            expected_binding(&signer_payload).unwrap(),
            json!({
                "referencedAssertions": [{
                    "url": "self#jumbf=c2pa.assertions/c2pa.hash.data",
                    "alg": "sha256",
                    // Standard base 64: `+` and `/`, never `-` and `_`.
                    "hash": "+/8B",
                }],
                "role": ["cawg.creator"],
            })
        );
    }

    #[test]
    fn aggregation_merges_arrays_and_rejects_conflicts() {
        let outer = json!({"type": "C2PAAssetBinding", "role": ["cawg.creator"], "x": 1});
        let inner =
            json!({"type": "C2PAAssetBinding", "role": ["cawg.creator", "cawg.editor"], "x": 1});
        let conflicting = json!({"type": "C2PAAssetBinding", "x": 2});

        let aggregated =
            aggregate_terms_of_use([outer.as_object().unwrap(), inner.as_object().unwrap()])
                .unwrap();
        assert_eq!(
            Value::Object(aggregated),
            json!({"role": ["cawg.creator", "cawg.editor"], "x": 1})
        );

        assert_eq!(
            aggregate_terms_of_use([outer.as_object().unwrap(), conflicting.as_object().unwrap()]),
            Err("x".to_owned())
        );
    }

    #[test]
    fn finds_asset_bindings_in_object_or_array() {
        let single = json!({"type": "C2PAAssetBinding", "role": []});
        assert_eq!(asset_bindings(Some(&single)).len(), 1);

        let many = json!([{"type": "Other"}, {"type": "C2PAAssetBinding"}]);
        assert_eq!(asset_bindings(Some(&many)).len(), 1);

        assert!(asset_bindings(None).is_empty());
    }
}
