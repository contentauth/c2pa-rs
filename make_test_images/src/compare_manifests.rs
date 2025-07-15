// Copyright 2024 Adobe. All rights reserved.
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

//! Compares two manifest stores and prints out the differences.
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::Path,
};

use c2pa::{Error, Reader, Result};
use regex::Regex;
use serde_json::Value;

/// Compares all the files in two directories and returns a list of issues
pub fn compare_folders<P: AsRef<Path>, Q: AsRef<Path>>(folder1: P, folder2: Q) -> Result<()> {
    let folder1 = folder1.as_ref();
    let folder2 = folder2.as_ref();

    // handle the case we have files instead of folders
    if folder1.is_file() && folder2.is_file() {
        let issues = compare_image_manifests(folder1, folder2)?;
        if !issues.is_empty() {
            eprintln!("Failed {folder1:?}");
            for issue in issues {
                eprintln!("  {issue}");
            }
        } else {
            println!("Passed {folder1:?}");
        }
        return Ok(());
    } else if !(folder1.is_dir() && folder2.is_dir()) {
        eprintln!("must be two folders or two files");
        return Err(Error::BadParam(
            "must be two folders or two files".to_string(),
        ));
    }

    for entry in fs::read_dir(folder1)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let relative_path = path.strip_prefix(folder1).unwrap();
            let other_path = folder2.join(relative_path);
            let mut issues = Vec::new();
            if other_path.exists() {
                let result = compare_image_manifests(&path, &other_path)?;
                issues.extend(result);
            } else {
                issues.push(format!(
                    "File {} does not exist in {}",
                    relative_path.display(),
                    folder2.display()
                ));
            }
            if !issues.is_empty() {
                eprintln!("Failed {relative_path:?}");
                for issue in issues {
                    eprintln!("  {issue}");
                }
            } else {
                println!("Passed {relative_path:?}");
            }
        }
    }
    Ok(())
}

/// Compares files with manifest stores and returns a list of issues
pub fn compare_image_manifests<P: AsRef<Path>, Q: AsRef<Path>>(
    m1: P,
    m2: Q,
) -> Result<Vec<String>> {
    let manifest_store1 = match m1.as_ref().extension() {
        Some(ext) if ext == "json" => Reader::from_json(&fs::read_to_string(m1)?),
        _ => Reader::from_file(m1.as_ref()),
    };
    let manifest_store2 = match m2.as_ref().extension() {
        Some(ext) if ext == "json" => Reader::from_json(&fs::read_to_string(m2)?),
        _ => Reader::from_file(m2.as_ref()),
    };

    match (manifest_store1, manifest_store2) {
        (Ok(manifest_store1), Ok(manifest_store2)) => {
            compare_manifests(&manifest_store1, &manifest_store2)
        }
        (Err(Error::JumbfNotFound), Err(Error::JumbfNotFound)) => Ok(Vec::new()),
        (_, Err(err)) => Err(err),
        (Err(err), _) => Err(err),
    }
}

/// Compares two manifest stores and returns a list of issues.
pub fn compare_manifests(
    manifest_store1: &Reader,
    manifest_store2: &Reader,
) -> Result<Vec<String>> {
    // first we need to gather all the manifests in the order they are first seen recursively
    let mut labels1 = Vec::new();
    if let Some(label) = manifest_store1.active_label() {
        gather_manifests(manifest_store1, label, &mut labels1);
    }
    let mut labels2 = Vec::new();
    if let Some(label) = manifest_store2.active_label() {
        gather_manifests(manifest_store2, label, &mut labels2);
    }
    // now we have two lists of manifests, we need to match them up
    let manifest_map: HashMap<_, _> = labels1.into_iter().zip(labels2).collect();

    // now we can compare the manifests
    let mut issues = Vec::new();
    for (label1, label2) in manifest_map.iter() {
        let value1 = serde_json::to_value(manifest_store1.get_manifest(label1))?;
        let value2 = serde_json::to_value(manifest_store2.get_manifest(label2))?;
        compare_json_values(
            &format!("manifests.{label1}"),
            &normalize_json(value1),
            &normalize_json(value2),
            &mut issues,
        );
    }
    Ok(issues)
}

// creates list of manifests in the order they are first seen from the active manifest
fn gather_manifests(manifest_store: &Reader, manifest_label: &str, labels: &mut Vec<String>) {
    if !labels.contains(&manifest_label.to_string()) {
        labels.push(manifest_label.to_string());
    }
    if let Some(manifest) = manifest_store.get_manifest(manifest_label) {
        for ingredient in manifest.ingredients() {
            if let Some(label) = ingredient.active_manifest() {
                gather_manifests(manifest_store, label, labels);
            }
        }
    }
}

fn get_object_identifier(obj: &Value) -> Option<String> {
    if let Some(map) = obj.as_object() {
        // Use label for assertions and ingredients
        if let Some(label) = map.get("label").and_then(|v| v.as_str()) {
            return Some(label.to_string());
        }
        // if let Some(instance_id) = map.get("instance_id").and_then(|v| v.as_str()) {
        //     return Some(instance_id.to_string()); // ingredient
        // }
        if let Some(action) = map.get("action").and_then(|v| v.as_str()) {
            if let Some(params) = map.get("parameters") {
                if let Some(ingredients) = params.get("ingredients") {
                    if let Some(arr) = ingredients.as_array() {
                        // Use first ingredient url if present
                        if let Some(first) = arr.first() {
                            if let Some(url) = first.get("url").and_then(|v| v.as_str()) {
                                return Some(format!("{action}:{url}"));
                            }
                        }
                    }
                }
            }
            // Fallback to just action
            return Some(action.to_string());
        }
        // Use url for ingredient reference in action
        if let Some(url) = map.get("url").and_then(|v| v.as_str()) {
            return Some(url.to_string());
        }
    }
    None
}

fn normalize_json(value: Value) -> Value {
    lazy_static::lazy_static! {
        static ref GUID_RE: Regex = Regex::new(r"([a-zA-Z0-9\._-]+:)?(urn:(c2pa|uuid):|xmp.iid:)[0-9a-fA-F\-]{36}").unwrap();
        static ref JUMBF_GUID_RE: Regex = Regex::new(r"self#jumbf=/c2pa/[^:]+:urn:uuid:[0-9a-fA-F\-]{36}(/.*)?").unwrap();
        static ref UTC_TIMESTAMP_RE: Regex = Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?([+-]\d{2}:\d{2}|Z)$").unwrap();
        static ref VERSION_RE: Regex = Regex::new(r"0\.\d+\.\d+").unwrap();
    }

    match value {
        Value::Object(map) => {
            let new_map: BTreeMap<String, Value> = map
                .into_iter()
                .map(|(k, v)| {
                    let new_v = if k == "pad" {
                        Value::String("<PAD>".to_string())
                    } else {
                        normalize_json(v)
                    };
                    (k, new_v)
                })
                .collect();
            Value::Object(new_map.into_iter().collect())
        }
        Value::Array(arr) => {
            let mut new_arr: Vec<Value> = arr.into_iter().map(normalize_json).collect();

            // If this is an array of objects with identifiers, sort it.
            if !new_arr.is_empty()
                && new_arr.iter().all(|v| v.is_object())
                && new_arr.iter().all(|v| get_object_identifier(v).is_some())
            {
                new_arr.sort_by_key(get_object_identifier);
            }
            Value::Array(new_arr)
        }
        Value::String(s) => {
            if GUID_RE.is_match(&s) {
                Value::String(GUID_RE.replace_all(&s, "<GUID>").to_string())
            } else if JUMBF_GUID_RE.is_match(&s) {
                // Only replace the GUID portion, keep the rest of the string
                let replaced = JUMBF_GUID_RE.replace(&s, |caps: &regex::Captures| {
                    let prefix = caps.get(0).map_or("", |m| m.as_str());
                    let guid_re = Regex::new(r"urn:uuid:[0-9a-fA-F\-]{36}").unwrap();
                    guid_re.replace_all(prefix, "<GUID>").to_string()
                });
                Value::String(replaced.to_string())
            } else if UTC_TIMESTAMP_RE.is_match(&s) {
                Value::String("<TIMESTAMP>".to_string())
            } else if VERSION_RE.is_match(&s) {
                Value::String("<VERSION>".to_string())
            } else {
                Value::String(s)
            }
        }
        _ => value,
    }
}

/// Recursively compare two JSON values
fn compare_json_values(path: &str, val1: &Value, val2: &Value, issues: &mut Vec<String>) {
    if val1 == val2 {
        return;
    }

    // Suppress reporting changes in hash fields
    if path.ends_with(".hash") || path.contains("].hash") {
        return;
    }

    match (val1, val2) {
        (Value::Object(map1), Value::Object(map2)) => {
            let keys1: Vec<_> = map1.keys().collect();
            let keys2: Vec<_> = map2.keys().collect();

            for key in keys1 {
                let new_path = format!("{path}.{key}");
                match map2.get(key) {
                    Some(v2) => compare_json_values(&new_path, map1.get(key).unwrap(), v2, issues),
                    None => issues.push(format!("Removed {new_path}: {}", map1.get(key).unwrap())),
                }
            }

            for key in keys2 {
                if !map1.contains_key(key) {
                    issues.push(format!("Added {path}.{key}: {}", map2.get(key).unwrap()));
                }
            }
        }
        (Value::Array(arr1), Value::Array(arr2)) => {
            // Use custom identifier logic for validation_results arrays
            let use_custom_id = !arr1.is_empty()
                && arr1.iter().all(|v| v.is_object())
                && arr1.iter().all(|v| get_array_identifier(path, v).is_some());
            // For ingredients and actions arrays, use simplified matching
            if path.contains("ingredients") || path.contains("actions") {
                if arr1.len() != arr2.len() {
                    issues.push(format!(
                        "Array length changed at {path}: {} vs {}",
                        arr1.len(),
                        arr2.len()
                    ));
                } else {
                    // Match by title for ingredients
                    if path.contains("ingredients") {
                        let mut map1 = std::collections::HashMap::new();
                        let mut map2 = std::collections::HashMap::new();
                        for v in arr1 {
                            if let Some(title) = v.get("title").and_then(|t| t.as_str()) {
                                map1.insert(title, v);
                            }
                        }
                        for v in arr2 {
                            if let Some(title) = v.get("title").and_then(|t| t.as_str()) {
                                map2.insert(title, v);
                            }
                        }
                        for title in map1.keys() {
                            if let (Some(v1), Some(v2)) = (map1.get(title), map2.get(title)) {
                                compare_json_values(&format!("{path}[{title}]"), v1, v2, issues);
                            }
                        }
                    } else if path.contains("actions") {
                        let mut map1 = std::collections::HashMap::new();
                        let mut map2 = std::collections::HashMap::new();
                        for v in arr1 {
                            if let Some(action) = v.get("action").and_then(|a| a.as_str()) {
                                map1.insert(action, v);
                            }
                        }
                        for v in arr2 {
                            if let Some(action) = v.get("action").and_then(|a| a.as_str()) {
                                map2.insert(action, v);
                            }
                        }
                        for action in map1.keys() {
                            if let (Some(v1), Some(v2)) = (map1.get(action), map2.get(action)) {
                                compare_json_values(&format!("{path}[{action}]"), v1, v2, issues);
                            }
                        }
                    }
                }
            } else if use_custom_id {
                use std::collections::HashMap;
                let mut map1: HashMap<String, (usize, &Value)> = HashMap::new();
                let mut map2: HashMap<String, (usize, &Value)> = HashMap::new();
                for (i, v) in arr1.iter().enumerate() {
                    let id = get_array_identifier(path, v).unwrap();
                    map1.insert(id, (i, v));
                }
                for (i, v) in arr2.iter().enumerate() {
                    let id = get_array_identifier(path, v).unwrap();
                    map2.insert(id, (i, v));
                }
                // Report removed items
                for (id, (idx, v)) in &map1 {
                    if !map2.contains_key(id) {
                        issues.push(format!("Removed {path}[{id}] at {idx}: {v}",));
                    }
                }
                // Report inserted items
                for (id, (idx, v)) in &map2 {
                    if !map1.contains_key(id) {
                        issues.push(format!("Inserted {path}[{id}] at {idx}: {v}",));
                    }
                }
                // Report moved items only if value is unchanged
                for (id, (idx1, v1)) in &map1 {
                    if let Some((idx2, v2)) = map2.get(id) {
                        if idx1 != idx2 && v1 == v2 {
                            issues.push(format!("Moved {path}[{id}]: from {idx1} to {idx2}"));
                        }
                        // Only report value changes for items in the same position
                        if idx1 == idx2 && v1 != v2 {
                            let new_path = format!("{path}[{id}]");
                            compare_json_values(&new_path, v1, v2, issues);
                        }
                    }
                }
            } else {
                // Fallback: compare by index
                if arr1.len() != arr2.len() {
                    issues.push(format!(
                        "Array length mismatch at {path}: {} vs {}",
                        arr1.len(),
                        arr2.len()
                    ));
                }
                for (i, (v1, v2)) in arr1.iter().zip(arr2.iter()).enumerate() {
                    let new_path = format!("{path}[{i}]");
                    compare_json_values(&new_path, v1, v2, issues);
                }
            }
        }
        (v1, v2) => {
            issues.push(format!("Changed {path}: {v1} vs {v2}"));
        }
    }
}

fn normalize_url(url: &str) -> String {
    // Replace GUIDs in the url with a placeholder
    let guid_re = Regex::new(r"urn:uuid:[0-9a-fA-F\-]{36}").unwrap();
    guid_re.replace_all(url, "<GUID>").to_string()
}

fn get_array_identifier(path: &str, obj: &Value) -> Option<String> {
    // Use url for validation_results.*.(success|informational|failure) arrays
    if path.contains("validation_results")
        && (path.contains("success") || path.contains("informational") || path.contains("failure"))
    {
        if let Some(map) = obj.as_object() {
            if let Some(url) = map.get("url").and_then(|v| v.as_str()) {
                // Use normalized url only
                return Some(normalize_url(url));
            }
        }
        // Fallback: use the full JSON string as identifier
        Some(serde_json::to_string(obj).unwrap_or_default())
    } else {
        get_object_identifier(obj)
    }
}
