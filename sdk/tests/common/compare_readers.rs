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

/// Compares two manifest stores and prints out the differences.
use std::collections::HashMap;
use std::{fs, path::Path};

use c2pa::{Error, Reader, Result};

use super::reader_from_file;

#[allow(unused)]
/// Compares all the files in two directories and returns a list of issues
pub fn compare_folders<P: AsRef<Path>, Q: AsRef<Path>>(folder1: P, folder2: Q) -> Result<()> {
    let folder1 = folder1.as_ref();
    let folder2 = folder2.as_ref();

    // handle the case we have files instead of folders
    if folder1.is_file() && folder2.is_file() {
        let issues = compare_files(folder1, folder2)?;
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
            //println!("Comparing {:?} to {:?}", path, other_path);
            let mut issues = Vec::new();
            if other_path.exists() {
                let result = compare_files(&path, &other_path)?;
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
pub fn compare_files<P: AsRef<Path>, Q: AsRef<Path>>(m1: P, m2: Q) -> Result<Vec<String>> {
    let result1 = match m1.as_ref().extension() {
        Some(ext) if ext == "json" => Reader::from_json(&fs::read_to_string(m1)?),
        _ => reader_from_file(m1.as_ref()),
    };
    let result2 = match m2.as_ref().extension() {
        Some(ext) if ext == "json" => Reader::from_json(&fs::read_to_string(m2)?),
        _ => reader_from_file(m2.as_ref()),
    };
    match (result1, result2) {
        (Ok(reader1), Ok(reader2)) => compare_readers(&reader1, &reader2),
        (Err(Error::JumbfNotFound), Err(Error::JumbfNotFound)) => Ok(Vec::new()),
        (_, Err(err)) => Err(err),
        (Err(err), _) => Err(err),
    }
}

/// Compares two manifest stores and returns a list of issues.
pub fn compare_readers(reader1: &Reader, reader2: &Reader) -> Result<Vec<String>> {
    // first we need to gather all the manifests in the order they are first seen recursively
    let mut labels1 = Vec::new();
    if let Some(label) = reader1.active_label() {
        gather_manifests(reader1, label, &mut labels1);
    }
    let mut labels2 = Vec::new();
    if let Some(label) = reader2.active_label() {
        gather_manifests(reader2, label, &mut labels2);
    }
    // now we have two lists of manifests, we need to match them up
    let manifest_map: HashMap<_, _> = labels1.into_iter().zip(labels2).collect();

    // now we can compare the manifests
    let mut issues = Vec::new();
    for (label1, label2) in manifest_map.iter() {
        // convert manifests into json values and compare them
        let value1 = serde_json::to_value(reader1.get_manifest(label1))?;
        let value2 = serde_json::to_value(reader2.get_manifest(label2))?;
        compare_json_values(
            &format!("manifests.{label1}"),
            &value1,
            &value2,
            &mut issues,
        );
    }
    Ok(issues)
}

// creates list of manifests in the order they are first seen from the active manifest
fn gather_manifests(reader: &Reader, manifest_label: &str, labels: &mut Vec<String>) {
    if !labels.contains(&manifest_label.to_string()) {
        labels.push(manifest_label.to_string());
    }
    if let Some(manifest) = reader.get_manifest(manifest_label) {
        for ingredient in manifest.ingredients() {
            if let Some(label) = ingredient.active_manifest() {
                gather_manifests(reader, label, labels);
            }
        }
    }
}

/// Recursively compare two ManifestStore JSON values
fn compare_json_values(
    path: &str,
    val1: &serde_json::Value,
    val2: &serde_json::Value,
    issues: &mut Vec<String>,
) {
    match (val1, val2) {
        (serde_json::Value::Object(map1), serde_json::Value::Object(map2)) => {
            for (key, val1) in map1 {
                let val2 = map2.get(key).unwrap_or(&serde_json::Value::Null);
                compare_json_values(&format!("{path}.{key}"), val1, val2, issues);
            }

            for (key, value) in map2 {
                if map1.get(key).is_none() {
                    issues.push(format!("Added {path}.{key}: {value}"));
                }
            }
        }
        (serde_json::Value::Array(arr1), serde_json::Value::Array(arr2)) => {
            for (i, (val1, val2)) in arr1.iter().zip(arr2.iter()).enumerate() {
                compare_json_values(&format!("{path}[{i}]"), val1, val2, issues);
            }
        }
        (val1, val2) if val1 != val2 => {
            if !(path.ends_with(".instance_id")
                || path.ends_with(".instanceId")
                || path.ends_with(".identifier")
                || path.ends_with(".time")
                || path.contains(".hash")
                || path.contains(".label")
                || path.contains("claim_generator")  // changes with every version (todo: get more specific)
                || val1.is_string() && val2.is_string() && val1.to_string().contains("urn:uuid:"))
            {
                if val2.is_null() {
                    issues.push(format!("Missing {path}: {val1}"));
                } else if val2.is_null() {
                    issues.push(format!("Added {path}: {val2}"));
                } else {
                    issues.push(format!("Changed {path}: {val1} vs {val2}"));
                }
            }
        }
        _ => (),
    }
}
