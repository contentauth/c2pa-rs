// Copyright 2023 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::hashed_uri::HashedUri;

/// Description of the claim generator, or the software used in generating the claim.
///
/// Also used for actions `softwareAgent`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ClaimGeneratorInfo {
    /// Human-readable name of the claim generator
    pub name: String,

    /// Human-readable product version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Hashed URI to the icon (embedded or remote)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<HashedUri>,

    /// Operating system the generator runs on
    #[serde(
        alias = "schema.org.SoftwareApplication.operatingSystem",
        skip_serializing_if = "Option::is_none"
    )]
    pub operating_system: Option<String>,

    /// Any non-standard fields
    #[serde(flatten)]
    pub other: HashMap<String, Value>,
}

impl ClaimGeneratorInfo {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: None,
            icon: None,
            operating_system: None,
            other: HashMap::new(),
        }
    }

    pub fn icon(&self) -> Option<&HashedUri> {
        self.icon.as_ref()
    }

    pub fn set_version(&mut self, version: impl Into<String>) -> &mut Self {
        self.version = Some(version.into());
        self
    }

    pub fn set_icon(&mut self, icon: HashedUri) -> &mut Self {
        self.icon = Some(icon);
        self
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) -> &mut Self {
        self.other.insert(key.into(), value.into());
        self
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.other.get(key)
    }
}
