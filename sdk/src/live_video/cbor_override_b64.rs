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

//! Serde helpers for `AssertionDefinition::cbor_override`.
//!
//! `cbor_override` carries pre-encoded CBOR bytes that must survive a
//! JSON round-trip (used in remote/embedded signing via `Builder::to_json()`
//! and subsequent deserialization). These helpers encode the bytes as a
//! standard Base64 string in JSON so the override is not silently lost.

use serde::{Deserialize, Deserializer, Serializer};

pub(crate) fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(bytes) => serializer.serialize_str(&crate::crypto::base64::encode(bytes)),
        None => serializer.serialize_none(),
    }
}

pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;

    match opt {
        Some(s) => {
            let bytes = crate::crypto::base64::decode(&s).map_err(serde::de::Error::custom)?;
            Ok(Some(bytes))
        }
        None => Ok(None),
    }
}
