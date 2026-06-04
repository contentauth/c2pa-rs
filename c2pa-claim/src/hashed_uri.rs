// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A `HashedUri` provides a reference to content available within the same
/// manifest store.
///
/// Described in the C2PA Technical Specification §URI References.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct HashedUri {
    /// JUMBF URI reference
    url: String,

    /// Cryptographic hash algorithm used to compute the hash
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,

    /// Byte string containing the hash value
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,

    /// Salt used to generate the hash
    #[serde(skip_deserializing, skip_serializing)]
    salt: Option<Vec<u8>>,
}

impl HashedUri {
    pub fn new(url: String, alg: Option<String>, hash_bytes: &[u8]) -> Self {
        Self {
            url,
            alg,
            hash: hash_bytes.to_vec(),
            salt: None,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns true if this is a relative (same-manifest) JUMBF URI.
    ///
    /// A relative URI contains `self#jumbf=`; an absolute URI does not.
    pub fn is_relative_url(&self) -> bool {
        self.url.contains("self#jumbf=")
    }

    pub fn alg(&self) -> Option<&str> {
        self.alg.as_deref()
    }

    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    pub fn update_hash(&mut self, hash: Vec<u8>) {
        self.hash = hash;
    }

    pub fn add_salt(&mut self, salt: Option<Vec<u8>>) {
        self.salt = salt;
    }

    pub fn salt(&self) -> &Option<Vec<u8>> {
        &self.salt
    }
}

impl fmt::Debug for HashedUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.hash.len();
        let preview: Vec<String> = self
            .hash
            .iter()
            .take(20)
            .map(|b| format!("{b:02x}"))
            .collect();
        let hash_repr = if n == 0 {
            "(empty)".to_string()
        } else {
            format!("{n} bytes starting with [{}", preview.join(", "))
                + if n > 20 { ", ...]" } else { "]" }
        };
        f.debug_struct("HashedUri")
            .field("url", &self.url)
            .field("alg", &self.alg)
            .field("hash", &hash_repr)
            .finish()
    }
}

impl fmt::Display for HashedUri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "url: {}, alg: {:?}, hash", self.url, self.alg)
    }
}
