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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::labels,
    error::Result,
};

/// Helper class to create Timestamp assertions
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
pub struct TimeStamp(HashMap<String, ByteBuf>);

#[allow(dead_code)]
impl TimeStamp {
    /// Label prefix for an [`Timestamp`] assertion.
    ///
    /// See <https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_actions>.
    pub const LABEL: &'static str = labels::TIMESTAMP;

    pub fn new() -> Self {
        TimeStamp(HashMap::new())
    }

    //
    pub fn add_timestamp(&mut self, manifest_id: &str, timestamp: &[u8]) {
        self.0
            .insert(manifest_id.to_string(), ByteBuf::from(timestamp.to_vec()));
    }

    /// Get the timestamp for a given manifest id
    pub fn get_timestamp(&self, manifest_id: &str) -> Option<&[u8]> {
        self.0.get(manifest_id).map(|buf| buf.as_ref())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn send_timestamp_token_request(tsa_url: &str, message: &[u8]) -> Result<Vec<u8>> {
        use crate::{crypto::cose::CertificateTrustPolicy, status_tracker::StatusTracker, Error};

        let body = crate::crypto::time_stamp::default_rfc3161_message(message)?;
        let headers = None;

        let bytes =
            crate::crypto::time_stamp::default_rfc3161_request(tsa_url, headers, &body, message)
                .map_err(|_e| Error::OtherError("timestamp token not found".into()))?;

        // make sure it is a good response
        let ctp = CertificateTrustPolicy::passthrough();
        let mut tracker = StatusTracker::default();
        crate::crypto::time_stamp::verify_time_stamp(&bytes, message, &ctp, &mut tracker)?;

        let token = crate::crypto::cose::timestamptoken_from_timestamprsp(&bytes)
            .ok_or(Error::OtherError("timestamp token not found".into()))?;

        Ok(token)
    }
}

impl AsRef<HashMap<String, ByteBuf>> for TimeStamp {
    fn as_ref(&self) -> &HashMap<String, ByteBuf> {
        &self.0
    }
}

impl AssertionCbor for TimeStamp {}

impl AssertionBase for TimeStamp {
    const LABEL: &'static str = Self::LABEL;

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}
