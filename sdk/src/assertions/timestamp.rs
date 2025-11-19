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

use async_generic::async_generic;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::labels,
    crypto::cose::CertificateTrustPolicy,
    error::Result,
    http::{AsyncHttpResolver, SyncHttpResolver},
    settings::Settings,
    status_tracker::StatusTracker,
    store::Store,
    Error,
};

/// Helper class to create Timestamp assertions
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
pub struct TimeStamp(HashMap<String, ByteBuf>);

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

    #[async_generic(async_signature(
        &mut self,
        store: &Store,
        time_authority_url: &str,
        manifest_id: &str,
        http_resolver: &impl AsyncHttpResolver,
    ))]
    pub(crate) fn refresh_timestamp(
        &mut self,
        store: &Store,
        time_authority_url: &str,
        manifest_id: &str,
        http_resolver: &impl SyncHttpResolver,
    ) -> Result<&[u8]> {
        let signature = store
            .get_cose_sign1_signature(manifest_id)
            .ok_or(Error::ClaimMissingSignatureBox)?;

        let timestamp_token = if _sync {
            TimeStamp::send_timestamp_token_request(time_authority_url, &signature, http_resolver)?
        } else {
            TimeStamp::send_timestamp_token_request_async(
                time_authority_url,
                &signature,
                http_resolver,
            )
            .await?
        };

        Ok(self
            .0
            .entry(manifest_id.to_owned())
            .or_insert(ByteBuf::from(timestamp_token))
            .as_slice())
    }

    #[async_generic(async_signature(
        time_authority_url: &str,
        message: &[u8],
        http_resolver: &impl AsyncHttpResolver,
    ))]
    pub(crate) fn send_timestamp_token_request(
        time_authority_url: &str,
        message: &[u8],
        http_resolver: &impl SyncHttpResolver,
    ) -> Result<Vec<u8>> {
        let body = crate::crypto::time_stamp::default_rfc3161_message(message)?;
        let headers = None;

        let bytes = if _sync {
            crate::crypto::time_stamp::default_rfc3161_request(
                time_authority_url,
                headers,
                &body,
                message,
                http_resolver,
            )
        } else {
            crate::crypto::time_stamp::default_rfc3161_request_async(
                time_authority_url,
                headers,
                &body,
                message,
                http_resolver,
            )
            .await
        }
        .map_err(|_e| Error::OtherError("timestamp token not found".into()))?;

        // make sure it is a good response
        let ctp = CertificateTrustPolicy::passthrough();
        let mut tracker = StatusTracker::default();

        // TODO: separate verifying time stamp and verifying time stamp trust into separate functions?
        //       do we need to pass settings here at all if `ctp` is set to pasthrough anyways?
        let mut settings = Settings::default();
        settings.verify.verify_timestamp_trust = false;

        if _sync {
            crate::crypto::time_stamp::verify_time_stamp(
                &bytes,
                message,
                &ctp,
                &mut tracker,
                &settings,
            )?;
        } else {
            crate::crypto::time_stamp::verify_time_stamp_async(
                &bytes,
                message,
                &ctp,
                &mut tracker,
                &settings,
            )
            .await?;
        }

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
