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
    status_tracker::StatusTracker,
    Error,
};

/// Helper class to create a `TimeStamp` assertion.
///
/// <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#timestamp_assertion>
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
pub struct TimeStamp(pub HashMap<String, ByteBuf>);

impl TimeStamp {
    /// Label prefix for an [`TimeStamp`] assertion.
    ///
    /// See <https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_actions>.
    pub const LABEL: &'static str = labels::TIMESTAMP;

    /// Construct a new, empty [`TimeStamp`] assertion.
    pub fn new() -> Self {
        TimeStamp(HashMap::new())
    }

    /// Add a timestamp token for the given manifest id.
    pub fn add_timestamp(&mut self, manifest_id: &str, timestamp: &[u8]) {
        self.0
            .insert(manifest_id.to_string(), ByteBuf::from(timestamp.to_vec()));
    }

    /// Get the timestamp token for a given manifest id.
    pub fn get_timestamp(&self, manifest_id: &str) -> Option<&[u8]> {
        self.0.get(manifest_id).map(|buf| buf.as_ref())
    }

    /// Refresh the timestamp token for a given manifest id.
    ///
    /// The `sig_structure_hash` is expected to be the CBOR-encoded `Sig_structure` with fields as
    /// defined by:
    /// - [C2PA spec (§10.3.2.5 Time-stamps)](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_time_stamps)
    /// - [RFC 8152 spec (§4.4 Signing and Verification Process)](https://datatracker.ietf.org/doc/html/rfc8152)
    //
    // The `sig_structure_hash` is normally obtained from [`Claim::timestamp_v2_sig_structure`].
    //
    // [`Store::timestamp_v2_sig_structure`][crate::claim::Claim::timestamp_v2_sig_structure].
    #[async_generic(async_signature(
        &mut self,
        tsa_url: &str,
        manifest_id: &str,
        sig_structure_hash: &[u8],
        http_resolver: &(impl AsyncHttpResolver + ?Sized),
    ))]
    pub(crate) fn refresh_timestamp(
        &mut self,
        tsa_url: &str,
        manifest_id: &str,
        sig_structure_hash: &[u8],
        http_resolver: &(impl SyncHttpResolver + ?Sized),
    ) -> Result<()> {
        let timestamp_token = if _sync {
            TimeStamp::send_timestamp_token_request(tsa_url, sig_structure_hash, http_resolver)?
        } else {
            TimeStamp::send_timestamp_token_request_async(
                tsa_url,
                sig_structure_hash,
                http_resolver,
            )
            .await?
        };

        self.0
            .insert(manifest_id.to_owned(), ByteBuf::from(timestamp_token));

        Ok(())
    }

    /// Send a timestamp token request to the `tsa_url` with the given `message`.
    ///
    /// This function will verify the structure of the returned response but not the trust.
    ///
    /// See [`TimeStamp::refresh_timestamp`] for more information.
    #[async_generic(async_signature(
        tsa_url: &str,
        message: &[u8],
        http_resolver: &(impl AsyncHttpResolver + ?Sized),
    ))]
    pub(crate) fn send_timestamp_token_request(
        tsa_url: &str,
        message: &[u8],
        http_resolver: &(impl SyncHttpResolver + ?Sized),
    ) -> Result<Vec<u8>> {
        let body = crate::crypto::time_stamp::default_rfc3161_message(message)?;
        let headers = None;

        let bytes = if _sync {
            crate::crypto::time_stamp::default_rfc3161_request(
                tsa_url,
                headers,
                &body,
                message,
                http_resolver,
            )
        } else {
            crate::crypto::time_stamp::default_rfc3161_request_async(
                tsa_url,
                headers,
                &body,
                message,
                http_resolver,
            )
            .await
        }
        .map_err(|err| Error::OtherError(format!("timestamp token not found: {err:?}").into()))?;

        // make sure it is a good response
        let ctp = CertificateTrustPolicy::passthrough();
        let mut tracker = StatusTracker::default();

        if _sync {
            crate::crypto::time_stamp::verify_time_stamp(
                &bytes,
                message,
                &ctp,
                &mut tracker,
                false,
            )?;
        } else {
            crate::crypto::time_stamp::verify_time_stamp_async(
                &bytes,
                message,
                &ctp,
                &mut tracker,
                false,
            )
            .await?;
        }

        let token =
            crate::crypto::cose::timestamptoken_from_timestamprsp(&bytes).map_err(|err| {
                Error::OtherError(format!("timestamp token not found: {err:?}").into())
            })?;

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
