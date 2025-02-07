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

use std::fmt::Debug;

use serde::Serialize;

use crate::identity_assertion::signer_payload::SignerPayload;

#[derive(Debug, Serialize)]
pub(crate) struct IdentityAssertionReport<T: Serialize> {
    #[serde(flatten)]
    pub(crate) signer_payload: SignerPayload,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) named_actor: Option<T>,
}
