// Copyright 2022 Adobe. All rights reserved.
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

mod claim_assertion;
mod claim_core;
mod claim_signature;
mod claim_verify;

#[cfg(test)]
pub(crate) use self::claim_core::AssertionStoreJsonFormat;
pub(crate) use self::claim_verify::ALLOWED_UPDATE_MANIFEST_ACTIONS;
pub use self::{
    claim_assertion::{ClaimAssertion, ClaimAssertionType},
    claim_core::{Claim, RemoteManifest},
    claim_verify::ClaimAssetData,
};

#[cfg(test)]
pub mod claim_test;
