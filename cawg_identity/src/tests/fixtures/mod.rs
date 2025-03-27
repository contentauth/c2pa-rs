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

#![allow(unused)]

pub(crate) mod claim_aggregation;

mod default_built_in_signature_verifier;
pub(crate) use default_built_in_signature_verifier::default_built_in_signature_verifier;

mod manifest_json;
pub(crate) use manifest_json::{manifest_json, parent_json};

mod naive_credential_holder;
pub(crate) use naive_credential_holder::{
    NaiveAsyncCredentialHolder, NaiveCredentialHolder, NaiveSignatureVerifier,
};

mod test_credentials;
pub(crate) use test_credentials::cert_chain_and_private_key_for_alg;
