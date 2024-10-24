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

//! This module contains the APIs you will use to build a
//! C2PA manifest that contains one or more CAWG identity assertions.
//!
//! This code must be used instead of the APIs in [`c2pa::Manifest`]
//! to ensure that the identity assertion properly references the
//! finalized hard binding assertion.

pub(crate) mod credential_holder;
pub use credential_holder::CredentialHolder;

pub(crate) mod identity_assertion_builder;
pub use identity_assertion_builder::IdentityAssertionBuilder;

mod manifest_builder;
pub use manifest_builder::ManifestBuilder;
