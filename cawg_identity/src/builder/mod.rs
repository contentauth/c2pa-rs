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
//! C2PA Manifest that contains one or more CAWG identity assertions.

mod async_identity_assertion_signer;
pub use async_identity_assertion_signer::AsyncIdentityAssertionSigner;

mod credential_holder;
pub use credential_holder::{AsyncCredentialHolder, CredentialHolder};

mod error;
pub use error::IdentityBuilderError;

mod identity_assertion_builder;
pub use identity_assertion_builder::{AsyncIdentityAssertionBuilder, IdentityAssertionBuilder};

mod identity_assertion_signer;
pub use identity_assertion_signer::IdentityAssertionSigner;
