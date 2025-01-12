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

use std::fmt::Debug;

use c2pa::HashedUri;
use serde::{Deserialize, Serialize};

/// A set of _referenced assertions_ and other related data, known overall as
/// the **signer payload.** This binding **SHOULD** generally be construed as
/// authorization of or participation in the creation of the statements
/// described by those assertions and corresponding portions of the C2PA asset
/// in which they appear.
///
/// This is described in [§5.1, Overview], of the CAWG Identity Assertion
/// specification.
///
/// [§5.1, Overview]: https://cawg.io/identity/1.1-draft/#_overview
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct SignerPayload {
    /// List of assertions referenced by this credential signature
    pub referenced_assertions: Vec<HashedUri>,

    /// A string identifying the data type of the `signature` field
    pub sig_type: String,
    // TO DO: Add role and expected_* fields.
    // (https://github.com/contentauth/c2pa-rs/issues/816)
}
