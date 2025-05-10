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
#[deprecated(since = "0.14.0", note = "Moved to c2pa::identity::SignerPayload")]
pub use c2pa::identity::SignerPayload;
