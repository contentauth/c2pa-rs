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

/// Describes the ways in which a CAWG identity claims aggregation credential
/// can fail validation.
///
/// Intended to be used as a subtype for [`ValidationError`].
///
/// [`ValidationError`]: crate::ValidationError
#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::claim_aggregation::IcaValidationError"
)]
pub use c2pa::identity::claim_aggregation::IcaValidationError;
