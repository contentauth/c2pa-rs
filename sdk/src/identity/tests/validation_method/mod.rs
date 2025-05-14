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

//! This test suite checks the enforcement of generic identity assertion
//! validation as described in [§7.1, Validation method].
//!
//! IMPORTANT: The CAWG SDK does not currently support the optional fields named
//! * `expected_partial_claim`
//! * `expected_claim_generator`
//! * `expected_countersigners`
//!
//! [§7.1, Validation method]: https://cawg.io/identity/1.1-draft/#_validation_method

mod continue_when_possible;
mod stop_on_error;
