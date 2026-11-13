// Copyright 2026 Adobe. All rights reserved.
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

//! RFC 3161 timestamp workflows.
//!
//! Acquisition returns unverified response bytes. Verification authenticates
//! signature and message-imprint facts. Certificate-profile validity, chain/trust
//! validation, and timestamp acceptance remain separate host responsibilities.

pub mod acquisition;
pub mod verification;

pub(crate) mod response;
