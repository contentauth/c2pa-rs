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

mod invalid_claim;
mod store_core;
mod store_io;
mod store_signature;
mod store_verify;

pub(crate) use self::store_verify::StoreValidationInfo;
pub use self::{invalid_claim::InvalidClaimError, store_core::Store};

#[cfg(test)]
pub mod store_test;
