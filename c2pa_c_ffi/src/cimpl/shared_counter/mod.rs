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

//! Instance tags for telling one loaded copy of this crate from another.
//!
//! A handle is only meaningful to the registry that minted it. When two copies
//! of this crate are loaded into one process — two dynamic libraries each
//! linking it statically, or two semver-incompatible versions in one dependency
//! graph — each has its own registry and its own counter, so both mint the same
//! ids for different objects. Passing a handle to the wrong copy then looks
//! exactly like passing a stale one.
//!
//! Every registry claims a tag at startup and encodes it in the ids it mints,
//! so a foreign handle can be named as such instead of being reported as
//! untracked.
//!
//! Only [`fallback`] exists so far: it hands out tag 0 without coordinating
//! with anything, which is correct whenever a single copy is loaded. Detecting
//! the multi-copy case needs a counter shared across copies, which is a
//! platform-specific shared memory segment and is not implemented here.

pub(crate) mod fallback;

/// Source of an instance tag, unique among the loaded copies of this crate.
pub(crate) trait SharedCounter {
    /// Claims a tag for this copy. Called once per registry.
    ///
    /// Returning a duplicate is a correctness failure: two copies sharing a tag
    /// can mint the same id for different objects, which is the collision the
    /// tag exists to prevent.
    fn claim_tag(&self) -> u16;
}
