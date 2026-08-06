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

//! Support for the C2PA soft binding algorithm list registry and the
//! [Soft Binding Resolution API](https://spec.c2pa.org/specifications/specifications/2.2/softbinding/Decoupled.html)
//! ("Decoupled" soft binding).
//!
//! This module deliberately does not perform any local watermark/fingerprint
//! embedding or extraction; callers are expected to obtain a soft binding
//! `alg` and `value` themselves (e.g. via a proprietary decoder) and pass it
//! to [`crate::Reader::with_soft_binding`].

pub mod algorithm_list;
pub mod resolution_api;

pub use algorithm_list::{
    SoftBindingAlgorithm, SoftBindingAlgorithmType, SoftBindingEntryMetadata, SoftBindingList,
    SoftBindingMediaType,
};
pub use resolution_api::{SoftBindingMatch, SoftBindingQueryResult};
