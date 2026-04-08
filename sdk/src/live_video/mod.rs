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

//! Support for C2PA Live Video signing (section 19 of the C2PA Technical Specification).
//!
//! Implements the per-segment C2PA Manifest Box method (section 19.3), where each segment
//! carries its own C2PA Manifest with a [`LiveVideoSegment`] assertion for continuity tracking.
//!
//! # Signing
//!
//! Use [`LiveVideoSigner`] to sign an init segment and a sequence of media segments.
//!
//! See [C2PA Technical Specification — Live Video](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_live_video).

mod signing;

pub use signing::LiveVideoSigner;
