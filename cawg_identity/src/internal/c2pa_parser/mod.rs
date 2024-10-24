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

//! A set of very lightweight utilities for working with C2PA data structures.

mod assertion_store;
pub(crate) use assertion_store::AssertionStore;

mod claim;
pub(crate) use claim::Claim;

mod manifest;
pub(crate) use manifest::Manifest;

mod manifest_store;
pub(crate) use manifest_store::ManifestStore;
