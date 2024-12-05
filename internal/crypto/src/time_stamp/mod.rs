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

//! Functions for working with [RFC 3161] time stamp service providers.
//!
//! [RFC 3161]: https://www.ietf.org/rfc/rfc3161.txt

mod error;
pub use error::TimeStampError;

#[cfg(not(target_arch = "wasm32"))]
mod http_request;

mod provider;
pub use provider::{AsyncTimeStampProvider, TimeStampProvider};

mod response;

mod verify;
/// TEMPORARILY PUBLIC while refactoring
pub use verify::{verify_time_stamp, verify_time_stamp_async};
