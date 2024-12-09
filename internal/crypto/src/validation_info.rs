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

//! Signature validation info.

use crate::SigningAlg;
use chrono::{DateTime, Utc};
use x509_parser::num_bigint::BigUint;

/// Describes a signature's validation data and status.
#[derive(Debug, Default)]
pub struct ValidationInfo {
    /// Algorithm used to validate the signature
    pub alg: Option<SigningAlg>,
    /// Date the signature was created
    pub date: Option<DateTime<Utc>>,
    /// Certificate serial number
    pub cert_serial_number: Option<BigUint>,
    /// Certificate issuer organization
    pub issuer_org: Option<String>,
    /// Signature validity
    pub validated: bool,
    /// Certificate chain used to validate the signature
    pub cert_chain: Vec<u8>,
    /// Signature revocation status
    pub revocation_status: Option<bool>,
}
