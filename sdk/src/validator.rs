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

use c2pa_crypto::SigningAlg;
use chrono::{DateTime, Utc};
use x509_parser::num_bigint::BigUint;

#[derive(Debug, Default)]
pub struct ValidationInfo {
    pub alg: Option<SigningAlg>, // validation algorithm
    pub date: Option<DateTime<Utc>>,
    pub cert_serial_number: Option<BigUint>,
    pub issuer_org: Option<String>,
    pub validated: bool,     // claim signature is valid
    pub cert_chain: Vec<u8>, // certificate chain used to validate signature
    pub revocation_status: Option<bool>,
}
