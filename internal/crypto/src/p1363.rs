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

//! Utilities for working with the P1363 signature format used by C2PA in ECDSA
//! signatures.

use x509_parser::der_parser::{
    der::{parse_der_integer, parse_der_sequence_defined_g},
    error::BerResult,
};

/// Parse an ASN.1 DER object that contains a P1363 format into its components.
///
/// This format is used by C2PA to describe ECDSA signature keys.
pub fn parse_ec_der_sig(data: &[u8]) -> BerResult<EcSigComps> {
    parse_der_sequence_defined_g(|content: &[u8], _| {
        let (rem1, r) = parse_der_integer(content)?;
        let (_rem2, s) = parse_der_integer(rem1)?;

        Ok((
            data,
            EcSigComps {
                r: r.as_slice()?,
                s: s.as_slice()?,
            },
        ))
    })(data)
}

/// Component data for ECDSA signature components.
#[allow(missing_docs)]
pub struct EcSigComps<'a> {
    pub r: &'a [u8],
    pub s: &'a [u8],
}
