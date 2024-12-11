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

#[cfg(not(target_arch = "wasm32"))] // Maye will be used later?
use crate::{raw_signature::RawSignerError, SigningAlg};

#[cfg(not(target_arch = "wasm32"))] // Maye will be used later?
pub(crate) fn der_to_p1363(data: &[u8], alg: SigningAlg) -> Result<Vec<u8>, RawSignerError> {
    // P1363 format: r | s

    let (_, p) = parse_ec_der_sig(data)
        .map_err(|err| RawSignerError::InternalError(format!("invalid DER signature: {err}")))?;

    let mut r = const_hex::encode(p.r);
    let mut s = const_hex::encode(p.s);

    let sig_len: usize = match alg {
        SigningAlg::Es256 => 64,
        SigningAlg::Es384 => 96,
        SigningAlg::Es512 => 132,
        _ => {
            return Err(RawSignerError::InternalError(
                "unsupported algorithm for der_to_p1363".to_string(),
            ))
        }
    };

    // Pad or truncate as needed.
    let rp = if r.len() > sig_len {
        let offset = r.len() - sig_len;
        &r[offset..r.len()]
    } else {
        while r.len() != sig_len {
            r.insert(0, '0');
        }
        r.as_ref()
    };

    let sp = if s.len() > sig_len {
        let offset = s.len() - sig_len;
        &s[offset..s.len()]
    } else {
        while s.len() != sig_len {
            s.insert(0, '0');
        }
        s.as_ref()
    };

    if rp.len() != sig_len || rp.len() != sp.len() {
        return Err(RawSignerError::InternalError(
            "invalid signature components".to_string(),
        ));
    }

    // Merge r and s strings.
    let new_sig = format!("{rp}{sp}");

    // Convert back from hex string to byte array.
    const_hex::decode(&new_sig)
        .map_err(|e| RawSignerError::InternalError(format!("invalid signature components {e}")))
}
