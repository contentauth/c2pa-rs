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

use c2pa_crypto::{p1363::parse_ec_der_sig, raw_signature::RawSignerError, SigningAlg};

use crate::{Error, Result};

pub(crate) fn der_to_p1363(data: &[u8], alg: SigningAlg) -> Result<Vec<u8>> {
    // P1363 format: r | s

    let (_, p) = parse_ec_der_sig(data)
        .map_err(|_err| Error::InvalidEcdsaSignature)?;

    let mut r = extfmt::Hexlify(p.r).to_string();
    let mut s = extfmt::Hexlify(p.s).to_string();

    let sig_len: usize = match alg {
        SigningAlg::Es256 => 64,
        SigningAlg::Es384 => 96,
        SigningAlg::Es512 => 132,
        _ => return Err(Error::UnsupportedType),
    };

    // pad or truncate as needed
    let rp = if r.len() > sig_len {
        // truncate
        let offset = r.len() - sig_len;
        &r[offset..r.len()]
    } else {
        // pad
        while r.len() != sig_len {
            r.insert(0, '0');
        }
        r.as_ref()
    };

    let sp = if s.len() > sig_len {
        // truncate
        let offset = s.len() - sig_len;
        &s[offset..s.len()]
    } else {
        // pad
        while s.len() != sig_len {
            s.insert(0, '0');
        }
        s.as_ref()
    };

    if rp.len() != sig_len || rp.len() != sp.len() {
        return Err(Error::InvalidEcdsaSignature);
    }

    // merge r and s strings
    let mut new_sig = rp.to_string();
    new_sig.push_str(sp);

    // convert back from hex string to byte array
    (0..new_sig.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&new_sig[i..i + 2], 16)
                .map_err(|_err| Error::InvalidEcdsaSignature)
        })
        .collect()
}
