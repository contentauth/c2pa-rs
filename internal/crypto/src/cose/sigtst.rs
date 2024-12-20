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

use async_generic::async_generic;
use coset::{sig_structure_data, ProtectedHeader, SignatureContext};
use serde::{Deserialize, Serialize};

use crate::{
    asn1::rfc3161::TstInfo,
    cose::CoseError,
    time_stamp::{verify_time_stamp, verify_time_stamp_async},
};

/// Parse the `sigTst` header from a COSE signature, which should contain one or
/// more `TstInfo` structures ([RFC 3161] time stamps).
///
/// Validate each time stamp and return them if valid.
///
/// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
#[async_generic]
pub fn parse_and_validate_sigtst(
    sigtst_cbor: &[u8],
    data: &[u8],
    p_header: &ProtectedHeader,
) -> Result<Vec<TstInfo>, CoseError> {
    let tst_container: TstContainer = ciborium::from_reader(sigtst_cbor)
        .map_err(|err| CoseError::CborParsingError(err.to_string()))?;

    let mut tstinfos: Vec<TstInfo> = vec![];

    for token in &tst_container.tst_tokens {
        let tbs = cose_countersign_data(data, p_header);
        let tst_info = if _sync {
            verify_time_stamp(&token.val, &tbs)?
        } else {
            verify_time_stamp_async(&token.val, &tbs).await?
        };

        tstinfos.push(tst_info);
    }

    if tstinfos.is_empty() {
        Err(CoseError::NoTimeStampToken)
    } else {
        Ok(tstinfos)
    }
}

/// Given an arbitrary message and a COSE protected header, generate the binary
/// blob to be signed as part of the COSE signature.
pub fn cose_countersign_data(data: &[u8], p_header: &ProtectedHeader) -> Vec<u8> {
    let aad: Vec<u8> = vec![];

    sig_structure_data(
        SignatureContext::CounterSignature,
        p_header.clone(),
        None,
        &aad,
        data,
    )
}

/// Raw contents of an [RFC 3161] time stamp.
///
/// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TstToken {
    #[allow(missing_docs)]
    #[serde(with = "serde_bytes")]
    pub val: Vec<u8>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct TstContainer {
    #[serde(rename = "tstTokens")]
    tst_tokens: Vec<TstToken>,
}
