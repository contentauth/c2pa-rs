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
use ciborium::value::Value;
use coset::{sig_structure_data, Label, ProtectedHeader, SignatureContext};
use serde::{Deserialize, Serialize};

use crate::{
    asn1::rfc3161::TstInfo,
    cose::CoseError,
    time_stamp::{
        verify_time_stamp, verify_time_stamp_async, AsyncTimeStampProvider, TimeStampError,
        TimeStampProvider,
    },
};

/// Given a COSE signature, retrieve the `sigTst` header from it and validate
/// the information within it.
///
/// Return a [`TstInfo`] struct if available and valid.
#[async_generic]
pub fn validate_cose_tst_info(sign1: &coset::CoseSign1, data: &[u8]) -> Result<TstInfo, CoseError> {
    let Some(sigtst) = &sign1
        .unprotected
        .rest
        .iter()
        .find_map(|x: &(Label, Value)| {
            if x.0 == Label::Text("sigTst".to_string()) {
                Some(x.1.clone())
            } else {
                None
            }
        })
    else {
        return Err(CoseError::NoTimeStampToken);
    };

    let mut time_cbor: Vec<u8> = vec![];
    ciborium::into_writer(sigtst, &mut time_cbor)
        .map_err(|e| CoseError::InternalError(e.to_string()))?;

    let tst_infos = if _sync {
        parse_and_validate_sigtst(&time_cbor, data, &sign1.protected)?
    } else {
        parse_and_validate_sigtst_async(&time_cbor, data, &sign1.protected).await?
    };

    // For now, we only pay attention to the first time stamp header.
    // Technically, more are permitted, but we ignore them for now.
    let Some(tst_info) = tst_infos.into_iter().next() else {
        return Err(CoseError::NoTimeStampToken);
    };

    Ok(tst_info)
}

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

/// TO DO: Determine if this needs to be public after refactoring.
///
/// Given a COSE [`ProtectedHeader`] and an arbitrary block of data, use the
/// provided [`RawSigner`] or [`AsyncRawSigner`] to request a timestamp for that
/// block of data.
#[async_generic(
    async_signature(
        ts_provider: &dyn AsyncTimeStampProvider,
        data: &[u8],
        p_header: &ProtectedHeader,
    ))]
pub fn timestamp_countersignature(
    ts_provider: &dyn TimeStampProvider,
    data: &[u8],
    p_header: &ProtectedHeader,
) -> Option<Result<Vec<u8>, TimeStampError>> {
    let sd = cose_countersign_data(data, p_header);

    if _sync {
        ts_provider.send_time_stamp_request(&sd)
    } else {
        ts_provider.send_time_stamp_request(&sd).await
    }
}
