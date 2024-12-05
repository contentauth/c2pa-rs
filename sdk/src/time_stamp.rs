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
use c2pa_crypto::{
    asn1::rfc3161::TstInfo,
    time_stamp::{verify_time_stamp, verify_time_stamp_async},
};
use coset::{sig_structure_data, ProtectedHeader};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    AsyncSigner, Signer,
};

// Generate TimeStamp signature according to https://datatracker.ietf.org/doc/html/rfc3161
// using the specified Time Authority

#[allow(dead_code)]
pub(crate) fn cose_countersign_data(data: &[u8], p_header: &ProtectedHeader) -> Vec<u8> {
    let aad: Vec<u8> = Vec::new();

    // create sig_structure_data to be signed
    sig_structure_data(
        coset::SignatureContext::CounterSignature,
        p_header.clone(),
        None,
        &aad,
        data,
    )
}

#[async_generic(
    async_signature(
        signer: &dyn AsyncSigner,
        data: &[u8],
        p_header: &ProtectedHeader,
    ))]
pub(crate) fn cose_timestamp_countersign(
    signer: &dyn Signer,
    data: &[u8],
    p_header: &ProtectedHeader,
) -> Option<Result<Vec<u8>>> {
    // create countersignature with TimeStampReq parameters
    // payload: data
    // context "CounterSigner"
    // certReq true
    // algorithm sha256

    // create sig data structure to be time stamped
    let sd = cose_countersign_data(data, p_header);

    if _sync {
        timestamp_data(signer, &sd)
    } else {
        timestamp_data_async(signer, &sd).await
    }
}

#[async_generic]
pub(crate) fn cose_sigtst_to_tstinfos(
    sigtst_cbor: &[u8],
    data: &[u8],
    p_header: &ProtectedHeader,
) -> Result<Vec<TstInfo>> {
    let tst_container: TstContainer =
        serde_cbor::from_slice(sigtst_cbor).map_err(|_err| Error::CoseTimeStampGeneration)?;

    let mut tstinfos: Vec<TstInfo> = Vec::new();

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
        Err(Error::NotFound)
    } else {
        Ok(tstinfos)
    }
}

// Generate TimeStamp based on rfc3161 using "data" as MessageImprint and return raw TimeStampRsp bytes
#[async_generic(async_signature(signer: &dyn AsyncSigner, data: &[u8]))]
pub fn timestamp_data(signer: &dyn Signer, data: &[u8]) -> Option<Result<Vec<u8>>> {
    if _sync {
        signer
            .send_time_stamp_request(data)
            .map(|r| r.map_err(|e| e.into()))
    } else {
        signer
            .send_time_stamp_request(data)
            .await
            .map(|r| r.map_err(|e| e.into()))
        // TO DO: Fix bug in async_generic. This .await
        // should be automatically removed.
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct TstToken {
    #[serde(with = "serde_bytes")]
    pub val: Vec<u8>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct TstContainer {
    #[serde(rename = "tstTokens")]
    pub tst_tokens: Vec<TstToken>,
}

impl TstContainer {
    pub fn new() -> Self {
        TstContainer {
            tst_tokens: Vec::new(),
        }
    }

    pub fn add_token(&mut self, token: TstToken) {
        self.tst_tokens.push(token);
    }
}

impl Default for TstContainer {
    fn default() -> Self {
        Self::new()
    }
}

// Wrap rfc3161 TimeStampRsp in COSE sigTst object
pub(crate) fn make_cose_timestamp(ts_data: &[u8]) -> TstContainer {
    let token = TstToken {
        val: ts_data.to_vec(),
    };

    let mut container = TstContainer::new();
    container.add_token(token);

    container
}
