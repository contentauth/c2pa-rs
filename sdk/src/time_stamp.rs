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
use c2pa_crypto::cose::{cose_countersign_data, TstToken};
use coset::ProtectedHeader;
use serde::{Deserialize, Serialize};

use crate::{error::Result, AsyncSigner, Signer};

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

// Generate TimeStamp based on rfc3161 using "data" as MessageImprint and return raw TimeStampRsp bytes
#[async_generic(async_signature(signer: &dyn AsyncSigner, data: &[u8]))]
fn timestamp_data(signer: &dyn Signer, data: &[u8]) -> Option<Result<Vec<u8>>> {
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

// Wrap rfc3161 TimeStampRsp in COSE sigTst object
pub(crate) fn make_cose_timestamp(ts_data: &[u8]) -> TstContainer {
    let token = TstToken {
        val: ts_data.to_vec(),
    };

    let mut container = TstContainer::default();
    container.add_token(token);

    container
}

#[derive(Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct TstContainer {
    #[serde(rename = "tstTokens")]
    pub(crate) tst_tokens: Vec<TstToken>,
}

impl TstContainer {
    pub fn add_token(&mut self, token: TstToken) {
        self.tst_tokens.push(token);
    }
}
