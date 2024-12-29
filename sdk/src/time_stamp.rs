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

use c2pa_crypto::cose::TstToken;
use serde::{Deserialize, Serialize};

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
