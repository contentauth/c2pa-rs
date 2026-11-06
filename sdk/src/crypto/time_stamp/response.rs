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

#[cfg(test)]
pub(crate) mod tests {
    use rasn::prelude::*;

    #[allow(clippy::unwrap_used)]
    pub(crate) fn response_der(status: u8, token: Option<&[u8]>) -> Vec<u8> {
        #[derive(AsnType, Encode)]
        struct Status {
            status: rasn::types::Integer,
        }
        #[derive(AsnType, Encode)]
        struct Response {
            status: Status,
            token: Option<Any>,
        }
        rasn::der::encode(&Response {
            status: Status {
                status: status.into(),
            },
            token: token.map(|token| Any::new(token.to_vec())),
        })
        .unwrap()
    }
}
