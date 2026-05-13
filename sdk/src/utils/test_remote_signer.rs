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

#![allow(clippy::unwrap_used)]
#![cfg(not(target_arch = "wasm32"))]

use httpmock::{HttpMockRequest, HttpMockResponse};

use crate::signer::BoxedSigner;
pub(crate) fn remote_signer_mock_server<'a>(
    server: &'a httpmock::MockServer,
    signed_bytes: &[u8],
) -> httpmock::Mock<'a> {
    server.mock(|when, then| {
        when.method(httpmock::Method::POST);
        then.status(200).body(signed_bytes);
    })
}

pub(crate) fn remote_signer_respond_with_signature(
    server: &'_ httpmock::MockServer,
    signer: BoxedSigner,
) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        when.path("/").method(httpmock::Method::POST);
        then.respond_with(move |req: &HttpMockRequest| {
            let signature = signer.sign(req.body_ref()).unwrap();
            HttpMockResponse::builder()
                .status(200)
                .header("content-type", "application/octet-stream")
                .body(signature)
                .build()
        });
    })
}
