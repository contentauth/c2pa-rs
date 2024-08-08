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

use bcder::{Integer, OctetString, Oid};
use bytes::Bytes;
use x509_certificate::rfc5280::AlgorithmIdentifier;

use crate::internal::asn1::rfc3161::{
    MessageImprint, PkiStatus, PkiStatusInfo, TimeStampReq, TimeStampResp,
};

#[test]
fn impl_clone() {
    // Silly test to generate coverage on #[derive] lines.

    let req = TimeStampReq {
        version: Integer::from(1),
        message_imprint: MessageImprint {
            hash_algorithm: AlgorithmIdentifier {
                algorithm: Oid(Bytes::new()),
                parameters: None,
            },
            hashed_message: OctetString::new(Bytes::new()),
        },
        req_policy: None,
        nonce: None,
        cert_req: None,
        extensions: None,
    };
    assert_eq!(req, req.clone());

    let resp = TimeStampResp {
        status: PkiStatusInfo {
            status: PkiStatus::GrantedWithMods,
            status_string: None,
            fail_info: None,
        },
        time_stamp_token: None,
    };
    assert_eq!(resp, resp.clone());
}
