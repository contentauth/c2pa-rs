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

use hex_literal::hex;

use crate::{HashedUri, SignerPayload};

#[test]
fn impl_clone() {
    // Silly test to ensure code coverage on #[derive] line.

    let signer_payload = SignerPayload {
        referenced_assertions: vec![{
            HashedUri {
                    url: "self#jumbf=c2pa/urn:uuid:F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4/c2pa.assertions/c2pa.hash.data".to_owned(),
                    alg: Some("sha256".to_owned()),
                    hash: hex!("53d1b2cf4e6d9a97ed9281183fa5d836c32751b9d2fca724b40836befee7d67f").to_vec(),            }
        }],
        sig_type: "NONSENSE".to_owned(),
    };

    assert_eq!(signer_payload, signer_payload.clone());
}
