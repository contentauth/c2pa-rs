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

use crate::HashedUri;

#[test]
fn impl_clone() {
    let h = HashedUri {
            url: "self#jumbf=c2pa/urn:uuid:F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4/c2pa.assertions/c2pa.hash.data".to_owned(),
            alg: Some("sha256".to_owned()),
            hash: hex!("53d1b2cf4e6d9a97ed9281183fa5d836c32751b9d2fca724b40836befee7d67f").to_vec(),
        };

    assert_eq!(h.clone(), h);
}

#[test]
fn impl_debug() {
    let h = HashedUri {
            url: "self#jumbf=c2pa/urn:uuid:F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4/c2pa.assertions/c2pa.hash.data".to_owned(),
            alg: Some("sha256".to_owned()),
            hash: hex!("53d1b2cf4e6d9a97ed9281183fa5d836c32751b9d2fca724b40836befee7d67f").to_vec(),
        };

    assert_eq!(format!("{:#?}", h), "HashedUri {\n    url: \"self#jumbf=c2pa/urn:uuid:F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4/c2pa.assertions/c2pa.hash.data\",\n    alg: Some(\n        \"sha256\",\n    ),\n    hash: 32 bytes starting with [53, d1, b2, cf, 4e, 6d, 9a, 97, ed, 92, 81, 18, 3f, a5, d8, 36, c3, 27, 51, b9],\n}");
}
