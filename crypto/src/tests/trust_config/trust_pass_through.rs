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

use std::io::Cursor;

use crate::{TrustHandlerConfig, TrustPassThrough};

#[test]
fn impl_debug() {
    let tpt: TrustPassThrough = TrustPassThrough::new();
    let debug = format!("{tpt:?}");

    assert_eq!(
        &debug,
        "TrustPassThrough { allowed_cert_set: {}, config_store: [] }"
    );
}

#[test]
#[should_panic]
fn load_trust_anchors_from_data() {
    let mut tpt: TrustPassThrough = TrustPassThrough::new();

    let allowed_list = include_bytes!("../fixtures/allow_list/allowed_list.pem").to_vec();
    let mut allowed_list = Cursor::new(allowed_list);

    tpt.load_trust_anchors_from_data(&mut allowed_list).unwrap();
    // ^^ is unimplemented
}
