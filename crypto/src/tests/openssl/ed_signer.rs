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

use crate::{tests::openssl::temp_signer, Signer, SigningAlg};

#[test]
fn ed25519_signer() {
    let signer = temp_signer::get_ed_signer(SigningAlg::Ed25519, None);

    let data = b"some sample content to sign";
    println!("data len = {}", data.len());

    let signature = signer.sign(data).unwrap();
    println!("signature.len = {}", signature.len());
    assert!(signature.len() >= 64);
    assert!(signature.len() <= signer.reserve_size());
}
