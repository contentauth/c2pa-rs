// Derived from
// https://github.com/spruceid/ssi/blob/ssi/v0.9.0/crates/jwk/src/lib.rs
// which was published under an Apache 2.0 license.

// Subsequent modifications are subject to license from Adobe
// as follows:

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

use crate::claim_aggregation::w3c_vc::jwk::*;

const ED25519_JSON: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"G80iskrv_nE69qbGLSpeOHJgmV4MKIzsy5l5iT6pCww","d":"39Ev8-k-jkKunJyFWog3k0OwgPjnKv_qwLhfqXdAXTY"}
"#;

#[test]
fn ed25519_from_str() {
    let _jwk: Jwk = serde_json::from_str(ED25519_JSON).unwrap();
}

#[test]
fn generate_ed25519() {
    let _key = Jwk::generate_ed25519().unwrap();
}
