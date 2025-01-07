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

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::raw_signature::{SigningAlg, UnknownAlgorithmError};

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn alg_from_str() {
    assert_eq!("es256".parse(), Ok(SigningAlg::Es256));
    assert_eq!("es384".parse(), Ok(SigningAlg::Es384));
    assert_eq!("es512".parse(), Ok(SigningAlg::Es512));
    assert_eq!("ps256".parse(), Ok(SigningAlg::Ps256));
    assert_eq!("ps384".parse(), Ok(SigningAlg::Ps384));
    assert_eq!("ps512".parse(), Ok(SigningAlg::Ps512));
    assert_eq!("ed25519".parse(), Ok(SigningAlg::Ed25519));

    let r: Result<SigningAlg, UnknownAlgorithmError> = "bogus".parse();
    assert_eq!(r, Err(UnknownAlgorithmError("bogus".to_string())));
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn signing_alg_impl_display() {
    assert_eq!(format!("{}", SigningAlg::Es256), "es256");
    assert_eq!(format!("{}", SigningAlg::Es384), "es384");
    assert_eq!(format!("{}", SigningAlg::Es512), "es512");
    assert_eq!(format!("{}", SigningAlg::Ps256), "ps256");
    assert_eq!(format!("{}", SigningAlg::Ps384), "ps384");
    assert_eq!(format!("{}", SigningAlg::Ps512), "ps512");
    assert_eq!(format!("{}", SigningAlg::Ed25519), "ed25519");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn err_impl_display() {
    assert_eq!(
        format!("{}", UnknownAlgorithmError("bogus".to_owned())),
        "UnknownAlgorithmError(bogus)"
    );
}
