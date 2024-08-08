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

// use crate::utils::test::temp_signer;

/* TODO [scouten 2024-07-13]: Restore this.

struct BogusSigner {}

impl BogusSigner {
    pub fn new() -> Self {
        BogusSigner {}
    }
}

impl crate::Signer for BogusSigner {
    fn sign(&self, _data: &[u8]) -> crate::error::Result<Vec<u8>> {
        eprintln!("Canary, canary, please cause this deploy to fail!");
        Ok(b"totally bogus signature".to_vec())
    }

    fn alg(&self) -> crate::SigningAlg {
        crate::SigningAlg::Ps256
    }

    fn certs(&self) -> crate::error::Result<Vec<Vec<u8>>> {
        let cert_vec: Vec<u8> = Vec::new();
        let certs = vec![cert_vec];
        Ok(certs)
    }

    fn reserve_size(&self) -> usize {
        1024
    }

    fn send_timestamp_request(&self, _message: &[u8]) -> Option<crate::error::Result<Vec<u8>>> {
        Some(Ok(Vec::new()))
    }
}

#[test]
fn test_bogus_signer() {
    let mut claim = Claim::new("bogus_sign_test", Some("contentauth"));
    claim.build().unwrap();

    let claim_bytes = claim.data().unwrap();

    let box_size = 10000;

    let signer = BogusSigner::new();

    let _cose_sign1 = sign_claim(&claim_bytes, &signer, box_size);

    #[cfg(feature = "openssl")] // there is no verify on sign when openssl is disabled
    assert!(_cose_sign1.is_err());
}
*/
