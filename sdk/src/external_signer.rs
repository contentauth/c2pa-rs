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

use crate::{
    claim::Claim, cose_sign::cose_sign, cose_validator::verify_cose, error::Result, signer::Signer,
    status_tracker::OneShotStatusTracker,
};

/// Signs and verifies Claim data using the supplied Signer.  If the claim_bytes do not
/// represent a valid Claim an error will be returned.  The box_size must correspond to the size
/// of the c2pa.signature JUMBF box for this Claim's manifest.  If successful a Vec<u8> of the
/// tagged Cbor representation of the CoseSign1 signature for the claim_data is returned. It length
/// of the CoseSign1 data will be box_size unless the box_size is too small to contain the generated
/// CoseSign1.  If this occurs an error will be returned.
pub fn external_sign(claim_bytes: &[u8], signer: &dyn Signer, box_size: usize) -> Result<Vec<u8>> {
    // must be a valid Claim
    let label = "dummy_label";
    let _claim = Claim::from_data(label, claim_bytes)?;

    // generate and verify a CoseSign1 representation of the data
    cose_sign(signer, claim_bytes, box_size).and_then(|sig| {
        // Sanity check: Ensure that this signature is valid.

        let mut cose_log = OneShotStatusTracker::new();
        match verify_cose(&sig, claim_bytes, b"", false, &mut cose_log) {
            Ok(_) => Ok(sig),
            Err(err) => Err(err),
        }
    })
}

#[allow(unused_imports)]
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    use crate::{utils::test::temp_signer, Signer};

    #[test]
    fn test_external_sign() {
        let mut claim = Claim::new("extern_sign_test", Some("contentauth"));
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let box_size = 10000;

        let signer = temp_signer();

        let cose_sign1 = external_sign(&claim_bytes, &signer, box_size).unwrap();

        assert_eq!(cose_sign1.len(), box_size);
    }
}
