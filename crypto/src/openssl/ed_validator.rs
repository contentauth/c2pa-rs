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

use openssl::pkey::PKey;

use crate::{validator::CoseValidator, Error, Result, SigningAlg};

pub struct EdValidator {
    _alg: SigningAlg,
}

impl EdValidator {
    pub fn new(alg: SigningAlg) -> Self {
        EdValidator { _alg: alg }
    }
}

impl CoseValidator for EdValidator {
    fn validate(&self, sig: &[u8], data: &[u8], pkey: &[u8]) -> Result<bool> {
        let _openssl = super::OpenSslMutex::acquire()?;

        let public_key = PKey::public_key_from_der(pkey).map_err(|_err| Error::CoseSignature)?;

        let mut verifier = openssl::sign::Verifier::new_without_digest(&public_key)
            .map_err(|_err| Error::CoseSignature)?;

        verifier
            .verify_oneshot(sig, data)
            .map_err(|_err| Error::CoseSignature)
    }
}
