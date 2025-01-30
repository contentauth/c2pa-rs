// Copyright 2025 Adobe. All rights reserved.
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

use std::cell::RefCell;

use c2pa::{DynamicAssertion, Result, Signer};
use c2pa_crypto::raw_signature::{RawSigner, SigningAlg};

use crate::builder::IdentityAssertionBuilder;

/// An `IdentityAssertionSigner` extends the [`Signer`] interface to add zero or
/// more identity assertions to a C2PA [`Manifest`] that is being produced.
///
/// [`Signer`]: c2pa::Signer
/// [`Manifest`]: c2pa::Manifest
pub struct IdentityAssertionSigner {
    signer: Box<dyn RawSigner>,
    identity_assertions: RefCell<Vec<IdentityAssertionBuilder>>,
}

impl IdentityAssertionSigner {
    /// Create an `IdentityAssertionSigner` wrapping the provided [`RawSigner`]
    /// instance.
    pub fn new(signer: Box<dyn RawSigner>) -> Self {
        Self {
            signer,
            identity_assertions: RefCell::new(vec![]),
        }
    }

    /// (FOR USE BY INTERNAL TESTS ONLY): Create an IdentityAssertionSigner
    /// using test credentials for a particular algorithm.
    #[cfg(test)]
    pub(crate) fn from_test_credentials(alg: SigningAlg) -> Self {
        use c2pa_crypto::raw_signature::signer_from_cert_chain_and_private_key;

        use crate::tests::fixtures::cert_chain_and_private_key_for_alg;

        let (cert_chain, private_key) = cert_chain_and_private_key_for_alg(alg);

        #[allow(clippy::unwrap_used)]
        Self {
            signer: signer_from_cert_chain_and_private_key(&cert_chain, &private_key, alg, None)
                .unwrap(),
            identity_assertions: RefCell::new(vec![]),
        }
    }

    /// Add an [`IdentityAssertionBuilder`] to be used when signing the
    /// next [`Manifest`].
    ///
    /// IMPORTANT: When [`sign()`] is called, the list of
    /// [`IdentityAssertionBuilder`]s will be cleared.
    ///
    /// [`Manifest`]: c2pa::Manifest
    /// [`sign()`]: Self::sign
    pub fn add_identity_assertion(&mut self, iab: IdentityAssertionBuilder) {
        #[allow(clippy::unwrap_used)]
        let mut identity_assertions = self.identity_assertions.try_borrow_mut().unwrap();
        // TO DO: Replace with error handling in the very unlikely case of a panic here.

        identity_assertions.push(iab);
    }
}

impl Signer for IdentityAssertionSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.signer.sign(data).map_err(|e| e.into())
    }

    fn alg(&self) -> SigningAlg {
        self.signer.alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        self.signer.cert_chain().map_err(|e| e.into())
    }

    fn reserve_size(&self) -> usize {
        self.signer.reserve_size()
    }

    fn ocsp_val(&self) -> Option<Vec<u8>> {
        self.signer.ocsp_response()
    }

    fn time_authority_url(&self) -> Option<String> {
        self.signer.time_stamp_service_url()
    }

    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        self.signer.time_stamp_request_headers()
    }

    fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.signer
            .time_stamp_request_body(message)
            .map_err(|e| e.into())
    }

    fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        self.signer
            .send_time_stamp_request(message)
            .map(|r| r.map_err(|e| e.into()))
    }

    fn raw_signer(&self) -> Option<Box<&dyn RawSigner>> {
        Some(Box::new(&*self.signer))
    }

    fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
        #[allow(clippy::unwrap_used)]
        let mut identity_assertions = self.identity_assertions.try_borrow_mut().unwrap();
        // TO DO: Replace with error handling in the very unlikely case of a panic here.

        let ia_clone = identity_assertions.split_off(0);
        let mut dynamic_assertions: Vec<Box<dyn DynamicAssertion>> = vec![];

        for ia in ia_clone.into_iter() {
            dynamic_assertions.push(Box::new(ia));
        }

        dynamic_assertions
    }
}
