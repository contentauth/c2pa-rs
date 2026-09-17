// Copyright 2026 Adobe. All rights reserved.
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

//! Signing abstractions used internally by the COSE layer.
//!
//! Unlike [`RawSigner`](crate::RawSigner), which produces only a raw signature,
//! a [`CoseSigner`] bundles the raw signature with the time stamp and OCSP
//! information the COSE `Sign1` builder needs. The raw-signature primitive lives
//! in `c2pa-raw-crypto`; time stamping and OCSP are concerns of this crate, so
//! they are layered on here.

use async_trait::async_trait;
use c2pa_raw_crypto::{RawSigner, RawSignerError, SigningAlg};

use crate::{
    crypto::time_stamp::{AsyncTimeStampProvider, TimeStampProvider},
    maybe_send_sync::{MaybeSend, MaybeSync},
};

/// A `CoseSigner` produces a raw signature and supplies the time stamp and OCSP
/// information needed to assemble a COSE `Sign1` structure.
///
/// If an implementation _can_ be asynchronous, prefer [`AsyncCoseSigner`].
pub(crate) trait CoseSigner: TimeStampProvider {
    /// Return a raw signature over `data`.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError>;

    /// Return the algorithm implemented by this signer.
    fn alg(&self) -> SigningAlg;

    /// Return the signing certificate chain, end-entity first, each in DER form.
    fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError>;

    /// Return a pre-queried OCSP response for the signing certificate, if any.
    fn ocsp_response(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Asynchronous counterpart to [`CoseSigner`].
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub(crate) trait AsyncCoseSigner: AsyncTimeStampProvider + MaybeSync + MaybeSend {
    /// Return a raw signature over `data`.
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>, RawSignerError>;

    /// Return the algorithm implemented by this signer.
    fn alg(&self) -> SigningAlg;

    /// Return the signing certificate chain, end-entity first, each in DER form.
    fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError>;

    /// Return a pre-queried OCSP response for the signing certificate, if any.
    async fn ocsp_response(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Adapts a bare [`RawSigner`] plus its signing certificate chain into a
/// [`CoseSigner`].
///
/// The raw signer carries no certificate chain, time stamp service, or OCSP
/// information, so the chain is supplied here and the resulting COSE signature
/// has no time stamp or OCSP. (Those are configured at higher layers when
/// needed.)
pub(crate) struct RawSignerCoseSigner<'a> {
    signer: &'a dyn RawSigner,
    cert_chain: &'a [Vec<u8>],
}

impl<'a> RawSignerCoseSigner<'a> {
    pub(crate) fn new(signer: &'a dyn RawSigner, cert_chain: &'a [Vec<u8>]) -> Self {
        Self { signer, cert_chain }
    }
}

impl CoseSigner for RawSignerCoseSigner<'_> {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        self.signer.sign(data)
    }

    fn alg(&self) -> SigningAlg {
        self.signer.alg()
    }

    fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError> {
        Ok(self.cert_chain.to_vec())
    }
}

impl TimeStampProvider for RawSignerCoseSigner<'_> {}
