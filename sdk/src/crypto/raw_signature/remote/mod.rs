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
    crypto::raw_signature::{RawSigner, RawSignerError},
    SigningAlg,
};

mod cert_chain;
mod remote_signer;

/// Return a built-in [`RawSigner`] instance using the provided signing
/// certificate and url to the remote signing service.
///
/// Which signers are available depends on the remote signing service.
/// It is assumed that the signature returned by the remote signing service
/// conforms to the public key in the certificate chain
///
/// May return an `Err` response if the certificate chain is invalid.
#[cfg(feature = "remote_signing")]
pub(crate) fn signer_from_cert_chain_and_url(
    cert_chain: &[u8],
    url: url::Url,
    alg: SigningAlg,
    time_stamp_service_url: Option<String>,
) -> Result<Box<dyn RawSigner + Send + Sync>, RawSignerError> {
    Ok(Box::new(
        remote_signer::RemoteRawSigner::from_cert_chain_and_url(
            cert_chain,
            url,
            alg,
            time_stamp_service_url,
        )?,
    ))
}
