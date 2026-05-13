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

use crate::crypto::raw_signature::RawSignerError;

/// Utility method that selects the implementation
///
/// # Arguments
/// * `cert_chain` - A chain of PEM X509 certificates to convert
///
/// # Returns
/// A Result containing a Vec of DER-encoded certificates or an error
pub(crate) fn parse_and_check_chain_order(
    cert_chain: &[u8],
) -> Result<Vec<Vec<u8>>, RawSignerError> {
    #[cfg(all(
        feature = "openssl",
        not(any(feature = "rust_native_crypto", target_arch = "wasm32"))
    ))]
    return crate::crypto::raw_signature::openssl::cert_chain::parse_and_check_chain_order(
        cert_chain,
    );

    //TODO: Actually check if the order of the certificates in the chain is valid..
    #[cfg(any(feature = "rust_native_crypto", target_arch = "wasm32"))]
    return crate::crypto::raw_signature::rust_native::cert_chain::cert_chain_to_der(cert_chain);
}
