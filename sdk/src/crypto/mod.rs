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

#![deny(missing_docs)]

pub(crate) mod asn1;
pub(crate) mod base64;
pub mod cose;
pub(crate) mod hash;
pub(crate) mod internal;
pub mod ocsp;
pub mod time_stamp;

/// Parse a PEM certificate chain into DER-encoded certificates, end-entity
/// first.
///
/// Accepts JSON-encoded PEM (with literal `\n` escapes) as well as standard
/// PEM. This lives here because the raw signer no longer tracks the signing
/// certificate chain; that is now the SDK's responsibility.
pub(crate) fn cert_chain_pem_to_der(cert_chain_pem: &[u8]) -> crate::Result<Vec<Vec<u8>>> {
    let fixed = String::from_utf8_lossy(cert_chain_pem).replace("\\n", "\n");

    x509_parser::pem::Pem::iter_from_buffer(fixed.as_bytes())
        .map(|maybe_pem| {
            maybe_pem
                .map(|pem| pem.contents)
                .map_err(|_| crate::Error::CoseInvalidCert)
        })
        .collect()
}
