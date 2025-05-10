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

/// Contains information the X.509 certificate chain and the COSE signature that
/// was used to generate this identity assertion signature.
#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::x509::X509SignatureInfo"
)]
pub use c2pa::identity::x509::X509SignatureInfo;
#[doc(hidden)]
#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::x509::X509SignatureReport"
)]
pub use c2pa::identity::x509::X509SignatureReport;
/// An implementation of [`SignatureVerifier`] that supports COSE signatures
/// generated from X.509 credentials as specified in [§8.2, X.509 certificates
/// and COSE signatures].
///
/// [`SignatureVerifier`]: crate::SignatureVerifier
/// [§8.2, X.509 certificates and COSE signatures]: https://cawg.io/identity/1.1-draft/#_x_509_certificates_and_cose_signatures
#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::x509::X509SignatureVerifier"
)]
pub use c2pa::identity::x509::X509SignatureVerifier;
