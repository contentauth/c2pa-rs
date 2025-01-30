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

//! Contains implementations of [`AsyncCredentialHolder`] and
//! [`SignatureVerifier`] for the X.509 certificates credential type described
//! as specified in [§8.2, X.509 certificates and COSE signatures].
//!
//! [`AsyncCredentialHolder`]: crate::builder::AsyncCredentialHolder
//! [`SignatureVerifier`]: crate::SignatureVerifier
//! [§8.2, X.509 certificates and COSE signatures]: https://cawg.io/identity/1.1-draft/#_x_509_certificates_and_cose_signatures

mod x509_credential_holder;
pub use x509_credential_holder::X509CredentialHolder;

mod x509_signature_verifier;
pub use x509_signature_verifier::X509SignatureVerifier;

const CAWG_X509_SIG_TYPE: &str = "cawg.x509.cose";
