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

use std::fmt::Debug;

use thiserror::Error;

/// Describes errors that can occur when building a CAWG identity assertion.
#[derive(Debug, Error)]
pub enum IdentityBuilderError {
    /// The box size provided for the signature is too small.
    #[error("the signature box is too small")]
    BoxSizeTooSmall,

    /// An error occurred while generating CBOR.
    #[error("error while generating CBOR ({0})")]
    CborGenerationError(String),

    /// The credentials provided could not be used.
    #[error("credential-related error ({0})")]
    CredentialError(String),

    /// An error occurred when generating the underlying signature.
    #[error("error while generating signature ({0})")]
    SignerError(String),

    /// An unexpected internal error occured while requesting the time stamp
    /// response.
    #[error("internal error ({0})")]
    InternalError(String),
}

impl<T: Debug> From<ciborium::ser::Error<T>> for IdentityBuilderError {
    fn from(err: ciborium::ser::Error<T>) -> Self {
        Self::CborGenerationError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::identity::builder::IdentityBuilderError;

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn impl_from_ciborium_err() {
        let ciborium_err: ciborium::ser::Error<String> =
            ciborium::ser::Error::Value("foo".to_string());
        let builder_err: IdentityBuilderError = ciborium_err.into();

        assert_eq!(
            builder_err.to_string(),
            "error while generating CBOR (Value(\"foo\"))"
        );
    }
}
