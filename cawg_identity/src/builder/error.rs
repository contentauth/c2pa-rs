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
pub enum IdentityBuilderError<SignerError> {
    /// The box size provided for the signature is too small.
    #[error("the signature box is too small")]
    BoxSizeTooSmall,

    /// An error occurred while generating CBOR.
    #[error("error while generating CBOR ({0})")]
    CborGenerationError(String),

    /// An error occurred when generating the underlying signature.
    #[error(transparent)]
    SignerError(#[from] SignerError),

    /// An unexpected internal error occured while requesting the time stamp
    /// response.
    #[error("internal error ({0})")]
    InternalError(String),
}
