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

use thiserror::Error;

use crate::{cose::CertificateProfileError, time_stamp::TimeStampError};

/// Describes errors that can occur when processing or generating [COSE]
/// signatures.
///
/// [COSE]: https://datatracker.ietf.org/doc/rfc9052/
#[derive(Debug, Error)]
pub enum CoseError {
    /// No signing certificate chain was found.
    #[error("missing signing certificate chain")]
    MissingSigningCertificateChain,

    /// Signing certificates appeared in both protected and unprotected headers.
    #[error("multiple signing certificate chains detected")]
    MultipleSigningCertificateChains,

    /// No time stamp token found.
    #[error("no time stamp token found in sigTst or sigTst2 header")]
    NoTimeStampToken,

    /// An error occurred while parsing CBOR.
    #[error("error while parsing CBOR ({0})")]
    CborParsingError(String),

    /// An error occurred while parsing a time stamp.
    #[error(transparent)]
    TimeStampError(#[from] TimeStampError),

    /// The signing certificate(s) did not match the required certificate
    /// profile.
    #[error(transparent)]
    CertificateProfileError(#[from] CertificateProfileError),

    /// An unexpected internal error occured while requesting the time stamp
    /// response.
    #[error("internal error ({0})")]
    InternalError(String),
}
