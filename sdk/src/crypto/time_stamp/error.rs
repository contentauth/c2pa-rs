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

/// Describes errors that can occur when requesting or verifying an [RFC 3161]
/// time stamp.
///
/// [RFC 3161]: https://www.ietf.org/rfc/rfc3161.txt
#[derive(Debug, Error)]
pub enum TimeStampError {
    /// The time stamp uses a certificate that was not valid at the time of
    /// signing.
    ///
    /// This typically occurs when the certificate is used beyond its period of
    /// validity, but may also occur when the certificate has not yet become
    /// valid.
    #[error("time stamp has an expired certificate")]
    ExpiredCertificate,

    /// The time stamp in the signature did not match the signed data.
    #[error("time stamp does not match data")]
    InvalidData,

    /// The time stamp uses an unsupported signing or hash algorithm.
    #[error("time stamp contains an unsupported algorithm")]
    UnsupportedAlgorithm,

    /// The time stamp authority is not on trust list
    #[error("time stamp authority is untrusted")]
    Untrusted,

    /// An error was encountered when decoding the time stamp response.
    #[error("decode error ({0})")]
    DecodeError(String),

    /// An I/O error occurred while processing the HTTPS time stamp response.
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    /// The time stamp service did not respond with the same nonce as provided.
    #[error("nonce mismatch")]
    NonceMismatch,

    /// The time stamp service responded with an error condition.
    #[error("service responded with an HTTP error (status = {0}, content-type = {1})")]
    HttpErrorResponse(u16, String),

    /// Unable to complete the HTTPS time stamp request.
    ///
    /// This error should be used _only_ if no response is received from the
    /// time stamp service. Any error response from the service should be
    /// described using `HttpRequestError`.
    #[error("unable to complete HTTP request ({0})")]
    HttpConnectionError(String),

    /// An unexpected internal error occurred while requesting the time stamp
    /// response.
    #[error("internal error ({0})")]
    InternalError(String),
}
