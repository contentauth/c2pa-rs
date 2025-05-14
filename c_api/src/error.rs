// Copyright 2023 Adobe. All rights reserved.
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

use std::cell::RefCell;

use thiserror::Error;
pub type Result<T> = std::result::Result<T, Error>;

// LAST_ERROR handling borrowed from Copyright (c) 2018 Michael Bryan
thread_local! {
    static LAST_ERROR: RefCell<Option<Error>> = const { RefCell::new(None) };
}

#[derive(Error, Debug)]
/// Defines all possible errors that can occur in this library
pub enum Error {
    #[error("Assertion: {0}")]
    Assertion(String),
    #[error("AssertionNotFound: {0}")]
    AssertionNotFound(String),
    #[error("Decoding: {0}")]
    Decoding(String),
    #[error("Encoding: {0}")]
    Encoding(String),
    #[error("FileNotFound: {0}")]
    FileNotFound(String),
    #[error("Io: {0}")]
    Io(String),
    #[error("Json: {0}")]
    Json(String),
    #[error("Manifest: {0}")]
    Manifest(String),
    #[error("ManifestNotFound: {0}")]
    ManifestNotFound(String),
    #[error("NotSupported: {0}")]
    NotSupported(String),
    #[error("Other: {0}")]
    Other(String),
    #[error("NullParameter: {0}")]
    NullParameter(String),
    #[error("Remote: {0}")]
    RemoteManifest(String),
    #[error("ResourceNotFound: {0}")]
    ResourceNotFound(String),
    #[error("Signature: {0}")]
    Signature(String),
    #[error("Verify: {0}")]
    Verify(String),
}

impl Error {
    // Convert c2pa errors to published API errors
    #[allow(unused_variables)]
    pub(crate) fn from_c2pa_error(err: c2pa::Error) -> Self {
        use c2pa::Error::*;
        let err_str = err.to_string();
        match err {
            c2pa::Error::AssertionMissing { url } => Self::AssertionNotFound("".to_string()),
            AssertionInvalidRedaction
            | AssertionRedactionNotFound
            | AssertionUnsupportedVersion => Self::Assertion(err_str),
            ClaimAlreadySigned
            | ClaimUnsigned
            | ClaimMissingSignatureBox
            | ClaimMissingIdentity
            | ClaimVersion
            | ClaimInvalidContent
            | ClaimMissingHardBinding
            | ClaimSelfRedact
            | ClaimDisallowedRedaction
            | UpdateManifestInvalid
            | TooManyManifestStores => Self::Manifest(err_str),
            ClaimMissing { label } => Self::ManifestNotFound(err_str),
            AssertionDecoding(_) | ClaimDecoding => Self::Decoding(err_str),
            AssertionEncoding(_) | XmlWriteError | ClaimEncoding => Self::Encoding(err_str),
            InvalidCoseSignature { coset_error } => Self::Signature(err_str),
            CoseSignatureAlgorithmNotSupported
            | CoseMissingKey
            | CoseX5ChainMissing
            | CoseInvalidCert
            | CoseSignature
            | CoseVerifier
            | CoseCertExpiration
            | CoseCertRevoked
            | CoseInvalidTimeStamp
            | CoseTimeStampValidity
            | CoseTimeStampMismatch
            | CoseTimeStampGeneration
            | CoseTimeStampAuthority
            | CoseSigboxTooSmall
            | TimeStampError(_)
            | RawSignatureValidationError(_)
            | RawSignerError(_)
            | CertificateProfileError(_)
            | CertificateTrustError(_)
            | InvalidCertificateError(_)
            | InvalidEcdsaSignature => Self::Signature(err_str),
            RemoteManifestFetch(_) | RemoteManifestUrl(_) => Self::RemoteManifest(err_str),
            JumbfNotFound => Self::ManifestNotFound(err_str),
            IoError(_) => Self::Io(err_str),
            JsonError(e) => Self::Json(err_str),
            NotFound | ResourceNotFound(_) | MissingDataBox => Self::ResourceNotFound(err_str),
            FileNotFound(_) => Self::FileNotFound(err_str),
            UnsupportedType => Self::NotSupported(err_str),
            ClaimVerification(_) | InvalidClaim(_) | JumbfParseError(_) => Self::Verify(err_str),
            BadParam(_)
            | MissingFeature(_)
            | VersionCompatibility(_)
            | InsufficientMemory
            | OutOfRange
            | InternalError(_)
            | _ => Self::Other(err_str),
        }
    }

    /// Converts a type and message to an Error
    /// This is used to create an error from a string
    /// The type is the first part of the string, and the message is the rest
    /// For example, "Io: Reading" would be converted to Error::Io("Reading")
    /// The type is used to determine the type of error, and the message is used to provide more information
    /// If the type is not recognized, it will be converted to Error::Other
    /// and the message will be used as the message
    /// # Arguments
    /// * `error_type` - The type of error
    /// * `error_message` - The message of the error
    /// # Returns
    /// * `Error` - The error
    pub fn from_type_and_message<S: Into<String>>(error_type: &str, error_message: S) -> Self {
        let error_message = error_message.into();
        match error_type {
            "Assertion" => Self::Assertion(error_message),
            "AssertionNotFound" => Self::AssertionNotFound(error_message),
            "Decoding" => Self::Decoding(error_message),
            "Encoding" => Self::Encoding(error_message),
            "FileNotFound" => Self::FileNotFound(error_message),
            "Io" => Self::Io(error_message),
            "Json" => Self::Json(error_message),
            "Manifest" => Self::Manifest(error_message),
            "ManifestNotFound" => Self::ManifestNotFound(error_message),
            "NotSupported" => Self::NotSupported(error_message),
            "Other" => Self::Other(error_message),
            "NullParameter" => Self::NullParameter(error_message),
            "Remote" => Self::RemoteManifest(error_message),
            "ResourceNotFound" => Self::ResourceNotFound(error_message),
            "Signature" => Self::Signature(error_message),
            "Verify" => Self::Verify(error_message),
            _ => Self::Other(format!("{error_type}: {error_message}")),
        }
    }

    /// Returns the last error as String
    pub fn last_message() -> Option<String> {
        LAST_ERROR.with(|prev| prev.borrow().as_ref().map(|e| e.to_string()))
    }

    /// Sets the last error
    pub fn set_last(self) {
        LAST_ERROR.with(|prev| *prev.borrow_mut() = Some(self));
    }

    /// Takes the the last error and clears it
    pub fn take_last() -> Option<Error> {
        LAST_ERROR.with(|prev| prev.borrow_mut().take())
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        let parts: Vec<&str> = err.split(": ").collect();
        if parts.len() == 2 {
            Self::from_type_and_message(parts[0], parts[1])
        } else {
            Self::Other(err.to_string())
        }
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::from(err.as_str())
    }
}
