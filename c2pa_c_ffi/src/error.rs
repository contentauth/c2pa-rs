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

use thiserror::Error;

#[derive(Error, Debug)]
/// Defines all possible errors that can occur in this library
pub enum C2paError {
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

pub type Error = C2paError;
pub type Result<T> = std::result::Result<T, Error>;

impl C2paError {
    /// Returns the error code for this error type
    pub fn code(&self) -> i32 {
        match self {
            Self::Assertion(_) => 100,
            Self::AssertionNotFound(_) => 101,
            Self::Decoding(_) => 102,
            Self::Encoding(_) => 103,
            Self::FileNotFound(_) => 104,
            Self::Io(_) => 105,
            Self::Json(_) => 106,
            Self::Manifest(_) => 107,
            Self::ManifestNotFound(_) => 108,
            Self::NotSupported(_) => 109,
            Self::Other(_) => 110,
            Self::NullParameter(_) => 111,
            Self::RemoteManifest(_) => 112,
            Self::ResourceNotFound(_) => 113,
            Self::Signature(_) => 114,
            Self::Verify(_) => 115,
        }
    }

    /// Returns the last error message stored in thread-local storage
    pub fn last_message() -> String {
        crate::cimpl::CimplError::last_message().unwrap_or_default()
    }

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
            AssertionDecoding(_) | ClaimDecoding(_) => Self::Decoding(err_str),
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
            _ => Self::Other(err_str),
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
}

impl From<c2pa::Error> for crate::cimpl::CimplError {
    fn from(val: c2pa::Error) -> Self {
        let c2pa_error = C2paError::from_c2pa_error(val);
        crate::cimpl::CimplError::new(c2pa_error.code(), c2pa_error.to_string())
    }
}

impl From<C2paError> for crate::cimpl::CimplError {
    fn from(err: C2paError) -> Self {
        crate::cimpl::CimplError::new(err.code(), err.to_string())
    }
}

impl From<std::io::Error> for crate::cimpl::CimplError {
    fn from(err: std::io::Error) -> Self {
        let c2pa_error = C2paError::Io(err.to_string());
        crate::cimpl::CimplError::new(c2pa_error.code(), c2pa_error.to_string())
    }
}

impl From<serde_json::Error> for crate::cimpl::CimplError {
    fn from(err: serde_json::Error) -> Self {
        let c2pa_error = C2paError::Json(err.to_string());
        crate::cimpl::CimplError::new(c2pa_error.code(), c2pa_error.to_string())
    }
}

impl From<crate::cimpl::CimplError> for C2paError {
    fn from(err: crate::cimpl::CimplError) -> Self {
        // Map CimplError codes to appropriate C2paError variants
        match err.code() {
            1 => C2paError::NullParameter(err.message().to_string()),
            2 => C2paError::Other(err.message().to_string()), // StringTooLong
            3 => C2paError::Other(err.message().to_string()), // InvalidHandle
            4 => C2paError::Other(err.message().to_string()), // WrongHandleType
            5 => C2paError::Other(err.message().to_string()), // Other
            // Codes 100+ are C2paError codes - parse the message to reconstruct
            code if code >= 100 => {
                // The message format is "ErrorType: message"
                C2paError::from(err.message())
            }
            _ => C2paError::Other(err.to_string()),
        }
    }
}

impl From<&str> for C2paError {
    fn from(err: &str) -> Self {
        // Split only on the first ": " to handle messages that contain ": "
        let parts: Vec<&str> = err.splitn(2, ": ").collect();
        if parts.len() == 2 {
            Self::from_type_and_message(parts[0], parts[1])
        } else {
            Self::Other(err.to_string())
        }
    }
}

impl From<String> for C2paError {
    fn from(err: String) -> Self {
        Self::from(err.as_str())
    }
}

// impl From<&str> for Error {
//     fn from(err: &str) -> Self {
//         let parts: Vec<&str> = err.split(": ").collect();
//         if parts.len() == 2 {
//             Self::from_type_and_message(parts[0], parts[1])
//         } else {
//             Self::Other(err.to_string())
//         }
//     }
// }

// impl From<String> for Error {
//     fn from(err: String) -> Self {
//         Error::from(err.as_str())
//     }
// }

// impl From<crate::cimpl::cimpl_error::CimplError> for Error {
//     fn from(err: crate::cimpl::cimpl_error::CimplError) -> Self {
//         Error::Other(err.to_string())
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cimpl::CimplError;

    #[test]
    fn test_c2pa_error_roundtrip_manifest_not_found() {
        // Create a C2paError
        let original = C2paError::ManifestNotFound("test label".to_string());
        assert!(matches!(original, C2paError::ManifestNotFound(_)));

        // Convert to CimplError (as happens when storing)
        let cimpl_err: CimplError = original.into();
        assert_eq!(cimpl_err.code(), 108); // ManifestNotFound code
        assert_eq!(cimpl_err.message(), "ManifestNotFound: test label");

        // Convert back to C2paError
        let recovered: C2paError = cimpl_err.into();
        assert!(
            matches!(recovered, C2paError::ManifestNotFound(ref msg) if msg == "test label"),
            "Expected ManifestNotFound, got: {:?}",
            recovered
        );
    }

    #[test]
    fn test_c2pa_error_roundtrip_with_colon_in_message() {
        // Message contains ": " which could break naive splitting
        let original = C2paError::ManifestNotFound("claim missing: some label".to_string());

        let cimpl_err: CimplError = original.into();
        assert_eq!(
            cimpl_err.message(),
            "ManifestNotFound: claim missing: some label"
        );

        let recovered: C2paError = cimpl_err.into();
        assert!(
            matches!(recovered, C2paError::ManifestNotFound(ref msg) if msg == "claim missing: some label"),
            "Expected ManifestNotFound with full message, got: {:?}",
            recovered
        );
    }

    #[test]
    fn test_c2pa_error_roundtrip_all_variants() {
        let test_cases = vec![
            (C2paError::Assertion("test".into()), 100),
            (C2paError::AssertionNotFound("test".into()), 101),
            (C2paError::Decoding("test".into()), 102),
            (C2paError::Encoding("test".into()), 103),
            (C2paError::FileNotFound("test".into()), 104),
            (C2paError::Io("test".into()), 105),
            (C2paError::Json("test".into()), 106),
            (C2paError::Manifest("test".into()), 107),
            (C2paError::ManifestNotFound("test".into()), 108),
            (C2paError::NotSupported("test".into()), 109),
            (C2paError::Other("test".into()), 110),
            (C2paError::NullParameter("test".into()), 111),
            (C2paError::RemoteManifest("test".into()), 112),
            (C2paError::ResourceNotFound("test".into()), 113),
            (C2paError::Signature("test".into()), 114),
            (C2paError::Verify("test".into()), 115),
        ];

        for (original, expected_code) in test_cases {
            let original_str = original.to_string();
            let cimpl_err: CimplError = original.into();
            assert_eq!(
                cimpl_err.code(),
                expected_code,
                "Code mismatch for {}",
                original_str
            );

            let recovered: C2paError = cimpl_err.into();
            let recovered_str = recovered.to_string();
            assert_eq!(
                original_str, recovered_str,
                "Round-trip failed: {} -> {}",
                original_str, recovered_str
            );
        }
    }

    #[test]
    fn test_remote_manifest_fetch_maps_to_remote_prefix_for_c2pa_c() {
        // c2pa-c Builder.SignStreamCloudUrl test expects error_message.rfind("Remote:", 0) == 0
        let c2pa_err = c2pa::Error::RemoteManifestFetch(
            "an error occurred from the underlying http resolver".to_string(),
        );
        let cimpl_err: CimplError = c2pa_err.into();
        let msg = cimpl_err.message();
        assert!(
            msg.starts_with("Remote:"),
            "C2paException in c2pa-c checks for 'Remote:' prefix; got: {}",
            msg
        );
    }

    #[test]
    fn test_cimpl_null_parameter_maps_to_c2pa_null_parameter() {
        let cimpl_err = CimplError::null_parameter("my_param");
        let c2pa_err: C2paError = cimpl_err.into();
        assert!(
            matches!(c2pa_err, C2paError::NullParameter(_)),
            "Expected NullParameter, got: {:?}",
            c2pa_err
        );
    }

    #[test]
    fn test_cimpl_infrastructure_errors_map_to_other() {
        // StringTooLong (code 2)
        let err: C2paError = CimplError::string_too_long("param").into();
        assert!(matches!(err, C2paError::Other(_)));

        // UntrackedPointer (code 3)
        let err: C2paError = CimplError::untracked_pointer(123).into();
        assert!(matches!(err, C2paError::Other(_)));

        // WrongPointerType (code 4)
        let err: C2paError = CimplError::wrong_pointer_type(456).into();
        assert!(matches!(err, C2paError::Other(_)));

        // Other (code 5)
        let err: C2paError = CimplError::other("generic error").into();
        assert!(matches!(err, C2paError::Other(_)));

        // MutexPoisoned (code 6)
        let err: C2paError = CimplError::mutex_poisoned().into();
        assert!(matches!(err, C2paError::Other(_)));

        // InvalidBufferSize (code 7)
        let err: C2paError = CimplError::invalid_buffer_size(999, "data").into();
        assert!(matches!(err, C2paError::Other(_)));
    }
}
