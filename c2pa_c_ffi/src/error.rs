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
/// Error categories published by the C FFI, distinct from the SDK's errors.
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
    #[error("PointerInUse: {0}")]
    PointerInUse(String),
    #[error("WrongWrapperKind: {0}")]
    WrongWrapperKind(String),
    #[error("ForeignProcess: {0}")]
    ForeignProcess(String),
    #[error("TrackingRefused: {0}")]
    TrackingRefused(String),
    #[error("InvalidBufferSize: {0}")]
    InvalidBufferSize(String),
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
    /// Returns the last error using the published C API categories, without clearing it.
    pub fn last_message() -> String {
        cimpl::Error::last_message()
            .map(|message| Self::from(message).to_string())
            .unwrap_or_default()
    }

    // Convert c2pa errors to published API errors
    #[allow(unused_variables)]
    pub(crate) fn from_c2pa_error(err: c2pa::Error) -> Self {
        use c2pa::Error::*;
        let err_str = err.to_string();
        match err {
            c2pa::Error::AssertionMissing { url } => Self::AssertionNotFound("".to_string()),
            AssertionInvalidRedaction | AssertionRedactionNotFound => Self::Assertion(err_str),
            ClaimUnsigned
            | ClaimMissingSignatureBox
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
            CoseSignatureAlgorithmNotSupported
            | CoseX5ChainMissing
            | CoseInvalidCert
            | CoseSignature
            | CoseVerifier
            | CoseTimeStampGeneration
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
            ClaimVerification(_) | InvalidClaim(_) | InvalidManifest(_) | JumbfParseError(_) => {
                Self::Verify(err_str)
            }
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
            "PointerInUse" => Self::PointerInUse(error_message),
            "WrongWrapperKind" => Self::WrongWrapperKind(error_message),
            "ForeignProcess" => Self::ForeignProcess(error_message),
            "TrackingRefused" => Self::TrackingRefused(error_message),
            "InvalidBufferSize" => Self::InvalidBufferSize(error_message),
            "Remote" => Self::RemoteManifest(error_message),
            "ResourceNotFound" => Self::ResourceNotFound(error_message),
            "Signature" => Self::Signature(error_message),
            "Verify" => Self::Verify(error_message),
            _ => Self::Other(format!("{error_type}: {error_message}")),
        }
    }
}

impl From<c2pa::Error> for Error {
    fn from(val: c2pa::Error) -> Self {
        C2paError::from_c2pa_error(val)
    }
}

impl From<C2paError> for cimpl::Error {
    fn from(err: C2paError) -> Self {
        // Preserve the published prefix rather than deriving it from Debug.
        let message = err.to_string();
        let (variant, details) = message
            .split_once(": ")
            .expect("C2paError always formats as 'Variant: message'");
        Self::new(variant, details)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        C2paError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        C2paError::Json(err.to_string())
    }
}

impl From<cimpl::Error> for C2paError {
    fn from(err: cimpl::Error) -> Self {
        // The message is formatted as "Variant: details"; parse it back into
        // the matching C2paError variant (falling back to Other).
        C2paError::from(err.message())
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

/// Converts domain errors at the C boundary without remapping cimpl errors.
pub(crate) trait IntoCimplError {
    fn into_cimpl_error(self) -> cimpl::Error;
}

impl IntoCimplError for cimpl::Error {
    fn into_cimpl_error(self) -> cimpl::Error {
        self
    }
}

impl IntoCimplError for C2paError {
    fn into_cimpl_error(self) -> cimpl::Error {
        self.into()
    }
}

impl IntoCimplError for c2pa::Error {
    fn into_cimpl_error(self) -> cimpl::Error {
        C2paError::from(self).into()
    }
}

impl IntoCimplError for std::io::Error {
    fn into_cimpl_error(self) -> cimpl::Error {
        C2paError::from(self).into()
    }
}

impl IntoCimplError for serde_json::Error {
    fn into_cimpl_error(self) -> cimpl::Error {
        C2paError::from(self).into()
    }
}

#[cfg(test)]
mod tests {
    use cimpl::Error as CimplError;

    use super::*;

    #[test]
    fn test_c2pa_error_roundtrip_manifest_not_found() {
        // Create a C2paError
        let original = C2paError::ManifestNotFound("test label".to_string());
        assert!(matches!(original, C2paError::ManifestNotFound(_)));

        // Convert to CimplError (as happens when storing)
        let cimpl_err: CimplError = original.into();
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
            C2paError::Assertion("test".into()),
            C2paError::AssertionNotFound("test".into()),
            C2paError::Decoding("test".into()),
            C2paError::Encoding("test".into()),
            C2paError::FileNotFound("test".into()),
            C2paError::Io("test".into()),
            C2paError::Json("test".into()),
            C2paError::Manifest("test".into()),
            C2paError::ManifestNotFound("test".into()),
            C2paError::NotSupported("test".into()),
            C2paError::Other("test".into()),
            C2paError::NullParameter("test".into()),
            C2paError::RemoteManifest("test".into()),
            C2paError::ResourceNotFound("test".into()),
            C2paError::Signature("test".into()),
            C2paError::Verify("test".into()),
            C2paError::InvalidBufferSize("test".into()),
            C2paError::PointerInUse("test".into()),
            C2paError::WrongWrapperKind("test".into()),
            C2paError::ForeignProcess("test".into()),
            C2paError::TrackingRefused("test".into()),
        ];

        for original in test_cases {
            let original_str = original.to_string();
            let cimpl_err: CimplError = original.into();

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
        // c2pa-c checks this prefix to select its exception type.
        let c2pa_err = c2pa::Error::RemoteManifestFetch(
            "an error occurred from the underlying http resolver".to_string(),
        );
        let expected = format!("Remote: {c2pa_err}");
        let cimpl_err = c2pa_err.into_cimpl_error();
        assert!(cimpl_err.message().starts_with("Remote:"));
        assert_eq!(cimpl_err.message(), expected);
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
    }

    #[test]
    fn test_cimpl_typed_errors_keep_their_type() {
        let err: C2paError = CimplError::invalid_buffer_size(999, "data").into();
        assert!(matches!(err, C2paError::InvalidBufferSize(_)), "got {err}");
        assert_eq!(err.to_string(), "InvalidBufferSize: 999 for 'data'");
    }

    #[test]
    fn test_last_message_preserves_published_categories() {
        let cases = [
            (
                CimplError::null_parameter("reader"),
                "NullParameter: reader",
            ),
            (
                CimplError::invalid_buffer_size(999, "data"),
                "InvalidBufferSize: 999 for 'data'",
            ),
            (
                CimplError::new("PointerInUse", "handle busy"),
                "PointerInUse: handle busy",
            ),
            (
                CimplError::new("Remote", "resolver: failed"),
                "Remote: resolver: failed",
            ),
            (
                CimplError::string_too_long("format"),
                "Other: StringTooLong: format",
            ),
        ];
        for (error, expected) in cases {
            let raw_message = error.message().to_owned();
            error.set_last();
            assert_eq!(C2paError::last_message(), expected);
            assert_eq!(C2paError::last_message(), expected);
            assert_eq!(CimplError::take_last().unwrap().message(), raw_message);
        }
        assert_eq!(C2paError::last_message(), "");
    }
}
