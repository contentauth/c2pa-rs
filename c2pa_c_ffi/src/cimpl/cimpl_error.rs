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

use std::cell::RefCell;

pub type Result<T> = std::result::Result<T, crate::C2paError>;

// LAST_ERROR handling borrowed from Copyright (c) 2018 Michael Bryan
thread_local! {
    static LAST_ERROR: RefCell<Option<CimplError>> = const { RefCell::new(None) };
}

/// CimplError - FFI error container with variant name and message
///
/// This struct holds errors in a format designed for cross-language FFI bindings.
/// Errors are formatted as: `"VariantName: details"`
///
/// Library developers implement `From` to convert their error types to this struct.
///
/// # Format Convention
///
/// Errors follow the format: `"VariantName: message details"`
/// - **VariantName**: The error type (for parsing in language bindings)
/// - **message details**: Human-readable description
///
/// This format allows language bindings to parse the variant name and create
/// typed exceptions/errors in the target language.
///
/// # Example
///
/// ```rust,ignore
/// // Implement From for your error type
/// impl From<mylib::Error> for CimplError {
///     fn from(e: mylib::Error) -> Self {
///         // Automatic: uses Debug for variant, Display for message
///         CimplError::from_error(e)
///     }
/// }
///
/// // Macros automatically use From/Into
/// let result = ok_or_return_null!(parse_something());
/// ```
#[derive(Debug, Clone)]
pub struct CimplError {
    message: String,
}

impl CimplError {
    /// Creates a new error with variant name and message
    ///
    /// The error will be formatted as: `"variant: message"`
    ///
    /// # Example
    /// ```rust,ignore
    /// let err = CimplError::new("ParseError", "invalid character 'x'");
    /// assert_eq!(err.message(), "ParseError: invalid character 'x'");
    /// assert_eq!(err.variant(), Some("ParseError"));
    /// assert_eq!(err.details(), Some("invalid character 'x'"));
    /// ```
    pub fn new(variant: &str, message: impl Into<String>) -> Self {
        Self {
            message: format!("{}: {}", variant, message.into()),
        }
    }

    /// Creates an error from a message that is already formatted as
    /// `"Variant: details"`, without re-wrapping it in another prefix.
    pub(crate) fn from_formatted(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Creates an error from a std::error::Error
    ///
    /// Extracts the variant name from Debug output and uses Display for the message.
    /// Falls back to "Unknown" variant if Debug format cannot be parsed.
    pub fn from_error<E: std::error::Error>(e: E) -> Self {
        let debug = format!("{:?}", e);

        // Extract variant name from Debug output
        // Works with derived Debug: "Variant", "Variant(data)", "Variant { field }"
        let variant = debug
            .split(['(', '{'])
            .next()
            .and_then(|s| {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            })
            .unwrap_or("Unknown");

        Self::new(variant, e.to_string())
    }

    /// Returns the full formatted error message
    ///
    /// Format: `"VariantName: details"`
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Extracts the variant name from the error message
    ///
    /// Returns None if the message doesn't contain the expected format.
    pub fn variant(&self) -> Option<&str> {
        self.message.split_once(": ").map(|(v, _)| v)
    }

    /// Extracts the details from the error message (without variant name)
    ///
    /// Returns None if the message doesn't contain the expected format.
    pub fn details(&self) -> Option<&str> {
        self.message.split_once(": ").map(|(_, d)| d)
    }

    // Convenience constructors for common cimpl internal errors

    pub fn null_parameter<S: Into<String>>(param: S) -> Self {
        Self::new("NullParameter", param.into())
    }

    pub fn string_too_long<S: Into<String>>(param: S) -> Self {
        Self::new("StringTooLong", param.into())
    }

    pub fn untracked_pointer(ptr: u64) -> Self {
        Self::new("UntrackedPointer", format!("0x{:x}", ptr))
    }

    pub fn wrong_pointer_type(ptr: u64) -> Self {
        Self::new("WrongPointerType", format!("0x{:x}", ptr))
    }

    pub fn invalid_buffer_size(size: usize, param: &str) -> Self {
        Self::new("InvalidBufferSize", format!("{} for '{}'", size, param))
    }

    pub fn other<S: Into<String>>(msg: S) -> Self {
        Self::new("Other", msg.into())
    }

    /// Registry call made from a process that did not create the registry.
    pub fn foreign_process() -> Self {
        Self::new(
            "ForeignProcess",
            "forked child can't access a registry it doesn't own",
        )
    }

    /// Handle is tracked as `Arc` and single ownership was demanded through the registry,
    /// but other clones of `Arc` may exist so single ownership can't be guaranteed.
    pub fn wrong_wrapper_kind() -> Self {
        Self::new(
            "WrongWrapperKind",
            "Arc-backed handle can't have single ownership",
        )
    }

    /// A pointer could not be recorded by the registry and was rejected.
    /// `cause` lists the error.
    pub fn tracking_refused(cause: &str) -> Self {
        Self::new("TrackingRefused", cause)
    }

    /// An exclusive borrow is already in-flight for this handle.
    pub fn pointer_in_use() -> Self {
        Self::new("PointerInUse", "handle already in (exclusive) use")
    }

    /// Peeks at the last error message without clearing it
    ///
    /// Returns None if no error is set. This does not clear the error.
    pub fn last_message() -> Option<String> {
        LAST_ERROR.with(|prev| prev.borrow().as_ref().map(|e| e.message.clone()))
    }

    /// Sets this error as the last error
    pub fn set_last(self) {
        LAST_ERROR.with(|prev| *prev.borrow_mut() = Some(self));
    }

    /// Takes the last error and clears it
    ///
    /// This is rarely needed - errors naturally get overwritten by new errors.
    /// Provided for completeness and testing.
    pub fn take_last() -> Option<CimplError> {
        LAST_ERROR.with(|prev| prev.borrow_mut().take())
    }
}

impl std::fmt::Display for CimplError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CimplError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = CimplError::new("TestError", "test message");
        assert_eq!(err.message(), "TestError: test message");
        assert_eq!(err.variant(), Some("TestError"));
        assert_eq!(err.details(), Some("test message"));
    }

    #[test]
    fn test_null_parameter_error() {
        let err = CimplError::null_parameter("input_ptr");
        assert_eq!(err.variant(), Some("NullParameter"));
        assert_eq!(err.details(), Some("input_ptr"));
    }

    #[test]
    fn test_invalid_buffer_size_error() {
        let err = CimplError::invalid_buffer_size(1000, "data");
        assert_eq!(err.variant(), Some("InvalidBufferSize"));
        assert_eq!(err.details(), Some("1000 for 'data'"));
    }

    #[test]
    fn test_tracking_refused_error() {
        let err = CimplError::tracking_refused("id space of handles exhausted");
        assert_eq!(err.variant(), Some("TrackingRefused"));
        assert_eq!(err.details(), Some("id space of handles exhausted"));
    }

    #[test]
    fn test_from_error() {
        #[derive(Debug)]
        enum TestError {
            Parse(String),
            Validate,
        }

        impl std::fmt::Display for TestError {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match self {
                    TestError::Parse(s) => write!(f, "parse failed: {}", s),
                    TestError::Validate => write!(f, "validation failed"),
                }
            }
        }

        impl std::error::Error for TestError {}

        let err = CimplError::from_error(TestError::Parse("bad input".to_string()));
        assert_eq!(err.variant(), Some("Parse"));
        assert!(err.details().unwrap().contains("parse failed"));

        let err2 = CimplError::from_error(TestError::Validate);
        assert_eq!(err2.variant(), Some("Validate"));
        assert!(err2.details().unwrap().contains("validation failed"));
    }

    #[test]
    fn test_last_error_storage_and_take() {
        CimplError::new("Temporary", "temp").set_last();

        let err = CimplError::take_last();
        assert!(err.is_some());
        assert_eq!(err.unwrap().variant(), Some("Temporary"));

        assert_eq!(CimplError::last_message(), None);
    }

    #[test]
    fn test_variant_with_colon_in_details() {
        let err = CimplError::new("IoError", "file not found: /path/to/file");
        assert_eq!(err.variant(), Some("IoError"));
        assert_eq!(err.details(), Some("file not found: /path/to/file"));
    }
}
