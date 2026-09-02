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

/// CimplError - holds an error code and message
///
/// This is a simple struct that can represent any error with an integer code
/// and a descriptive message. Library developers implement `From` to convert
/// their error types to this struct.
///
/// # Error Code Ranges
///
/// - **0**: No error (returned by error_code functions when no error is set)
/// - **1-99**: Reserved for cimpl infrastructure errors
/// - **100+**: Available for library-specific errors
///
/// # Example
///
/// ```rust,ignore
/// // Define your error codes
/// #[repr(i32)]
/// pub enum MyLibError {
///     ParseError = 100,
///     ValidationError = 101,
/// }
///
/// // Implement From for your error type
/// impl From<mylib::Error> for CimplError {
///     fn from(e: mylib::Error) -> Self {
///         match e {
///             mylib::Error::Parse(msg) => {
///                 CimplError::new(
///                     MyLibError::ParseError as i32,
///                     format!("ParseError: {}", msg)
///                 )
///             }
///             mylib::Error::Validation(msg) => {
///                 CimplError::new(
///                     MyLibError::ValidationError as i32,
///                     format!("ValidationError: {}", msg)
///                 )
///             }
///         }
///     }
/// }
///
/// // Macros automatically use From/Into
/// let result = ok_or_return_null!(parse_something());
/// ```
#[derive(Debug, Clone)]
pub struct CimplError {
    code: i32,
    message: String,
}

/// Error codes crossing C FFI.
pub(crate) mod codes {
    pub(crate) const NULL_PARAMETER: i32 = 1;
    pub(crate) const STRING_TOO_LONG: i32 = 2;
    pub(crate) const UNTRACKED_POINTER: i32 = 3;
    pub(crate) const WRONG_POINTER_TYPE: i32 = 4;
    pub(crate) const OTHER: i32 = 5;
    pub(crate) const MUTEX_POISONED: i32 = 6;
    pub(crate) const INVALID_BUFFER_SIZE: i32 = 7;
    pub(crate) const POINTER_IN_USE: i32 = 8;
    pub(crate) const WRONG_WRAPPER_KIND: i32 = 9;
    pub(crate) const FOREIGN_PROCESS: i32 = 10;
    pub(crate) const TRACKING_REFUSED: i32 = 11;
}

impl CimplError {
    /// Creates a new error with the given code and message
    pub fn new<S: Into<String>>(code: i32, message: S) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Returns the error code
    pub fn code(&self) -> i32 {
        self.code
    }

    /// Returns the error message
    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn null_parameter<S: Into<String>>(param: S) -> Self {
        Self::new(
            codes::NULL_PARAMETER,
            format!("NullParameter: {}", param.into()),
        )
    }

    pub fn string_too_long<S: Into<String>>(param: S) -> Self {
        Self::new(
            codes::STRING_TOO_LONG,
            format!("StringTooLong: {}", param.into()),
        )
    }

    pub fn untracked_pointer(ptr: u64) -> Self {
        Self::new(
            codes::UNTRACKED_POINTER,
            format!("UntrackedPointer: 0x{:x}", ptr),
        )
    }

    pub fn wrong_pointer_type(ptr: u64) -> Self {
        Self::new(
            codes::WRONG_POINTER_TYPE,
            format!("WrongPointerType: 0x{:x}", ptr),
        )
    }

    pub fn mutex_poisoned() -> Self {
        Self::new(
            codes::MUTEX_POISONED,
            "MutexPoisoned: thread panic detected".to_string(),
        )
    }

    pub fn invalid_buffer_size(size: usize, param: &str) -> Self {
        Self::new(
            codes::INVALID_BUFFER_SIZE,
            format!("InvalidBufferSize: {} for '{}'", size, param),
        )
    }

    pub fn other<S: Into<String>>(msg: S) -> Self {
        Self::new(codes::OTHER, format!("Other: {}", msg.into()))
    }

    /// Registry call made from a process that did not create the registry.
    pub fn foreign_process() -> Self {
        Self::new(
            codes::FOREIGN_PROCESS,
            "ForeignProcess: forked child can't access a registry it doesn't own".to_string(),
        )
    }

    /// Handle is tracked as `Arc` and single ownership was demanded through the registry,
    /// but other clones of `Arc` may exist so single ownership can't be guaranteed.
    pub fn wrong_wrapper_kind() -> Self {
        Self::new(
            codes::WRONG_WRAPPER_KIND,
            "WrongWrapperKind: Arc-backed handle can't have single ownership".to_string(),
        )
    }

    /// A pointer could not be recorded by the registry and was rejected.
    /// `cause` lists the error.
    pub fn tracking_refused(cause: &str) -> Self {
        Self::new(codes::TRACKING_REFUSED, format!("TrackingRefused: {cause}"))
    }

    /// An exclusive borrow is already in-flight for this handle.
    pub fn pointer_in_use() -> Self {
        Self::new(
            codes::POINTER_IN_USE,
            "PointerInUse: handle already in (exclusive) use".to_string(),
        )
    }

    /// Peeks at the last error message without clearing it
    ///
    /// Returns None if no error is set. This does not clear the error.
    pub fn last_message() -> Option<String> {
        LAST_ERROR.with(|prev| prev.borrow().as_ref().map(|e| e.message.clone()))
    }

    /// Peeks at the last error code without clearing it
    ///
    /// Returns 0 if no error is set. This does not clear the error.
    ///
    /// # Error Code Convention
    ///
    /// - **0**: No error set
    /// - **1-99**: cimpl infrastructure errors
    /// - **100+**: Library-specific errors
    pub fn last_code() -> i32 {
        LAST_ERROR.with(|prev| prev.borrow().as_ref().map(|e| e.code).unwrap_or(0))
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
