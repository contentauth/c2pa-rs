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

pub type Result<T> = std::result::Result<T, CimplError>;

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

impl CimplError {
    /// Creates a new error with the given code and message
    pub fn new<S: Into<String>>(code: i32, message: S) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn null_parameter<S: Into<String>>(param: S) -> Self {
        Self::new(1, format!("NullParameter: {}", param.into()))
    }

    pub fn string_too_long<S: Into<String>>(param: S) -> Self {
        Self::new(2, format!("StringTooLong: {}", param.into()))
    }

    pub fn invalid_handle(id: u64) -> Self {
        Self::new(3, format!("InvalidHandle: {}", id))
    }

    pub fn wrong_handle_type(id: u64) -> Self {
        Self::new(4, format!("WrongHandleType: {}", id))
    }

    pub fn other<S: Into<String>>(msg: S) -> Self {
        Self::new(5, format!("Other: {}", msg.into()))
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
