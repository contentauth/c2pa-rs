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

//! FFI Helper Macros
//!
//! This module provides a set of macros for building safe,
//! ergonomic C FFI bindings. The macros handle common FFI patterns like:
//! - Null pointer checking
//! - C string conversion
//! - Result/error handling with early returns
//! - Handle-based object management
//!
//! All macros that perform early returns include `_or_return_` in their names
//! to make control flow explicit and obvious.

// Re-export types/functions that macros need
#[doc(hidden)]
#[allow(unused_imports)] // May not be directly used but needed for macro expansion
pub use crate::ffi_handle_system::{get_handles, handle_to_ptr, ptr_to_handle, Handle};

// ============================================================================
// Core Flexible Macros (explicit "return" makes control flow clear)
// ============================================================================

/// Check pointer not null or early-return with error value
#[macro_export]
macro_rules! ptr_or_return {
    ($ptr:expr, $err_val:expr) => {
        if $ptr.is_null() {
            Error::set_last(Error::NullParameter(stringify!($ptr).to_string()));
            return $err_val;
        }
    };
}

/// Convert C string or early-return with error value
#[macro_export]
macro_rules! cstr_or_return {
    ($ptr:expr, $err_val:expr) => {
        if $ptr.is_null() {
            Error::set_last(Error::NullParameter(stringify!($ptr).to_string()));
            return $err_val;
        } else {
            std::ffi::CStr::from_ptr($ptr)
                .to_string_lossy()
                .into_owned()
        }
    };
}

/// Handle Result or early-return with error value
#[macro_export]
macro_rules! result_or_return {
    // For c2pa::Error results that need transformation
    ($result:expr, $transform:expr, $err_val:expr) => {
        match $result {
            Ok(value) => $transform(value),
            Err(err) => {
                Error::from_c2pa_error(err).set_last();
                return $err_val;
            }
        }
    };
    // For our Error type results (no conversion needed)
    (@local $result:expr, $transform:expr, $err_val:expr) => {
        match $result {
            Ok(value) => $transform(value),
            Err(err) => {
                err.set_last();
                return $err_val;
            }
        }
    };
}

// ============================================================================
// Named Shortcuts (self-documenting for common error values)
// ============================================================================

/// Handle Result, early-return with -1 (negative) on error
#[macro_export]
macro_rules! result_or_return_neg {
    ($result:expr, $transform:expr) => {
        result_or_return!($result, $transform, -1)
    };
}

/// Handle Result, early-return with null on error
#[macro_export]
macro_rules! result_or_return_null {
    ($result:expr, $transform:expr) => {
        result_or_return!($result, $transform, std::ptr::null_mut())
    };
}

/// Handle Result, early-return with 0 on error
#[macro_export]
macro_rules! result_or_return_zero {
    ($result:expr, $transform:expr) => {
        result_or_return!($result, $transform, 0)
    };
}

/// Handle Result, early-return with false on error
#[macro_export]
macro_rules! result_or_return_false {
    ($result:expr, $transform:expr) => {
        result_or_return!($result, $transform, false)
    };
}

// ============================================================================
// Legacy Macro Aliases (for backward compatibility)
// ============================================================================

/// If the expression is null, set the last error and return null.
#[macro_export]
macro_rules! ptr_or_return_null {
    ($ptr : expr) => {
        ptr_or_return!($ptr, std::ptr::null_mut())
    };
}

/// If the expression is null, set the last error and return -1.
#[macro_export]
macro_rules! ptr_or_return_int {
    ($ptr : expr) => {
        ptr_or_return!($ptr, -1)
    };
}

/// If the expression is null, set the last error and return std::ptr::null_mut().
#[macro_export]
macro_rules! cstr_or_return_null {
    ($ptr : expr) => {
        cstr_or_return!($ptr, std::ptr::null_mut())
    };
}

// Internal routine to convert a *const c_char to a rust String or return a -1 int error.
#[macro_export]
macro_rules! from_cstr_or_return_int {
    ($ptr : expr) => {
        cstr_or_return!($ptr, -1)
    };
}

// Internal routine to convert a *const c_char to Option<String>.
#[macro_export]
macro_rules! from_cstr_option {
    ($ptr : expr) => {
        if $ptr.is_null() {
            None
        } else {
            Some(
                std::ffi::CStr::from_ptr($ptr)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    };
}

#[macro_export]
macro_rules! ok_or_return_null {
    ($result:expr, $transform:expr) => {
        result_or_return_null!($result, $transform)
    };
}

#[macro_export]
macro_rules! ok_or_return_int {
    ($result:expr, $transform:expr) => {
        result_or_return_neg!($result, $transform)
    };
}

// ============================================================================
// Handle Management Macros
// ============================================================================

/// Convert a Result into a typed opaque pointer (handle disguised as pointer)
#[macro_export]
macro_rules! return_handle {
    ($result:expr, $type:ty) => {
        match $result {
            Ok(value) => {
                let handle = get_handles().insert(value);
                handle_to_ptr::<$type>(handle)
            }
            Err(err) => {
                Error::from_c2pa_error(err).set_last();
                std::ptr::null_mut()
            }
        }
    };
}

/// Free a typed pointer (handle)
#[macro_export]
macro_rules! free_handle {
    ($ptr:expr, $type:ty) => {{
        if $ptr.is_null() {
            return 0; // NULL is considered already freed
        }
        let handle = ptr_to_handle($ptr);
        match get_handles().remove::<$type>(handle) {
            Ok(_) => 0,
            Err(err) => {
                err.set_last();
                -1
            }
        }
    }};
}

/// Guard a handle parameter, creating an immutable reference with the given name
/// Returns early with -1 on error
#[macro_export]
macro_rules! guard_handle_or_return_neg {
    ($ptr:expr, $type:ty, $name:ident) => {
        ptr_or_return!($ptr, -1);
        let __arc = result_or_return!(@local get_handles().get($ptr as Handle), |v| v, -1);
        let __guard = match __arc.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // Mutex was poisoned by a panic, but we can still access the data
                eprintln!("WARNING: Mutex poisoned for handle {}, recovering", $ptr as Handle);
                poisoned.into_inner()
            }
        };
        let $name = match __guard.downcast_ref::<$type>() {
            Some(val) => val,
            None => {
                Error::WrongHandleType($ptr as Handle).set_last();
                return -1;
            }
        };
    };
}

/// Guard a handle parameter, creating an immutable reference with the given name
/// Returns early with null pointer on error
#[macro_export]
macro_rules! guard_handle_or_null {
    ($ptr:expr, $type:ty, $name:ident) => {
        ptr_or_return!($ptr, std::ptr::null_mut());
        let __arc = result_or_return!(@local get_handles().get($ptr as Handle), |v| v, std::ptr::null_mut());
        let __guard = match __arc.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                eprintln!("WARNING: Mutex poisoned for handle {}, recovering", $ptr as Handle);
                poisoned.into_inner()
            }
        };
        let $name = match __guard.downcast_ref::<$type>() {
            Some(val) => val,
            None => {
                Error::WrongHandleType($ptr as Handle).set_last();
                return std::ptr::null_mut();
            }
        };
    };
}

/// Guard a handle parameter, creating a mutable reference with the given name
/// Returns early with -1 on error
#[macro_export]
macro_rules! guard_handle_mut_or_return_neg {
    ($ptr:expr, $type:ty, $name:ident) => {
        ptr_or_return!($ptr, -1);
        let __arc = result_or_return!(@local get_handles().get($ptr as Handle), |v| v, -1);
        let mut __guard = match __arc.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                eprintln!("WARNING: Mutex poisoned for handle {}, recovering", $ptr as Handle);
                poisoned.into_inner()
            }
        };
        let $name = match __guard.downcast_mut::<$type>() {
            Some(val) => val,
            None => {
                Error::WrongHandleType($ptr as Handle).set_last();
                return -1;
            }
        };
    };
}

/// Guard a handle parameter mutably (return void on error)
#[macro_export]
macro_rules! guard_handle_mut_or_return {
    ($ptr:expr, $type:ty, $name:ident) => {
        if $ptr.is_null() {
            Error::set_last(Error::NullParameter(stringify!($ptr).to_string()));
            return;
        }
        let __arc = result_or_return!(@local get_handles().get($ptr as Handle), |v| v, ());
        let mut __guard = match __arc.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                eprintln!("WARNING: Mutex poisoned for handle {}, recovering", $ptr as Handle);
                poisoned.into_inner()
            }
        };
        let $name = match __guard.downcast_mut::<$type>() {
            Some(val) => val,
            None => {
                Error::WrongHandleType($ptr as Handle).set_last();
                return;
            }
        };
    };
}

/// Guard a handle parameter (return default value on error)
/// Useful for bool, usize, or other non-pointer returns
#[macro_export]
macro_rules! guard_handle_or_default {
    ($ptr:expr, $type:ty, $name:ident, $default:expr) => {
        ptr_or_return!($ptr, $default);
        let __arc = result_or_return!(@local get_handles().get($ptr as Handle), |v| v, $default);
        let __guard = match __arc.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                eprintln!("WARNING: Mutex poisoned for handle {}, recovering", $ptr as Handle);
                poisoned.into_inner()
            }
        };
        let $name = match __guard.downcast_ref::<$type>() {
            Some(val) => val,
            None => {
                Error::WrongHandleType($ptr as Handle).set_last();
                return $default;
            }
        };
    };
}
