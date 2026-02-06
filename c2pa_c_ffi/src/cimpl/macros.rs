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
//! - Option handling for validation
//! - Handle-based object management
//!
//! All macros that perform early returns include `_or_return_` in their names
//! to make control flow explicit and obvious.
//!
//! # 🔍 Test Mode Debugging & Leak Detection
//!
//! The FFI layer includes comprehensive memory tracking and debugging features to catch
//! memory management bugs during development and testing.
//!
//! ## Automatic Leak Detection (All Builds)
//!
//! The pointer registry automatically detects memory leaks at program shutdown. When the
//! registry is dropped, it checks for any pointers that were never freed:
//!
//! ```text
//! ⚠️  WARNING: 3 pointer(s) were not freed at shutdown!
//! This indicates C code did not properly free all allocated pointers.
//! Each pointer should be freed exactly once with cimpl_free().
//! ```
//!
//! **This runs in ALL builds** (debug, release, test) and helps identify:
//! - Forgotten `cimpl_free()` calls in C code
//! - Pointers returned to C that were never cleaned up
//! - Resource leaks that could accumulate over time
//!
//! ## Test-Mode Error Reporting
//!
//! In test builds (`#[cfg(test)]`), additional error reporting is enabled for immediate feedback:
//!
//! ### `cimpl_free` Error Output
//!
//! When `cimpl_free` fails in test mode, it prints detailed diagnostic information to stderr:
//!
//! ```text
//! ⚠️  ERROR: cimpl_free failed for pointer 0x12345678: pointer not tracked
//! This usually means:
//! 1. The pointer was not allocated with box_tracked!/track_box
//! 2. The pointer was already freed (double-free)
//! 3. The pointer is invalid/corrupted
//! ```
//!
//! ## Why These Errors Matter
//!
//! Memory management errors caught by these mechanisms indicate serious bugs:
//! - **Untracked allocations**: Using `Box::into_raw` without `track_box` means `cimpl_free`
//!   cannot safely deallocate the memory, causing memory leaks
//! - **Double-free**: Calling `cimpl_free` twice on the same pointer is undefined behavior
//! - **Invalid pointers**: Corrupted or uninitialized pointers will be caught
//! - **Memory leaks**: Pointers never freed waste resources and accumulate over program lifetime
//!
//! ## Production Behavior
//!
//! **In production builds** (without `#[cfg(test)]`):
//! - Leak detection at shutdown still runs (helps catch bugs in integration testing)
//! - `cimpl_free` errors are still returned (as `-1`) and set via [`crate::CimplError::set_last`]
//! - No stderr output for individual `cimpl_free` failures (quieter for library usage)
//! - C code should always check return values and handle errors appropriately
//!
//! # ⚠️  CRITICAL: Anti-Pattern Detection Guide ⚠️
//!
//! **Before writing ANY FFI code, scan for these patterns and replace:**
//!
//! ```text
//! ❌ if ptr.is_null() { Error::...; return -1; }
//! ✅ deref_mut_or_return_int!(ptr, Type)
//!
//! ❌ match result { Ok(v) => ..., Err(e) => { Error::...; return null } }
//! ✅ ok_or_return_null!(result.map_err(InternalError::from))
//!
//! ❌ unsafe { if ptr.is_null() { ... } &mut *ptr }
//! ✅ deref_mut_or_return_int!(ptr, Type)
//!
//! ❌ unsafe { &*ptr } or unsafe { &mut *ptr }
//! ✅ deref_or_return_int!(ptr, Type) or deref_mut_or_return_int!(ptr, Type)
//!
//! ❌ Manual string length checks and conversion
//! ✅ cstr_or_return!(ptr, -1)
//! ```
//!
//! **Literal strings to search for in your code:**
//! - `if ptr.is_null()` or `if ctx.is_null()` → Use a macro
//! - `match result { Ok` → Use `ok_or_return!`
//! - `unsafe { &*` → Use `deref_or_return!`
//! - `unsafe { &mut *` → Use `deref_mut_or_return!`
//!
//! If you see ANY of these patterns, **STOP and use the appropriate macro below.**
//!
//! # Quick Reference: Which Macro to Use?
//!
//! ## Input Validation (from C)
//! - **Pointer from C**: `deref_or_return_null!(ptr, Type)` → validates & dereferences to `&Type`
//! - **String from C**: `cstr_or_return_null!(c_str)` → converts C string to Rust `String`
//! - **Byte array from C**: `bytes_or_return_null!(ptr, len, "name")` → validates & converts to `&[u8]`
//! - **Check not null**: `ptr_or_return_null!(ptr)` → just null check, no deref (for output params)
//!
//! ## Output Creation (to C)
//! - **Box a value**: `box_tracked!(value)` → heap allocate and return pointer
//! - **Return string**: `to_c_string(rust_string)` → convert to C string
//! - **Optional string**: `option_to_c_string!(opt)` → `None` becomes `NULL`
//!
//! ## Error Handling
//! - **External crate Result**: `ok_or_return_null!(result)` → uses From trait automatically
//! - **cimpl::Error Result**: `ok_or_return_null!(result)` → used directly
//!
//! ## Naming Pattern
//! All macros follow: `action_or_return_<what>`
//! - `_null`: Returns `NULL` pointer
//! - `_int`: Returns `-1`
//! - `_zero`: Returns `0`  
//! - `_false`: Returns `false`
//!
//! # Type Mapping Guide
//!
//! | Rust Type              | C receives      | Macro to use                      | Example |
//! |------------------------|-----------------|-----------------------------------|---------|
//! | `*mut T` (from C)      | -               | `deref_or_return_null!(ptr, T)`   | Getting object from C |
//! | `*const c_char` (from C)| -              | `cstr_or_return_null!(s)`         | Getting string from C |
//! | `*const c_uchar` + len | -               | `bytes_or_return_null!(p, len, "name")` | Getting byte array from C |
//! | `Result<T, ExtErr>`    | pointer/int     | `ok_or_return_null!(r)`           | External crate errors (From trait) |
//! | `Result<T, cimpl::Err>`| pointer/int     | `ok_or_return_null!(r)`           | Internal validation |
//! | `Option<T>` custom     | pointer/int     | `some_or_return_null!(o, err)`    | Specific error needed |
//! | `T` (owned)            | `*mut T`        | `box_tracked!(value)`             | Returning new object |
//! | `String`               | `*mut c_char`   | `to_c_string(s)`                  | Returning string |
//! | `Option<String>`       | `*mut c_char`   | `option_to_c_string!(opt)`        | Optional string |
//!
//! # Common FFI Function Patterns
//!
//! ## Pattern 1: Constructor (returns new object)
//! ```rust,ignore
//! #[no_mangle]
//! pub extern "C" fn thing_new(value: i32) -> *mut Thing {
//!     let thing = some_or_return_other_null!(
//!         Thing::try_new(value),
//!         "Invalid value"
//!     );
//!     box_tracked!(thing)
//! }
//! ```
//!
//! ## Pattern 2: Parser (external crate Result with centralized mapping)
//! ```rust,ignore
//! // 1. Define error code enum
//! #[repr(i32)]
//! pub enum UuidError {
//!     ParseError = 100,
//! }
//!
//! // 2. Implement From trait (centralized mapping!)
//! impl From<uuid::Error> for cimpl::Error {
//!     fn from(e: uuid::Error) -> Self {
//!         cimpl::Error::new(
//!             UuidError::ParseError as i32,
//!             format!("ParseError: {}", e)
//!         )
//!     }
//! }
//!
//! // 3. Use in FFI (automatic conversion via From!)
//! #[no_mangle]
//! pub extern "C" fn uuid_parse(s: *const c_char) -> *mut Uuid {
//!     let s_str = cstr_or_return_null!(s);
//!     let uuid = ok_or_return_null!(Uuid::from_str(&s_str));
//!     box_tracked!(uuid)
//! }
//! ```
//!
//! ## Pattern 3: Method (operates on object)
//! ```rust,ignore
//! #[no_mangle]
//! pub extern "C" fn thing_add(thing: *mut Thing, value: i32) -> i32 {
//!     let obj = deref_or_return_int!(thing, Thing);
//!     obj.add(value)
//! }
//! ```
//!
//! ## Pattern 4: Method with validation (Option)
//! ```rust,ignore
//! #[no_mangle]
//! pub extern "C" fn date_add_days(date: *mut Date, days: i64) -> *mut Date {
//!     let obj = deref_or_return_null!(date, Date);
//!     let new_date = some_or_return_other_null!(
//!         obj.checked_add_days(days),
//!         "Date overflow"
//!     );
//!     box_tracked!(new_date)
//! }
//! ```

// Re-export types/functions that macros need
#[doc(hidden)]
#[allow(unused_imports)]
// May not be directly used but needed for macro expansion
//pub use crate::utils::validate_pointer;
//
// ============================================================================
// Pointer Management Macros
// ============================================================================
//
// These macros follow a consistent naming pattern:
// - deref_or_return_*: Validate and return reference immediately
// - deref_mut_or_return_*: Same as above, but mutable
//
// All variants support the standard suffixes:
// - _null: Returns NULL on error
// - _neg: Returns -1 on error
// - _zero: Returns 0 on error
// - _false: Returns false on error
// - (base): Custom return value
//
// ----------------------------------------------------------------------------
// Deref Macros - Return reference immediately
// ----------------------------------------------------------------------------
/// Validate pointer and dereference immutably, returning reference
/// Returns early with custom value on error
///
/// # Examples
/// ```rust,ignore
/// let value = deref_or_return!(ptr, Type, -1);
/// ```
#[macro_export]
macro_rules! deref_or_return {
    ($ptr:expr, $type:ty, $err_val:expr) => {{
        $crate::ptr_or_return!($ptr, $err_val);
        match $crate::validate_pointer::<$type>($ptr) {
            Ok(()) => unsafe { &*($ptr as *const $type) },
            Err(e) => {
                $crate::CimplError::from(e).set_last();
                return $err_val;
            }
        }
    }};
}

/// Validate pointer and dereference immutably, returning reference
/// Returns NULL on error
/// # Examples
/// ```rust,ignore
/// let value = deref_or_return_null!(ptr, Type);
/// ```
#[macro_export]
macro_rules! deref_or_return_null {
    ($ptr:expr, $type:ty) => {{
        $crate::deref_or_return!($ptr, $type, std::ptr::null_mut())
    }};
}

/// Validate pointer and dereference immutably, returning reference
/// Returns -1 on error
#[macro_export]
macro_rules! deref_or_return_int {
    ($ptr:expr, $type:ty) => {{
        $crate::deref_or_return!($ptr, $type, -1)
    }};
}

/// Validate pointer and dereference immutably, returning reference
/// Returns 0 on error
#[macro_export]
macro_rules! deref_or_return_zero {
    ($ptr:expr, $type:ty) => {{
        $crate::deref_or_return!($ptr, $type, 0)
    }};
}

/// Validate pointer and dereference immutably, returning reference
/// Returns false on error
#[macro_export]
macro_rules! deref_or_return_false {
    ($ptr:expr, $type:ty) => {{
        $crate::deref_or_return!($ptr, $type, false)
    }};
}

/// Validate pointer and dereference mutably, returning reference
/// Returns early with custom value on error
#[macro_export]
macro_rules! deref_mut_or_return {
    ($ptr:expr, $type:ty, $err_val:expr) => {{
        $crate::ptr_or_return!($ptr, $err_val);
        match $crate::validate_pointer::<$type>($ptr) {
            Ok(()) => unsafe { &mut *($ptr as *mut $type) },
            Err(e) => {
                $crate::CimplError::from(e).set_last();
                return $err_val;
            }
        }
    }};
}

/// Validate pointer and dereference mutably, returning reference
/// Returns NULL on error
#[macro_export]
macro_rules! deref_mut_or_return_null {
    ($ptr:expr, $type:ty) => {{
        $crate::deref_mut_or_return!($ptr, $type, std::ptr::null_mut())
    }};
}

/// Validate pointer and dereference mutably, returning reference
/// Returns -1 on error
#[macro_export]
macro_rules! deref_mut_or_return_int {
    ($ptr:expr, $type:ty) => {{
        $crate::deref_mut_or_return!($ptr, $type, -1)
    }};
}

/// Create a Box-wrapped pointer and track it
/// Returns the raw pointer
#[macro_export]
macro_rules! box_tracked {
    ($expr:expr) => {{
        let obj = $expr;
        let ptr = Box::into_raw(Box::new(obj));
        $crate::track_box(ptr)
    }};
}

/// Create an Arc-wrapped pointer and track it
/// Returns the raw pointer
#[macro_export]
macro_rules! arc_tracked {
    ($expr:expr) => {{
        let obj = $expr;
        let ptr = Arc::into_raw(Arc::new(obj)) as *mut _;
        $crate::track_arc(ptr)
    }};
}

/// Maximum length for C strings when using bounded conversion (64KB)
pub const MAX_CSTRING_LEN: usize = 65536;

/// Convert C string with bounded length check or early-return with error value
/// Uses a safe bounded approach to prevent reading unbounded memory.
/// Maximum string length is MAX_CSTRING_LEN (64KB).
#[macro_export]
macro_rules! cstr_or_return {
    ($ptr:expr, $err_val:expr) => {{
        let ptr = $ptr;
        if ptr.is_null() {
            $crate::CimplError::null_parameter(stringify!($ptr)).set_last();
            return $err_val;
        } else {
            // SAFETY: We create a bounded slice up to MAX_CSTRING_LEN.
            // Caller must ensure ptr is valid for reading and points to a
            // null-terminated string within MAX_CSTRING_LEN bytes.
            let bytes = unsafe {
                std::slice::from_raw_parts(ptr as *const u8, $crate::macros::MAX_CSTRING_LEN)
            };
            match std::ffi::CStr::from_bytes_until_nul(bytes) {
                Ok(cstr) => cstr.to_string_lossy().into_owned(),
                Err(_) => {
                    $crate::CimplError::string_too_long(stringify!($ptr)).set_last();
                    return $err_val;
                }
            }
        }
    }};
}

/// Convert C string with custom length limit or early-return with error value
/// Allows specifying a custom maximum length for the string.
#[macro_export]
macro_rules! cstr_or_return_with_limit {
    ($ptr:expr, $max_len:expr, $err_val:expr) => {{
        let ptr = $ptr;
        let max_len = $max_len;
        if ptr.is_null() {
            $crate::cimpl_error::null_parameter(stringify!($ptr)).set_last();
            return $err_val;
        } else {
            // SAFETY: We create a bounded slice up to max_len.
            // Caller must ensure ptr is valid for reading and points to a
            // null-terminated string within max_len bytes.
            let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, max_len) };
            match std::ffi::CStr::from_bytes_until_nul(bytes) {
                Ok(cstr) => cstr.to_string_lossy().into_owned(),
                Err(_) => {
                    $crate::cimpl_error::string_too_long(stringify!($ptr).to_string());
                    return $err_val;
                }
            }
        }
    }};
}

/// Handle Result or early-return with error value
///
/// This macro handles Result types using standard Rust From/Into conversion:
/// - External errors are automatically converted via From trait
/// - cimpl::Error is used directly
///
/// # Examples
///
/// ```rust,ignore
/// // External error - automatically converted via From<uuid::Error>
/// let uuid = ok_or_return!(Uuid::from_str(&s), |v| v, std::ptr::null_mut());
///
/// // With cimpl::Error
/// let data = ok_or_return!(some_operation(), |v| v, std::ptr::null_mut());
/// ```
#[macro_export]
macro_rules! ok_or_return {
    ($result:expr, $transform:expr, $err_val:expr) => {
        match $result {
            Ok(value) => $transform(value),
            Err(e) => {
                $crate::CimplError::from(e).set_last();
                return $err_val;
            }
        }
    };
}

// ============================================================================
// Named Shortcuts (self-documenting for common error values)
// ============================================================================

/// Handle Result, early-return with -1 (negative) on error
///
/// Uses From trait for automatic error conversion.
#[macro_export]
macro_rules! ok_or_return_int {
    ($result:expr) => {
        $crate::ok_or_return!($result, |v| v, -1)
    };
}

/// Handle Result, early-return with null on error
///
/// Uses From trait for automatic error conversion.
///
/// # Examples
///
/// ```rust,ignore
/// // Automatically converts external error via From trait
/// let uuid = ok_or_return_null!(Uuid::from_str(&s));
///
/// // Works with cimpl::Error too
/// let data = ok_or_return_null!(validate_something());
/// ```
#[macro_export]
macro_rules! ok_or_return_null {
    ($result:expr) => {
        $crate::ok_or_return!($result, |v| v, std::ptr::null_mut())
    };
}

/// Handle Result, early-return with 0 on error
///
/// Uses From trait for automatic error conversion.
#[macro_export]
macro_rules! ok_or_return_zero {
    ($result:expr) => {
        $crate::ok_or_return!($result, |v| v, 0)
    };
}

/// Handle Result, early-return with false on error
///
/// Uses From trait for automatic error conversion.
#[macro_export]
macro_rules! ok_or_return_false {
    ($result:expr) => {
        $crate::ok_or_return!($result, |v| v, false)
    };
}

// ============================================================================
// Option Handling Macros
// ============================================================================
//
// These macros convert Option<T> to FFI-friendly error returns.
// Useful for Rust APIs that return Option instead of Result.

/// Handle Option, early-return with custom value if None
///
/// Takes a cimpl::Error to set when the option is None.
///
/// # Examples
///
/// ```rust,ignore
/// // With Error::Other
/// let date = some_or_return!(
///     NaiveDate::from_ymd_opt(2024, 1, 20),
///     Error::Other("Invalid date".to_string()),
///     std::ptr::null_mut()
/// );
///
/// // With different error type
/// let handle = some_or_return!(
///     get_handle(id),
///     Error::InvalidHandle(id),
///     -1
/// );
/// ```
#[macro_export]
macro_rules! some_or_return {
    ($option:expr, $error:expr, $err_val:expr) => {
        match $option {
            Some(value) => value,
            None => {
                $error.set_last();
                return $err_val;
            }
        }
    };
}

/// Handle Option, early-return with NULL if None
///
/// Takes a cimpl::Error to set when the option is None.
///
/// # Examples
///
/// ```rust,ignore
/// let date = some_or_return_null!(
///     NaiveDate::from_ymd_opt(2024, 1, 20),
///     Error::Other("Invalid date".to_string())
/// );
/// ```
#[macro_export]
macro_rules! some_or_return_null {
    ($option:expr, $error:expr) => {
        $crate::some_or_return!($option, $error, std::ptr::null_mut())
    };
}

/// Handle Option, early-return with -1 if None
///
/// Takes a cimpl::Error to set when the option is None.
#[macro_export]
macro_rules! some_or_return_int {
    ($option:expr, $error:expr) => {
        $crate::some_or_return!($option, $error, -1)
    };
}

/// Handle Option, early-return with 0 if None
///
/// Takes a cimpl::Error to set when the option is None.
#[macro_export]
macro_rules! some_or_return_zero {
    ($option:expr, $error:expr) => {
        $crate::some_or_return!($option, $error, 0)
    };
}

/// Handle Option, early-return with false if None
///
/// Takes a cimpl::Error to set when the option is None.
#[macro_export]
macro_rules! some_or_return_false {
    ($option:expr, $error:expr) => {
        $crate::some_or_return!($option, $error, false)
    };
}

/// Check pointer not null or early-return with error value
#[macro_export]
macro_rules! ptr_or_return {
    ($ptr:expr, $err_val:expr) => {
        if $ptr.is_null() {
            $crate::CimplError::null_parameter(stringify!($ptr)).set_last();
            return $err_val;
        }
    };
}

/// If the expression is null, set the last error and return null.
#[macro_export]
macro_rules! ptr_or_return_null {
    ($ptr : expr) => {
        $crate::ptr_or_return!($ptr, std::ptr::null_mut())
    };
}

/// If the expression is null, set the last error and return -1.
#[macro_export]
macro_rules! ptr_or_return_int {
    ($ptr : expr) => {
        $crate::ptr_or_return!($ptr, -1)
    };
}

/// If the expression is null, set the last error and return std::ptr::null_mut().
#[macro_export]
macro_rules! cstr_or_return_null {
    ($ptr : expr) => {
        $crate::cstr_or_return!($ptr, std::ptr::null_mut())
    };
}

// Internal routine to convert a *const c_char to a rust String or return a -1 int error.
#[macro_export]
macro_rules! cstr_or_return_int {
    ($ptr : expr) => {
        $crate::cstr_or_return!($ptr, -1)
    };
}

/// Convert a *const c_char to `Option<String>`.
/// Returns None if the pointer is null.
/// Returns `Some(String)` if the pointer is not null.
/// Returns None if the string is too long.
/// # Examples
/// ```rust,ignore
/// let string = cstr_option!(ptr);
/// ```
#[macro_export]
macro_rules! cstr_option {
    ($ptr : expr) => {{
        let ptr = $ptr;
        if ptr.is_null() {
            None
        } else {
            // SAFETY: We create a bounded slice up to MAX_CSTRING_LEN.
            // Caller must ensure ptr is valid for reading and points to a
            // null-terminated string within MAX_CSTRING_LEN bytes.
            let bytes = unsafe {
                std::slice::from_raw_parts(ptr as *const u8, $crate::macros::MAX_CSTRING_LEN)
            };
            match std::ffi::CStr::from_bytes_until_nul(bytes) {
                Ok(cstr) => Some(cstr.to_string_lossy().into_owned()),
                Err(_) => {
                    $crate::CimplError::string_too_long(stringify!($ptr)).set_last();
                    None
                }
            }
        }
    }};
}

/// Converts an `Option<String>` to a C string pointer.
/// Returns `null_mut()` if the Option is None.
///
/// This is commonly used for FFI functions that return optional strings,
/// such as error messages that may or may not be present.
///
/// # Example
/// ```rust,ignore
/// #[no_mangle]
/// pub extern "C" fn get_error_message() -> *mut c_char {
///     option_to_c_string!(Error::last_message())
/// }
/// ```
#[macro_export]
macro_rules! option_to_c_string {
    ($opt:expr) => {
        match $opt {
            Some(msg) => $crate::to_c_string(msg.to_string()),
            None => std::ptr::null_mut(),
        }
    };
}

// ============================================================================
// Byte Array Validation Macros
// ============================================================================

/// Validate and convert raw C byte array to safe slice, returning early on error.
///
/// This macro combines null pointer checking with bounds validation using
/// `safe_slice_from_raw_parts`. It's specifically for byte arrays (`*const c_uchar`)
/// passed from C with an associated length.
///
/// # Examples
///
/// ```rust,ignore
/// #[no_mangle]
/// pub unsafe extern "C" fn process_data(
///     data: *const c_uchar,
///     len: usize
/// ) -> *mut Result {
///     let bytes = bytes_or_return_null!(data, len, "data");
///     // bytes is now a safe &[u8]
///     let result = process(bytes);
///     box_tracked!(result)
/// }
/// ```
#[macro_export]
macro_rules! bytes_or_return {
    ($ptr:expr, $len:expr, $name:expr, $err_val:expr) => {{
        match $crate::safe_slice_from_raw_parts($ptr, $len, $name) {
            Ok(slice) => slice,
            Err(err) => {
                $crate::CimplError::from(err).set_last();
                return $err_val;
            }
        }
    }};
}

/// Validate and convert raw C byte array to safe slice, return NULL on error.
#[macro_export]
macro_rules! bytes_or_return_null {
    ($ptr:expr, $len:expr, $name:expr) => {{
        $crate::bytes_or_return!($ptr, $len, $name, std::ptr::null_mut())
    }};
}

/// Validate and convert raw C byte array to safe slice, return -1 on error.
#[macro_export]
macro_rules! bytes_or_return_int {
    ($ptr:expr, $len:expr, $name:expr) => {{
        $crate::bytes_or_return!($ptr, $len, $name, -1)
    }};
}

/// Free a pointer that was allocated by cimpl.
///
/// This is a convenience macro wrapper around `cimpl_free` (see [`crate::cimpl::utils::cimpl_free`]).
///
/// # Returns
/// - `0` on success
/// - `-1` on error (see [`crate::cimpl::utils::cimpl_free`] for details)
///
/// # Error Handling
///
/// On error, the error is set via [`crate::CimplError::set_last`] and can be retrieved
/// using C2PA error functions. In test mode, errors are also printed to stderr.
///
/// **Best Practice**: Check the return value in production code:
/// ```rust,ignore
/// if cimpl_free!(ptr) != 0 {
///     // Handle error
/// }
/// ```
///
/// # Examples
/// ```rust,ignore
/// let ptr = box_tracked!(MyStruct::new());
/// // ... use ptr ...
/// cimpl_free!(ptr); // Returns 0 on success, -1 on error
/// ```
#[macro_export]
macro_rules! cimpl_free {
    ($ptr:expr) => {
        $crate::cimpl_free($ptr as *mut _)
    };
}
