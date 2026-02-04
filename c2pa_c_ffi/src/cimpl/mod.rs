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

//! # Cimpl - Simple C implementations from Rust
//!
//! A Rust library providing utilities and macros for creating safe, ergonomic C FFI bindings.
//!
//! ## Features
//!
//! - **Handle-based API**: Thread-safe handle management system for passing Rust objects to C
//! - **Allocation tracking**: Prevents double-free of raw pointers with automatic leak detection at shutdown
//! - **Buffer safety**: Validates buffer sizes and pointer arithmetic
//! - **FFI macros**: Ergonomic macros for null checks, string conversion, and error handling
//! - **Memory leak detection**: Automatically reports unfreed pointers when the program exits
//! - **Test-mode debugging**: Enhanced error reporting in test builds for memory management issues
//!
//! ## Memory Safety
//!
//! All pointers allocated via `box_tracked!` or `track_box` are tracked in a global registry.
//! When the program shuts down, any pointers that weren't freed are reported:
//!
//! ```text
//! ⚠️  WARNING: 3 pointer(s) were not freed at shutdown!
//! This indicates C code did not properly free all allocated pointers.
//! Each pointer should be freed exactly once with cimpl_free().
//! ```
//!
//! This helps catch memory leaks during development and testing. See the [`macros`] module
//! documentation for details on test-mode debugging features.
//!
//! ## Example
//!
//! ```rust,ignore
//! use cimpl::{cstr_or_return_null, to_c_string};
//!
//! #[no_mangle]
//! pub extern "C" fn process_string(
//!     input: *const std::os::raw::c_char,
//! ) -> *mut std::os::raw::c_char {
//!     // Convert C string to Rust String with automatic null check
//!     let rust_string = cstr_or_return_null!(input);
//!
//!     // Process the string
//!     let result = rust_string.to_uppercase();
//!
//!     // Convert back to C string (automatically tracked for memory safety)
//!     to_c_string(result)
//! }
//! ```

// Declare foundational modules first
pub mod cimpl_error;
pub mod utils;

// Then macros that depend on them
#[macro_use]
pub mod macros;

// Re-export internal utilities (for macro use only - not part of public API)
#[doc(hidden)]
pub use cimpl_error::CimplError;
#[doc(hidden)]
pub use utils::validate_pointer;
pub use utils::{
    cimpl_free, safe_slice_from_raw_parts, to_c_bytes, to_c_string, track_arc, track_arc_mutex,
    track_box,
};
