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

//! FFI Utilities
//!
//! Provides utilities for safe FFI bindings, including:
//! - Handle-based API: Thread-safe handle management system
//! - Allocation tracking: Prevents double-free of raw pointers
//! - Buffer safety: Validates buffer sizes and pointer arithmetic

use std::{
    any::TypeId,
    collections::HashMap,
    os::raw::c_uchar,
    sync::{Arc, Mutex},
};

use crate::{cimpl::cimpl_error::CimplError, error::Error};

// ============================================================================
// Pointer Registry - Tracks pointers with their cleanup functions
// ============================================================================

type CleanupFn = Box<dyn FnMut() + Send>;

/// Registry that tracks pointers allocated from Rust and passed to C.
/// Each pointer is associated with its type and a cleanup function,
/// enabling type validation and universal freeing via `cimpl_free()`.
pub struct PointerRegistry {
    tracked: Mutex<HashMap<usize, (TypeId, CleanupFn)>>,
}

impl PointerRegistry {
    fn new() -> Self {
        Self {
            tracked: Mutex::new(HashMap::new()),
        }
    }

    /// Track a pointer with its type and cleanup function
    fn track(&self, ptr: usize, type_id: TypeId, cleanup: CleanupFn) {
        if ptr != 0 {
            self.tracked.lock().unwrap().insert(ptr, (type_id, cleanup));
        }
    }

    /// Validate that a pointer is tracked and has the expected type
    pub fn validate(&self, ptr: usize, expected_type: TypeId) -> Result<(), Error> {
        if ptr == 0 {
            return Err(Error::from(CimplError::null_parameter("pointer")));
        }

        let tracked = self.tracked.lock().unwrap();
        match tracked.get(&ptr) {
            Some((actual_type, _)) if *actual_type == expected_type => Ok(()),
            Some(_) => Err(Error::from(CimplError::wrong_handle_type(ptr as u64))),
            None => Err(Error::from(CimplError::invalid_handle(ptr as u64))),
        }
    }

    /// Free a tracked pointer by calling its cleanup function
    pub fn free(&self, ptr: usize) -> Result<(), Error> {
        if ptr == 0 {
            return Ok(()); // NULL is always safe
        }

        let mut cleanup = {
            let mut tracked = self.tracked.lock().unwrap();
            match tracked.remove(&ptr) {
                Some((_, cleanup)) => cleanup,
                None => return Err(Error::from(CimplError::invalid_handle(ptr as u64))),
            }
        }; // Release lock before cleanup

        cleanup(); // Run the cleanup function
        Ok(())
    }

    /// Apply a builder chain to a boxed value without changing the pointer address
    ///
    /// This enables the Rust builder pattern (`self -> Self`) across FFI boundaries.
    /// The consuming builder methods are applied while keeping the pointer stable.
    ///
    /// # Arguments
    /// * `ptr` - Raw pointer to a Box-wrapped value
    /// * `f` - Closure that applies builder chain: `|value| value.with_x().with_y()`
    ///
    /// # Type Parameters
    /// * `T` - Must implement `Default` to allow temporary swapping
    /// * `F` - Closure that consumes and returns `T`
    ///
    /// # Returns
    /// * `Ok(())` if the chain was applied successfully
    /// * `Err` if the pointer is invalid or has wrong type
    ///
    /// # Safety
    /// This function is unsafe because it dereferences raw pointers. The caller must ensure:
    /// - `ptr` is a valid pointer created with `Box::into_raw()`
    /// - `ptr` has been tracked with `track_box()`
    /// - `ptr` is not accessed concurrently (use `apply_to_mutex` for multi-threaded cases)
    ///
    /// # Example
    /// ```ignore
    /// // C creates a builder
    /// let builder = Box::into_raw(Box::new(Builder::new()));
    /// track_box(builder);
    ///
    /// // C calls a with_ method
    /// unsafe {
    ///     get_registry().apply_to_box(builder, |b| b.with_setting("value"))?;
    /// }
    /// // Pointer address unchanged, contents updated
    /// ```
    pub unsafe fn apply_to_box<T, F>(&self, ptr: *mut T, f: F) -> Result<(), Error>
    where
        T: 'static + Default,
        F: FnOnce(T) -> T,
    {
        // Validate pointer is tracked with correct type
        self.validate(ptr as usize, TypeId::of::<T>())?;

        // Temporarily swap out the value (no clone needed!)
        let value = std::ptr::replace(ptr, T::default());

        // Apply the builder chain (consumes and returns value)
        let new_value = f(value);

        // Write back to same address (drops temporary default)
        ptr.write(new_value);

        Ok(())
    }

    /// Apply a builder chain to a mutex-wrapped value (thread-safe)
    ///
    /// Like `apply_to_box`, but for values wrapped in `Mutex<T>`. Use this when
    /// the same pointer may be accessed from multiple threads.
    ///
    /// # Arguments
    /// * `ptr` - Raw pointer to a Mutex-wrapped value
    /// * `f` - Closure that applies builder chain: `|value| value.with_x().with_y()`
    ///
    /// # Type Parameters
    /// * `T` - Must implement `Default` to allow temporary swapping
    /// * `F` - Closure that consumes and returns `T`
    ///
    /// # Returns
    /// * `Ok(())` if the chain was applied successfully
    /// * `Err` if the pointer is invalid, has wrong type, or mutex is poisoned
    ///
    /// # Safety
    /// This function is unsafe because it dereferences raw pointers. The caller must ensure:
    /// - `ptr` is a valid pointer to a `Mutex<T>`
    /// - `ptr` has been tracked with appropriate tracking function
    ///
    /// # Example
    /// ```ignore
    /// // For Arc<Mutex<Builder>> or Box<Mutex<Builder>>
    /// let builder = Arc::into_raw(Arc::new(Mutex::new(Builder::new())));
    /// track_arc_mutex(builder);
    ///
    /// // Thread-safe mutation
    /// unsafe {
    ///     get_registry().apply_to_mutex(builder, |b| b.with_setting("value"))?;
    /// }
    /// ```
    pub unsafe fn apply_to_mutex<T, F>(&self, ptr: *mut Mutex<T>, f: F) -> Result<(), Error>
    where
        T: 'static + Default,
        F: FnOnce(T) -> T,
    {
        // Validate pointer is tracked with correct type
        self.validate(ptr as usize, TypeId::of::<Mutex<T>>())?;

        // Get reference to mutex (pointer is valid per contract)
        let mutex = &*ptr;

        // Lock and swap - all atomic under the lock
        let mut guard = mutex.lock().unwrap();

        // Swap out the value
        let value = std::mem::take(&mut *guard);

        // Apply the builder chain
        let new_value = f(value);

        // Put back (still holding lock)
        *guard = new_value;

        Ok(())
    }
}

impl Drop for PointerRegistry {
    fn drop(&mut self) {
        let tracked = self.tracked.lock().unwrap();
        if !tracked.is_empty() {
            eprintln!(
                "\n⚠️  WARNING: {} pointer(s) were not freed at shutdown!",
                tracked.len()
            );
            eprintln!("This indicates C code did not properly free all allocated pointers.");
            eprintln!("Each pointer should be freed exactly once with cimpl_free().\n");
        }
    }
}

/// Get the global pointer registry
pub(crate) fn get_registry() -> &'static PointerRegistry {
    use std::sync::OnceLock;
    static REGISTRY: OnceLock<PointerRegistry> = OnceLock::new();
    REGISTRY.get_or_init(PointerRegistry::new)
}

// ============================================================================
// Tracking Functions for Different Wrapper Types
// ============================================================================

/// Track a Box-wrapped pointer
///
/// Use this when you allocate with `Box::into_raw()`.
/// The pointer will be freed with `Box::from_raw()` when `cimpl_free()` is called.
///
/// # Returns
/// Returns the same pointer for convenient chaining
///
/// # Example
/// ```ignore
/// let ptr = track_box(Box::into_raw(Box::new(value)));
/// ```
pub fn track_box<T: 'static>(ptr: *mut T) -> *mut T {
    let ptr_val = ptr as usize; // Store as usize to make it Send
    let cleanup = move || unsafe {
        drop(Box::from_raw(ptr_val as *mut T));
    };
    get_registry().track(ptr as usize, TypeId::of::<T>(), Box::new(cleanup));
    ptr
}

/// Track an Arc-wrapped pointer
///
/// Use this when you allocate with `Arc::into_raw()`.
/// The pointer will be freed with `Arc::from_raw()` when `cimpl_free()` is called.
///
/// # Returns
/// Returns the same pointer for convenient chaining
///
/// # Example
/// ```ignore
/// let ptr = track_arc(Arc::into_raw(Arc::new(value)));
/// ```
pub fn track_arc<T: 'static>(ptr: *mut T) -> *mut T {
    let ptr_val = ptr as usize; // Store as usize to make it Send
    let cleanup = move || unsafe {
        drop(Arc::from_raw(ptr_val as *const T));
    };
    get_registry().track(ptr as usize, TypeId::of::<T>(), Box::new(cleanup));
    ptr
}

/// Track an Arc<Mutex<T>>-wrapped pointer
///
/// Use this when you allocate with `Arc::into_raw(Arc::new(Mutex::new(value)))`.
/// The pointer will be freed with `Arc::from_raw()` when `cimpl_free()` is called.
///
/// # Returns
/// Returns the same pointer for convenient chaining
///
/// # Example
/// ```ignore
/// let ptr = track_arc_mutex(Arc::into_raw(Arc::new(Mutex::new(value))));
/// ```
pub fn track_arc_mutex<T: 'static>(ptr: *mut Mutex<T>) -> *mut Mutex<T> {
    let ptr_val = ptr as usize; // Store as usize to make it Send
    let cleanup = move || unsafe {
        drop(Arc::from_raw(ptr_val as *const Mutex<T>));
    };
    get_registry().track(ptr as usize, TypeId::of::<Mutex<T>>(), Box::new(cleanup));
    ptr
}

/// Validate that a pointer is tracked and has the expected type
pub fn validate_pointer<T: 'static>(ptr: *mut T) -> Result<(), Error> {
    get_registry().validate(ptr as usize, TypeId::of::<T>())
}

/// Universal free function for any tracked pointer
///
/// This is the universal free function exposed to C. It works for ANY pointer
/// that was allocated and tracked through cimpl, regardless of the wrapper type
/// (Box, Arc, etc.) or the underlying Rust type.
///
/// # Returns
/// - 0 on success
/// - -1 if pointer was not tracked (invalid or double-free)
///
/// # Safety
/// Safe to call with NULL (returns 0).
/// Safe to call with any tracked pointer.
/// DO NOT call on untracked pointers.
///
/// # Example (C)
/// ```c
/// MyString* str = mystring_create("hello");
/// char* value = mystring_get_value(str);
///
/// cimpl_free(value);  // Free the returned string
/// cimpl_free(str);    // Free the MyString - same function!
/// ```
#[no_mangle]
pub extern "C" fn cimpl_free(ptr: *mut std::ffi::c_void) -> i32 {
    match get_registry().free(ptr as usize) {
        Ok(()) => 0,
        Err(e) => {
            CimplError::from(e).set_last();
            -1
        }
    }
}

// ============================================================================
// Buffer Safety Utilities
// ============================================================================

/// Validates that a buffer size is within safe bounds and doesn't cause integer overflow
/// when used with pointer arithmetic.
///
/// # Arguments
/// * `size` - Size to validate
/// * `ptr` - Pointer to validate against (for address space checks)
///
/// # Returns
/// * `true` if the size is safe to use
/// * `false` if the size would cause integer overflow
///
/// # Safety
/// Caller must ensure that `ptr` points to valid memory if not null.
/// This function performs pointer arithmetic with `ptr.add(size)` which requires
/// that the pointer and size are valid for the memory region being checked.
pub unsafe fn is_safe_buffer_size(size: usize, ptr: *const c_uchar) -> bool {
    // Combined checks for early return - improves branch prediction
    if size == 0 || size > isize::MAX as usize {
        return false;
    }

    // Check if the buffer would extend beyond address space to fail fast
    if !ptr.is_null() {
        let end_ptr = ptr.add(size);
        if end_ptr < ptr {
            return false; // Wrapped around
        }
    }

    true
}

/// Creates a safe slice from raw parts with bounds validation
///
/// # Arguments
/// * `ptr` - Pointer to the data
/// * `len` - Length of the data
/// * `param_name` - Name of the parameter for error reporting
///
/// # Returns
/// * `Ok(slice)` if the slice is safe to create
/// * `Err(Error)` if bounds validation fails
///
/// # Safety
/// Caller must ensure that:
/// - `ptr` points to valid, initialized memory for at least `len` bytes
/// - The memory remains valid for the lifetime of the returned slice
/// - The memory is not mutated while the slice exists
/// - `len` does not exceed the actual size of the allocated memory
pub unsafe fn safe_slice_from_raw_parts(
    ptr: *const c_uchar,
    len: usize,
    param_name: &str,
) -> Result<&[u8], Error> {
    if ptr.is_null() {
        return Err(Error::from(CimplError::null_parameter(param_name)));
    }

    if !is_safe_buffer_size(len, ptr) {
        return Err(Error::from(CimplError::other(format!(
            "Buffer size {len} is invalid for parameter '{param_name}'",
        ))));
    }

    Ok(std::slice::from_raw_parts(ptr, len))
}

/// Converts a Rust String to a C string (*mut c_char)
///
/// The returned pointer is tracked for allocation safety and MUST be freed
/// by calling the appropriate free function (e.g., `c2pa_string_free`).
///
/// # Arguments
/// * `s` - The Rust String to convert
///
/// # Returns
/// * `*mut c_char` - Pointer to the C string, or null on error
///
/// # Safety
/// The returned pointer must be freed exactly once by C code
pub fn to_c_string(s: String) -> *mut std::os::raw::c_char {
    use std::ffi::CString;
    match CString::new(s) {
        Ok(c_str) => {
            let ptr = c_str.into_raw();
            let ptr_val = ptr as usize;
            get_registry().track(
                ptr_val,
                TypeId::of::<CString>(),
                Box::new(move || unsafe {
                    drop(CString::from_raw(ptr_val as *mut std::os::raw::c_char))
                }),
            );
            ptr
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Converts a `Vec <u8>` to a tracked C byte array pointer
///
/// The returned pointer is tracked for allocation safety and MUST be freed
/// by calling `free_c_bytes`.
///
/// # Arguments
/// * `bytes` - The byte vector to convert
///
/// # Returns
/// * `*const c_uchar` - Pointer to the byte array
///
/// # Safety
/// The returned pointer must be freed exactly once by calling `free_c_bytes`
pub fn to_c_bytes(bytes: Vec<u8>) -> *const c_uchar {
    let len = bytes.len();
    let ptr = Box::into_raw(bytes.into_boxed_slice()) as *const c_uchar;
    let ptr_val = ptr as usize;
    get_registry().track(
        ptr_val,
        TypeId::of::<Box<[u8]>>(),
        Box::new(move || {
            unsafe {
                // Reconstruct the slice with the original length
                drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                    ptr_val as *mut u8,
                    len,
                )))
            }
        }),
    );
    ptr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocation_tracking_double_free_string() {
        use std::ffi::CString;

        // Test that double-freeing a string is detected
        let test_string = CString::new("test allocation tracking").unwrap();
        let c_string = to_c_string(test_string.to_str().unwrap().to_string());
        assert!(!c_string.is_null());

        // First free should succeed
        let result1 = cimpl_free(c_string as *mut std::ffi::c_void);
        assert_eq!(result1, 0);

        // Second free should be detected and return error
        let result2 = cimpl_free(c_string as *mut std::ffi::c_void);
        assert_eq!(result2, -1);
    }

    #[test]
    fn test_to_c_string_basic() {
        // Test basic string conversion
        let rust_string = "Hello, C!".to_string();
        let c_string = to_c_string(rust_string);
        assert!(!c_string.is_null());

        // Clean up
        cimpl_free(c_string as *mut std::ffi::c_void);
    }

    #[test]
    fn test_to_c_bytes_basic() {
        // Test basic byte array conversion
        let bytes = vec![1, 2, 3, 4, 5];
        let ptr = to_c_bytes(bytes);
        assert!(!ptr.is_null());

        // Clean up
        cimpl_free(ptr as *mut std::ffi::c_void);
    }

    #[test]
    fn test_to_c_string_with_null_byte() {
        // Test that strings with embedded nulls return null
        let bad_string = "Hello\0World".to_string();
        let c_string = to_c_string(bad_string);
        assert!(c_string.is_null());
        // No need to free since it's null
    }
}
