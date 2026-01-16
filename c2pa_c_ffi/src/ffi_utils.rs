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
    any::Any,
    collections::HashMap,
    os::raw::c_uchar,
    sync::{atomic::AtomicU64, Arc, Mutex, RwLock},
};

use crate::error::Error;

// ============================================================================
// Handle Management System
// ============================================================================

pub type Handle = u64;
pub type HandleValue = Arc<Mutex<Box<dyn Any + Send>>>;

pub struct HandleMap {
    map: RwLock<HashMap<Handle, HandleValue>>,
    next_id: AtomicU64,
}

impl HandleMap {
    fn new() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1), // 0 = NULL
        }
    }

    /// Insert a value and return its handle
    pub fn insert<T: Any + Send + 'static>(&self, value: T) -> Handle {
        let handle = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut map = self.map.write().unwrap();
        map.insert(handle, Arc::new(Mutex::new(Box::new(value))));
        handle
    }

    /// Get an Arc to work with - avoids nested lock issues
    /// Returns the HandleValue which must be downcast by the caller
    pub fn get(&self, handle: Handle) -> Result<HandleValue, Error> {
        let map = self.map.read().unwrap();
        let arc = map
            .get(&handle)
            .ok_or(Error::InvalidHandle(handle))?
            .clone(); // Just increments Arc refcount - cheap!
        drop(map); // Release map lock immediately
        Ok(arc)
    }

    /// Remove and return a value
    pub fn remove<T: Any + 'static>(&self, handle: Handle) -> Result<T, Error> {
        let mut map = self.map.write().unwrap();
        let arc = map.remove(&handle).ok_or(Error::InvalidHandle(handle))?;
        drop(map); // Release write lock

        // Try to unwrap the Arc (will fail if anyone else holds a clone)
        let mutex =
            Arc::try_unwrap(arc).map_err(|_| Error::Other("Handle still in use".to_string()))?;

        let boxed = mutex.into_inner().unwrap();
        boxed
            .downcast::<T>()
            .map(|b| *b)
            .map_err(|_| Error::WrongHandleType(handle))
    }
}

impl Drop for HandleMap {
    fn drop(&mut self) {
        let map = self.map.read().unwrap();
        if !map.is_empty() {
            eprintln!(
                "\n⚠️  WARNING: {} handle(s) were not freed at shutdown!",
                map.len()
            );
            eprintln!("This indicates C code did not properly free all allocated handles.");
            eprintln!(
                "Each handle should be freed exactly once with the appropriate _free() function.\n"
            );
        }
    }
}

// Single global handle map - much simpler!
pub fn get_handles() -> &'static HandleMap {
    use std::sync::OnceLock;
    static HANDLES: OnceLock<HandleMap> = OnceLock::new();
    HANDLES.get_or_init(HandleMap::new)
}

/// Convert a typed pointer to a handle
pub fn ptr_to_handle<T>(ptr: *mut T) -> Handle {
    ptr as Handle
}

/// Convert a handle to a typed pointer
pub fn handle_to_ptr<T>(handle: Handle) -> *mut T {
    handle as *mut T
}

// ============================================================================
// Raw Pointer Allocation Tracking
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllocationType {
    String,
    ByteArray,
}

struct AllocationInfo {
    allocation_type: AllocationType,
    size: usize,
}

pub struct AllocationTracker {
    allocations: Mutex<HashMap<usize, AllocationInfo>>,
}

impl AllocationTracker {
    fn new() -> Self {
        Self {
            allocations: Mutex::new(HashMap::new()),
        }
    }

    /// Track a new allocation
    fn track(&self, ptr: *const u8, size: usize, allocation_type: AllocationType) {
        if !ptr.is_null() {
            let mut allocations = self.allocations.lock().unwrap();
            allocations.insert(
                ptr as usize,
                AllocationInfo {
                    allocation_type,
                    size,
                },
            );
        }
    }

    /// Untrack an allocation, returning true if it was tracked
    fn untrack(&self, ptr: *const u8) -> bool {
        if ptr.is_null() {
            return true; // NULL is always safe to "free"
        }
        let mut allocations = self.allocations.lock().unwrap();
        allocations.remove(&(ptr as usize)).is_some()
    }
}

impl Drop for AllocationTracker {
    fn drop(&mut self) {
        let allocations = self.allocations.lock().unwrap();
        if !allocations.is_empty() {
            let mut string_count = 0;
            let mut string_bytes = 0;
            let mut array_count = 0;
            let mut array_bytes = 0;

            for info in allocations.values() {
                match info.allocation_type {
                    AllocationType::String => {
                        string_count += 1;
                        string_bytes += info.size;
                    }
                    AllocationType::ByteArray => {
                        array_count += 1;
                        array_bytes += info.size;
                    }
                }
            }

            eprintln!(
                "\n⚠️  WARNING: {} raw allocation(s) were not freed at shutdown!",
                allocations.len()
            );
            if string_count > 0 {
                eprintln!(
                    "  - {} string(s) (approx. {} bytes)",
                    string_count, string_bytes
                );
            }
            if array_count > 0 {
                eprintln!(
                    "  - {} byte array(s) (approx. {} bytes)",
                    array_count, array_bytes
                );
            }
            eprintln!("This indicates C code did not properly free all allocated memory.\n");
        }
    }
}

// Single global allocation tracker
pub fn get_allocations() -> &'static AllocationTracker {
    use std::sync::OnceLock;
    static ALLOCATIONS: OnceLock<AllocationTracker> = OnceLock::new();
    ALLOCATIONS.get_or_init(AllocationTracker::new)
}

// Public API for tracking allocations
pub fn track_string_allocation(ptr: *const i8, len: usize) {
    get_allocations().track(ptr as *const u8, len, AllocationType::String);
}

pub fn track_bytes_allocation(ptr: *const u8, len: usize) {
    get_allocations().track(ptr, len, AllocationType::ByteArray);
}

pub fn untrack_allocation(ptr: *const u8) -> bool {
    get_allocations().untrack(ptr)
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
pub unsafe fn safe_slice_from_raw_parts(
    ptr: *const c_uchar,
    len: usize,
    param_name: &str,
) -> Result<&[u8], Error> {
    if ptr.is_null() {
        return Err(Error::NullParameter(param_name.to_string()));
    }

    if !is_safe_buffer_size(len, ptr) {
        return Err(Error::Other(format!(
            "Buffer size {len} is invalid for parameter '{param_name}'",
        )));
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
pub unsafe fn to_c_string(s: String) -> *mut std::os::raw::c_char {
    use std::ffi::CString;
    let len = s.len();
    match CString::new(s) {
        Ok(c_str) => {
            let ptr = c_str.into_raw();
            track_string_allocation(ptr, len + 1); // +1 for null terminator
            ptr
        }
        Err(_) => std::ptr::null_mut(),
    }
}
