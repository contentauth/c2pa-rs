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

//! FFI Handle Management System
//!
//! Provides a safe, thread-safe handle-based API for FFI bindings.
//! Instead of passing raw pointers across the FFI boundary, we store
//! Rust objects in a global map and return integer handles. This prevents
//! common FFI issues like double-free, use-after-free, and invalid pointers.

use std::{
    any::Any,
    collections::HashMap,
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

/// Helper for with_handle macro - needed for type inference
pub fn __with_handle_helper<T: Any + 'static, R, F>(handle: Handle, f: F) -> Result<R, Error>
where
    F: FnOnce(&T) -> R,
{
    let arc = get_handles().get(handle)?;
    let guard = match arc.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            eprintln!("WARNING: Mutex poisoned for handle {}, recovering", handle);
            poisoned.into_inner()
        }
    };
    let value = guard
        .downcast_ref::<T>()
        .ok_or(Error::WrongHandleType(handle))?;
    Ok(f(value))
}

/// Helper for with_handle_mut macro - needed for type inference
pub fn __with_handle_mut_helper<T: Any + 'static, R, F>(handle: Handle, f: F) -> Result<R, Error>
where
    F: FnOnce(&mut T) -> R,
{
    let arc = get_handles().get(handle)?;
    let mut guard = match arc.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            eprintln!("WARNING: Mutex poisoned for handle {}, recovering", handle);
            poisoned.into_inner()
        }
    };
    let value = guard
        .downcast_mut::<T>()
        .ok_or(Error::WrongHandleType(handle))?;
    Ok(f(value))
}
