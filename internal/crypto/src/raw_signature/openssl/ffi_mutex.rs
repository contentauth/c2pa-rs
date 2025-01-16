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

use std::{
    error::Error,
    fmt,
    sync::{Mutex, MutexGuard},
};

static FFI_MUTEX: Mutex<()> = Mutex::new(());

/// This mutex must be used by all code that accesses OpenSSL native code since
/// the OpenSSL native code library is not re-entrant.
///
/// Failure to do so has been observed to lead to unexpected behavior including
/// process crashes.
pub struct OpenSslMutex<'a> {
    // The dead code bypass is intentional. We don't need to read the () contents of this guard. We
    // only need to ensure that the guard is dropped when this struct is dropped.
    #[allow(dead_code)]
    guard: MutexGuard<'a, ()>,
}

impl OpenSslMutex<'_> {
    /// Acquire a mutex on OpenSSL FFI code.
    ///
    /// WARNING: Calling code MUST NOT PANIC inside this function or
    /// anything called by it, even in test code. This will poison the FFI mutex
    /// and leave OpenSSL unusable for the remainder of the process lifetime.
    pub fn acquire() -> Result<Self, OpenSslMutexUnavailable> {
        // Useful for debugging.
        // eprintln!(
        //     "ACQUIRING FFI MUTEX at\n{}",
        //     std::backtrace::Backtrace::force_capture()
        // );

        match FFI_MUTEX.lock() {
            Ok(guard) => Ok(Self { guard }),
            Err(_) => Err(OpenSslMutexUnavailable {}),
        }
    }
}

// Useful for debugging.
// impl<'a> Drop for OpenSslMutex<'a> {
//     fn drop(&mut self) {
//         eprintln!("Releasing FFI mutex\n\n\n");
//     }
// }

/// Error returned when unable to acquire the OpenSSL native code mutex.
///
/// If this occurs, it's likely that a prior invocation of OpenSSL code panicked
/// while holding the mutex. When this happens, the OpenSSL native code mutex is
/// considered poisoned for the remainder of the process lifetime.
///
/// See [Rustnomicon: Poisoning] for more information.
///
/// [Rustnomicon: Poisoning]: https://doc.rust-lang.org/nomicon/poisoning.html
#[derive(Debug, Eq, PartialEq)]
pub struct OpenSslMutexUnavailable;

impl fmt::Display for OpenSslMutexUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unable to acquire OpenSSL native code mutex")
    }
}

impl Error for OpenSslMutexUnavailable {}
