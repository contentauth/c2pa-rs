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

// OpenSSL code is not re-entrant. Use this to guard against race conditions.
use std::sync::{Mutex, MutexGuard};

use crate::{Error, Result};
static FFI_MUTEX: Mutex<()> = Mutex::new(());

pub(crate) struct OpenSslMutex<'a> {
    // Dead code here is intentional. We don't need to read the () contents
    // of this guard. We only need to ensure that the guard is dropped when
    // this struct is dropped.
    #[allow(dead_code)]
    guard: MutexGuard<'a, ()>,
}

impl<'a> OpenSslMutex<'a> {
    /// Acquire a mutex on OpenSSL FFI code.
    ///
    /// WARNING: Calling code MUST NOT PANIC inside this function or
    /// anything called by it, even in test code. This will poison the FFI mutex
    /// and leave OpenSSL unusable for the remainder of the process lifetime.
    pub(crate) fn acquire() -> Result<Self> {
        // Useful for debugging.
        // eprintln!(
        //     "ACQUIRING FFI MUTEX at\n{}",
        //     std::backtrace::Backtrace::force_capture()
        // );

        match FFI_MUTEX.lock() {
            Ok(guard) => Ok(Self { guard }),
            Err(_) => Err(Error::OpenSslMutexError),
        }
    }
}

// Useful for debugging.
// impl<'a> Drop for OpenSslMutex<'a> {
//     fn drop(&mut self) {
//         eprintln!("Releasing FFI mutex\n\n\n");
//     }
// }
