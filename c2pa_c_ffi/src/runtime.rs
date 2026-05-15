// Copyright 2026 Adobe. All rights reserved.
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

use std::sync::{Arc, OnceLock};

use tokio::runtime::{Builder, Runtime};

// SAFETY: This library must not be dynamically unloaded (dlclose). The
// runtime's worker thread holds a reference into this static allocation;
// unloading the library while it is alive causes undefined behavior.
// Callers must ensure the library lifetime exceeds all FFI call lifetimes.
//
// If the caller's thread already owns a tokio runtime,
// call set_runtime() before the first FFI operation to get the existing runtime.
static TOKIO_RUNTIME: OnceLock<Arc<Runtime>> = OnceLock::new();

/// Creates a `runtime` as the FFI's shared tokio runtime.
///
/// Must be called before the first FFI operation that requires async execution.
/// Returns `Err(runtime)` if a runtime is already running (either by a prior
/// call to this function or by a lazy `get_runtime` call).
pub fn set_runtime(runtime: Arc<Runtime>) -> Result<(), Arc<Runtime>> {
    TOKIO_RUNTIME.set(runtime)
}

pub(crate) fn get_runtime() -> &'static Runtime {
    TOKIO_RUNTIME.get_or_init(|| {
        // FFI: current_thread is enough: FFI call sites do a block_on
        // and return.
        Arc::new(
            Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("c2pa FFI: failed to initialise tokio runtime"),
        )
    })
}
