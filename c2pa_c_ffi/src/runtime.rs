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

use std::sync::OnceLock;

use tokio::runtime::{Builder, Runtime};

// SAFETY: This library must not be dynamically unloaded (dlclose). The
// runtime's worker thread holds a reference into this static allocation;
// unloading the library while it is alive causes undefined behaviour.
// Callers must ensure the library lifetime exceeds all FFI call lifetimes.
//
// If the caller's thread already owns a tokio runtime (e.g. the host is a
// tokio application), any FFI function that calls block_on will panic with
// "Cannot start a runtime from within a runtime." There is no escape hatch
// from the C API; callers in that situation must invoke the FFI from a
// dedicated non-async thread.
static TOKIO_RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub(crate) fn get_runtime() -> &'static Runtime {
    TOKIO_RUNTIME.get_or_init(|| {
        // current_thread is sufficient: all call sites do a single block_on
        // and return. A multi-thread pool would spawn num_cpus threads
        // permanently for no benefit.
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("c2pa FFI: failed to initialise tokio runtime")
    })
}
