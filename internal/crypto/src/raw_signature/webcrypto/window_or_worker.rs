// Copyright 2022 Adobe. All rights reserved.
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

#![allow(missing_docs)]

use thiserror::Error;
use wasm_bindgen::{prelude::*, JsCast, JsValue};
use web_sys::{Crypto, SubtleCrypto, Window, WorkerGlobalScope};

/// Adapted from gloo's implementation, since there doesn't seem to be a great
/// way to do context checking using `wasm-bindgen/web-sys` without using
/// something like `js_sys::eval`.
///
/// References:
///
/// - Issue: https://github.com/rustwasm/wasm-bindgen/issues/1046
/// - Issue: https://github.com/rustwasm/wasm-bindgen/issues/2148#issuecomment-638606446
/// - Code reference: https://git.io/J9crn
pub enum WindowOrWorker {
    Window(Window),
    Worker(WorkerGlobalScope),
}

impl WindowOrWorker {
    pub fn new() -> Result<Self, WasmCryptoError> {
        #[wasm_bindgen]
        extern "C" {
            type Global;

            #[wasm_bindgen(method, getter, js_name = Window)]
            fn window(this: &Global) -> JsValue;

            #[wasm_bindgen(method, getter, js_name = WorkerGlobalScope)]
            fn worker(this: &Global) -> JsValue;
        }

        let global: Global = js_sys::global().unchecked_into();

        if !global.window().is_undefined() {
            Ok(Self::Window(global.unchecked_into()))
        } else if !global.worker().is_undefined() {
            Ok(Self::Worker(global.unchecked_into()))
        } else {
            Err(WasmCryptoError::UnknownContext)
        }
    }

    pub fn crypto(&self) -> Result<Crypto, WasmCryptoError> {
        match self {
            Self::Window(window) => window.crypto(),
            Self::Worker(worker) => worker.crypto(),
        }
        .map_err(|_err| WasmCryptoError::NoCryptoAvailable)
    }

    pub fn subtle_crypto(&self) -> Result<SubtleCrypto, WasmCryptoError> {
        Ok(self.crypto()?.subtle())
    }
}

/// Error returned when cryptography libraries are unavailable.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum WasmCryptoError {
    /// Unknown context.
    #[error("could not find window or worker in global environment")]
    UnknownContext,

    /// Crypto library unavailable.
    #[error("window or worker's .crypto() method failed")]
    NoCryptoAvailable,
}
