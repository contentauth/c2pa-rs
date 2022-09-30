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

use wasm_bindgen::{prelude::*, JsCast, JsValue};
use web_sys::{SubtleCrypto, Window, WorkerGlobalScope};

use crate::{Error, Result};

// Adapted from gloo's implementation, since there doesn't seem to be a great way to do context checking using
// wasm-bindgen/web-sys without using something like `js_sys::eval`. References:
// - Issue: https://github.com/rustwasm/wasm-bindgen/issues/1046
// - Issue: https://github.com/rustwasm/wasm-bindgen/issues/2148#issuecomment-638606446
// - Code reference: https://git.io/J9crn

pub enum WindowOrWorker {
    Window(Window),
    Worker(WorkerGlobalScope),
}

impl WindowOrWorker {
    pub fn new() -> Result<Self> {
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
            Err(Error::WasmInvalidContext)
        }
    }

    pub fn subtle_crypto(&self) -> Result<SubtleCrypto> {
        let crypto = match self {
            Self::Window(window) => window.crypto(),
            Self::Worker(worker) => worker.crypto(),
        };
        let subtle_crypto = crypto.map_err(|_err| Error::WasmNoCrypto)?.subtle();

        Ok(subtle_crypto)
    }
}
