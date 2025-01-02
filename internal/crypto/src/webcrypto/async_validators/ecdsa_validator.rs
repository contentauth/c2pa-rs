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

use async_trait::async_trait;
use js_sys::{Array, ArrayBuffer, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::CryptoKey;

use crate::{
    raw_signature::{AsyncRawSignatureValidator, RawSignatureValidationError},
    webcrypto::WindowOrWorker,
};

/// An `EcdsaValidator` can validate raw signatures with one of the ECDSA
/// signature algorithms.
pub enum EcdsaValidator {
    /// ECDSA with SHA-256
    Es256,

    /// ECDSA with SHA-384
    Es384,

    // ECDSA with SHA-512
    Es512,
}

#[async_trait(?Send)]
impl AsyncRawSignatureValidator for EcdsaValidator {
    async fn validate_async(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        let context = WindowOrWorker::new();
        let subtle_crypto = context?.subtle_crypto()?;

        let (hash, named_curve) = match self {
            Self::Es256 => ("SHA-256", "P-256"),
            Self::Es384 => ("SHA-384", "P-384"),
            Self::Es512 => ("SHA-512", "P-521"),
        };

        let algorithm = EcKeyImportParams { hash, named_curve }
            .as_js_object()
            .map_err(|_err| {
                RawSignatureValidationError::InternalError(
                    "error creating JS object for EcKeyImportParams",
                )
            })?;

        let key_array_buf = data_as_array_buffer(public_key);

        let usages = Array::new();
        usages.push(&"verify".into());

        let promise = subtle_crypto
            .import_key_with_object("spki", &key_array_buf, &algorithm, true, &usages)
            .map_err(|_err| RawSignatureValidationError::InternalError("SPKI unavailable"))?;

        let crypto_key: CryptoKey = JsFuture::from(promise)
            .await
            .map_err(|_err| RawSignatureValidationError::InternalError("invalid ECDSA key"))?
            .into();

        let algorithm = EcdsaParams(hash).as_js_object().map_err(|_err| {
            RawSignatureValidationError::InternalError("error creating JS object for EcdsaParams")
        })?;

        let promise = subtle_crypto
            .verify_with_object_and_buffer_source_and_buffer_source(
                &algorithm,
                &crypto_key,
                &data_as_array_buffer(&sig),
                &data_as_array_buffer(&data),
            )
            .map_err(|_err| {
                RawSignatureValidationError::InternalError("unable to invoke SubtleCrypto verifier")
            })?;

        let verified: JsValue = JsFuture::from(promise)
            .await
            .map_err(|_err| {
                RawSignatureValidationError::InternalError(
                    "error creating JS future from SubtleCrypto promise",
                )
            })?
            .into();

        if verified.is_truthy() {
            Ok(())
        } else {
            Err(RawSignatureValidationError::SignatureMismatch)
        }
    }
}

struct EcKeyImportParams {
    named_curve: &'static str,
    hash: &'static str,
}

impl EcKeyImportParams {
    pub fn as_js_object(&self) -> Result<Object, JsValue> {
        let obj = Object::new();
        Reflect::set(&obj, &"name".into(), &"ECDSA".into())?;
        Reflect::set(&obj, &"namedCurve".into(), &self.named_curve.into())?;

        let inner_obj = Object::new();
        Reflect::set(&inner_obj, &"name".into(), &self.hash.into())?;
        Reflect::set(&obj, &"hash".into(), &inner_obj)?;

        Ok(obj)
    }
}

struct EcdsaParams(&'static str);

impl EcdsaParams {
    fn as_js_object(&self) -> Result<Object, JsValue> {
        let obj = Object::new();
        Reflect::set(&obj, &"name".into(), &"ECDSA".into())?;

        let inner_obj = Object::new();
        Reflect::set(&inner_obj, &"name".into(), &self.0.into())?;

        Reflect::set(&obj, &"hash".into(), &inner_obj)?;

        Ok(obj)
    }
}

fn data_as_array_buffer(data: &[u8]) -> ArrayBuffer {
    let typed_array = Uint8Array::new_with_length(data.len() as u32);
    typed_array.copy_from(data);
    typed_array.buffer()
}
