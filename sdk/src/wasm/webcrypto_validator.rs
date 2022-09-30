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

use std::convert::TryFrom;

use js_sys::{Array, ArrayBuffer, Object, Reflect, Uint8Array};
use rsa::{BigUint, PaddingScheme, PublicKey, RsaPublicKey};
use sha2::{Sha256, Sha384, Sha512};
use spki::SubjectPublicKeyInfo;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, SubtleCrypto};
use x509_parser::der_parser::ber::{parse_ber_sequence, BerObject};

use crate::{
    utils::hash_utils::hash_by_alg, wasm::context::WindowOrWorker, Error, Result, SigningAlg,
};

pub struct EcKeyImportParams {
    name: String,
    named_curve: String,
    hash: String,
}

impl EcKeyImportParams {
    pub fn new(name: &str, hash: &str, named_curve: &str) -> Self {
        EcKeyImportParams {
            name: name.to_owned(),
            named_curve: named_curve.to_owned(),
            hash: hash.to_owned(),
        }
    }

    pub fn as_js_object(&self) -> Object {
        let obj = Object::new();
        Reflect::set(&obj, &"name".into(), &self.name.clone().into()).expect("not valid name");
        Reflect::set(&obj, &"namedCurve".into(), &self.named_curve.clone().into())
            .expect("not valid name");

        let inner_obj = Object::new();
        Reflect::set(&inner_obj, &"name".into(), &self.hash.clone().into())
            .expect("not valid name");

        Reflect::set(&obj, &"hash".into(), &inner_obj).expect("not valid name");

        obj
    }
}

pub struct EcdsaParams {
    name: String,
    hash: String,
}

impl EcdsaParams {
    pub fn new(name: &str, hash: &str) -> Self {
        EcdsaParams {
            name: name.to_owned(),
            hash: hash.to_owned(),
        }
    }

    pub fn as_js_object(&self) -> Object {
        let obj = Object::new();
        Reflect::set(&obj, &"name".into(), &self.name.clone().into()).expect("not valid name");

        let inner_obj = Object::new();
        Reflect::set(&inner_obj, &"name".into(), &self.hash.clone().into())
            .expect("not valid name");

        Reflect::set(&obj, &"hash".into(), &inner_obj).expect("not valid name");

        obj
    }
}

fn data_as_array_buffer(data: &[u8]) -> ArrayBuffer {
    let typed_array = Uint8Array::new_with_length(data.len() as u32);
    typed_array.copy_from(data);
    typed_array.buffer()
}

async fn crypto_is_verified(
    subtle_crypto: &SubtleCrypto,
    alg: &Object,
    key: &CryptoKey,
    sig: &Object,
    data: &Object,
) -> Result<bool> {
    let promise = subtle_crypto
        .verify_with_object_and_buffer_source_and_buffer_source(alg, key, sig, data)
        .map_err(|_err| Error::WasmVerifier)?;
    let verified: JsValue = JsFuture::from(promise)
        .await
        .map_err(|_err| Error::WasmVerifier)?
        .into();
    let result = verified.is_truthy();
    web_sys::console::debug_2(&"verified".into(), &result.into());
    Ok(result)
}

// Conversion utility from num-bigint::BigUint (used by x509_parser)
// to num-bigint-dig::BigUint (used by rsa)
fn biguint_val(ber_object: &BerObject) -> BigUint {
    ber_object
        .as_biguint()
        .map(|x| x.to_u32_digits())
        .map(BigUint::new)
        .unwrap_or_default()
}

fn pss_padding_from_hash(hash: &str, salt_len: &u32) -> Result<PaddingScheme> {
    let salt_len = usize::try_from(salt_len.clone())
        .map_err(|err| Error::WasmRsaKeyImport(err.to_string()))?;
    let rng = rand::thread_rng();

    match hash {
        "SHA-256" => Ok(PaddingScheme::new_pss_with_salt::<Sha256, _>(rng, salt_len)),
        "SHA-384" => Ok(PaddingScheme::new_pss_with_salt::<Sha384, _>(rng, salt_len)),
        "SHA-512" => Ok(PaddingScheme::new_pss_with_salt::<Sha512, _>(rng, salt_len)),
        &_ => Err(Error::WasmRsaKeyImport(format!(
            "Invalid PSS hash supplied for padding: {}",
            hash
        ))),
    }
}

async fn async_validate(
    algo: String,
    hash: String,
    salt_len: u32,
    pkey: Vec<u8>,
    sig: Vec<u8>,
    data: Vec<u8>,
) -> Result<bool> {
    let context = WindowOrWorker::new();
    let subtle_crypto = context?.subtle_crypto()?;
    let sig_array_buf = data_as_array_buffer(&sig);
    let data_array_buf = data_as_array_buffer(&data);

    match algo.as_ref() {
        "RSA-PSS" => {
            let spki = SubjectPublicKeyInfo::try_from(pkey.as_ref())
                .map_err(|err| Error::WasmRsaKeyImport(err.to_string()))?;
            let (_, seq) = parse_ber_sequence(spki.subject_public_key)
                .map_err(|err| Error::WasmRsaKeyImport(err.to_string()))?;
            let hashed_data = hash_by_alg(&hash, &data, None);
            let modulus = biguint_val(&seq[0]);
            let exp = biguint_val(&seq[1]);
            let public_key = RsaPublicKey::new(modulus, exp)
                .map_err(|err| Error::WasmRsaKeyImport(err.to_string()))?;
            let padding = pss_padding_from_hash(&hash, &salt_len)?;
            let result = public_key.verify(padding, &hashed_data, &sig);

            match result {
                Ok(()) => Ok(true),
                Err(err) => {
                    web_sys::console::debug_2(
                        &"RSA-PSS validation failed:".into(),
                        &err.to_string().into(),
                    );
                    Ok(false)
                }
            }
        }
        "ECDSA" => {
            // Create Key
            let named_curve = match hash.as_ref() {
                "SHA-256" => "P-256".to_string(),
                "SHA-384" => "P-384".to_string(),
                "SHA-512" => "P-521".to_string(),
                _ => return Err(Error::UnsupportedType),
            };
            let mut algorithm = EcKeyImportParams::new(&algo, &hash, &named_curve).as_js_object();
            let key_array_buf = data_as_array_buffer(&pkey);
            let usages = Array::new();
            usages.push(&"verify".into());

            let promise = subtle_crypto
                .import_key_with_object("spki", &key_array_buf, &algorithm, true, &usages)
                .map_err(|_err| Error::WasmKey)?;
            let crypto_key: CryptoKey = JsFuture::from(promise).await.unwrap().into();
            web_sys::console::debug_2(&"CryptoKey".into(), &crypto_key);

            // Create verifier
            algorithm = EcdsaParams::new(&algo, &hash).as_js_object();
            crypto_is_verified(
                &subtle_crypto,
                &algorithm,
                &crypto_key,
                &sig_array_buf,
                &data_array_buf,
            )
            .await
        }
        _ => Err(Error::UnsupportedType),
    }
}

pub async fn validate_async(alg: SigningAlg, sig: &[u8], data: &[u8], pkey: &[u8]) -> Result<bool> {
    web_sys::console::debug_2(&"Validating with algorithm".into(), &alg.to_string().into());

    match alg {
        SigningAlg::Ps256 => {
            async_validate(
                "RSA-PSS".to_string(),
                "SHA-256".to_string(),
                32,
                pkey.to_vec(),
                sig.to_vec(),
                data.to_vec(),
            )
            .await
        }
        SigningAlg::Ps384 => {
            async_validate(
                "RSA-PSS".to_string(),
                "SHA-384".to_string(),
                48,
                pkey.to_vec(),
                sig.to_vec(),
                data.to_vec(),
            )
            .await
        }
        SigningAlg::Ps512 => {
            async_validate(
                "RSA-PSS".to_string(),
                "SHA-512".to_string(),
                64,
                pkey.to_vec(),
                sig.to_vec(),
                data.to_vec(),
            )
            .await
        }
        // "rs256" => {
        //     async_validate(
        //         "RSASSA-PKCS1-v1_5".to_string(),
        //         "SHA-256".to_string(),
        //         0,
        //         pkey.to_vec(),
        //         sig.to_vec(),
        //         data.to_vec(),
        //     )
        //     .await
        // }
        // "rs384" => {
        //     async_validate(
        //         "RSASSA-PKCS1-v1_5".to_string(),
        //         "SHA-384".to_string(),
        //         0,
        //         pkey.to_vec(),
        //         sig.to_vec(),
        //         data.to_vec(),
        //     )
        //     .await
        // }
        // "rs512" => {
        //     async_validate(
        //         "RSASSA-PKCS1-v1_5".to_string(),
        //         "SHA-512".to_string(),
        //         0,
        //         pkey.to_vec(),
        //         sig.to_vec(),
        //         data.to_vec(),
        //     )
        //     .await
        // }
        SigningAlg::Es256 => {
            async_validate(
                "ECDSA".to_string(),
                "SHA-256".to_string(),
                0,
                pkey.to_vec(),
                sig.to_vec(),
                data.to_vec(),
            )
            .await
        }
        SigningAlg::Es384 => {
            async_validate(
                "ECDSA".to_string(),
                "SHA-384".to_string(),
                0,
                pkey.to_vec(),
                sig.to_vec(),
                data.to_vec(),
            )
            .await
        }
        SigningAlg::Es512 => {
            async_validate(
                "ECDSA".to_string(),
                "SHA-512".to_string(),
                0,
                pkey.to_vec(),
                sig.to_vec(),
                data.to_vec(),
            )
            .await
        }
        // TODO: Can we cover Ed25519?
        _ => return Err(Error::UnsupportedType),
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    use super::*;
    use crate::SigningAlg;

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[wasm_bindgen_test]
    async fn test_async_verify_rsa_pss() {
        // PS signatures
        let sig_bytes = include_bytes!("../../tests/fixtures/sig_ps256.data");
        let data_bytes = include_bytes!("../../tests/fixtures/data_ps256.data");
        let key_bytes = include_bytes!("../../tests/fixtures/key_ps256.data");

        let validated = validate_async(SigningAlg::Ps256, sig_bytes, data_bytes, key_bytes)
            .await
            .unwrap();

        assert_eq!(validated, true);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[wasm_bindgen_test]
    async fn test_async_verify_ecdsa() {
        // EC signatures
        let sig_es384_bytes = include_bytes!("../../tests/fixtures/sig_es384.data");
        let data_es384_bytes = include_bytes!("../../tests/fixtures/data_es384.data");
        let key_es384_bytes = include_bytes!("../../tests/fixtures/key_es384.data");

        let mut validated = validate_async(
            SigningAlg::Es384,
            sig_es384_bytes,
            data_es384_bytes,
            key_es384_bytes,
        )
        .await
        .unwrap();

        assert_eq!(validated, true);

        let sig_es512_bytes = include_bytes!("../../tests/fixtures/sig_es512.data");
        let data_es512_bytes = include_bytes!("../../tests/fixtures/data_es512.data");
        let key_es512_bytes = include_bytes!("../../tests/fixtures/key_es512.data");

        validated = validate_async(
            SigningAlg::Es512,
            sig_es512_bytes,
            data_es512_bytes,
            key_es512_bytes,
        )
        .await
        .unwrap();

        assert_eq!(validated, true);

        let sig_es256_bytes = include_bytes!("../../tests/fixtures/sig_es256.data");
        let data_es256_bytes = include_bytes!("../../tests/fixtures/data_es256.data");
        let key_es256_bytes = include_bytes!("../../tests/fixtures/key_es256.data");

        let validated = validate_async(
            SigningAlg::Es256,
            sig_es256_bytes,
            data_es256_bytes,
            key_es256_bytes,
        )
        .await
        .unwrap();

        assert_eq!(validated, true);
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[wasm_bindgen_test]
    #[ignore]
    async fn test_async_verify_bad() {
        let sig_bytes = include_bytes!("../../tests/fixtures/sig_ps256.data");
        let data_bytes = include_bytes!("../../tests/fixtures/data_ps256.data");
        let key_bytes = include_bytes!("../../tests/fixtures/key_ps256.data");

        let mut bad_bytes = data_bytes.to_vec();
        bad_bytes[0] = b'c';
        bad_bytes[1] = b'2';
        bad_bytes[2] = b'p';
        bad_bytes[3] = b'a';

        let validated = validate_async(SigningAlg::Ps256, sig_bytes, &bad_bytes, key_bytes)
            .await
            .unwrap();

        assert_eq!(validated, false);
    }
}
