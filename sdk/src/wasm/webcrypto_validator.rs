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

use c2pa_crypto::webcrypto::WindowOrWorker;
use js_sys::{Array, ArrayBuffer, Object, Reflect, Uint8Array};
use spki::SubjectPublicKeyInfoRef;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, SubtleCrypto};
use x509_parser::der_parser::ber::{parse_ber_sequence, BerObject};

use crate::{Error, Result};

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
fn biguint_val(ber_object: &BerObject) -> rsa::BigUint {
    ber_object
        .as_biguint()
        .map(|x| x.to_u32_digits())
        .map(rsa::BigUint::new)
        .unwrap_or_default()
}

// Validate an Ed25519 signature for the provided data.  The pkey must
// be the raw bytes representing CompressedEdwardsY.  The length must 32 bytes.
fn ed25519_validate(sig: Vec<u8>, data: Vec<u8>, pkey: Vec<u8>) -> Result<bool> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};

    if pkey.len() == PUBLIC_KEY_LENGTH {
        let ed_sig = Signature::from_slice(&sig).map_err(|_| Error::CoseInvalidCert)?;

        // convert to VerifyingKey
        let mut cert_slice: [u8; 32] = Default::default();
        cert_slice.copy_from_slice(&pkey[0..PUBLIC_KEY_LENGTH]);

        let vk = VerifyingKey::from_bytes(&cert_slice).map_err(|_| Error::CoseInvalidCert)?;

        match vk.verify(&data, &ed_sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    } else {
        web_sys::console::debug_2(
            &"Ed25519 public key incorrect length: ".into(),
            &pkey.len().to_string().into(),
        );
        Err(Error::CoseInvalidCert)
    }
}

pub(crate) async fn async_validate(
    algo: String,
    hash: String,
    _salt_len: u32,
    pkey: Vec<u8>,
    sig: Vec<u8>,
    data: Vec<u8>,
) -> Result<bool> {
    use rsa::{
        sha2::{Sha256, Sha384, Sha512},
        RsaPublicKey,
    };

    let context = WindowOrWorker::new();
    let subtle_crypto = context?.subtle_crypto()?;
    let sig_array_buf = data_as_array_buffer(&sig);
    let data_array_buf = data_as_array_buffer(&data);

    match algo.as_ref() {
        "RSASSA-PKCS1-v1_5" => {
            use rsa::{pkcs1v15::Signature, signature::Verifier};

            // used for certificate validation
            let spki = SubjectPublicKeyInfoRef::try_from(pkey.as_ref())
                .map_err(|err| Error::WasmRsaKeyImport(err.to_string()))?;

            let (_, seq) = parse_ber_sequence(&spki.subject_public_key.raw_bytes())
                .map_err(|err| Error::WasmRsaKeyImport(err.to_string()))?;

            let modulus = biguint_val(&seq[0]);
            let exp = biguint_val(&seq[1]);
            let public_key = RsaPublicKey::new(modulus, exp)
                .map_err(|err| Error::WasmRsaKeyImport(err.to_string()))?;
            let normalized_hash = hash.clone().replace("-", "").to_lowercase();

            let result = match normalized_hash.as_ref() {
                "sha256" => {
                    let vk = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
                    let signature: Signature = sig.as_slice().try_into().map_err(|_e| {
                        Error::WasmRsaKeyImport("could no process RSA signature".to_string())
                    })?;
                    vk.verify(&data, &signature)
                }
                "sha384" => {
                    let vk = rsa::pkcs1v15::VerifyingKey::<Sha384>::new(public_key);
                    let signature: Signature = sig.as_slice().try_into().map_err(|_e| {
                        Error::WasmRsaKeyImport("could no process RSA signature".to_string())
                    })?;
                    vk.verify(&data, &signature)
                }
                "sha512" => {
                    let vk = rsa::pkcs1v15::VerifyingKey::<Sha512>::new(public_key);
                    let signature: Signature = sig.as_slice().try_into().map_err(|_e| {
                        Error::WasmRsaKeyImport("could no process RSA signature".to_string())
                    })?;
                    vk.verify(&data, &signature)
                }
                _ => return Err(Error::UnknownAlgorithm),
            };

            match result {
                Ok(()) => {
                    web_sys::console::debug_1(&"RSA validation success:".into());
                    Ok(true)
                }
                Err(err) => {
                    web_sys::console::debug_2(
                        &"RSA validation failed:".into(),
                        &err.to_string().into(),
                    );
                    Ok(false)
                }
            }
        }
        "RSA-PSS" => {
            use rsa::{pss::Signature, signature::Verifier};

            let spki = SubjectPublicKeyInfoRef::try_from(pkey.as_ref())
                .map_err(|err| Error::WasmRsaKeyImport(err.to_string()))?;

            let (_, seq) = parse_ber_sequence(&spki.subject_public_key.raw_bytes())
                .map_err(|err| Error::WasmRsaKeyImport(err.to_string()))?;

            // We need to normalize this from SHA-256 (the format WebCrypto uses) to sha256
            // (the format the util function expects) so that it maps correctly
            let normalized_hash = hash.clone().replace("-", "").to_lowercase();
            let modulus = biguint_val(&seq[0]);
            let exp = biguint_val(&seq[1]);
            let public_key = RsaPublicKey::new(modulus, exp)
                .map_err(|err| Error::WasmRsaKeyImport(err.to_string()))?;

            let result = match normalized_hash.as_ref() {
                "sha256" => {
                    let vk = rsa::pss::VerifyingKey::<Sha256>::new(public_key);
                    let signature: Signature = sig.as_slice().try_into().map_err(|_e| {
                        Error::WasmRsaKeyImport("could no process RSA signature".to_string())
                    })?;
                    vk.verify(&data, &signature)
                }
                "sha384" => {
                    let vk = rsa::pss::VerifyingKey::<Sha384>::new(public_key);
                    let signature: Signature = sig.as_slice().try_into().map_err(|_e| {
                        Error::WasmRsaKeyImport("could no process RSA signature".to_string())
                    })?;
                    vk.verify(&data, &signature)
                }
                "sha512" => {
                    let vk = rsa::pss::VerifyingKey::<Sha512>::new(public_key);
                    let signature: Signature = sig.as_slice().try_into().map_err(|_e| {
                        Error::WasmRsaKeyImport("could no process RSA signature".to_string())
                    })?;
                    vk.verify(&data, &signature)
                }
                _ => return Err(Error::UnknownAlgorithm),
            };

            match result {
                Ok(()) => {
                    web_sys::console::debug_1(&"RSA-PSS validation success:".into());
                    Ok(true)
                }
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
            let crypto_key: CryptoKey = JsFuture::from(promise)
                .await
                .map_err(|_| Error::CoseInvalidCert)?
                .into();
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
        "ED25519" => {
            use x509_parser::{prelude::*, public_key::PublicKey};

            // pull out raw Ed code points
            if let Ok((_, certificate_public_key)) = SubjectPublicKeyInfo::from_der(&pkey) {
                match certificate_public_key.parsed() {
                    Ok(key) => match key {
                        PublicKey::Unknown(raw_key) => {
                            ed25519_validate(sig, data, raw_key.to_vec())
                        }
                        _ => Err(Error::OtherError(
                            "could not unwrap Ed25519 public key".into(),
                        )),
                    },
                    Err(_) => Err(Error::OtherError(
                        "could not recognize Ed25519 public key".into(),
                    )),
                }
            } else {
                Err(Error::OtherError(
                    "could not parse Ed25519 public key".into(),
                ))
            }
        }
        _ => Err(Error::UnsupportedType),
    }
}
