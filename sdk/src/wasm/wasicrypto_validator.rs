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

use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use spki::SubjectPublicKeyInfoRef;
use x509_parser::der_parser::ber::{parse_ber_sequence, BerObject};

use crate::{Error, Result, SigningAlg};

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
        /*
        web_sys::console::debug_2(
            &"Ed25519 public key incorrect length: ".into(),
            &pkey.len().to_string().into(),
        );
        */
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

    match algo.as_ref() {
        "RSASSA-PKCS1-v1_5" => {
            use rsa::{pkcs1v15::Signature, signature::Verifier};

            // used for certificate validation
            let spki = SubjectPublicKeyInfoRef::try_from(pkey.as_ref())
                .map_err(|err| Error::WasmRsaKeyImport(err.to_string()))?;

            let (_, seq) = parse_ber_sequence(spki.subject_public_key.raw_bytes())
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
                    //web_sys::console::debug_1(&"RSA validation success:".into());
                    Ok(true)
                }
                Err(err) => {
                    /*
                    web_sys::console::debug_2(
                        &"RSA validation failed:".into(),
                        &err.to_string().into(),
                    );
                    */
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
                    //web_sys::console::debug_1(&"RSA-PSS validation success:".into());
                    Ok(true)
                }
                Err(err) => {
                    /*
                    web_sys::console::debug_2(
                        &"RSA-PSS validation failed:".into(),
                        &err.to_string().into(),
                    );
                    */
                    Ok(false)
                }
            }
        }
        "ECDSA" => {
            let alg: &dyn VerificationAlgorithm = match hash.as_ref() {
                "SHA-256" => &signature::ECDSA_P256_SHA256_ASN1,
                "SHA-384" => &signature::ECDSA_P384_SHA384_ASN1,
                _ => return Err(Error::UnknownAlgorithm),
            };
            let public_key = UnparsedPublicKey::new(alg, &sig);
            match public_key.verify(&data, &sig) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
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

// This interface is called from CoseValidator. RSA validation not supported here.
pub async fn validate_async(alg: SigningAlg, sig: &[u8], data: &[u8], pkey: &[u8]) -> Result<bool> {
    //web_sys::console::debug_2(&"Validating with algorithm".into(), &alg.to_string().into());

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
        SigningAlg::Ed25519 => {
            async_validate(
                "ED25519".to_string(),
                "SHA-512".to_string(),
                0,
                pkey.to_vec(),
                sig.to_vec(),
                data.to_vec(),
            )
            .await
        }
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::SigningAlg;

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
