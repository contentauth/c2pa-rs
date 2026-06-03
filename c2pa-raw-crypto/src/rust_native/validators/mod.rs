// Copyright 2025 Adobe. All rights reserved.
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

//! This module binds Rust native logic for generating raw signatures to this
//! crate's [`RawSignatureValidator`] trait.

use crate::{oids::*, RawSignatureValidator, SigningAlg};

mod ecdsa_validator;
pub(crate) use ecdsa_validator::EcdsaValidator;

mod ed25519_validator;
pub(crate) use ed25519_validator::Ed25519Validator;

mod rsa_legacy_validator;
pub(crate) use rsa_legacy_validator::RsaLegacyValidator;

mod rsa_validator;
pub(crate) use rsa_validator::RsaValidator;

/// Returns a validator for the given signing algorithm.
pub(crate) fn validator_for_signing_alg(alg: SigningAlg) -> Option<Box<dyn RawSignatureValidator>> {
    match alg {
        SigningAlg::Ed25519 => Some(Box::new(Ed25519Validator {})),
        SigningAlg::Ps256 => Some(Box::new(RsaValidator::Ps256)),
        SigningAlg::Ps384 => Some(Box::new(RsaValidator::Ps384)),
        SigningAlg::Ps512 => Some(Box::new(RsaValidator::Ps512)),
        SigningAlg::Es256 => Some(Box::new(EcdsaValidator::Es256)),
        SigningAlg::Es384 => Some(Box::new(EcdsaValidator::Es384)),
        SigningAlg::Es512 => Some(Box::new(EcdsaValidator::Es512)),
    }
}

/// Selects a validator based on signing algorithm and hash type or EC curve.
///
/// `sig_alg` and `hash_alg` are the DER content octets of the respective OIDs.
pub(crate) fn validator_for_sig_and_hash_algs(
    sig_alg: &[u8],
    hash_alg: &[u8],
) -> Option<Box<dyn RawSignatureValidator>> {
    // Try signature algorithms first.
    if sig_alg == ECDSA_WITH_SHA256_OID.as_bytes() {
        return Some(Box::new(EcdsaValidator::Es256));
    }
    if sig_alg == ECDSA_WITH_SHA384_OID.as_bytes() {
        return Some(Box::new(EcdsaValidator::Es384));
    }
    if sig_alg == ECDSA_WITH_SHA512_OID.as_bytes() {
        return Some(Box::new(EcdsaValidator::Es512));
    }
    if sig_alg == SHA256_WITH_RSAENCRYPTION_OID.as_bytes() {
        return Some(Box::new(RsaLegacyValidator::Rsa256));
    }
    if sig_alg == SHA384_WITH_RSAENCRYPTION_OID.as_bytes() {
        return Some(Box::new(RsaLegacyValidator::Rsa384));
    }
    if sig_alg == SHA512_WITH_RSAENCRYPTION_OID.as_bytes() {
        return Some(Box::new(RsaLegacyValidator::Rsa512));
    }
    if sig_alg == ED25519_OID.as_bytes() {
        return Some(Box::new(Ed25519Validator {}));
    }

    // Test for public key algorithms next.

    // Handle legacy RSA.
    if sig_alg == RSA_OID.as_bytes() {
        if hash_alg == SHA256_OID.as_bytes() {
            return Some(Box::new(RsaLegacyValidator::Rsa256));
        } else if hash_alg == SHA384_OID.as_bytes() {
            return Some(Box::new(RsaLegacyValidator::Rsa384));
        } else if hash_alg == SHA512_OID.as_bytes() {
            return Some(Box::new(RsaLegacyValidator::Rsa512));
        }
    }

    // Handle RSS-PSS.
    if sig_alg == RSA_PSS_OID.as_bytes() {
        if hash_alg == SHA256_OID.as_bytes() {
            return Some(Box::new(RsaValidator::Ps256));
        } else if hash_alg == SHA384_OID.as_bytes() {
            return Some(Box::new(RsaValidator::Ps384));
        } else if hash_alg == SHA512_OID.as_bytes() {
            return Some(Box::new(RsaValidator::Ps512));
        }
    }

    // Handle elliptical curve and hash combinations.
    if sig_alg == EC_PUBLICKEY_OID.as_bytes() {
        if hash_alg == SHA256_OID.as_bytes() {
            return Some(Box::new(EcdsaValidator::Es256));
        } else if hash_alg == SHA384_OID.as_bytes() {
            return Some(Box::new(EcdsaValidator::Es384));
        } else if hash_alg == SHA512_OID.as_bytes() {
            return Some(Box::new(EcdsaValidator::Es512));
        }
    }

    // Handle ED25519.
    if sig_alg == ED25519_OID.as_bytes() {
        return Some(Box::new(Ed25519Validator {}));
    }

    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use bcder::Oid;
    use rasn::types::OctetString;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::{rust_native, RawSignatureValidationError, SigningAlg};

    const SAMPLE_DATA: &[u8] = b"some sample content to sign";

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn es256() {
        let signature = include_bytes!("../../../tests/fixtures/raw_signature/es256.raw_sig");
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/es256.pub_key");

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Es256).unwrap();

        validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn es256_bad_signature() {
        let mut signature =
            include_bytes!("../../../tests/fixtures/raw_signature/es256.raw_sig").to_vec();
        assert_ne!(signature[10], 10);
        signature[10] = 10;

        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/es256.pub_key");

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Es256).unwrap();

        assert_eq!(
            validator
                .validate(&signature, SAMPLE_DATA, pub_key)
                .unwrap_err(),
            RawSignatureValidationError::SignatureMismatch
        );
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn es256_bad_data() {
        let signature = include_bytes!("../../../tests/fixtures/raw_signature/es256.raw_sig");
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/es256.pub_key");

        let mut data = SAMPLE_DATA.to_vec();
        data[10] = 0;

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Es256).unwrap();

        assert_eq!(
            validator.validate(signature, &data, pub_key).unwrap_err(),
            RawSignatureValidationError::SignatureMismatch
        );
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn es384() {
        let signature = include_bytes!("../../../tests/fixtures/raw_signature/es384.raw_sig");
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/es384.pub_key");

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Es384).unwrap();

        validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn es512() {
        let signature = include_bytes!("../../../tests/fixtures/raw_signature/es512.raw_sig");
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/es512.pub_key");

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Es512).unwrap();

        validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn ed25519() {
        let signature = include_bytes!("../../../tests/fixtures/raw_signature/ed25519.raw_sig");
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/ed25519.pub_key");

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Ed25519).unwrap();

        validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn ed25519_bad_data() {
        let signature = include_bytes!("../../../tests/fixtures/raw_signature/ed25519.raw_sig");
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/ed25519.pub_key");

        let mut data = SAMPLE_DATA.to_vec();
        data[5] = 10;
        data[6] = 11;

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Ed25519).unwrap();

        assert_eq!(
            validator.validate(signature, &data, pub_key).unwrap_err(),
            RawSignatureValidationError::SignatureMismatch
        );
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn ps256() {
        let signature = include_bytes!("../../../tests/fixtures/raw_signature/ps256.raw_sig");
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/ps256.pub_key");

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Ps256).unwrap();

        validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn ps256_bad_signature() {
        let mut signature =
            include_bytes!("../../../tests/fixtures/raw_signature/ps256.raw_sig").to_vec();
        assert_ne!(signature[10], 10);
        signature[10] = 10;

        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/ps256.pub_key");

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Ps256).unwrap();

        assert_eq!(
            validator
                .validate(&signature, SAMPLE_DATA, pub_key)
                .unwrap_err(),
            RawSignatureValidationError::SignatureMismatch
        );
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn ps256_bad_data() {
        let signature = include_bytes!("../../../tests/fixtures/raw_signature/ps256.raw_sig");
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/ps256.pub_key");

        let mut data = SAMPLE_DATA.to_vec();
        data[10] = 0;

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Ps256).unwrap();

        assert_eq!(
            validator.validate(signature, &data, pub_key).unwrap_err(),
            RawSignatureValidationError::SignatureMismatch
        );
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn ps384() {
        let signature = include_bytes!("../../../tests/fixtures/raw_signature/ps384.raw_sig");
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/ps384.pub_key");

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Ps384).unwrap();

        validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn ps512() {
        let signature = include_bytes!("../../../tests/fixtures/raw_signature/ps512.raw_sig");
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/ps512.pub_key");

        let validator =
            rust_native::validators::validator_for_signing_alg(SigningAlg::Ps512).unwrap();

        validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
    }

    // Argh. Different Oid types across different crates, so we have to construct
    // our own constants here.
    const RSA_OID: Oid<OctetString> = bcder::Oid(OctetString::from_static(&[
        42, 134, 72, 134, 247, 13, 1, 1, 1,
    ]));

    const SHA256_OID: Oid<OctetString> =
        bcder::Oid(OctetString::from_static(&[96, 134, 72, 1, 101, 3, 4, 2, 1]));

    const SHA384_OID: Oid<OctetString> =
        bcder::Oid(OctetString::from_static(&[96, 134, 72, 1, 101, 3, 4, 2, 2]));

    const SHA512_OID: Oid<OctetString> =
        bcder::Oid(OctetString::from_static(&[96, 134, 72, 1, 101, 3, 4, 2, 3]));

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn legacy_rs256() {
        let signature =
            include_bytes!("../../../tests/fixtures/raw_signature/legacy/rs256.raw_sig");
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/legacy/rs256.pub_key");

        let validator = rust_native::validators::validator_for_sig_and_hash_algs(
            RSA_OID.as_ref(),
            SHA256_OID.as_ref(),
        )
        .unwrap();

        validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn legacy_rs256_bad_signature() {
        let mut signature =
            include_bytes!("../../../tests/fixtures/raw_signature/legacy/rs256.raw_sig").to_vec();
        assert_ne!(signature[10], 10);
        signature[10] = 10;

        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/legacy/rs256.pub_key");

        let validator = rust_native::validators::validator_for_sig_and_hash_algs(
            RSA_OID.as_ref(),
            SHA256_OID.as_ref(),
        )
        .unwrap();

        assert_eq!(
            validator
                .validate(&signature, SAMPLE_DATA, pub_key)
                .unwrap_err(),
            RawSignatureValidationError::SignatureMismatch
        );
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn legacy_rs256_bad_data() {
        let signature =
            include_bytes!("../../../tests/fixtures/raw_signature/legacy/rs256.raw_sig");
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/legacy/rs256.pub_key");

        let mut data = SAMPLE_DATA.to_vec();
        data[10] = 0;

        let validator = rust_native::validators::validator_for_sig_and_hash_algs(
            RSA_OID.as_ref(),
            SHA256_OID.as_ref(),
        )
        .unwrap();

        assert_eq!(
            validator.validate(signature, &data, pub_key).unwrap_err(),
            RawSignatureValidationError::SignatureMismatch
        );
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn rs384() {
        let signature =
            include_bytes!("../../../tests/fixtures/raw_signature/legacy/rs384.raw_sig");
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/legacy/rs384.pub_key");

        let validator = rust_native::validators::validator_for_sig_and_hash_algs(
            RSA_OID.as_ref(),
            SHA384_OID.as_ref(),
        )
        .unwrap();

        validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn rs512() {
        let signature =
            include_bytes!("../../../tests/fixtures/raw_signature/legacy/rs512.raw_sig");
        let pub_key = include_bytes!("../../../tests/fixtures/raw_signature/legacy/rs512.pub_key");

        let validator = rust_native::validators::validator_for_sig_and_hash_algs(
            RSA_OID.as_ref(),
            SHA512_OID.as_ref(),
        )
        .unwrap();

        validator.validate(signature, SAMPLE_DATA, pub_key).unwrap();
    }
}
