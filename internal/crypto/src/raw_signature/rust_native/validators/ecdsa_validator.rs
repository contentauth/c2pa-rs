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

use std::str::FromStr;

use bcder::Oid;
use der::Decode;
use ecdsa::{
    signature::{hazmat::PrehashVerifier, Verifier as EcdsaVerifier},
    Signature as EcdsaSignature, SignatureBytes, SignatureWithOid, ECDSA_SHA256_OID,
};
use p256::{ecdsa::VerifyingKey as P256VerifyingKey, NistP256, PublicKey as P256PublicKey};
use p384::{ecdsa::VerifyingKey as P384VerifyingKey, NistP384, PublicKey as P384PublicKey};
use p521::{ecdsa::VerifyingKey as P521VerifyingKey, NistP521, PublicKey as P521PublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::{
    ec_utils::{der_to_p1363, ec_curve_from_public_key_der, EcdsaCurve},
    raw_signature::{oids::*, RawSignatureValidationError, RawSignatureValidator, SigningAlg},
};

/// An `EcdsaValidator` can validate raw signatures with one of the ECDSA
/// signature algorithms.
pub enum EcdsaValidator {
    /// ECDSA with SHA-256
    Es256,

    /// ECDSA with SHA-384
    Es384,

    /// ECDSA with SHA-512
    Es512,
}

impl RawSignatureValidator for EcdsaValidator {
    fn validate(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError> {
        let digest = match self {
            EcdsaValidator::Es256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            EcdsaValidator::Es384 => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            EcdsaValidator::Es512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
        };

        // determine curve from public key
        let curve = ec_curve_from_public_key_der(public_key)
            .ok_or(RawSignatureValidationError::InvalidPublicKey)?;

        // requires fixed sized P1363 signature
        let adjusted_sig = match der_to_p1363(sig, curve.p1363_sig_len()) {
            Ok(p1363) => p1363,
            Err(_) => sig.to_vec(),
        };

        let result = match curve {
            EcdsaCurve::P256 => {
                use p256::pkcs8::DecodePublicKey;
                let signature = EcdsaSignature::from_slice(&adjusted_sig)
                    .map_err(|_| RawSignatureValidationError::InvalidSignature)?;

                let vk = P256VerifyingKey::from_public_key_der(public_key)
                    .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

                vk.verify_prehash(&digest, &signature)
            }
            EcdsaCurve::P384 => {
                use p384::pkcs8::DecodePublicKey;
                let signature = EcdsaSignature::from_slice(&adjusted_sig)
                    .map_err(|_| RawSignatureValidationError::InvalidSignature)?;

                let vk = P384VerifyingKey::from_public_key_der(public_key)
                    .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

                vk.verify_prehash(&digest, &signature)
            }
            EcdsaCurve::P521 => {
                use p521::pkcs8::DecodePublicKey;
                let signature = EcdsaSignature::from_slice(&adjusted_sig)
                    .map_err(|_| RawSignatureValidationError::InvalidSignature)?;

                // internal from_public_key not implemented for P521VerifyingKey so manually
                // load
                let pk = P521PublicKey::from_public_key_der(public_key)
                    .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;
                let pk_bytes = pk.to_sec1_bytes();

                let vk = P521VerifyingKey::from_sec1_bytes(&pk_bytes)
                    .map_err(|_| RawSignatureValidationError::InvalidPublicKey)?;

                vk.verify_prehash(&digest, &signature)
            }
        };

        match result {
            Ok(_) => Ok(()),
            Err(err) => Err(RawSignatureValidationError::SignatureMismatch),
        }
    }
}
