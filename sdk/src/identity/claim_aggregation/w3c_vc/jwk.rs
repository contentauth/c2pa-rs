// Derived from
// https://github.com/spruceid/ssi/blob/ssi/v0.9.0/crates/jwk/src/lib.rs
// which was published under an Apache 2.0 license.

// Subsequent modifications are subject to license from Adobe
// as follows:

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

#![allow(unused)] // TEMPORARY

use std::{
    convert::TryFrom, fmt, num::ParseIntError, result::Result, str::FromStr, string::FromUtf8Error,
};

use base64::{DecodeError as Base64Error, Engine};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
pub(crate) struct Jwk {
    #[serde(rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_use: Option<String>,

    #[serde(rename = "key_ops")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_operations: Option<Vec<String>>,

    #[serde(rename = "alg")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<Algorithm>,

    #[serde(rename = "kid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    #[serde(rename = "x5u")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<String>,

    #[serde(rename = "x5c")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_certificate_chain: Option<Vec<String>>,

    #[serde(rename = "x5t")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_thumbprint_sha1: Option<Base64urlUInt>,

    #[serde(rename = "x5t#S256")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_thumbprint_sha256: Option<Base64urlUInt>,

    #[serde(flatten)]
    pub params: Params,
}

impl FromStr for Jwk {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl TryFrom<&[u8]> for Jwk {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

impl TryFrom<serde_json::Value> for Jwk {
    type Error = serde_json::Error;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        serde_json::from_value(value)
    }
}

impl fmt::Display for Jwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json =
            serde_json::to_string_pretty(self).unwrap_or_else(|_| "unable to serialize".to_owned());
        f.write_str(&json)
    }
}

impl From<Params> for Jwk {
    fn from(params: Params) -> Self {
        Self {
            params,
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
#[serde(tag = "kty")]
pub enum Params {
    // TEMPORARY: Only supporting Ed25519 for now
    // EC(ECParams),
    // RSA(RSAParams),
    // #[serde(rename = "oct")]
    // Symmetric(SymmetricParams),
    #[serde(rename = "OKP")]
    Okp(OctetParams),
}

impl Params {
    /// Strip private key material
    #[cfg(test)] // So far, only used in test code
    pub fn to_public(&self) -> Self {
        match self {
            // Self::EC(params) => Self::EC(params.to_public()),
            // Self::RSA(params) => Self::RSA(params.to_public()),
            // Self::Symmetric(params) => Self::Symmetric(params.to_public()),
            Self::Okp(params) => Self::Okp(params.to_public()),
        }
    }
}

impl Drop for OctetParams {
    fn drop(&mut self) {
        // Zeroize private key
        if let Some(ref mut d) = self.private_key {
            d.zeroize();
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
pub struct OctetParams {
    // Parameters for Octet Key Pair Public Keys
    #[serde(rename = "crv")]
    pub curve: String,

    #[serde(rename = "x")]
    pub public_key: Base64urlUInt,

    // Parameters for Octet Key Pair Private Keys
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Base64urlUInt>,
}

impl OctetParams {
    pub fn to_public(&self) -> Self {
        Self {
            curve: self.curve.clone(),
            public_key: self.public_key.clone(),
            private_key: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
#[serde(try_from = "String")]
#[serde(into = "Base64urlUIntString")]
pub struct Base64urlUInt(pub Vec<u8>);
type Base64urlUIntString = String;

impl Jwk {
    #[cfg(test)]
    pub fn generate_ed25519() -> Result<Jwk, JwkError> {
        let mut csprng = rand::rngs::OsRng {};
        let secret = ed25519_dalek::SigningKey::generate(&mut csprng);
        let public = secret.verifying_key();
        Ok(Jwk::from(Params::Okp(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(public.as_ref().to_vec()),
            private_key: Some(Base64urlUInt(secret.to_bytes().to_vec())),
        })))
    }

    #[cfg(test)]
    pub fn get_algorithm(&self) -> Option<Algorithm> {
        if let Some(algorithm) = self.algorithm {
            return Some(algorithm);
        }
        match &self.params {
            Params::Okp(okp_params) if okp_params.curve == "Ed25519" => {
                return Some(Algorithm::EdDsa);
            }
            _ => {}
        };
        None
    }

    /// Strip private key material
    #[cfg(test)]
    pub fn to_public(&self) -> Self {
        let mut key = self.clone();
        key.params = key.params.to_public();
        key
    }
}

impl TryFrom<&OctetParams> for ed25519_dalek::VerifyingKey {
    type Error = JwkError;

    fn try_from(params: &OctetParams) -> Result<Self, Self::Error> {
        if params.curve != *"Ed25519" {
            return Err(JwkError::CurveNotImplemented(params.curve.to_string()));
        }
        Ok(params.public_key.0.as_slice().try_into()?)
    }
}

impl TryFrom<&OctetParams> for ed25519_dalek::SigningKey {
    type Error = JwkError;

    fn try_from(params: &OctetParams) -> Result<Self, Self::Error> {
        if params.curve != *"Ed25519" {
            return Err(JwkError::CurveNotImplemented(params.curve.to_string()));
        }

        let private_key = params
            .private_key
            .as_ref()
            .ok_or(JwkError::MissingPrivateKey)?;

        Ok(private_key.0.as_slice().try_into()?)
    }
}

impl From<ed25519_dalek::VerifyingKey> for Jwk {
    fn from(value: ed25519_dalek::VerifyingKey) -> Self {
        Jwk::from(Params::Okp(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(value.to_bytes().to_vec()),
            private_key: None,
        }))
    }
}

const BASE64_URL_SAFE_INDIFFERENT_PAD: base64::engine::GeneralPurpose =
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );

impl TryFrom<String> for Base64urlUInt {
    type Error = base64::DecodeError;

    fn try_from(data: String) -> Result<Self, Self::Error> {
        Ok(Base64urlUInt(BASE64_URL_SAFE_INDIFFERENT_PAD.decode(data)?))
    }
}

impl From<&Base64urlUInt> for String {
    fn from(data: &Base64urlUInt) -> String {
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(&data.0)
    }
}

impl From<Base64urlUInt> for Base64urlUIntString {
    fn from(data: Base64urlUInt) -> Base64urlUIntString {
        String::from(&data)
    }
}

/// Signature algorithm.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Hash, Eq)]
pub enum Algorithm {
    // TEMPORARY: Only supporting Ed25519 for now.
    #[serde(rename = "EdDSA")]
    EdDsa,

    #[serde(alias = "None")]
    None,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JwkError {
    /// Missing curve in JWK
    #[error("Missing curve in JWK")]
    MissingCurve,

    /// Missing elliptic curve point in JWK
    #[error("Missing elliptic curve point in JWK")]
    MissingPoint,

    /// Missing key value for symmetric key
    #[error("Missing key value for symmetric key")]
    MissingKeyValue,

    /// Key type is not supported
    #[error("Key type not supported")]
    UnsupportedKeyType,

    /// Key type not implemented
    #[error("Key type {0} not implemented")]
    KeyTypeNotImplemented(String),

    /// Curve not implemented
    #[error("Curve not implemented: '{0}'")]
    CurveNotImplemented(String),

    /// Missing private key parameter in JWK
    #[error("Missing private key parameter in JWK")]
    MissingPrivateKey,

    /// Invalid key length
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),

    /// Error parsing a UTF-8 string
    #[error(transparent)]
    FromUtf8(#[from] FromUtf8Error),

    /// Error decoding Base64
    #[error(transparent)]
    Base64(#[from] Base64Error),

    /// Error parsing integer
    #[error(transparent)]
    ParseInt(#[from] ParseIntError),

    /// Expected 64 byte uncompressed key or 33 bytes compressed key
    #[error("Expected 64 byte uncompressed key or 33 bytes compressed key but found length: {0}")]
    P256KeyLength(usize),

    /// Expected 96 byte uncompressed key or 49 bytes compressed key (P-384)
    #[error("Expected 96 byte uncompressed key or 49 bytes compressed key but found length: {0}")]
    P384KeyLength(usize),

    /// Unable to decompress elliptic curve
    #[error("Unable to decompress elliptic curve")]
    ECDecompress,

    #[error(transparent)]
    CryptoErr(#[from] ed25519_dalek::ed25519::Error),

    /// Unexpected length for publicKeyMultibase
    #[error("Unexpected length for publicKeyMultibase")]
    MultibaseKeyLength(usize, usize),

    /// Error parsing or producing multibase
    #[error(transparent)]
    Multibase(#[from] multibase::Error),

    #[error("Invalid coordinates")]
    InvalidCoordinates,
}
