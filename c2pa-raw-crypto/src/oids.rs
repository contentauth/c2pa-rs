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

//! ASN.1 object identifiers (OIDs) for the signature, hash, and key algorithms
//! used by C2PA.
//!
//! Each constant is an [`Oid`] wrapping the DER _content octets_ for the
//! corresponding OID (the encoded sub-identifiers, without the leading tag and
//! length).

use crate::Oid;

/// `rsaEncryption` (1.2.840.113549.1.1.1).
pub const RSA_OID: Oid<'static> = Oid::new(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);

/// `id-RSASSA-PSS` (1.2.840.113549.1.1.10).
pub const RSA_PSS_OID: Oid<'static> =
    Oid::new(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a]);

/// `sha1WithRSAEncryption` (1.2.840.113549.1.1.5).
pub const SHA1_WITH_RSAENCRYPTION_OID: Oid<'static> =
    Oid::new(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05]);

/// `sha256WithRSAEncryption` (1.2.840.113549.1.1.11).
pub const SHA256_WITH_RSAENCRYPTION_OID: Oid<'static> =
    Oid::new(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);

/// `sha384WithRSAEncryption` (1.2.840.113549.1.1.12).
pub const SHA384_WITH_RSAENCRYPTION_OID: Oid<'static> =
    Oid::new(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c]);

/// `sha512WithRSAEncryption` (1.2.840.113549.1.1.13).
pub const SHA512_WITH_RSAENCRYPTION_OID: Oid<'static> =
    Oid::new(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d]);

/// `id-sha1` (1.3.14.3.2.26).
pub const SHA1_OID: Oid<'static> = Oid::new(&[0x2b, 0x0e, 0x03, 0x02, 0x1a]);

/// `id-sha256` (2.16.840.1.101.3.4.2.1).
pub const SHA256_OID: Oid<'static> =
    Oid::new(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);

/// `id-sha384` (2.16.840.1.101.3.4.2.2).
pub const SHA384_OID: Oid<'static> =
    Oid::new(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]);

/// `id-sha512` (2.16.840.1.101.3.4.2.3).
pub const SHA512_OID: Oid<'static> =
    Oid::new(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]);

/// `id-ecPublicKey` (1.2.840.10045.2.1).
pub const EC_PUBLICKEY_OID: Oid<'static> = Oid::new(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);

/// `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
pub const ECDSA_WITH_SHA256_OID: Oid<'static> =
    Oid::new(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);

/// `ecdsa-with-SHA384` (1.2.840.10045.4.3.3).
pub const ECDSA_WITH_SHA384_OID: Oid<'static> =
    Oid::new(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]);

/// `ecdsa-with-SHA512` (1.2.840.10045.4.3.4).
pub const ECDSA_WITH_SHA512_OID: Oid<'static> =
    Oid::new(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04]);

/// NIST curve P-521, `secp521r1` (1.3.132.0.35).
pub const SECP521R1_OID: Oid<'static> = Oid::new(&[0x2b, 0x81, 0x04, 0x00, 0x23]);

/// NIST curve P-384, `secp384r1` (1.3.132.0.34).
pub const SECP384R1_OID: Oid<'static> = Oid::new(&[0x2b, 0x81, 0x04, 0x00, 0x22]);

/// NIST curve P-256, `prime256v1` / `secp256r1` (1.2.840.10045.3.1.7).
pub const PRIME256V1_OID: Oid<'static> =
    Oid::new(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);

/// `id-Ed25519` (1.3.101.112).
pub const ED25519_OID: Oid<'static> = Oid::new(&[0x2b, 0x65, 0x70]);
