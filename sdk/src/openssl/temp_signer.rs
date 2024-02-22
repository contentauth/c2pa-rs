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

#![deny(missing_docs)]

//! Temporary signing instances for testing purposes.
//!
//! This module contains functions to create self-signed certificates
//! and provision [`Signer`] instances for each of the supported signature
//! formats.
//!
//! Private-key and signing certificate pairs are created in a directory
//! provided by the caller. It is recommended to use a temporary directory
//! that is deleted upon completion of the test. (We recommend using
//! the [tempfile](https://crates.io/crates/tempfile) crate.)
//!
//! This module should be used only for testing purposes.

// Since this module is intended for testing purposes, all of
// its functions are allowed to panic.
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

#[cfg(feature = "file_io")]
use std::path::{Path, PathBuf};

#[cfg(feature = "file_io")]
use crate::{
    openssl::{EcSigner, EdSigner, RsaSigner},
    signer::ConfigurableSigner,
    SigningAlg,
};

/// Create an OpenSSL ES256 signer that can be used for testing purposes.
///
/// # Arguments
///
/// * `path` - A directory (which must already exist) to receive the temporary
///   private key / certificate pair.
/// * `alg` - A format for signing. Must be one of the `SigningAlg::Es*` variants.
/// * `tsa_url` - Optional URL for a timestamp authority.
///
/// # Returns
///
/// Returns a tuple of `(signer, sign_cert_path)` where `signer` is
/// the [`Signer`] instance and `sign_cert_path` is the path to the
/// signing certificate.
///
/// # Panics
///
/// Can panic if unable to invoke OpenSSL executable properly.
#[cfg(feature = "file_io")]
pub fn get_ec_signer<P: AsRef<Path>>(
    path: P,
    alg: SigningAlg,
    tsa_url: Option<String>,
) -> (EcSigner, PathBuf) {
    match alg {
        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => (),
        _ => {
            panic!("Unknown EC signer alg {alg:#?}");
        }
    }

    let mut sign_cert_path = path.as_ref().to_path_buf();
    sign_cert_path.push(alg.to_string());
    sign_cert_path.set_extension("pub");

    let mut pem_key_path = path.as_ref().to_path_buf();
    pem_key_path.push(alg.to_string());
    pem_key_path.set_extension("pem");

    (
        EcSigner::from_files(&sign_cert_path, &pem_key_path, alg, tsa_url).unwrap(),
        sign_cert_path,
    )
}

/// Create an OpenSSL ES256 signer that can be used for testing purposes.
///
/// # Arguments
///
/// * `path` - A directory (which must already exist) to look for
///   private key / certificate pair.
/// * `alg` - A format for signing. Must be `ed25519`.
/// * `tsa_url` - Optional URL for a timestamp authority.
///
/// # Returns
///
/// Returns a tuple of `(signer, sign_cert_path)` where `signer` is
/// the [`Signer`] instance and `sign_cert_path` is the path to the
/// signing certificate.
///
/// # Panics
///
/// Can panic if unable to invoke OpenSSL executable properly.
#[cfg(feature = "file_io")]
pub fn get_ed_signer<P: AsRef<Path>>(
    path: P,
    alg: SigningAlg,
    tsa_url: Option<String>,
) -> (EdSigner, PathBuf) {
    if alg != SigningAlg::Ed25519 {
        panic!("Unknown ED signer alg {alg:#?}");
    }

    let mut sign_cert_path = path.as_ref().to_path_buf();
    sign_cert_path.push(alg.to_string());
    sign_cert_path.set_extension("pub");

    let mut pem_key_path = path.as_ref().to_path_buf();
    pem_key_path.push(alg.to_string());
    pem_key_path.set_extension("pem");

    (
        EdSigner::from_files(&sign_cert_path, &pem_key_path, alg, tsa_url).unwrap(),
        sign_cert_path,
    )
}

/// Create an OpenSSL SHA+RSA signer that can be used for testing purposes.
///
/// # Arguments
///
/// * `path` - A directory (which must already exist) to receive the temporary
///   private key / certificate pair.
/// * `alg` - A format for signing. Must be one of the `SignerAlg::Ps*` options.
/// * `tsa_url` - Optional URL for a timestamp authority.
///
/// # Returns
///
/// Returns a tuple of `(signer, sign_cert_path)` where `signer` is
/// the [`Signer`] instance and `sign_cert_path` is the path to the
/// signing certificate.
///
/// # Panics
///
/// Can panic if unable to invoke OpenSSL executable properly.
#[cfg(feature = "file_io")]
pub fn get_rsa_signer<P: AsRef<Path>>(
    path: P,
    alg: SigningAlg,
    tsa_url: Option<String>,
) -> (RsaSigner, PathBuf) {
    match alg {
        SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512 => (),
        _ => {
            panic!("Unknown RSA signer alg {alg:#?}");
        }
    }

    let mut sign_cert_path = path.as_ref().to_path_buf();
    sign_cert_path.push(alg.to_string());
    sign_cert_path.set_extension("pub");

    let mut pem_key_path = path.as_ref().to_path_buf();
    pem_key_path.push(alg.to_string());
    pem_key_path.set_extension("pem");

    if !sign_cert_path.exists() || !pem_key_path.exists() {
        panic!(
            "path found: {}, {}",
            sign_cert_path.display(),
            pem_key_path.display()
        );
    }

    (
        RsaSigner::from_files(&sign_cert_path, &pem_key_path, alg, tsa_url).unwrap(),
        sign_cert_path,
    )
}
