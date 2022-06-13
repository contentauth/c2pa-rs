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

use std::path::{Path, PathBuf};

use crate::{
    openssl::{EcSigner, EdSigner, RsaSigner},
    signer::ConfigurableSigner,
    Signer,
};

/// Create a [`Signer`] instance that can be used for testing purposes.
///
/// This is a suitable default for use when you need a [`Signer`], but
/// don't care what the format is.
///
/// # Arguments
///
/// * `path` - A directory (which must already exist) to receive the temporary
///   private key / certificate pair.
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
pub fn get_temp_signer<P: AsRef<Path>>(path: P) -> (RsaSigner, PathBuf) {
    let mut sign_cert_path = path.as_ref().to_path_buf();
    sign_cert_path.push("ps256");
    sign_cert_path.set_extension("pub");

    let mut pem_key_path = path.as_ref().to_path_buf();
    pem_key_path.push("ps256");
    pem_key_path.set_extension("pem");

    (
        RsaSigner::from_files(&sign_cert_path, &pem_key_path, "ps256".to_string(), None).unwrap(),
        sign_cert_path,
    )
}

/// Create an OpenSSL ES256 signer that can be used for testing purposes.
///
/// # Arguments
///
/// * `path` - A directory (which must already exist) to receive the temporary
///   private key / certificate pair.
/// * `alg` - A format for signing. Must be one of (`es256`, `es384`, or `es512`).
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
pub fn get_ec_signer<P: AsRef<Path>>(
    path: P,
    alg: &str,
    tsa_url: Option<String>,
) -> (EcSigner, PathBuf) {
    match alg {
        "es256" | "es384" | "es512" => (),
        _ => {
            panic!("Unknown EC signer alg {:#?}", alg);
        }
    }

    let mut sign_cert_path = path.as_ref().to_path_buf();
    sign_cert_path.push(alg);
    sign_cert_path.set_extension("pub");

    let mut pem_key_path = path.as_ref().to_path_buf();
    pem_key_path.push(alg);
    pem_key_path.set_extension("pem");

    (
        EcSigner::from_files(&sign_cert_path, &pem_key_path, alg.to_string(), tsa_url).unwrap(),
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
pub fn get_ed_signer<P: AsRef<Path>>(
    path: P,
    alg: &str,
    tsa_url: Option<String>,
) -> (EdSigner, PathBuf) {
    if alg != "ed25519" {
        panic!("Unknown ED signer alg {:#?}", alg);
    }

    let mut sign_cert_path = path.as_ref().to_path_buf();
    sign_cert_path.push(alg);
    sign_cert_path.set_extension("pub");

    let mut pem_key_path = path.as_ref().to_path_buf();
    pem_key_path.push(alg);
    pem_key_path.set_extension("pem");

    (
        EdSigner::from_files(&sign_cert_path, &pem_key_path, alg.to_string(), tsa_url).unwrap(),
        sign_cert_path,
    )
}

/// Create an OpenSSL SHA+RSA signer that can be used for testing purposes.
///
/// # Arguments
///
/// * `path` - A directory (which must already exist) to receive the temporary
///   private key / certificate pair.
/// * `alg` - A format for signing. Must be one of (`rs256`, `rs384`, `rs512`,
///   `ps256`, `ps384`, or `ps512`).
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
pub fn get_rsa_signer<P: AsRef<Path>>(
    path: P,
    alg: &str,
    tsa_url: Option<String>,
) -> (RsaSigner, PathBuf) {
    match alg {
        "ps256" | "ps384" | "ps512" => (),
        _ => {
            panic!("Unknown RSA signer alg {:#?}", alg);
        }
    }

    println!("path: {}", path.as_ref().display());

    let mut sign_cert_path = path.as_ref().to_path_buf();
    sign_cert_path.push(alg);
    sign_cert_path.set_extension("pub");

    let mut pem_key_path = path.as_ref().to_path_buf();
    pem_key_path.push(alg);
    pem_key_path.set_extension("pem");

    if !sign_cert_path.exists() || !pem_key_path.exists() {
        panic!(
            "path found: {}, {}",
            sign_cert_path.display(),
            pem_key_path.display()
        );
    }

    println!(
        "path: {}, {}",
        sign_cert_path.display(),
        pem_key_path.display()
    );

    (
        RsaSigner::from_files(&sign_cert_path, &pem_key_path, alg.to_string(), tsa_url).unwrap(),
        sign_cert_path,
    )
}

/// Create a signer that can be used for testing purposes.
///
/// Can generate a [`Signer`] instance for all supported formats.
///
/// # Arguments
///
/// * `path` - A directory (which must already exist) to receive the temporary
///   private key / certificate pair.
/// * `alg` - A format for signing. Must be one of (`rs256`, `rs384`, `rs512`,
///   `ps256`, `ps384`, `ps512`, `es256`, `es384`, `es512`, or `ed25519`).
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
pub fn get_temp_signer_by_alg<P: AsRef<Path>>(
    path: P,
    alg: &str,
    tsa_url: Option<String>,
) -> (Box<dyn Signer>, PathBuf) {
    match alg.to_lowercase().as_str() {
        "ps256" | "ps384" | "ps512" => {
            let (signer, sign_cert_path) = get_rsa_signer(path, alg, tsa_url);
            (Box::new(signer), sign_cert_path)
        }
        "es256" | "es384" | "es512" => {
            let (signer, sign_cert_path) = get_ec_signer(path, alg, tsa_url);
            (Box::new(signer), sign_cert_path)
        }

        "ed25519" => {
            let (signer, sign_cert_path) = get_ed_signer(path, alg, tsa_url);
            (Box::new(signer), sign_cert_path)
        }
        _ => {
            let (signer, sign_cert_path) = get_rsa_signer(path, "ps256", tsa_url);
            (Box::new(signer), sign_cert_path)
        }
    }
}
