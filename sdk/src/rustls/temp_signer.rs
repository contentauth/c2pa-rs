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
#![allow(dead_code)]

//! Temporary signing instances for testing purposes.
//!
//! This module contains functions to create self-signed certificates
//! and provision [`RustlsSigner`] instances for each of the supported signature
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

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use crate::{
    rustls::RustlsSigner,
    signer::{ConfigurableSigner, Signer},
    SigningAlg,
};

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
pub fn get_temp_signer<P: AsRef<Path>>(path: P) -> (RustlsSigner, PathBuf) {
    let (sign_cert_path, pem_key_path) = make_key_path_pair(path, "temp_key");
    //
    create_x509_key_pair(
        &sign_cert_path,
        &pem_key_path,
        false,
        Some("rsa_padding_mode:pss"),
        Some("-sha256"),
    );

    (
        RustlsSigner::from_files(&sign_cert_path, &pem_key_path, SigningAlg::Ps256, None).unwrap(),
        sign_cert_path,
    )
}

fn make_key_path_pair<P: AsRef<Path>>(path: P, key_name: &str) -> (PathBuf, PathBuf) {
    let mut sign_cert_path = path.as_ref().to_path_buf();

    let mut pem_key_path = sign_cert_path.join(key_name);
    pem_key_path.set_extension("pem");

    sign_cert_path.push(key_name);
    sign_cert_path.set_extension("pub");

    (sign_cert_path, pem_key_path)
}

// The .x509 directory at the root of this repo is flagged
// as outside of source control via .gitignore.
//
// This function panics if unable to invoke openssl as expected.
//
fn create_x509_key_pair(
    sign_cert_path: &Path,
    pem_key_path: &Path,
    has_priv_key: bool,
    rsa_padding_mode: Option<&str>,
    sha_mode: Option<&str>,
) {
    let mut openssl = Command::new("openssl");
    openssl.arg("req").arg("-new");

    if !has_priv_key {
        openssl.arg("-newkey").arg("rsa:4096").arg("-nodes");
    }

    if let Some(rsa_padding_mode) = rsa_padding_mode {
        openssl.arg("-sigopt").arg(rsa_padding_mode);
    }

    openssl
        .arg("-days")
        .arg("180")
        .arg("-extensions")
        .arg("v3_ca")
        .arg("-addext")
        .arg("keyUsage = digitalSignature")
        .arg("-addext")
        .arg("extendedKeyUsage = emailProtection")
        .arg("-x509")
        .arg(if has_priv_key { "-key" } else { "-keyout" })
        .arg(pem_key_path)
        .arg("-out")
        .arg(sign_cert_path);

    if let Some(sha_mode) = sha_mode {
        openssl.arg(sha_mode);
    }

    openssl
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut openssl = spawn_openssl(&mut openssl);

    let mut openssl_stdin = openssl.stdin.take().unwrap();
    writeln!(&mut openssl_stdin, "us").unwrap();
    writeln!(&mut openssl_stdin, "ca").unwrap();
    writeln!(&mut openssl_stdin, "Somewhere").unwrap();
    writeln!(&mut openssl_stdin, "Some Company").unwrap();
    writeln!(&mut openssl_stdin, "FOR TESTING ONLY").unwrap();
    writeln!(&mut openssl_stdin, "example.com").unwrap();
    writeln!(&mut openssl_stdin).unwrap(); // Don't provide an email address.
    drop(openssl_stdin);

    process_openssl_output(openssl);
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
    alg: SigningAlg,
    tsa_url: Option<String>,
) -> (RustlsSigner, PathBuf) {
    match alg {
        // SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => (),
        SigningAlg::Es256 | SigningAlg::Es384 => (),
        _ => {
            panic!("Unknown EC signer alg {:#?}", alg);
        }
    }

    let mut sign_cert_path = path.as_ref().to_path_buf();
    sign_cert_path.push(alg.to_string());
    sign_cert_path.set_extension("pub");

    let mut pem_key_path = path.as_ref().to_path_buf();
    pem_key_path.push(alg.to_string());
    pem_key_path.set_extension("pem");

    (
        RustlsSigner::from_files(&sign_cert_path, &pem_key_path, alg, tsa_url).unwrap(),
        sign_cert_path,
    )
}

/// Create an OpenSSL ES256 signer that can be used for testing purposes.
///
/// # Arguments
///
/// * `path` - A directory (which must already exist) to receive the temporary
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
    alg: SigningAlg,
    tsa_url: Option<String>,
) -> (RustlsSigner, PathBuf) {
    if alg != SigningAlg::Ed25519 {
        panic!("Unknown ED signer alg {:#?}", alg);
    }

    let mut sign_cert_path = path.as_ref().to_path_buf();
    sign_cert_path.push(alg.to_string());
    sign_cert_path.set_extension("pub");

    let mut pem_key_path = path.as_ref().to_path_buf();
    pem_key_path.push(alg.to_string());
    pem_key_path.set_extension("pem");

    (
        RustlsSigner::from_files(&sign_cert_path, &pem_key_path, alg, tsa_url).unwrap(),
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
    alg: SigningAlg,
    tsa_url: Option<String>,
) -> (RustlsSigner, PathBuf) {
    match alg {
        SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512 => (),
        _ => {
            panic!("Unknown RSA signer alg {:#?}", alg);
        }
    }

    let mut sign_cert_path = path.as_ref().to_path_buf();
    sign_cert_path.push(alg.to_string());
    sign_cert_path.set_extension("pub");

    let mut pem_key_path = path.as_ref().to_path_buf();
    pem_key_path.push(alg.to_string());
    pem_key_path.set_extension("pem");

    println!(
        "path found: {}, {}",
        sign_cert_path.display(),
        pem_key_path.display()
    );

    if !sign_cert_path.exists() || !pem_key_path.exists() {
        panic!(
            "path found: {}, {}",
            sign_cert_path.display(),
            pem_key_path.display()
        );
    }

    (
        RustlsSigner::from_files(&sign_cert_path, &pem_key_path, alg, tsa_url).unwrap(),
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
    alg: &SigningAlg,
    tsa_url: Option<String>,
) -> (Box<dyn Signer>, PathBuf) {
    match alg {
        SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512 => {
            let (signer, sign_cert_path) = get_rsa_signer(path, *alg, tsa_url);
            (Box::new(signer), sign_cert_path)
        }
        // SigningAlg::Es512
        SigningAlg::Es256 | SigningAlg::Es384 => {
            let (signer, sign_cert_path) = get_ec_signer(path, *alg, tsa_url);
            (Box::new(signer), sign_cert_path)
        }
        SigningAlg::Ed25519 => {
            let (signer, sign_cert_path) = get_ed_signer(path, *alg, tsa_url);
            (Box::new(signer), sign_cert_path)
        }
        _ => {
            let (signer, sign_cert_path) = get_rsa_signer(path, SigningAlg::Ps256, tsa_url);
            (Box::new(signer), sign_cert_path)
        }
    }
}

fn spawn_openssl(openssl: &mut Command) -> Child {
    match openssl.spawn() {
        Ok(openssl) => openssl,
        Err(e) => {
            eprintln!("Please ensure that openssl is installed on this device.");
            print_mac_openssl_warning();
            panic!("Unable to invoke openssl\n\n{:#?}", e);
        }
    }
}

fn process_openssl_output(openssl: Child) {
    let output = openssl.wait_with_output().unwrap();

    if !output.status.success() {
        eprintln!("openssl exited with status {:?}\n\n", output.status);

        if let Ok(stdout) = String::from_utf8(output.stdout) {
            eprintln!("stdout\n\n{stdout:?}\n\n");
        }
        if let Ok(stderr) = String::from_utf8(output.stderr) {
            eprintln!("stderr\n\n{stderr:?}\n\n");
        }

        print_mac_openssl_warning();

        panic!("Unable to construct public/private key pair; exiting");
    }
}

fn print_mac_openssl_warning() {
    #[cfg(target_os = "macos")]
    {
        eprintln!();
        eprintln!("If you have problems generating certs on MacOS, you may need to replace the built-in version");
        eprintln!("of openssl with a more current version. Try this:");
        eprintln!();
        eprintln!("    $ openssl version");
        eprintln!();
        eprintln!("If your version is 1.x.x, try this:");
        eprintln!();
        eprintln!("    $ brew install openssl");
        eprintln!();
        eprintln!("and then update your path (via .zshrc or similar) as follows:");
        eprintln!();
        eprintln!("    $ export PATH=\"/usr/local/opt/openssl@3/bin:$PATH\"");
        eprintln!();
    }
}

/// Create a signer that can be used for testing purposes.
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
pub fn get_signer<P: AsRef<Path>>(
    path: P,
    alg: SigningAlg,
    tsa_url: Option<String>,
) -> (RustlsSigner, PathBuf) {
    let (key_name, ec_key_name) = match alg {
        SigningAlg::Es256 => ("ec256_key", "prime256v1"),
        SigningAlg::Es384 => ("ec384_key", "secp384r1"),
        _ => {
            panic!("Unknown EC signer alg {:#?}", alg);
        }
    };

    let (sign_cert_path, pem_key_path) = make_key_path_pair(path, key_name);

    let mut openssl = Command::new("openssl");
    openssl
        .arg("ecparam")
        .arg("-genkey")
        .arg("-name")
        .arg(ec_key_name)
        .arg("-noout")
        .arg("-out")
        .arg(&pem_key_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    process_openssl_output(spawn_openssl(&mut openssl));

    create_x509_key_pair(&sign_cert_path, &pem_key_path, true, None, Some("-sha256"));

    (
        RustlsSigner::from_files(&sign_cert_path, &pem_key_path, alg, tsa_url).unwrap(),
        sign_cert_path,
    )
}
