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

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

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
pub fn get_signer<P: AsRef<Path>>(path: P) -> (RsaSigner, PathBuf) {
    let (sign_cert_path, pem_key_path) = make_key_path_pair(path, "temp_key");

    create_x509_key_pair(
        &sign_cert_path,
        &pem_key_path,
        false,
        Some("rsa_padding_mode:pss"),
        Some("-sha256"),
    );

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
    let (key_name, _ec_key_name) = match alg {
        "es256" => ("ec256_key", "prime256v1"),
        "es384" => ("ec384_key", "secp384r1"),
        "es512" => ("ec512_key", "secp521r1"),
        _ => {
            panic!("Unknown EC signer alg {:#?}", alg);
        }
    };

    let (sign_cert_path, pem_key_path) = make_key_path_pair(&path, key_name);

    make_cert_chain(&path, key_name, alg);

    (
        EcSigner::from_files(&sign_cert_path, &pem_key_path, alg.to_string(), tsa_url).unwrap(),
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
    alg: &str,
    tsa_url: Option<String>,
) -> (EdSigner, PathBuf) {
    let (key_name, _openssl_alg_name) = match alg {
        "ed25519" => ("ed25519_key", "ED25519"),
        _ => {
            panic!("Unknown ED signer alg {:#?}", alg);
        }
    };

    let (sign_cert_path, pem_key_path) = make_key_path_pair(&path, key_name);

    make_cert_chain(&path, key_name, alg);

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
    let (key_name, _sha_mode, _rsa_padding_mode) = match alg {
        "rs256" => ("rsa256_key", "-sha256", None),
        "rs384" => ("rsa384_key", "-sha384", None),
        "rs512" => ("rsa512_key", "-sha512", None),
        "ps256" => ("rsa-pss256_key", "-sha256", Some("rsa_padding_mode:pss")),
        "ps384" => ("rsa-pss384_key", "-sha384", Some("rsa_padding_mode:pss")),
        "ps512" => ("rsa-pss512_key", "-sha512", Some("rsa_padding_mode:pss")),
        _ => {
            panic!("Unknown RSA signer alg {:#?}", alg);
        }
    };

    let (sign_cert_path, pem_key_path) = make_key_path_pair(&path, key_name);

    make_cert_chain(&path, key_name, alg);

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
pub fn get_signer_by_alg<P: AsRef<Path>>(
    path: P,
    alg: &str,
    tsa_url: Option<String>,
) -> (Box<dyn Signer>, PathBuf) {
    match alg.to_lowercase().as_str() {
        "rs256" | "rs384" | "rs512" | "ps256" | "ps384" | "ps512" => {
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

fn make_key_path_pair<P: AsRef<Path>>(path: P, key_name: &str) -> (PathBuf, PathBuf) {
    let mut sign_cert_path = path.as_ref().to_path_buf();
    sign_cert_path.push(key_name);
    sign_cert_path.set_extension("pub");
    //println!("sign_cert_path = {:#?}", sign_cert_path);

    let mut pem_key_path = sign_cert_path.clone();
    pem_key_path.set_extension("pem");
    //println!("pem_key_path = {:#?}", pem_key_path);

    (sign_cert_path, pem_key_path)
}

// Create key of specified type for the desired signature type
fn create_keys_by_alg<P: AsRef<Path>>(pem_key_path: P, key_name: &str, key_type: &str) {
    let mut private_key = pem_key_path.as_ref().to_path_buf();
    private_key.push(key_name);
    private_key.set_extension("pkey");
    let private_key_clone = private_key.clone();

    let mut openssl = Command::new("openssl");
    openssl.arg("genpkey").arg("-algorithm");

    match key_type {
        "rsa256" | "rsa384" | "rs512" => {
            openssl
                .arg("RSA")
                .arg("-pkeyopt")
                .arg("rsa_keygen_bits:4096")
                .arg("-out")
                .arg(private_key);
        }
        "ps256" => {
            openssl
                .arg("RSA-PSS")
                .arg("-pkeyopt")
                .arg("rsa_keygen_bits:4096")
                .arg("-pkeyopt")
                .arg("rsa_pss_keygen_md:sha256")
                .arg("-pkeyopt")
                .arg("rsa_pss_keygen_mgf1_md:sha256")
                .arg("-pkeyopt")
                .arg("rsa_pss_keygen_saltlen:32")
                .arg("-out")
                .arg(private_key);
        }
        "ps384" => {
            openssl
                .arg("RSA-PSS")
                .arg("-pkeyopt")
                .arg("rsa_keygen_bits:4096")
                .arg("-pkeyopt")
                .arg("rsa_pss_keygen_md:sha384")
                .arg("-pkeyopt")
                .arg("rsa_pss_keygen_mgf1_md:sha384")
                .arg("-pkeyopt")
                .arg("rsa_pss_keygen_saltlen:48")
                .arg("-out")
                .arg(private_key);
        }
        "ps512" => {
            openssl
                .arg("RSA-PSS")
                .arg("-pkeyopt")
                .arg("rsa_keygen_bits:4096")
                .arg("-pkeyopt")
                .arg("rsa_pss_keygen_md:sha512")
                .arg("-pkeyopt")
                .arg("rsa_pss_keygen_mgf1_md:sha512")
                .arg("-pkeyopt")
                .arg("rsa_pss_keygen_saltlen:64")
                .arg("-out")
                .arg(private_key);
        }
        "es256" => {
            openssl
                .arg("EC")
                .arg("-pkeyopt")
                .arg("ec_paramgen_curve:P-256")
                .arg("-outform")
                .arg("PEM")
                .arg("-out")
                .arg(private_key);
        }
        "es384" => {
            openssl
                .arg("EC")
                .arg("-pkeyopt")
                .arg("ec_paramgen_curve:P-384")
                .arg("-outform")
                .arg("PEM")
                .arg("-out")
                .arg(private_key);
        }
        "es512" => {
            openssl
                .arg("EC")
                .arg("-pkeyopt")
                .arg("ec_paramgen_curve:P-521")
                .arg("-outform")
                .arg("PEM")
                .arg("-out")
                .arg(private_key);
        }
        "ed25519" => {
            openssl.arg("ED25519").arg("-out").arg(private_key);
        }
        _ => return,
    }

    openssl
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let openssl = spawn_openssl(&mut openssl);

    process_openssl_output(openssl);

    // generate the public key name
    let mut public_key = pem_key_path.as_ref().to_path_buf();
    public_key.push(key_name);
    public_key.set_extension("pub_key");

    // generate the public key
    let mut openssl = Command::new("openssl");
    openssl
        .arg("pkey")
        .arg("-in")
        .arg(private_key_clone)
        .arg("-pubout")
        .arg("-outform")
        .arg("PEM")
        .arg("-out")
        .arg(public_key);

    openssl
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let openssl = spawn_openssl(&mut openssl);

    process_openssl_output(openssl);
}

#[allow(dead_code)]
enum CertType {
    Root,
    Intermediate,
    Client,
}

// Generate a typical certificate chain from root CA -> intermediate CA -> C2PA signing cert
fn make_cert_chain<P: AsRef<Path>>(path: P, key_name: &str, alg: &str) {
    let root_name = format!("{}_root", key_name);
    let intermediate_name = format!("{}_intermediate", key_name);
    let signer_name = format!("{}_signer", key_name);

    let (sign_chain_path, pem_key_path) = make_key_path_pair(&path, key_name);

    // create Root CA
    create_keys_by_alg(&path, &root_name, alg);

    let root_path = create_x509_cert_by_type(
        &path,
        &root_name,
        alg,
        "C2PA Test Root CA",
        "Root CA",
        CertType::Root,
        None,
    );

    // create intermediate Root CA
    create_keys_by_alg(&path, &intermediate_name, alg);

    let intermediate_path = create_x509_cert_by_type(
        &path,
        &intermediate_name,
        alg,
        "C2PA Test Intermediate Root CA",
        "Intermediate CA",
        CertType::Intermediate,
        Some(root_name),
    );

    // create signing certificate
    create_keys_by_alg(&path, &signer_name, alg);

    let mut signer_path = create_x509_cert_by_type(
        &path,
        &signer_name,
        alg,
        "C2PA Test Signing Cert",
        "C2PA Signer",
        CertType::Client,
        Some(intermediate_name),
    );

    // make cert chain
    let mut cat = if cfg!(target_os = "windows") {
        let mut cmd = Command::new("copy");
        cmd.arg(signer_path.clone())
            .arg("+")
            .arg(intermediate_path)
            .arg("+")
            .arg(root_path)
            .arg(sign_chain_path.clone());

        cmd
    } else {
        let mut cmd = Command::new("cat");
        cmd.arg(signer_path.clone())
            .arg(intermediate_path)
            .arg(root_path);

        cmd
    };

    match cat.output() {
        Ok(cat_stat) => {
            if cat_stat.status.success() {
                // capture the output for systems that support "cat"
                if !cfg!(target_os = "windows")
                    && std::fs::write(sign_chain_path, &cat_stat.stdout).is_err()
                {
                    eprintln!("Could not generate certificate chain");
                    panic!("Unable to merge certs");
                }
            } else {
                eprintln!(
                    "Could not generate certificate chain for {}:{}",
                    key_name, alg
                );
                panic!("Unable to merge certs\n\n{:#?}", cat_stat.status.code());
            }
        }
        Err(e) => {
            eprintln!(
                "Could not generate certificate chain for {}:{}",
                key_name, alg
            );
            panic!("Unable to merge certs\n\n{:#?}", e);
        }
    }

    // copy signing private key
    signer_path.set_extension("pkey");
    if std::fs::copy(signer_path, pem_key_path).is_err() {
        eprintln!("Could not copy private key for {}:{}", key_name, alg);
        panic!("Unable to copy file");
    }
}
fn add_root_extensions(openssl: &mut Command) {
    openssl
        .arg("-days")
        .arg("3650")
        .arg("-addext")
        .arg("authorityKeyIdentifier = keyid:always,issuer")
        .arg("-addext")
        .arg("basicConstraints = critical,CA:true")
        .arg("-addext")
        .arg("keyUsage = critical,digitalSignature,keyCertSign,cRLSign");
}

fn add_intermediate_extensions(openssl: &mut Command) {
    openssl
        .arg("-addext")
        .arg("basicConstraints = critical,CA:true")
        .arg("-addext")
        .arg("keyUsage =critical,digitalSignature,keyCertSign,cRLSign");
}

fn add_client_extensions(openssl: &mut Command) {
    openssl
        .arg("-addext")
        .arg("basicConstraints = critical,CA:false")
        .arg("-addext")
        .arg("extendedKeyUsage = critical,emailProtection")
        .arg("-addext")
        .arg("keyUsage = critical,digitalSignature,nonRepudiation");
}

fn add_cert_hash(openssl: &mut Command, key_type: &str) {
    match key_type {
        "rsa256" | "es256" => openssl.arg("-sha256"),
        "rsa384" | "es384" => openssl.arg("-sha384"),
        "rs512" | "es512" => openssl.arg("-sha512"),
        "ps256" => openssl.arg("-sha256"),
        "ps384" => openssl.arg("-sha384"),
        "ps512" => openssl.arg("-sha512"),
        _ => openssl.arg("-sha256"),
    };
}
fn create_x509_cert_by_type<P: AsRef<Path>>(
    pem_key_path: P,
    key_name: &str,
    key_type: &str,
    organization: &str,
    common_name: &str,
    cert_type: CertType,
    signing_ca: Option<String>,
) -> PathBuf {
    let mut private_key = pem_key_path.as_ref().to_path_buf();
    private_key.push(key_name);
    private_key.set_extension("pkey");

    let mut ca = pem_key_path.as_ref().to_path_buf();
    ca.push(key_name);
    ca.set_extension("pub");

    let outpath = ca.clone(); // return path to generated certificate

    let subj = format!(
        "/C=US/ST=CA/L=Somewhere/O={}/OU=FOR TESTING_ONLY/CN={}",
        organization, common_name
    );

    let mut openssl = Command::new("openssl");

    match cert_type {
        CertType::Root => {
            // create cert
            openssl
                .arg("req")
                .arg("-x509")
                .arg("-key")
                .arg(private_key)
                .arg("-out")
                .arg(ca)
                .arg("-subj")
                .arg(subj);

            // make root cert
            add_root_extensions(&mut openssl);

            // add cert hash
            add_cert_hash(&mut openssl, key_type);

            // execute command
            process_openssl_output(spawn_openssl(&mut openssl));
        }
        CertType::Intermediate => {
            if let Some(signing_ca) = signing_ca {
                let mut csr = pem_key_path.as_ref().to_path_buf();
                csr.push(key_name);
                csr.set_extension("csr");

                // create csr
                openssl
                    .arg("req")
                    .arg("-key")
                    .arg(private_key)
                    .arg("-new")
                    .arg("-out")
                    .arg(csr.clone())
                    .arg("-subj")
                    .arg(subj);

                // make intermediate cert
                add_intermediate_extensions(&mut openssl);

                // execute command
                process_openssl_output(spawn_openssl(&mut openssl));

                // sign CSR with desired cert
                let mut signer = pem_key_path.as_ref().to_path_buf();
                signer.push(signing_ca.clone());
                signer.set_extension("pub");

                let mut signer_pkey = pem_key_path.as_ref().to_path_buf();
                signer_pkey.push(signing_ca);
                signer_pkey.set_extension("pkey");

                let mut openssl = Command::new("openssl");

                openssl
                    .arg("x509")
                    .arg("-req")
                    .arg("-in")
                    .arg(csr)
                    .arg("-CA")
                    .arg(signer)
                    .arg("-CAkey")
                    .arg(signer_pkey)
                    .arg("-days")
                    .arg("365")
                    .arg("-out")
                    .arg(ca)
                    .arg("-copy_extensions")
                    .arg("copyall");

                // add cert hash
                add_cert_hash(&mut openssl, key_type);

                // execute command
                process_openssl_output(spawn_openssl(&mut openssl));
            }
        }
        CertType::Client => {
            if let Some(signing_ca) = signing_ca {
                let mut csr = pem_key_path.as_ref().to_path_buf();
                csr.push(key_name);
                csr.set_extension("csr");

                // create csr
                openssl
                    .arg("req")
                    .arg("-key")
                    .arg(private_key)
                    .arg("-new")
                    .arg("-out")
                    .arg(csr.clone())
                    .arg("-subj")
                    .arg(subj);

                // make intermediate cert
                add_client_extensions(&mut openssl);

                // execute command
                process_openssl_output(spawn_openssl(&mut openssl));

                // sign CSR with desired cert
                let mut signer = pem_key_path.as_ref().to_path_buf();
                signer.push(signing_ca.clone());
                signer.set_extension("pub");

                let mut signer_pkey = pem_key_path.as_ref().to_path_buf();
                signer_pkey.push(signing_ca);
                signer_pkey.set_extension("pkey");

                let mut openssl = Command::new("openssl");

                openssl
                    .arg("x509")
                    .arg("-req")
                    .arg("-in")
                    .arg(csr)
                    .arg("-CA")
                    .arg(signer)
                    .arg("-CAkey")
                    .arg(signer_pkey)
                    .arg("-days")
                    .arg("90")
                    .arg("-out")
                    .arg(ca.clone())
                    .arg("-copy_extensions")
                    .arg("copyall");

                // add cert hash
                add_cert_hash(&mut openssl, key_type);

                // execute command
                process_openssl_output(spawn_openssl(&mut openssl));
            }
        }
    }
    outpath
}

// The .x509 directory at the root of this repo is flagged
// as outside of source control via .gitignore.
//
// This function panics if unable to invoke openssl as expected.
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

fn spawn_openssl(openssl: &mut Command) -> Child {
    //println!("openssl command = {:#?}", openssl);

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
            eprintln!("stdout\n\n{:?}\n\n", stdout);
        }
        if let Ok(stderr) = String::from_utf8(output.stderr) {
            eprintln!("stderr\n\n{:?}\n\n", stderr);
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
