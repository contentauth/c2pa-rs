use std::path::Path;

use super::rustls_signer::RustlsSigner;
use crate::{
    error::{Error, Result},
    signer::ConfigurableSigner,
    Signer,
};

/// Creates a signer using signcert and public key
///
/// Can generate a [`Signer`] instance for all supported formats.
///
/// # Arguments
///
/// * `signcert` - A buffer containing a signcert
/// * `pkey` - A buffer containing a public key file
/// * `alg` - A format for signing. Must be one of (`rs256`, `rs384`, `rs512`,
///   `ps256`, `ps384`, `ps512`, `es256`, `es384`, `es512`, or `ed25519`).
/// * `tsa_url` - Optional URL for a timestamp authority.
///
/// # Returns
///
/// Returns a [`Signer`] instance or Error
pub fn get_signer(
    signcert: &[u8],
    pkey: &[u8],
    alg: &str,
    tsa_url: Option<String>,
) -> Result<Box<dyn Signer>> {
    Ok(match alg {
        "ps256" | "ps384" | "ps512" | "es256" | "es384" | "ed25519" => Box::new(
            RustlsSigner::from_signcert_and_pkey(signcert, pkey, alg.to_owned(), tsa_url)?,
        ),
        _ => return Err(Error::BadParam(alg.to_owned())),
    })
}

/// Creates a signer using signcert and public key files
///
/// Can generate a [`Signer`] instance for all supported formats.
///
/// # Arguments
///
/// * `signcert_path` - A path to the signing cert file
/// * `pkey_path` - A path to the public key file
/// * `alg` - A format for signing. Must be one of (`rs256`, `rs384`, `rs512`,
///   `ps256`, `ps384`, `ps512`, `es256`, `es384`, `es512`, or `ed25519`).
/// * `tsa_url` - Optional URL for a timestamp authority.
///
/// # Returns
///
/// Returns a [`Signer`] instance or Error
pub fn get_signer_from_files<P: AsRef<Path>>(
    signcert_path: P,
    pkey_path: P,
    alg: &str,
    tsa_url: Option<String>,
) -> Result<Box<dyn Signer>> {
    Ok(match alg {
        "ps256" | "ps384" | "ps512" | "es256" | "es384" | "ed25519" => Box::new(
            RustlsSigner::from_files(&signcert_path, &pkey_path, alg.to_owned(), tsa_url)?,
        ),
        _ => return Err(Error::BadParam(alg.to_owned())),
    })
}
