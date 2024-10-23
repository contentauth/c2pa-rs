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

//! The `create_signer` module provides a way to obtain a [`Signer`]
//! instance for each signing format supported by this crate.
#[cfg(feature = "file_io")]
use std::path::Path;

use crate::{
    error::Result,
    openssl::{EcSigner, EdSigner, RsaSigner},
    signer::ConfigurableSigner,
    Signer, SigningAlg,
};

/// Creates a [`Signer`] instance using signing certificate and private key
/// as byte slices.
///
/// The signing certificate and private key are passed to the underlying
/// C++ code, which copies them into its own storage.
///
/// # Arguments
///
/// * `signcert` - Signing certificate
/// * `pkey` - Private key
/// * `alg` - Format for signing
/// * `tsa_url` - Optional URL for a timestamp authority
pub fn from_keys(
    signcert: &[u8],
    pkey: &[u8],
    alg: SigningAlg,
    tsa_url: Option<String>,
) -> Result<Box<dyn Signer>> {
    Ok(match alg {
        SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512 => Box::new(
            RsaSigner::from_signcert_and_pkey(signcert, pkey, alg, tsa_url)?,
        ),
        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => Box::new(
            EcSigner::from_signcert_and_pkey(signcert, pkey, alg, tsa_url)?,
        ),
        SigningAlg::Ed25519 => Box::new(EdSigner::from_signcert_and_pkey(
            signcert, pkey, alg, tsa_url,
        )?),
    })
}

/// Creates a [`Signer`] instance using signing certificate and
/// private key files.
///
/// # Arguments
///
/// * `signcert_path` - Path to the signing certificate file
/// * `pkey_path` - Path to the private key file
/// * `alg` - Format for signing
/// * `tsa_url` - Optional URL for a timestamp authority
#[cfg(feature = "file_io")]
pub fn from_files<P: AsRef<Path>>(
    signcert_path: P,
    pkey_path: P,
    alg: SigningAlg,
    tsa_url: Option<String>,
) -> Result<Box<dyn Signer>> {
    Ok(match alg {
        SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512 => Box::new(
            RsaSigner::from_files(&signcert_path, &pkey_path, alg, tsa_url)?,
        ),
        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => Box::new(
            EcSigner::from_files(&signcert_path, &pkey_path, alg, tsa_url)?,
        ),
        SigningAlg::Ed25519 => Box::new(EdSigner::from_files(
            &signcert_path,
            &pkey_path,
            alg,
            tsa_url,
        )?),
    })
}
