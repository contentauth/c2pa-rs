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

#![deny(missing_docs)]

//! The `callback_signer` module provides a way to obtain a [`Signer`]
//! using a callback and public signing certificates.

use crate::{
    error::{Error, Result},
    Signer, SigningAlg,
};

/// Defines a callback interface for a signer
// pub trait SignerCallback: Send + Sync {
//     /// Sign the given bytes and return the signature
//     /// The private key should only be known by the callback's implementation
//     fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>>;
// }
pub type SignerCallback = dyn Fn(&[u8]) -> std::result::Result<Vec<u8>, Error>;

/// Defines a signer that uses a callback to sign data
/// The private key should only be known by the callback
/// This structure is private to this module
/// Should only be created using the `create_callback_signer` function
struct CallbackSigner {
    alg: SigningAlg,

    callback: Box<SignerCallback>,

    signcerts: Vec<u8>,

    reserve_size: usize,

    tsa_url: Option<String>,
}

impl CallbackSigner {
    /// Create a new callback signer
    fn new<C: Into<Vec<u8>>, F>(
        alg: SigningAlg,
        signcerts: C,
        callback: F,
        reserve_size: usize,
        tsa_url: Option<String>,
    ) -> Self
    where
        F: Fn(&[u8]) -> std::result::Result<Vec<u8>, Error> + 'static,
    {
        Self {
            alg,
            callback: Box::new(callback),
            signcerts: signcerts.into(),
            reserve_size,
            tsa_url,
        }
    }
}

impl Signer for CallbackSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        (self.callback)(data)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        let mut pems =
            pem::parse_many(&self.signcerts).map_err(|e| Error::OtherError(Box::new(e)))?;
        Ok(pems.drain(..).map(|p| p.into_contents()).collect())
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }
}

/// Creates a callback signer
/// The private key should only be known by the callback
/// The `signcerts` parameter should be a PEM-encoded certificate chain
/// The `callback` parameter should be a callback that will be used to sign data
/// The `tsa_url` parameter is optional and should be the URL of a Time Stamping Authority
///
/// # Example
/// ```
/// # use c2pa::{create_callback_signer, SigningAlg, SignerCallback, Result};
/// # fn main() -> Result<()> {
///     const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
///     struct MyCallback;
///     impl SignerCallback for MyCallback {
///        fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
///          Ok(vec![0; 64])
///        }
///      }
///      let callback = Box::new(MyCallback);
///      let signer = create_callback_signer(SigningAlg::Ed25519, CERTS, callback, None)?;
/// #    Ok(())
/// }
/// ```
pub fn create_callback_signer<P: Into<Vec<u8>>, F>(
    alg: SigningAlg,
    signcerts: P,
    callback: F, // Box<dyn SignerCallback>,
    tsa_url: Option<String>,
) -> Result<Box<dyn Signer>>
where
    F: Fn(&[u8]) -> Result<Vec<u8>> + 'static,
{
    let signer = CallbackSigner::new(alg, signcerts.into(), callback, 3000, tsa_url);
    Ok(Box::new(signer))
}
