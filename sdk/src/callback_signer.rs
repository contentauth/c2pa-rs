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

/// Defines a context for a signer
pub type SignerContext = dyn std::any::Any;

/// Defines a callback function interface for a signer
/// The callback should return a signature for the given data
/// The signature should be in the format expected by the `Signer`
/// The callback should return an error if the data cannot be signed
pub type CallbackFunc = dyn Fn(&SignerContext, &[u8]) -> std::result::Result<Vec<u8>, Error>;

/// Defines a signer that uses a callback to sign data
/// The private key should only be known by the callback
/// This structure is private to this module
/// Should only be created using the `create_callback_signer` function
pub struct CallbackSigner {
    /// An opaque context for the signer, used to store any necessary state
    pub context: Box<SignerContext>,
    /// The callback to use to sign data
    pub callback: Box<CallbackFunc>,
    /// The signing algorithm to use
    pub alg: SigningAlg,
    /// The public certificates to use in PEM format
    pub certs: Vec<u8>,
    /// A max size to reserve for the signature
    pub reserve_size: usize,
    /// The optional URL of a Time Stamping Authority
    pub tsa_url: Option<String>,
}

impl CallbackSigner {
    /// Create a new callback signer
    pub fn new<F, T>(callback: F, alg: SigningAlg, certs: T) -> Self
    where
        F: Fn(&SignerContext, &[u8]) -> std::result::Result<Vec<u8>, Error> + 'static,
        T: Into<Vec<u8>>,
    {
        let certs = certs.into();
        let reserve_size = 10000 + certs.len();
        Self {
            context: Box::new(()),
            callback: Box::new(callback),
            alg,
            certs,
            reserve_size,
            ..Default::default()
        }
    }

    /// Set a time stamping authority URL to call when signing
    pub fn set_tsa_url<S: Into<String>>(mut self, url: S) -> Self {
        self.tsa_url = Some(url.into());
        self
    }
}

// this default is only for for struct completion, do not use on its own
impl Default for CallbackSigner {
    fn default() -> Self {
        Self {
            context: Box::new(()),
            callback: Box::new(|_, _| Err(Error::UnsupportedType)),
            alg: SigningAlg::Es256,
            certs: Vec::new(),
            reserve_size: 10000,
            tsa_url: None,
        }
    }
}

impl Signer for CallbackSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        (self.callback)(&*self.context, data)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        let mut pems = pem::parse_many(&self.certs).map_err(|e| Error::OtherError(Box::new(e)))?;
        Ok(pems.drain(..).map(|p| p.into_contents()).collect())
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        let headers: Option<Vec<(String, String)>> = self.timestamp_request_headers();

        self.time_authority_url()
            .map(|url| crate::time_stamp::default_rfc3161_request(&url, headers, message))
    }

    #[cfg(target_arch = "wasm32")]
    fn send_timestamp_request(&self, _message: &[u8]) -> Option<Result<Vec<u8>>> {
        None
    }
}
