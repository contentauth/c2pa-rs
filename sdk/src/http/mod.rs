// Copyright 2025 Adobe. All rights reserved.
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

//! HTTP abstraction layer.
//!
//! This module defines generic traits and helpers for performing HTTP requests
//! without hard-wiring a specific HTTP client. It allows host applications to
//! plug in their own HTTP implementation, restrict where the SDK may connect,
//! or disable networking entirely.
//!
//! # When do outbound network requests occur?
//!
//! The SDK may issue outbound HTTP/S requests in the following scenarios:
//! - [`Reader`]:
//!     - Fetching remote manifests
//!     - Validating CAWG identity assertions
//!     - Fetching OCSP revocation status
//! - [`Builder`]:
//!     - Fetching ingredient remote manifests
//!     - Fetching timestamps
//!     - Fetching [`TimeStamp`] assertions
//!     - Fetching OCSP staples
//!     - Fetching [`CertificateStatus`] assertions
//!
//! [`Reader`]: crate::Reader
//! [`Builder`]: crate::Builder
//! [`TimeStamp`]: crate::assertions::TimeStamp
//! [`CertificateStatus`]: crate::assertions::CertificateStatus

use std::io::{self, Read};

use async_trait::async_trait;
use http::{Request, Response};

use crate::Result;

mod reqwest;
pub mod restricted;
mod ureq;
mod wasi;

// Since we use `http::Request` and `http::Response` we also expose the `http` crate.
pub use http;

/// A resolver for sync (blocking) HTTP requests.
pub trait SyncHttpResolver {
    /// Resolve a [`Request`] into a [`Response`] with a streaming body.
    ///
    /// [`Request`]: http::Request
    /// [`Response`]: http::Response
    fn http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError>;
}

/// A resolver for non-blocking (async) HTTP requests.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait AsyncHttpResolver {
    /// Resolve a [`Request`] into a [`Response`] with a streaming body.
    ///
    /// [`Request`]: http::Request
    /// [`Response`]: http::Response
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError>;
}

/// A generic resolver for [`SyncHttpResolver`].
///
/// This implementation will automatically choose a [`SyncHttpResolver`] based on the
/// enabled features:
/// * `ureq` - use [`ureq::Agent`].
/// * `reqwest_blocking` - use [`reqwest::blocking::Client`].
/// * `wasi` (WASI-only) - use [`wasi::http::outgoing_handler::handle`].
///
/// Note that WASM (non-WASI) does not have a built-in [`SyncHttpResolver`].
pub struct SyncGenericResolver(sync_resolver::Impl);

impl SyncGenericResolver {
    /// Create a new [`SyncGenericResolver`] with an auto-specified [`SyncHttpResolver`].
    ///
    /// This function will create a [`SyncHttpResolver`] that returns [`Error::SyncHttpResolverNotImplemented`]
    /// under any of the following conditions:
    /// * If both `http_reqwest_blocking` and `http_ureq` aren't enabled.
    /// * If the platform is WASM.
    /// * If the platform is WASI and `http_wasi` isn't enabled.
    pub fn new() -> Self {
        Self(sync_resolver::new())
    }
}

impl Default for SyncGenericResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncHttpResolver for SyncGenericResolver {
    fn http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        self.0.http_resolve(request)
    }
}

/// A generic resolver for [`AsyncHttpResolver`].
///
/// This implementation will automatically choose a [`AsyncHttpResolver`] based on the
/// enabled features:
/// * `reqwest` - use [`reqwest::Client`].
/// * `wstd` (WASI-only) - use [`wstd::http::Client`].
pub struct AsyncGenericResolver(async_resolver::Impl);

impl AsyncGenericResolver {
    /// Create a new [`AsyncGenericResolver`] with an auto-specified [`AsyncHttpResolver`].
    ///
    /// This function will create a [`AsyncHttpResolver`] that returns [`Error::AsyncHttpResolverNotImplemented`]
    /// under any of the following conditions:
    /// * If `http_reqwest` isn't enabled.
    /// * If the platform is WASI and `http_wstd` isn't enabled.
    pub fn new() -> Self {
        Self(async_resolver::new())
    }
}

impl Default for AsyncGenericResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AsyncHttpResolver for AsyncGenericResolver {
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        self.0.http_resolve_async(request).await
    }
}

/// An error that occurs during sync/async HTTP resolver resolution.
#[derive(Debug, thiserror::Error)]
pub enum HttpResolverError {
    /// An error occured in the [`http`] crate.
    #[error(transparent)]
    Http(#[from] http::Error),

    /// An error occured in during I/O.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// The sync HTTP resolver is not implemented.
    ///
    /// Note this often occurs when the http-related features are improperly enabled.
    #[error("the sync http resolver is not implemented")]
    SyncHttpResolverNotImplemented,

    /// The async HTTP resolver is not implemented.
    ///
    /// Note this often occurs when the http-related features are improperly enabled.
    #[error("the async http resolver is not implemented")]
    AsyncHttpResolverNotImplemented,

    /// The remote URI is blocked by the allowed list.
    ///
    /// The allowed list is normally set in a [`SyncRestrictedResolver`].
    ///
    /// [`SyncRestrictedResolver`]: restricted::SyncRestrictedResolver
    #[error("remote URI \"{uri}\" is not permitted by the allowed list")]
    UriDisallowed { uri: String },

    /// An error occured from the underlying HTTP resolver.
    #[error("an error occurred from the underlying http resolver")]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "http_reqwest_blocking",
    not(feature = "http_ureq")
))]
mod sync_resolver {
    pub type Impl = reqwest::blocking::Client;
    pub fn new() -> Impl {
        reqwest::blocking::Client::new()
    }
}
#[cfg(all(not(target_arch = "wasm32"), feature = "http_ureq"))]
mod sync_resolver {
    pub type Impl = ureq::Agent;
    pub fn new() -> Impl {
        ureq::agent()
    }
}
#[cfg(all(target_os = "wasi", feature = "http_wasi"))]
mod sync_resolver {
    pub type Impl = super::wasi::sync_impl::SyncWasiResolver;
    pub fn new() -> Impl {
        super::wasi::sync_impl::SyncWasiResolver::new()
    }
}
#[cfg(not(any(
    all(target_os = "wasi", feature = "http_wasi"),
    all(
        not(target_arch = "wasm32"),
        any(feature = "http_ureq", feature = "http_reqwest_blocking")
    )
)))]
mod sync_resolver {
    use super::*;

    pub type Impl = SyncNoopResolver;
    pub fn new() -> Impl {
        SyncNoopResolver
    }

    pub struct SyncNoopResolver;

    impl SyncHttpResolver for SyncNoopResolver {
        fn http_resolve(
            &self,
            _request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            Err(HttpResolverError::SyncHttpResolverNotImplemented)
        }
    }
}

#[cfg(all(not(target_os = "wasi"), feature = "http_reqwest"))]
mod async_resolver {
    pub type Impl = reqwest::Client;
    pub fn new() -> Impl {
        reqwest::Client::new()
    }
}
#[cfg(all(target_os = "wasi", feature = "http_wstd"))]
mod async_resolver {
    pub type Impl = wstd::http::Client;
    pub fn new() -> Impl {
        wstd::http::Client::new()
    }
}
#[cfg(not(any(
    feature = "http_reqwest",
    all(target_os = "wasi", feature = "http_wstd")
)))]
mod async_resolver {
    use super::*;

    pub type Impl = AsyncNoopResolver;
    pub fn new() -> Impl {
        AsyncNoopResolver
    }

    pub struct AsyncNoopResolver;

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl AsyncHttpResolver for AsyncNoopResolver {
        async fn http_resolve_async(
            &self,
            _request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            Err(HttpResolverError::AsyncHttpResolverNotImplemented)
        }
    }
}

// TODO: Use `httpmock` when it's supported for WASM https://github.com/contentauth/c2pa-rs/issues/1378
//       And then also implement `wasi`/`wstd` networking tests.
#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use async_generic::async_generic;

    use super::*;

    fn remote_mock_server<'a>(server: &'a httpmock::MockServer) -> httpmock::Mock<'a> {
        server.mock(|when, then| {
            when.method(httpmock::Method::GET);
            then.status(200).body([1, 2, 3]);
        })
    }

    #[async_generic(async_signature(resolver: impl AsyncHttpResolver))]
    pub fn assert_http_resolver(resolver: impl SyncHttpResolver) {
        use httpmock::MockServer;

        let server = MockServer::start();
        let mock = remote_mock_server(&server);

        let request = Request::get(server.base_url()).body(vec![1, 2, 3]).unwrap();

        let response = if _sync {
            resolver.http_resolve(request).unwrap()
        } else {
            resolver.http_resolve_async(request).await.unwrap()
        };

        let mut response_body = Vec::new();
        response
            .into_body()
            .read_to_end(&mut response_body)
            .unwrap();
        assert_eq!(&response_body, &[1, 2, 3]);

        mock.assert();
    }
}
