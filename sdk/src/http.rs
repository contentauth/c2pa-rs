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

use std::io::{self, Read};

use async_trait::async_trait;
use http::{Request, Response};

use crate::Result;

/// A resolver for sync (blocking) HTTP requests.
pub trait SyncHttpResolver {
    /// Resolve a [`http::Request`] into a [`http::Response`] with a streaming body.
    fn http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError>;
}

/// A resolver for non-blocking (async) HTTP requests.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait AsyncHttpResolver {
    /// Resolve a [`http::Request`] into a [`http::Response`] with a streaming body.
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
pub struct SyncGenericResolver {
    http_resolver: Box<dyn SyncHttpResolver>,
}

impl SyncGenericResolver {
    /// Create a new [`SyncGenericResolver`] with an auto-specified [`SyncHttpResolver`].
    ///
    /// Note that if `http_ureq` and `http_reqwest_blocking` are enabled at the same time, this
    /// function will panic.
    #[cfg(any(
        // 1. It's `wasi` and `http_wasi` is enabled.
        all(target_os = "wasi", feature = "http_wasi"),
        // 2. It's not `wasm32` and either `http_ureq` or `http_reqwest_blocking` are enabled.
        all(
            not(target_arch = "wasm32"),
            any(feature = "http_ureq", feature = "http_reqwest_blocking")
        )
    ))]
    pub fn new() -> Self {
        #[cfg(all(feature = "http_ureq", feature = "http_reqwest_blocking"))]
        panic!("cannot auto-specify a `SyncHttpResolver` if `http_req` and `http_reqwest_blocking` are enabled simultaneously");

        Self {
            #[cfg(all(feature = "http_ureq", not(target_os = "wasi")))]
            http_resolver: Box::new(ureq::agent()),
            #[cfg(all(feature = "http_reqwest_blocking", not(target_os = "wasi")))]
            http_resolver: Box::new(reqwest::blocking::Client::new()),
            #[cfg(all(target_os = "wasi", feature = "http_wasi"))]
            http_resolver: Box::new(sync_wasi_resolver::SyncWasiResolver::new()),
        }
    }

    /// The `http_ureq`, `http_reqwest_blocking`, nor `http_wasi` features are enabled! Ensure only
    /// one feature is enabled otherwise this function will construct a [`SyncGenericResolver`] that
    /// always returns [`Error::SyncHttpResolverNotImplemented`].
    #[cfg(not(any(
        all(target_os = "wasi", feature = "http_wasi"),
        all(
            not(target_arch = "wasm32"),
            any(feature = "http_ureq", feature = "http_reqwest_blocking")
        )
    )))]
    pub fn new() -> Self {
        struct NoopSyncResolver;

        impl SyncHttpResolver for NoopSyncResolver {
            fn http_resolve(
                &self,
                _request: Request<Vec<u8>>,
            ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
                Err(HttpResolverError::SyncHttpResolverNotImplemented)
            }
        }

        Self {
            http_resolver: Box::new(NoopSyncResolver),
        }
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
        self.http_resolver.http_resolve(request)
    }
}

/// A generic resolver for [`AsyncHttpResolver`].
///
/// This implementation will automatically choose a [`AsyncHttpResolver`] based on the
/// enabled features:
/// * `reqwest` - use [`reqwest::Client`].
/// * `wstd` (WASI-only) - use [`wstd::http::Client`].
pub struct AsyncGenericResolver {
    #[cfg(not(target_os = "wasi"))]
    http_resolver: Box<dyn AsyncHttpResolver + Send + Sync>,
    #[cfg(target_os = "wasi")]
    http_resolver: Box<dyn AsyncHttpResolver>,
}

impl AsyncGenericResolver {
    /// Create a new [`AsyncGenericResolver`] with an auto-specified [`AsyncHttpResolver`].
    #[cfg(any(
        // 1. `http_reqwest` is enabled.
        feature = "http_reqwest",
        // 2. It's `wasi` and `http_wstd` is enabled.
        all(target_os = "wasi", feature = "http_wstd")
    ))]
    pub fn new() -> Self {
        Self {
            #[cfg(all(feature = "http_reqwest", not(target_os = "wasi")))]
            http_resolver: Box::new(reqwest::Client::new()),
            #[cfg(all(target_os = "wasi", feature = "http_wstd"))]
            http_resolver: Box::new(wstd::http::Client::new()),
        }
    }

    /// The `http_reqwest` nor `http_wstd` features are enabled! This function will
    /// construct a [`AsyncGenericResolver`] that always returns
    /// [`Error::AsyncHttpResolverNotImplemented`].
    #[cfg(not(any(
        feature = "http_reqwest",
        all(target_os = "wasi", feature = "http_wstd")
    )))]
    pub fn new() -> Self {
        struct NoopAsyncResolver;

        #[async_trait(?Send)]
        impl AsyncHttpResolver for NoopAsyncResolver {
            async fn http_resolve_async(
                &self,
                _request: Request<Vec<u8>>,
            ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
                Err(HttpResolverError::AsyncHttpResolverNotImplemented)
            }
        }

        Self {
            http_resolver: Box::new(NoopAsyncResolver),
        }
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
        self.http_resolver.http_resolve_async(request).await
    }
}

/// An error that occurs during sync/async http resolver resolution.
#[derive(Debug, thiserror::Error)]
pub enum HttpResolverError {
    /// An error occured in the [`http`] crate.
    #[error(transparent)]
    Http(#[from] http::Error),

    /// An error occured in during I/O.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// The sync http resolver is not implemented.
    ///
    /// Note this often occurs when the http-related features are improperly enabled.
    #[error("the sync http resolver is not implemented")]
    SyncHttpResolverNotImplemented,

    /// The async http resolver is not implemented.
    ///
    /// Note this often occurs when the http-related features are improperly enabled.
    #[error("the async http resolver is not implemented")]
    AsyncHttpResolverNotImplemented,

    /// An error occured from the underlying http resolver.
    #[error("an error occurred from the underlying http resolver")]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

#[cfg(all(feature = "http_reqwest_blocking", not(target_os = "wasi")))]
mod sync_reqwest_resolver {
    use std::io::Cursor;

    use super::*;

    impl SyncHttpResolver for reqwest::blocking::Client {
        fn http_resolve(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            let response = self.execute(request.try_into()?)?;

            let mut builder = http::Response::builder()
                .status(response.status())
                .version(response.version());

            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }

            Ok(builder.body(Box::new(Cursor::new(response.bytes()?)) as Box<dyn Read>)?)
        }
    }
}

#[cfg(all(feature = "http_ureq", not(target_os = "wasi")))]
mod sync_ureq_resolver {
    use http::header;

    use super::*;

    impl SyncHttpResolver for ureq::Agent {
        fn http_resolve(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            let response = self.run(request)?;

            let mut builder = http::Response::builder()
                .status(response.status())
                .version(response.version());

            if let Some(content_type) = response.headers().get(header::CONTENT_TYPE) {
                builder = builder.header(header::CONTENT_TYPE, content_type);
            }

            let body = response.into_body().into_reader();
            Ok(builder.body(Box::new(body) as Box<dyn Read>)?)
        }
    }

    impl From<ureq::Error> for HttpResolverError {
        fn from(value: ureq::Error) -> Self {
            Self::Other(Box::new(value))
        }
    }
}

#[cfg(all(feature = "http_reqwest", not(target_os = "wasi")))]
mod async_reqwest_resolver {
    use std::io::Cursor;

    use super::*;

    #[async_trait]
    impl AsyncHttpResolver for reqwest::Client {
        async fn http_resolve_async(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            let response = self.execute(request.try_into()?).await?;

            let mut builder = Response::builder()
                .status(response.status())
                .version(response.version());

            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }

            Ok(builder.body(Box::new(Cursor::new(response.bytes().await?)) as Box<dyn Read>)?)
        }
    }
}

#[cfg(all(
    any(feature = "http_reqwest", feature = "http_reqwest_blocking"),
    not(target_os = "wasi")
))]
mod reqwest_resolver {
    use super::*;

    impl From<reqwest::Error> for HttpResolverError {
        fn from(value: reqwest::Error) -> Self {
            Self::Other(Box::new(value))
        }
    }
}

// TODO: Switch to reqwest_blocking once it supports WASI https://github.com/seanmonstar/reqwest/issues/2294
#[cfg(all(target_os = "wasi", feature = "http_wasi"))]
mod sync_wasi_resolver {
    use std::io::Read;

    use wasi::http::{
        outgoing_handler::{self, OutgoingRequest},
        types::{Fields, IncomingBody, InputStream},
    };

    use super::*;

    struct WasiStream {
        // Important that `stream` is above `body` so that it's dropped first.
        stream: InputStream,
        _body: IncomingBody,
    }

    impl Read for WasiStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            Read::read(&mut self.stream, buf)
        }
    }

    /// A resolver for sync WASI network requests.
    pub struct SyncWasiResolver {}

    impl SyncWasiResolver {
        /// Create a new [`SyncWasiResolver`].
        pub fn new() -> Self {
            Self {}
        }
    }

    impl SyncHttpResolver for SyncWasiResolver {
        fn http_resolve(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            let wasi_request = OutgoingRequest::new(Fields::new());

            let path_with_query = request
                .uri()
                .path_and_query()
                .map(|path_and_query| path_and_query.as_str());
            wasi_request
                .set_path_with_query(path_with_query)
                .map_err(|_| WasiError)?;

            let authority = request
                .uri()
                .authority()
                .map(|authority| authority.as_str());
            wasi_request
                .set_authority(authority)
                .map_err(|_| WasiError)?;

            let scheme = match request.uri().scheme_str() {
                Some(scheme) => match scheme {
                    "http" => Some(wasi::http::types::Scheme::Http),
                    "https" => Some(wasi::http::types::Scheme::Https),
                    scheme => Some(wasi::http::types::Scheme::Other(scheme.to_owned())),
                },
                None => None,
            };
            wasi_request
                .set_scheme(scheme.as_ref())
                .map_err(|_| WasiError)?;

            let wasi_response = outgoing_handler::handle(wasi_request, None)?;
            wasi_response.subscribe().block();
            let wasi_response = wasi_response
                .get()
                .ok_or(WasiError)?
                .map_err(|_| WasiError)??;

            let mut response = Response::builder().status(wasi_response.status());
            for (name, value) in wasi_response.headers().entries() {
                response = response.header(name, value);
            }

            let body = wasi_response.consume().map_err(|_| WasiError)?;
            let stream = body.stream().map_err(|_| WasiError)?;

            // The reason we make this struct is because `body` must live for as long as `stream`
            // or else `wasi` will panic.
            let stream = WasiStream {
                stream,
                _body: body,
            };

            Ok(response.body(Box::new(stream) as Box<dyn Read>)?)
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("an unknown error occurred in `wasi`")]
    struct WasiError;

    // WASI returns `()` as their error type, sometimes..
    impl From<()> for WasiError {
        fn from(_: ()) -> Self {
            Self
        }
    }

    impl From<WasiError> for HttpResolverError {
        fn from(value: WasiError) -> Self {
            HttpResolverError::Other(Box::new(value))
        }
    }

    impl From<outgoing_handler::ErrorCode> for HttpResolverError {
        fn from(value: outgoing_handler::ErrorCode) -> Self {
            Self::Other(Box::new(value))
        }
    }
}

// TODO: Switch to reqwest once it supports WASI https://github.com/seanmonstar/reqwest/issues/2294
#[cfg(all(target_os = "wasi", feature = "http_wstd"))]
mod async_wasi_resolver {
    use std::io::Cursor;

    use wstd::http::body::StreamedBody;

    use super::*;

    #[async_trait(?Send)]
    impl AsyncHttpResolver for wstd::http::Client {
        async fn http_resolve_async(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            let request = request.map(|body| StreamedBody::new(wstd::io::Cursor::new(body)));
            let mut response = self.send(request).await?;

            let bytes = response.body_mut().bytes().await?;
            Ok(response.map(|_| Box::new(Cursor::new(bytes)) as Box<dyn Read>))
        }
    }

    // `wstd` errors are converted to a string because they do not implement `Send` nor `Sync`.
    // An alternative is to have a WASM-specific error that implements `Box<dyn Error>`, although
    // parts of our library depend on the error type being `Send + Sync`.
    #[derive(Debug, thiserror::Error)]
    #[error("{0}")]
    struct WstdError(String);

    impl From<wstd::http::error::Error> for HttpResolverError {
        fn from(value: wstd::http::error::Error) -> Self {
            Self::Other(Box::new(WstdError(value.to_string())))
        }
    }
}
