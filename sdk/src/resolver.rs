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

use async_trait::async_trait;
use http::{Request, Response};

use crate::{asset_io::CAIRead, Error, Result};

/// A resolver for sync (blocking) HTTP requests.
pub trait SyncHttpResolver {
    /// Resolve a [`http::Request`] into a [`http::Response`] with a streaming body.
    fn http_resolve(&self, request: Request<Vec<u8>>) -> Result<Response<Box<dyn CAIRead>>>;
}

impl<T: SyncHttpResolver + ?Sized> SyncHttpResolver for Box<T> {
    fn http_resolve(&self, request: Request<Vec<u8>>) -> Result<Response<Box<dyn CAIRead>>> {
        (**self).http_resolve(request)
    }
}

/// A resolver for non-blocking (async) HTTP requests.
#[async_trait]
pub trait AsyncHttpResolver {
    /// Resolve a [`http::Request`] into a [`http::Response`] with a streaming body.
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn CAIRead>>>;
}

#[async_trait]
impl<T: AsyncHttpResolver + ?Sized + Sync> AsyncHttpResolver for Box<T> {
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn CAIRead>>> {
        (**self).http_resolve_async(request).await
    }
}

/// A generic resolver for [`SyncHttpResolver`].
///
/// This implementation will automatically choose a [`SyncHttpResolver`] based on the
/// enabled features:
/// * `ureq` - use [`ureq::Agent`].
/// * `reqwest_blocking` - use [`reqwest::blocking::Client`].
/// * For WASI - use [`wasi::http::handle`].
pub struct SyncGenericResolver {
    http_resolver: Box<dyn SyncHttpResolver>,
}

impl SyncGenericResolver {
    /// Create a new [`SyncGenericResolver`] with an auto-specified [`SyncHttpResolver`].
    #[cfg(all(
        any(feature = "ureq", feature = "reqwest_blocking"),
        // `wasm32` doesn't support sync http resolvers, but `wasi` does.
        any(not(target_arch = "wasm32"), target_os = "wasi")
    ))]
    pub fn new() -> Self {
        Self {
            #[cfg(all(feature = "ureq", not(target_os = "wasi")))]
            http_resolver: Box::new(ureq::agent()),
            #[cfg(all(feature = "reqwest_blocking", not(target_os = "wasi")))]
            http_resolver: Box::new(reqwest::blocking::Client::new()),
            #[cfg(target_os = "wasi")]
            http_resolver: Box::new(wasi_resolver::SyncWasiResolver::new()),
        }
    }

    /// The `ureq` nor `reqwest_blocking` features are enabled! This function will
    /// construct a [`SyncGenericResolver`] that always returns
    /// [`Error::SyncHttpResolverNotImplemented`].
    #[cfg(any(
        not(any(feature = "ureq", feature = "reqwest_blocking")),
        // `wasm32` doesn't support sync http resolvers, but `wasi` does.
        all(target_arch = "wasm32", not(target_os = "wasi"))
    ))]
    pub fn new() -> Self {
        struct NoopSyncResolver;

        impl SyncHttpResolver for NoopSyncResolver {
            fn http_resolve(
                &self,
                request: Request<Vec<u8>>,
            ) -> Result<Response<Box<dyn CAIRead>>> {
                Err(Error::SyncHttpResolverNotImplemented)
            }
        }

        Self {
            http_resolver: Box::new(NoopSyncResolver),
        }
    }
}

impl SyncHttpResolver for SyncGenericResolver {
    fn http_resolve(&self, request: Request<Vec<u8>>) -> Result<Response<Box<dyn CAIRead>>> {
        self.http_resolver.http_resolve(request)
    }
}

/// A generic resolver for [`AsyncHttpResolver`].
///
/// This implementation will automatically choose a [`AsyncHttpResolver`] based on the
/// enabled features:
/// * `reqwest` - use [`reqwest::Client`].
/// * For WASI - use [`wstd::http::Client`].
pub struct AsyncGenericResolver {
    http_resolver: Box<dyn AsyncHttpResolver + Send + Sync>,
}

impl AsyncGenericResolver {
    /// Create a new [`AsyncGenericResolver`] with an auto-specified [`AsyncHttpResolver`].
    #[cfg(any(
        // `wasi` uses wstd for async http resolvers.
        feature = "reqwest", target_os = "wasi"
    ))]
    pub fn new() -> Self {
        Self {
            #[cfg(all(feature = "reqwest", not(target_os = "wasi")))]
            http_resolver: Box::new(reqwest::Client::new()),
            #[cfg(target_os = "wasi")]
            http_resolver: Box::new(wasi_resolver::AsyncWasiResolver::new()),
        }
    }

    /// The `reqwest` feature is not enabled! This function will
    /// construct a [`AsyncGenericResolver`] that always returns
    /// [`Error::AsyncHttpResolverNotImplemented`].
    #[cfg(not(any(
        // `wasi` uses wstd for async http resolvers.
        feature = "reqwest", target_os = "wasi"
    )))]
    pub fn new() -> Self {
        struct NoopAsyncResolver;

        #[async_trait]
        impl AsyncHttpResolver for NoopAsyncResolver {
            async fn http_resolve_async(
                &self,
                request: Request<Vec<u8>>,
            ) -> Result<Response<Box<dyn CAIRead>>> {
                Err(Error::AsyncHttpResolverNotImplemented)
            }
        }

        Self {
            http_resolver: Box::new(NoopAsyncResolver),
        }
    }
}

#[async_trait]
impl AsyncHttpResolver for AsyncGenericResolver {
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn CAIRead>>> {
        self.http_resolver.http_resolve_async(request).await
    }
}

#[cfg(any(feature = "reqwest", feature = "reqwest_blocking"))]
mod reqwest_resolver {
    use std::io::Cursor;

    use super::*;

    #[cfg(feature = "reqwest_blocking")]
    impl SyncHttpResolver for reqwest::blocking::Client {
        fn http_resolve(&self, request: Request<Vec<u8>>) -> Result<Response<Box<dyn CAIRead>>> {
            let response = self.execute(request.try_into()?)?;

            let mut builder = http::Response::builder()
                .status(response.status())
                .version(response.version());

            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }

            Ok(builder.body(Box::new(Cursor::new(response.bytes()?)) as Box<dyn CAIRead>)?)
        }
    }

    #[cfg(feature = "reqwest")]
    #[async_trait]
    impl AsyncHttpResolver for reqwest::Client {
        async fn http_resolve_async(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn CAIRead>>> {
            let response = self.execute(request.try_into()?).await?;

            let mut builder = Response::builder()
                .status(response.status())
                .version(response.version());

            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }

            // TODO: in the future we can add HTTP range request support via something like https://github.com/sam0x17/rseek
            // Ok(builder.body(Box::new(response.bytes_stream()) as Box<dyn CAIRead>)?)
            Ok(builder.body(Box::new(Cursor::new(response.bytes().await?)) as Box<dyn CAIRead>)?)
        }
    }
}

#[cfg(feature = "ureq")]
mod ureq_resolver {
    use std::io::Cursor;

    use http::header;

    use super::*;

    impl SyncHttpResolver for ureq::Agent {
        fn http_resolve(&self, request: Request<Vec<u8>>) -> Result<Response<Box<dyn CAIRead>>> {
            let response = self.run(request)?;

            let mut builder = http::Response::builder()
                .status(response.status())
                .version(response.version());

            if let Some(content_type) = response.headers().get(header::CONTENT_TYPE) {
                builder = builder.header(header::CONTENT_TYPE, content_type);
            }

            let body = Cursor::new(response.into_body().read_to_vec()?);
            Ok(builder.body(Box::new(body) as Box<dyn CAIRead>)?)
        }
    }

    #[async_trait]
    impl AsyncHttpResolver for ureq::Agent {
        async fn http_resolve_async(
            &self,
            _request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn CAIRead>>> {
            Err(Error::AsyncHttpResolverNotImplemented)
        }
    }
}

#[cfg(feature = "curl")]
mod curl_resolver {}

// TODO: Switch to reqwest once it supports WASI https://github.com/seanmonstar/reqwest/issues/2294
#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
mod wasi_resolver {
    use super::*;

    /// A resolver for sync WASI network requests.
    pub struct SyncWasiResolver {}

    impl SyncWasiResolver {
        /// Create a new [`SyncWasiResolver`].
        pub fn new() -> Self {
            Self {}
        }
    }

    impl SyncHttpResolver for SyncWasiResolver {
        fn http_resolve(&self, request: Request<Vec<u8>>) -> Result<Response<Box<dyn CAIRead>>> {
            // https://docs.rs/wasi/latest/wasi/http/outgoing_handler/fn.handle.html
            todo!()

            // TODO: inspiration

            // use url::Url;
            // use wasi::http::{
            //     outgoing_handler,
            //     types::{Fields, OutgoingRequest, Scheme},
            // };

            // let parsed_url = Url::parse(url)
            //     .map_err(|e| Error::RemoteManifestFetch(format!("invalid URL: {}", e)))?;
            // let authority = parsed_url.authority();
            // let path_with_query = parsed_url[url::Position::AfterPort..].to_string();
            // let scheme = match parsed_url.scheme() {
            //     "http" => Scheme::Http,
            //     "https" => Scheme::Https,
            //     _ => {
            //         return Err(Error::RemoteManifestFetch(
            //             "unsupported URL scheme".to_string(),
            //         ))
            //     }
            // };

            // let request = OutgoingRequest::new(Fields::new());
            // request.set_path_with_query(Some(&path_with_query)).unwrap();
            // request.set_authority(Some(&authority)).unwrap();
            // request.set_scheme(Some(&scheme)).unwrap();
            // match outgoing_handler::handle(request, None) {
            //     Ok(resp) => {
            //         resp.subscribe().block();
            //         let response = resp
            //             .get()
            //             .ok_or(Error::RemoteManifestFetch(
            //                 "HTTP request response missing".to_string(),
            //             ))?
            //             .map_err(|_| {
            //                 Error::RemoteManifestFetch(
            //                     "HTTP request response requested more than once".to_string(),
            //                 )
            //             })?
            //             .map_err(|_| Error::RemoteManifestFetch("HTTP request failed".to_string()))?;
            //     }
            // }
        }
    }

    /// A resolver for async WASI network requests.
    pub struct AsyncWasiResolver {}

    impl AsyncWasiResolver {
        /// Create a new [`AsyncWasiResolver`].
        pub fn new() -> Self {
            Self {}
        }
    }

    #[async_trait]
    impl AsyncHttpResolver for AsyncWasiResolver {
        async fn http_resolve_async(
            &self,
            _request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn CAIRead>>> {
            // https://docs.rs/wstd/latest/wstd/http/struct.Request.html
            todo!()

            // TODO: inspiration:

            // use wstd::{http, io, io::AsyncRead};

            // let request = http::Request::get(url)
            //     .header("User-Agent", http::HeaderValue::from_static(USER_AGENT))
            //     .header(
            //         "Accept",
            //         http::HeaderValue::from_static("application/did+json"),
            //     )
            //     .body(io::empty())
            //     .map_err(|e| DidWebError::Request(url.to_owned(), e.to_string()))?;
            // let resp = http::Client::new()
            //     .send(request)
            //     .await
            //     .map_err(|e| DidWebError::Request(url.to_owned(), e.to_string()))?;

            // let (parts, mut body) = resp.into_parts();
            // match parts.status {
            //     http::StatusCode::OK => (),
            //     http::StatusCode::NOT_FOUND => return Err(DidWebError::NotFound(url.to_string())),
            //     _ => return Err(DidWebError::Server(parts.status.to_string())),
            // };

            // let mut document = Vec::new();
            // body.read_to_end(&mut document)
            //     .await
            //     .map_err(|e| DidWebError::Response(e.to_string()))?;
            // Ok(document)
        }
    }
}
