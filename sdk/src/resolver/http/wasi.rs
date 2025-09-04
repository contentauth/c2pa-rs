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

// TODO: Switch to reqwest_blocking once it supports WASI https://github.com/contentauth/c2pa-rs/issues/1377
#[cfg(all(target_os = "wasi", feature = "http_wasi"))]
pub mod sync_impl {
    use std::io::{self, Read};

    use http::{Request, Response};
    use wasi::http::{
        outgoing_handler::{self, OutgoingRequest},
        types::{Fields, IncomingBody, InputStream},
    };

    use crate::resolver::http::{HttpResolverError, SyncHttpResolver};

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

// TODO: Switch to reqwest once it supports WASI https://github.com/contentauth/c2pa-rs/issues/1377
#[cfg(all(target_os = "wasi", feature = "http_wstd"))]
mod async_impl {
    use std::io::{Cursor, Read};

    use async_trait::async_trait;
    use http::{Request, Response};
    use wstd::http::body::StreamedBody;

    use crate::resolver::http::{AsyncHttpResolver, HttpResolverError};

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
