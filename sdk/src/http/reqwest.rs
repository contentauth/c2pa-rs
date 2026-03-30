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

#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "http_reqwest_blocking",
    not(feature = "http_ureq")
))]
pub mod sync_impl {
    use std::io::{Cursor, Read};

    use http::{Request, Response};

    use crate::http::{HttpResolverError, SyncHttpResolver};

    pub type Impl = reqwest::blocking::Client;

    pub fn new() -> Impl {
        // By default `reqwest::blocking::Client::new()` unwraps if the TLS backend cannot be initialized.
        // The behavior here is equivalent, except with a custom configuration.
        #[allow(clippy::unwrap_used)]
        reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    pub fn with_redirects() -> Option<Impl> {
        Some(reqwest::blocking::Client::new())
    }

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

    // TODO WASM doesn't support `httpmock` https://github.com/alexliesenfeld/httpmock/issues/121
    #[cfg(not(target_arch = "wasm32"))]
    #[cfg(test)]
    pub mod tests {
        #![allow(clippy::unwrap_used)]

        use crate::http::tests::{assert_http_resolver, assert_http_resolver_with_redirects};

        #[test]
        fn test_http_reqwest() {
            assert_http_resolver(super::new());
        }

        #[test]
        fn test_http_reqwest_with_redirects() {
            assert_http_resolver_with_redirects(super::with_redirects().unwrap());
        }
    }
}

#[cfg(all(feature = "http_reqwest", not(target_os = "wasi")))]
pub mod async_impl {
    use std::io::{Cursor, Read};

    use async_trait::async_trait;
    use http::{Request, Response};

    use crate::http::{AsyncHttpResolver, HttpResolverError};

    pub type Impl = reqwest::Client;

    pub fn new() -> Impl {
        let builder = reqwest::Client::builder();
        // `reqwest::redirect` isn't compiled on WASM.
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.redirect(reqwest::redirect::Policy::none());
        // By default `reqwest::Client::new()` unwraps if the TLS backend cannot be initialized.
        // The behavior here is equivalent, except with a custom configuration.
        #[allow(clippy::unwrap_used)]
        builder.build().unwrap()
    }

    pub fn with_redirects() -> Option<Impl> {
        Some(reqwest::Client::new())
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl AsyncHttpResolver for reqwest::Client {
        async fn http_resolve_async(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            let response = self.execute(request.try_into()?).await?;

            let mut builder = Response::builder().status(response.status());
            #[cfg(not(target_arch = "wasm32"))]
            {
                builder = builder.version(response.version());
            }

            for (name, value) in response.headers().iter() {
                builder = builder.header(name, value);
            }

            Ok(builder.body(Box::new(Cursor::new(response.bytes().await?)) as Box<dyn Read>)?)
        }
    }

    // TODO: Use `httpmock` when it's supported for WASM https://github.com/contentauth/c2pa-rs/issues/1378
    #[cfg(not(target_arch = "wasm32"))]
    #[cfg(test)]
    pub mod tests {
        #![allow(clippy::unwrap_used)]

        use crate::http::tests::{
            assert_http_resolver_async, assert_http_resolver_with_redirects_async,
        };

        #[tokio::test]
        async fn test_http_reqwest() {
            assert_http_resolver_async(super::new()).await;
        }

        #[tokio::test]
        async fn test_http_reqwest_with_redirects() {
            assert_http_resolver_with_redirects_async(super::with_redirects().unwrap()).await;
        }
    }
}

#[cfg(all(
    any(feature = "http_reqwest", feature = "http_reqwest_blocking"),
    not(target_os = "wasi")
))]
mod reqwest_resolver {
    use crate::http::HttpResolverError;

    impl From<reqwest::Error> for HttpResolverError {
        fn from(value: reqwest::Error) -> Self {
            Self::Other(Box::new(value))
        }
    }
}
