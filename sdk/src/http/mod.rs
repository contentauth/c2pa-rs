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
//! # When do network requests occur?
//!
//! The SDK may issue HTTP/S requests in the following scenarios:
//! - [`Reader`]:
//!     - Fetching remote manifests
//!     - Validating CAWG identity assertions
//!     - Fetching OCSP revocation status
//! - [`Builder`]:
//!     - Fetching ingredient remote manifests
//!     - Fetching timestamps
//!     - Fetching [`TimeStamp`] assertions
//!     - Fetching OCSP staples
//!
//! Network requests may also be issued during the signing process, such as when
//! [`SignerSettings::Remote`] is specified.
//!
//! # Network security policy (SSRF hardening)
//!
//! Because some request URLs come from untrusted content, following HTTP redirects can be abused to
//! reach internal or cloud-metadata endpoints (SSRF – CAI-12574). By default the SDK follows
//! redirects **except** when a redirect target is a non-globally-routable (internal) address, which
//! is rejected as [`HttpResolverError::RedirectTargetDisallowed`]. This is controlled by
//! [`Core::allow_redirects`]; set it to `false` to refuse redirects entirely (reported as
//! [`HttpResolverError::RedirectDisallowed`]). See [`Core::allowed_network_hosts`] for an explicit
//! host allow-list.
//!
//! ## Scope: which requests this policy governs
//!
//! The policy is applied by the SDK's HTTP *resolvers* ([`Context::resolver`] /
//! [`Context::resolver_async`]) and therefore covers the requests listed above — remote-manifest
//! fetches, OCSP, timestamps, and `did:web` resolution — on **both** the read/validate path and the
//! parts of the signing path that go through those resolvers (e.g. fetching a timestamp or OCSP
//! staple while building). It does **not** govern the remote-signer transport
//! ([`SignerSettings::Remote`]), which issues its own request to an operator-configured URL and is
//! outside this SSRF surface.
//!
//! ## Accepted risk: directly-named internal hosts are still reached
//!
//! **The redirect check applies to redirect *targets*, not the initial request.** A request that
//! *directly* names an internal host — a raw IPv4/IPv6 URL such as `http://169.254.169.254/…`, a
//! `localhost` development server acting as a `did:web` origin or manifest host, or an enterprise
//! OCSP responder on a private address — **is fetched normally**. This is a deliberate trade-off:
//! it keeps internal PKI and local development working, and the initial URL is visible to the
//! operator (unlike a stealthy redirect). Only being *redirected* to an internal address is blocked.
//! To constrain the initial host as well, configure [`Core::allowed_network_hosts`].
//!
//! To restrict which hosts the SDK may contact at all (including each redirect hop), use
//! [`Core::allowed_network_hosts`]:
//!
//! ```
//! # use c2pa::{Context, Settings};
//! # fn main() -> c2pa::Result<()> {
//! // Only allow requests to a local dev server on 127.0.0.1:8080.
//! let settings =
//!     Settings::new().with_value("core.allowed_network_hosts", ["127.0.0.1:8080".to_string()])?;
//! let context = Context::new().with_settings(settings)?;
//! # let _ = context;
//! # Ok(())
//! # }
//! ```
//!
//! [`Reader`]: crate::Reader
//! [`Builder`]: crate::Builder
//! [`TimeStamp`]: crate::assertions::TimeStamp
//! [`SignerSettings::Remote`]: crate::settings::signer::SignerSettings::Remote
//! [`Context::resolver`]: crate::Context::resolver
//! [`Context::resolver_async`]: crate::Context::resolver_async
//! [`HttpResolverError::RedirectTargetDisallowed`]: crate::http::HttpResolverError::RedirectTargetDisallowed
//! [`HttpResolverError::RedirectDisallowed`]: crate::http::HttpResolverError::RedirectDisallowed
//! [`Core::allow_redirects`]: crate::settings::Core::allow_redirects
//! [`Core::allowed_network_hosts`]: crate::settings::Core::allowed_network_hosts

use std::{
    io::{self, Cursor, Read},
    sync::Arc,
};

use async_trait::async_trait;
use http::{Request, Response};

use crate::{
    maybe_send_sync::{MaybeSend, MaybeSync},
    Result,
};

mod reqwest;
mod ureq;
mod wasi;

pub mod restricted;

// Since we expose `http::Request` and `http::Response` in the public API, we also expose the `http` crate.
pub use http;

/// A resolver for sync (blocking) HTTP requests.
//
// This trait is a supertrait of [`MaybeSend`] and [`MaybeSync`] for consistency with the
// [`AsyncHttpResolver`]. For more information on the rationale, see [`AsyncHttpResolver`].
//
// [`MaybeSend`]: crate::maybe_send_sync::MaybeSend
// [`MaybeSync`]: crate::maybe_send_sync::MaybeSync
pub trait SyncHttpResolver: MaybeSend + MaybeSync {
    /// Resolve a [`Request`] into a [`Response`] with a streaming body.
    ///
    /// [`Request`]: http::Request
    /// [`Response`]: http::Response
    fn http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError>;
}

/// This implementation is particularly useful for compatibility with the return
/// type of [`Context::resolver`].
///
/// [`Context::resolver`]: crate::Context::resolver
impl<T: SyncHttpResolver + ?Sized> SyncHttpResolver for Arc<T> {
    fn http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        (**self).http_resolve(request)
    }
}

/// A resolver for non-blocking (async) HTTP requests.
//
// This trait is a supertrait of [`MaybeSend`] and [`MaybeSync`] because in many cases
// we use the pattern `&dyn AsyncHttpResolver`. For that to cross an await point, it
// must implement `Send`, and for that to happen, it must also implement `Sync`. Thus,
// rather than creating a new trait that combines `AsyncHttpResolver + MaybeSend + MaybeSync`,
// we require it here to reduce complexity.
//
// [`MaybeSend`]: crate::maybe_send_sync::MaybeSend
// [`MaybeSync`]: crate::maybe_send_sync::MaybeSync
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait AsyncHttpResolver: MaybeSend + MaybeSync {
    /// Resolve a [`Request`] into a [`Response`] with a streaming body.
    ///
    /// [`Request`]: http::Request
    /// [`Response`]: http::Response
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError>;
}

/// This implementation is particularly useful for compatibility with the return
/// type of [`Context::resolver_async`].
///
/// [`Context::resolver_async`]: crate::Context::resolver_async
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<T: AsyncHttpResolver + ?Sized> AsyncHttpResolver for Arc<T> {
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        (**self).http_resolve_async(request).await
    }
}

/// A generic resolver for [`SyncHttpResolver`].
///
/// This implementation will automatically choose a [`SyncHttpResolver`] based on the
/// enabled features:
/// * `ureq` - use `ureq::Agent`.
/// * `reqwest_blocking` - use `reqwest::blocking::Client`.
/// * `wasi` (WASI-only) - use `wasi::http::outgoing_handler::handle`.
///
/// This resolver is a pure HTTP client wrapper with no domain-specific logic.
/// For host filtering or other access control, wrap this with [`RestrictedResolver`].
///
/// Note that WASM (non-WASI) does not have a built-in [`SyncHttpResolver`].
///
/// [`RestrictedResolver`]: restricted::RestrictedResolver
pub struct SyncGenericResolver {
    inner: sync_resolver::Impl,
}

impl SyncGenericResolver {
    /// Create a new [`SyncGenericResolver`] with an auto-specified [`SyncHttpResolver`].
    ///
    /// This function will create a [`SyncHttpResolver`] that returns [`HttpResolverError::SyncHttpResolverNotImplemented`]
    /// under any of the following conditions:
    /// * If both `http_reqwest_blocking` and `http_ureq` aren't enabled.
    /// * If the platform is WASM.
    /// * If the platform is WASI and `http_wasi` isn't enabled.
    pub fn new() -> Self {
        Self {
            inner: sync_resolver::new(),
        }
    }

    /// Create a new [`SyncGenericResolver`] with an auto-specified [`SyncHttpResolver`] that has
    /// redirects enabled. Returns `None` if unsupported for the enabled HTTP resolver features.
    ///
    /// For more information, see [`SyncGenericResolver::new`].
    pub fn with_redirects() -> Option<Self> {
        sync_resolver::with_redirects().map(|inner| Self { inner })
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
        self.inner.http_resolve(request)
    }
}

/// A generic resolver for [`AsyncHttpResolver`].
///
/// This implementation will automatically choose a [`AsyncHttpResolver`] based on the
/// enabled features:
/// * `reqwest` - use `reqwest::Client`.
/// * `wstd` (WASI-only) - use `wstd::http::Client`.
///
/// This resolver is a pure HTTP client wrapper with no domain-specific logic.
/// For host filtering or other access control, wrap this with [`RestrictedResolver`].
///
/// [`RestrictedResolver`]: restricted::RestrictedResolver
pub struct AsyncGenericResolver {
    inner: async_resolver::Impl,
    max_response_body_size: Option<u64>,
}

impl AsyncGenericResolver {
    /// Create a new [`AsyncGenericResolver`] with an auto-specified [`AsyncHttpResolver`].
    ///
    /// This function will create a [`AsyncHttpResolver`] that returns [`HttpResolverError::AsyncHttpResolverNotImplemented`]
    /// under any of the following conditions:
    /// * If `http_reqwest` isn't enabled.
    /// * If the platform is WASI and `http_wstd` isn't enabled.
    pub fn new() -> Self {
        Self {
            inner: async_resolver::new(),
            max_response_body_size: None,
        }
    }

    /// Create a new [`AsyncGenericResolver`] with an auto-specified [`AsyncHttpResolver`] that has
    /// redirects enabled. Returns `None` if unsupported for the enabled HTTP resolver features.
    ///
    /// For more information, see [`AsyncGenericResolver::new`].
    pub fn with_redirects() -> Option<Self> {
        async_resolver::with_redirects().map(|inner| Self {
            inner,
            max_response_body_size: None,
        })
    }

    /// Set the maximum number of bytes accepted from an HTTP response body.
    ///
    /// When set, [`http_resolve_async`] checks the `Content-Length` response header before
    /// returning the response. If the advertised size exceeds `limit`, it returns
    /// [`HttpResolverError::ResponseTooLarge`] immediately, without reading the body.
    ///
    /// This is an opt-in guard; the default is no limit (`None`).
    ///
    /// [`http_resolve_async`]: AsyncHttpResolver::http_resolve_async
    pub fn with_max_response_body_size(mut self, limit: u64) -> Self {
        self.max_response_body_size = Some(limit);
        self
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
        let response = self.inner.http_resolve_async(request).await?;

        if let Some(limit) = self.max_response_body_size {
            // Fast-fail if Content-Length exceeds the limit before reading body bytes.
            let reported_len = response
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            if let Some(len) = reported_len {
                if len > limit {
                    return Err(HttpResolverError::ResponseTooLarge);
                }
            }

            // Read the body with a hard cap so servers that omit or lie about
            // Content-Length are also bounded.
            let (parts, body) = response.into_parts();
            let mut buf = Vec::new();
            body.take(limit + 1).read_to_end(&mut buf)?;
            if buf.len() as u64 > limit {
                return Err(HttpResolverError::ResponseTooLarge);
            }
            return Ok(http::Response::from_parts(
                parts,
                Box::new(Cursor::new(buf)) as Box<dyn Read>,
            ));
        }

        Ok(response)
    }
}

/// Sanitizes a URI or other attacker-influenced string before it is embedded in an error message.
///
/// Errors may be logged, and their `uri`/`location` fields come from untrusted content (manifest
/// URLs, redirect targets). This escapes control characters (so a crafted value cannot inject
/// newlines or terminal escape sequences into logs) and truncates to a bounded length.
pub(crate) fn sanitize_for_log(value: &str) -> String {
    const MAX_LEN: usize = 256;

    let mut sanitized = String::new();
    for ch in value.chars().take(MAX_LEN) {
        if ch.is_control() {
            sanitized.extend(ch.escape_default());
        } else {
            sanitized.push(ch);
        }
    }

    if value.chars().nth(MAX_LEN).is_some() {
        sanitized.push('…');
    }

    sanitized
}

/// An error that occurs during sync/async HTTP resolver resolution.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpResolverError {
    /// An error occurred in the [`http`] crate.
    #[error(transparent)]
    Http(#[from] http::Error),

    /// An error occurred in during I/O.
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
    /// The allowed list can be set via:
    /// - [`RestrictedResolver`] (for wrapping custom resolvers)
    /// - SDK settings via [`Core::allowed_network_hosts`]
    ///
    /// [`RestrictedResolver`]: restricted::RestrictedResolver
    /// [`Core::allowed_network_hosts`]: crate::settings::Core::allowed_network_hosts
    #[error("remote URI \"{uri}\" is not permitted by the allowed list")]
    UriDisallowed { uri: String },

    /// The `Content-Length` response header exceeded the limit set via
    /// [`AsyncGenericResolver::with_max_response_body_size`].
    #[error("response body exceeded maximum allowed size")]
    ResponseTooLarge,

    /// An HTTP redirect response was received, but redirect following is disabled because
    /// [`allow_redirects`] is `false`.
    ///
    /// This is expected when a remote-manifest, OCSP, timestamp, or `did:web` URL responds with a
    /// 3xx redirect and the caller has turned redirect following off. To follow redirects (to
    /// public hosts) again, set `core.allow_redirects = true`.
    ///
    /// [`allow_redirects`]: crate::settings::Core::allow_redirects
    #[error(
        "HTTP redirect to \"{location}\" (from \"{uri}\") was not followed because \
         core.allow_redirects is false; set core.allow_redirects = true to follow redirects to \
         public hosts."
    )]
    RedirectDisallowed {
        /// The URI that returned the redirect response.
        uri: String,
        /// The redirect target from the response `Location` header.
        location: String,
    },

    /// An HTTP redirect pointed at a non-globally-routable (internal) address and was rejected as
    /// an SSRF risk (CAI-12574), even though [`allow_redirects`] is `true`.
    ///
    /// The redirect target is a loopback, private (RFC 1918), link-local / cloud-metadata,
    /// IPv6 unique-local/link-local, or similar internal address. Redirects to public hosts are
    /// followed normally; only internal targets are blocked. A URL that *directly* names an
    /// internal host (rather than being redirected to one) is not affected by this and is still
    /// fetched.
    ///
    /// [`allow_redirects`]: crate::settings::Core::allow_redirects
    #[error(
        "HTTP redirect to \"{location}\" (from \"{uri}\") was rejected: the target is a private or \
         internal address, which is not allowed as a redirect destination (SSRF protection)."
    )]
    RedirectTargetDisallowed {
        /// The URI that returned the redirect response.
        uri: String,
        /// The internal redirect target from the response `Location` header.
        location: String,
    },

    /// The request exceeded the maximum number of HTTP redirects the SDK will follow.
    #[error("too many HTTP redirects while resolving \"{uri}\"")]
    TooManyRedirects {
        /// The most recent URI in the redirect chain.
        uri: String,
    },

    /// An error occurred from the underlying HTTP resolver.
    #[error("an error occurred from the underlying http resolver: {0}")]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "http_reqwest_blocking",
    not(feature = "http_ureq")
))]
mod sync_resolver {
    pub use crate::http::reqwest::sync_impl::{new, with_redirects, Impl};
}

#[cfg(all(not(target_arch = "wasm32"), feature = "http_ureq"))]
mod sync_resolver {
    pub use crate::http::ureq::sync_impl::{new, with_redirects, Impl};
}

#[cfg(all(target_os = "wasi", feature = "http_wasi"))]
mod sync_resolver {
    pub use crate::http::wasi::sync_impl::{new, with_redirects, Impl};
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
    pub fn with_redirects() -> Option<Impl> {
        Some(SyncNoopResolver)
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
    pub use crate::http::reqwest::async_impl::{new, with_redirects, Impl};
}

#[cfg(all(target_os = "wasi", feature = "http_wstd"))]
mod async_resolver {
    pub use crate::http::wasi::async_impl::{new, with_redirects, Impl};
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
    pub fn with_redirects() -> Option<Impl> {
        Some(AsyncNoopResolver)
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

    fn mock_server<'a>(server: &'a httpmock::MockServer) -> httpmock::Mock<'a> {
        server.mock(|when, then| {
            when.method(httpmock::Method::GET);
            then.status(200).body([1, 2, 3]);
        })
    }

    fn redirect_mock_server<'a>(server: &'a httpmock::MockServer) -> httpmock::Mock<'a> {
        server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/redirect");
            then.status(302).header("Location", "/").body([3, 2, 1]);
        })
    }

    #[async_generic(async_signature(resolver: impl AsyncHttpResolver))]
    pub fn assert_http_resolver(resolver: impl SyncHttpResolver) {
        use httpmock::MockServer;

        let server = MockServer::start();
        let mock = mock_server(&server);

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

    #[async_generic(async_signature(resolver: impl AsyncHttpResolver))]
    pub fn assert_http_resolver_with_redirects(resolver: impl SyncHttpResolver) {
        use httpmock::MockServer;

        let server = MockServer::start();
        let redirect = redirect_mock_server(&server);
        let target = mock_server(&server);

        let request = Request::get(format!("{}/redirect", server.base_url()))
            .body(vec![3, 2, 1])
            .unwrap();

        let response = if _sync {
            resolver.http_resolve(request).unwrap()
        } else {
            resolver.http_resolve_async(request).await.unwrap()
        };

        assert_eq!(response.status(), 200);
        redirect.assert_calls(1);
        target.assert_calls(1);
    }

    // The underlying HTTP client (`new()`) must not auto-follow redirects on its own: it returns the
    // 3xx response as-is. That is the precondition that lets the SDK-level `RedirectResolver` inspect
    // and validate each redirect hop (SSRF hardening, CAI-12574) rather than the client silently
    // chasing them.
    #[async_generic(async_signature(resolver: impl AsyncHttpResolver))]
    pub fn assert_http_resolver_no_redirects(resolver: impl SyncHttpResolver) {
        use httpmock::MockServer;

        let server = MockServer::start();
        let redirect = redirect_mock_server(&server);
        let target = mock_server(&server);

        let request = Request::get(format!("{}/redirect", server.base_url()))
            .body(vec![3, 2, 1])
            .unwrap();

        let response = if _sync {
            resolver.http_resolve(request).unwrap()
        } else {
            resolver.http_resolve_async(request).await.unwrap()
        };

        // The redirect endpoint is hit exactly once and the target is never reached.
        assert_eq!(response.status(), 302);
        redirect.assert_calls(1);
        target.assert_calls(0);
    }
}
