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
//! or disable networking entirely. It re-exports the [`c2pa_http`] crate.
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
//! Independent of redirects, the *initial* request is also checked: by default a URL that directly
//! names a link-local or cloud-metadata address (e.g. `169.254.169.254`) is rejected as
//! [`HttpResolverError::MetadataOrLinkLocalUriDisallowed`] (SSRF – <https://github.com/contentauth/c2pa-rs/issues/2430>). See below for what
//! this does and does not cover.
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
//! ## Accepted risk: directly-named loopback/private hosts are still reached
//!
//! The initial-request check above only rejects link-local/cloud-metadata addresses. A request that
//! *directly* names a loopback or private (RFC 1918) host — a `localhost` development server acting
//! as a `did:web` origin or manifest host, or an enterprise OCSP responder on a private address —
//! **is fetched normally**. This is a deliberate trade-off: it keeps internal PKI and local
//! development working, and the initial URL is visible to the operator (unlike a stealthy redirect).
//! Redirects follow the broader [`RedirectTargetDisallowed`] policy above, which also rejects
//! loopback/private redirect targets — only the *initial* request gets the narrower check. To
//! constrain the initial host to an explicit set (including loopback/private hosts), configure
//! [`Core::allowed_network_hosts`].
//!
//! [`RedirectTargetDisallowed`]: crate::http::HttpResolverError::RedirectTargetDisallowed
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
//! [`HttpResolverError::MetadataOrLinkLocalUriDisallowed`]: crate::http::HttpResolverError::MetadataOrLinkLocalUriDisallowed
//! [`Core::allow_redirects`]: crate::settings::Core::allow_redirects
//! [`Core::allowed_network_hosts`]: crate::settings::Core::allowed_network_hosts

pub use c2pa_http::{
    http, restricted, AsyncGenericResolver, AsyncHttpResolver, CancellationToken,
    HttpResolverError, MaxResponseBodySize, RequestTimeout, SyncGenericResolver, SyncHttpResolver,
};
#[cfg(not(target_arch = "wasm32"))]
pub use c2pa_http::{RequestHandle, RequestScheduler, ScheduledResolver};

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]

    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        time::Duration,
    };

    /// Serves one request, stalling 600 ms before the response headers (or, with `delay_body`,
    /// before the body). Mirrors the helper in `c2pa_http`'s own tests.
    pub(crate) fn slow_server(delay_body: bool) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            {
                let mut reader = BufReader::new(&mut stream);
                loop {
                    let mut line = String::new();
                    assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                }
            }
            if delay_body {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
                    .unwrap();
            }
            std::thread::sleep(Duration::from_millis(600));
            if !delay_body {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n");
            }
            let _ = stream.write_all(b"body");
        });
        (url, task)
    }
}
