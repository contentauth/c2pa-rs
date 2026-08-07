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

//! HTTP request restriction layer.
//!
//! This module provides a [`RestrictedResolver`] that wraps an existing [`SyncHttpResolver`]
//! or [`AsyncHttpResolver`] to enforce host filtering.
//!
//! The SDK can also manage an allowed list for you via the [`Core::allowed_network_hosts`] setting.
//!
//! # Why restrict network requests?
//! In some environments, you may not want the SDK to talk to arbitrary hosts. Restricting
//! network requests help to:
//! - Reduce SSRF-style risks (e.g. requests to internal services).
//! - Constrain requests to a small, trusted set of domains.
//!
//! [`SyncGenericResolver`]: crate::http::SyncGenericResolver
//! [`AsyncGenericResolver`]: crate::http::AsyncGenericResolver
//!
//! # OCSP and other dynamic endpoints
//! Some protocols used by the SDK (like OCSP or CRLs) discover endpoints from certificate
//! metadata at runtime. In a restricted environment, there is no way for the resolver to
//! know that these endpoints are "special" unless you anticipate them in advance and add
//! their hosts to the allow-list.
//!
//! # Disabling networking completely
//! This restriction layer is a runtime control. To turn networking off entirely at compile
//! time, do not enable any of the HTTP features (`http_*`), see ["Features"].
//!
//! ["Features"]: crate#features
//! [`Core::allowed_network_hosts`]: crate::settings::Core::allowed_network_hosts

use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use async_trait::async_trait;
use http::{Request, Response, Uri};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    http::{AsyncHttpResolver, HttpResolverError, SyncHttpResolver},
    Result,
};

/// HTTP resolver wrapper that enforces an allowed list of hosts.
///
/// If the allowed list is empty, no filtering is applied and all requests are allowed.
///
/// When a URI is not permitted, the resolver returns [`HttpResolverError::UriDisallowed`].
#[derive(Debug)]
pub struct RestrictedResolver<T> {
    inner: T,
    allowed_hosts: Option<Vec<HostPattern>>,
}

impl<T> RestrictedResolver<T> {
    /// Creates a new `RestrictedResolver` with an empty allowed list.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            allowed_hosts: None,
        }
    }

    /// Creates a new `RestrictedResolver` with the specified allowed list.
    #[allow(dead_code)] // Public API, not used internally
    pub fn with_allowed_hosts(inner: T, allowed_hosts: Vec<HostPattern>) -> Self {
        Self {
            inner,
            allowed_hosts: Some(allowed_hosts),
        }
    }

    /// Replaces the current allowed list with the given allowed list if specified.
    pub fn set_allowed_hosts(&mut self, allowed_hosts: Option<Vec<HostPattern>>) {
        self.allowed_hosts = allowed_hosts;
    }

    /// Returns a reference to the allowed list.
    #[allow(dead_code)] // Public API, not used internally
    pub fn allowed_hosts(&self) -> Option<&[HostPattern]> {
        self.allowed_hosts.as_deref()
    }

    /// Returns true if the given URI is allowed by this resolver's policy.
    fn is_uri_allowed(&self, uri: &Uri) -> bool {
        self.allowed_hosts
            .as_ref()
            .map(|hosts| is_uri_allowed(hosts, uri))
            .unwrap_or(true) // None means allow all
    }
}

impl<T: SyncHttpResolver> SyncHttpResolver for RestrictedResolver<T> {
    fn http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        if !self.is_uri_allowed(request.uri()) {
            return Err(HttpResolverError::UriDisallowed {
                uri: request.uri().to_string(),
            });
        }
        self.inner.http_resolve(request)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<T: AsyncHttpResolver + Sync> AsyncHttpResolver for RestrictedResolver<T> {
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        if !self.is_uri_allowed(request.uri()) {
            return Err(HttpResolverError::UriDisallowed {
                uri: request.uri().to_string(),
            });
        }
        self.inner.http_resolve_async(request).await
    }
}

/// A host/scheme pattern used to restrict network requests.
///
/// Each pattern may include:
/// - A scheme (e.g. `https://` or `http://`)
/// - A hostname or IP address (e.g. `contentauthenticity.org` or `192.0.2.1`)
///     - The hostname may contain a single leading wildcard (e.g. `*.contentauthenticity.org`)
/// - An optional port (e.g. `contentauthenticity.org:443` or `192.0.2.1:8080`)
///
/// Matching is case-insensitive. A wildcard pattern such as `*.contentauthenticity.org` matches
/// `sub.contentauthenticity.org`, but does not match `contentauthenticity.org` or `fakecontentauthenticity.org`.
/// If a scheme is present in the pattern, only URIs using the same scheme are considered a match. If the scheme
/// is omitted, any scheme is allowed as long as the host matches.
///
/// # Examples
///
/// Pattern: `*.contentauthenticity.org`
/// - Does match:
///   - `https://sub.contentauthenticity.org`
///   - `http://api.contentauthenticity.org`
/// - Does **not** match:
///   - `https://contentauthenticity.org` (no subdomain)
///   - `https://sub.fakecontentauthenticity.org` (different host)
///
/// Pattern: `http://192.0.2.1:8080`
/// - Does match:
///   - `http://192.0.2.1:8080`
/// - Does **not** match:
///   - `https://192.0.2.1:8080` (scheme mismatch)
///   - `http://192.0.2.1` (port omitted)
///   - `http://192.0.2.2:8080` (different IP address)
#[cfg_attr(
    feature = "json_schema",
    derive(schemars::JsonSchema),
    schemars(with = "String")
)]
#[derive(Debug, Clone, PartialEq)]
pub struct HostPattern {
    pattern: String,
    scheme: Option<String>,
    host: Option<String>,
    port: Option<String>,
}

impl HostPattern {
    /// Creates a new `HostPattern` with the given pattern.
    pub fn new(pattern: &str) -> Self {
        let pattern = pattern.to_ascii_lowercase();
        let (scheme, rest): (Option<String>, &str) =
            if let Some(host) = pattern.strip_prefix("https://") {
                (Some("https".to_owned()), host)
            } else if let Some(host) = pattern.strip_prefix("http://") {
                (Some("http".to_owned()), host)
            } else {
                (None, &pattern)
            };

        let (host, port) = if let Some((host, port)) = rest.rsplit_once(':') {
            (host, Some(port.to_owned()))
        } else {
            (rest, None)
        };

        Self {
            host: if host.is_empty() {
                None
            } else {
                Some(host.to_owned())
            },
            pattern,
            scheme,
            port,
        }
    }

    /// Returns true if the given URI matches the `HostPattern`.
    pub fn matches(&self, uri: &Uri) -> bool {
        if let Some(allowed_host_pattern) = &self.host {
            if let Some(host) = uri.host() {
                // If there's a wildcard, do an suffix match, otherwise do an exact match.
                let is_host_allowed = if let Some(suffix) = allowed_host_pattern.strip_prefix("*.")
                {
                    let host = host.to_ascii_lowercase();

                    if host.len() <= suffix.len() || !host.ends_with(&suffix) {
                        false
                    } else {
                        // Make sure there is a component in place of the wildcard.
                        host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
                    }
                } else {
                    allowed_host_pattern.eq_ignore_ascii_case(host)
                };

                let is_port_allowed =
                    self.port.as_deref() == uri.port().as_ref().map(|port| port.as_str());

                if is_host_allowed && is_port_allowed {
                    if let Some(allowed_scheme) = &self.scheme {
                        if let Some(scheme) = uri.scheme() {
                            return scheme.as_str() == allowed_scheme;
                        }
                    } else {
                        return true;
                    }
                }
            }
        } else if let Some(allowed_scheme) = &self.scheme {
            if let Some(scheme) = uri.scheme() {
                return scheme.as_str() == allowed_scheme;
            }
        }

        false
    }
}

impl From<&str> for HostPattern {
    fn from(pattern: &str) -> Self {
        Self::new(pattern)
    }
}

impl Serialize for HostPattern {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.pattern.to_string())
    }
}

impl<'de> Deserialize<'de> for HostPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(HostPattern::new(&String::deserialize(deserializer)?))
    }
}

/// Returns true if the given URI matches at least one of the [`HostPattern`]s.
pub(crate) fn is_uri_allowed(patterns: &[HostPattern], uri: &Uri) -> bool {
    for pattern in patterns {
        if pattern.matches(uri) {
            return true;
        }
    }

    false
}

/// Resolver wrapper that rejects requests to non-globally-routable hosts.
///
/// Used by [`NetworkSecurity::Strict`] when [`Core::allowed_network_hosts`] is not configured: the
/// SDK still must not connect to internal addresses on the operator's behalf. This wrapper rejects
/// any request whose host is a non-globally-routable IP literal – loopback, private (RFC1918),
/// link-local (including the `169.254.169.254` cloud-metadata address), unique-local, CGNAT/shared,
/// documentation, or multicast – an obfuscated/malformed numeric address, or an obvious loopback
/// host name such as `localhost`. Rejected requests return [`HttpResolverError::UriDisallowed`].
///
/// This check runs on the request URI. Filtering based on the *resolved* IP (to defeat DNS names
/// that point at internal addresses, i.e. DNS rebinding) is tracked separately in
/// <https://github.com/contentauth/c2pa-rs/issues/2430>.
///
/// [`Core::allowed_network_hosts`]: crate::settings::Core::allowed_network_hosts
/// [`NetworkSecurity::Strict`]: crate::settings::NetworkSecurity::Strict
#[derive(Debug)]
pub(crate) struct NonGlobalHostGuard<T> {
    inner: T,
}

impl<T> NonGlobalHostGuard<T> {
    /// Wraps `inner` with the non-global-host rejection policy.
    pub(crate) fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: SyncHttpResolver> SyncHttpResolver for NonGlobalHostGuard<T> {
    fn http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        if host_is_non_global(request.uri()) {
            return Err(HttpResolverError::UriDisallowed {
                uri: request.uri().to_string(),
            });
        }
        self.inner.http_resolve(request)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<T: AsyncHttpResolver + Sync> AsyncHttpResolver for NonGlobalHostGuard<T> {
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        if host_is_non_global(request.uri()) {
            return Err(HttpResolverError::UriDisallowed {
                uri: request.uri().to_string(),
            });
        }
        self.inner.http_resolve_async(request).await
    }
}

/// Resolver wrapper that turns a blocked HTTP redirect into a clear, actionable error.
///
/// The underlying client is configured not to follow redirects (`max_redirects(0)` /
/// `redirect::Policy::none()`), so a redirect surfaces as a bare 3xx response. Passing that through
/// would give callers a confusing generic failure (e.g. "fetch failed: code 302"). Instead this
/// wrapper detects a redirect response and returns [`HttpResolverError::RedirectDisallowed`], naming
/// the blocked target and how to opt back in. Used by [`NetworkSecurity::Default`] and
/// [`NetworkSecurity::Strict`].
///
/// [`NetworkSecurity::Default`]: crate::settings::NetworkSecurity::Default
/// [`NetworkSecurity::Strict`]: crate::settings::NetworkSecurity::Strict
#[derive(Debug)]
pub(crate) struct RedirectGuard<T> {
    inner: T,
}

impl<T> RedirectGuard<T> {
    /// Wraps `inner` so that redirect responses are reported as errors rather than followed.
    pub(crate) fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: SyncHttpResolver> SyncHttpResolver for RedirectGuard<T> {
    fn http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        let uri = request.uri().to_string();
        let response = self.inner.http_resolve(request)?;
        redirect_error(&uri, &response).map_or(Ok(response), Err)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<T: AsyncHttpResolver + Sync> AsyncHttpResolver for RedirectGuard<T> {
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        let uri = request.uri().to_string();
        let response = self.inner.http_resolve_async(request).await?;
        redirect_error(&uri, &response).map_or(Ok(response), Err)
    }
}

/// Returns a [`HttpResolverError::RedirectDisallowed`] if `response` is an HTTP redirect (a 3xx
/// status carrying a `Location` header), otherwise `None`.
///
/// A 3xx without a `Location` (e.g. `304 Not Modified`) is not a redirect and passes through.
fn redirect_error<B>(uri: &str, response: &Response<B>) -> Option<HttpResolverError> {
    if !response.status().is_redirection() {
        return None;
    }

    let location = response
        .headers()
        .get(http::header::LOCATION)
        .and_then(|v| v.to_str().ok())?;

    Some(HttpResolverError::RedirectDisallowed {
        uri: uri.to_owned(),
        location: location.to_owned(),
    })
}

/// Returns true if `uri`'s host is not globally routable and must be blocked under
/// [`NetworkSecurity::Strict`].
///
/// See [`NonGlobalHostGuard`] for the rationale and the DNS-rebinding caveat.
///
/// [`NetworkSecurity::Strict`]: crate::settings::NetworkSecurity::Strict
pub(crate) fn host_is_non_global(uri: &Uri) -> bool {
    let Some(host) = uri.host() else {
        // A request with no host is malformed; reject it under the strict policy.
        return true;
    };

    let host = normalize_host(host);

    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip_is_non_global(ip);
    }

    // Reject numeric hosts that did not parse as a standard IP address. These are obfuscated or
    // malformed IPv4 forms (e.g. `2130706433`, `127.1`, `0x7f.0.0.1`) that an OS resolver may still
    // route to an internal address, so we fail closed. Comprehensive resolved-IP filtering is
    // tracked in <https://github.com/contentauth/c2pa-rs/issues/2430>.
    if looks_like_obfuscated_ip(&host) {
        return true;
    }

    // Otherwise treat it as a DNS name. Block the loopback host name; DNS names that resolve to
    // internal addresses are handled by resolved-IP filtering (see above).
    host == "localhost" || host.ends_with(".localhost")
}

/// Normalizes a URI host for comparison: strips IPv6 brackets and a fully-qualified trailing dot,
/// and lower-cases the result.
fn normalize_host(host: &str) -> String {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    let host = host.strip_suffix('.').unwrap_or(host);

    host.to_ascii_lowercase()
}

/// Returns true if `host` looks like a numeric IPv4 address in a non-standard/obfuscated form (all
/// digits and dots, or a `0x`/`0X` hex form). Standard addresses are handled by `IpAddr::parse`
/// before this is called; this only catches forms that parse failed on.
fn looks_like_obfuscated_ip(host: &str) -> bool {
    let digits_and_dots = !host.is_empty() && host.bytes().all(|b| b.is_ascii_digit() || b == b'.');

    digits_and_dots || host.starts_with("0x") || host.starts_with("0X")
}

/// Returns true if `ip` is not a globally routable unicast address and should therefore be blocked
/// by the default network policy.
fn ip_is_non_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_is_non_global(v4),
        IpAddr::V6(v6) => ipv6_is_non_global(v6),
    }
}

fn ipv4_is_non_global(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();

    ip.is_unspecified()          // 0.0.0.0
        || a == 0                // 0.0.0.0/8 "this network"
        || ip.is_loopback()      // 127.0.0.0/8
        || ip.is_private()       // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()    // 169.254.0.0/16 (includes 169.254.169.254)
        || ip.is_broadcast()     // 255.255.255.255
        || ip.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || ip.is_multicast()     // 224.0.0.0/4
        || (a == 100 && (b & 0xc0) == 64) // 100.64.0.0/10 CGNAT / shared address space
}

fn ipv6_is_non_global(ip: Ipv6Addr) -> bool {
    // Unwrap IPv4-mapped addresses (e.g. ::ffff:169.254.169.254) and apply the IPv4 rules.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return ipv4_is_non_global(v4);
    }

    let segments = ip.segments();

    ip.is_unspecified()                     // ::
        || ip.is_loopback()                 // ::1
        || ip.is_multicast()                // ff00::/8
        || (segments[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
        || (segments[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
}

#[cfg(test)]
mod test {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use super::*;

    struct NoopHttpResolver;

    impl SyncHttpResolver for NoopHttpResolver {
        fn http_resolve(
            &self,
            _request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            Ok(Response::new(Box::new(std::io::empty()) as Box<dyn Read>))
        }
    }

    fn assert_allowed_uri(resolver: &impl SyncHttpResolver, uri: &'static str) {
        let result = resolver.http_resolve(
            Request::get(Uri::from_static(uri))
                .body(Vec::new())
                .unwrap(),
        );
        assert!(matches!(result, Ok(..)));
    }

    fn assert_disallowed_uri(resolver: &impl SyncHttpResolver, uri: &'static str) {
        let result = resolver.http_resolve(
            Request::get(Uri::from_static(uri))
                .body(Vec::new())
                .unwrap(),
        );
        assert!(matches!(
            result,
            Err(HttpResolverError::UriDisallowed { .. })
        ));
    }

    #[test]
    fn allowed_http_request() {
        let allowed_list = vec![
            "*.prefix.contentauthenticity.org".into(),
            "test.contentauthenticity.org".into(),
            "fakecontentauthenticity.org".into(),
            "https://*.contentauthenticity.org".into(),
            "https://test.contentauthenticity.org".into(),
        ];
        let restricted_resolver =
            RestrictedResolver::with_allowed_hosts(NoopHttpResolver, allowed_list);

        assert_allowed_uri(&restricted_resolver, "fakecontentauthenticity.org");
        assert_allowed_uri(&restricted_resolver, "test.prefix.contentauthenticity.org");
        assert_allowed_uri(&restricted_resolver, "https://test.contentauthenticity.org");
        assert_allowed_uri(
            &restricted_resolver,
            "https://test2.contentauthenticity.org",
        );

        assert_disallowed_uri(&restricted_resolver, "test.test.contentauthenticity.org");
        assert_disallowed_uri(
            &restricted_resolver,
            "https://test.prefix.fakecontentauthenticity.org",
        );
        assert_disallowed_uri(
            &restricted_resolver,
            "https://test.fakecontentauthenticity.org",
        );
        assert_disallowed_uri(&restricted_resolver, "https://contentauthenticity.org");
    }

    #[test]
    fn allowed_none_http_request() {
        let allowed_list = vec![];
        let restricted_resolver =
            RestrictedResolver::with_allowed_hosts(NoopHttpResolver, allowed_list);

        assert_disallowed_uri(
            &restricted_resolver,
            "test.test.fakecontentauthenticity.org",
        );
        assert_disallowed_uri(
            &restricted_resolver,
            "https://test.prefix.fakecontentauthenticity.org",
        );
        assert_disallowed_uri(
            &restricted_resolver,
            "https://test.fakecontentauthenticity.org",
        );
        assert_disallowed_uri(&restricted_resolver, "https://contentauthenticity.org");
    }

    #[test]
    fn wildcard_pattern() {
        let pattern = HostPattern::new("*.contentauthenticity.org");

        let uri = Uri::from_static("test.contentauthenticity.org");
        assert!(pattern.matches(&uri));

        let uri = Uri::from_static("contentauthenticity.org");
        assert!(!pattern.matches(&uri));

        let uri = Uri::from_static("fakecontentauthenticity.org");
        assert!(!pattern.matches(&uri));
    }

    #[test]
    fn wildcard_pattern_with_scheme() {
        let pattern = HostPattern::new("https://*.contentauthenticity.org");

        let uri = Uri::from_static("test.contentauthenticity.org");
        assert!(!pattern.matches(&uri));

        let uri = Uri::from_static("contentauthenticity.org");
        assert!(!pattern.matches(&uri));

        let uri = Uri::from_static("fakecontentauthenticity.org");
        assert!(!pattern.matches(&uri));

        let uri = Uri::from_static("https://test.contentauthenticity.org");
        assert!(pattern.matches(&uri));

        let uri = Uri::from_static("https://contentauthenticity.org");
        assert!(!pattern.matches(&uri));

        let uri = Uri::from_static("https://fakecontentauthenticity.org");
        assert!(!pattern.matches(&uri));

        let uri = Uri::from_static("http://test.contentauthenticity.org");
        assert!(!pattern.matches(&uri));
    }

    #[test]
    fn case_insensitive_pattern() {
        let pattern = HostPattern::new("*.contentAuthenticity.org");

        let uri = Uri::from_static("tEst.conTentauthenticity.orG");
        assert!(pattern.matches(&uri));
    }

    #[test]
    fn exact_pattern() {
        let pattern = HostPattern::new("contentauthenticity.org");

        let uri = Uri::from_static("contentauthenticity.org");
        assert!(pattern.matches(&uri));

        let uri = Uri::from_static("https://contentauthenticity.org");
        assert!(pattern.matches(&uri));

        let uri = Uri::from_static("http://contentauthenticity.org");
        assert!(pattern.matches(&uri));
    }

    #[test]
    fn exact_pattern_with_schema() {
        let pattern = HostPattern::new("https://contentauthenticity.org");

        let uri = Uri::from_static("https://contentauthenticity.org");
        assert!(pattern.matches(&uri));

        let uri = Uri::from_static("http://contentauthenticity.org");
        assert!(!pattern.matches(&uri));

        let uri = Uri::from_static("contentauthenticity.org");
        assert!(!pattern.matches(&uri));
    }

    #[test]
    fn exact_pattern_ip_address() {
        let pattern = HostPattern::new("192.0.2.1");

        let uri = Uri::from_static("192.0.2.1");
        assert!(pattern.matches(&uri));

        let uri = Uri::from_static("192.0.2.1.1");
        assert!(!pattern.matches(&uri));
    }

    #[test]
    fn exact_pattern_ip_address_with_port() {
        let pattern = HostPattern::new("192.0.2.1:443");

        let uri = Uri::from_static("192.0.2.1:443");
        assert!(pattern.matches(&uri));

        let uri = Uri::from_static("192.0.2.1");
        assert!(!pattern.matches(&uri));
    }

    #[test]
    fn exact_pattern_hostname_with_port() {
        let pattern = HostPattern::new("contentauthenticity.org:8080");

        let uri = Uri::from_static("contentauthenticity.org:8080");
        assert!(pattern.matches(&uri));

        let uri = Uri::from_static("contentauthenticity.org");
        assert!(!pattern.matches(&uri));
    }

    #[test]
    fn scheme_only_pattern() {
        let pattern = HostPattern::new("https://");

        let uri = Uri::from_static("https://contentauthenticity.org");
        assert!(pattern.matches(&uri));

        let uri = Uri::from_static("http://contentauthenticity.org");
        assert!(!pattern.matches(&uri));

        let uri = Uri::from_static("contentauthenticity.org");
        assert!(!pattern.matches(&uri));
    }

    #[test]
    fn invalid_pattern() {
        let pattern = HostPattern::new("https:// ");

        let uri = Uri::from_static("https://contentauthenticity.org");
        assert!(!pattern.matches(&uri));
    }

    #[test]
    fn test_restricted_generic_resolver() {
        use crate::http::{HttpResolverError, SyncGenericResolver, SyncHttpResolver};

        let inner = SyncGenericResolver::new();
        let mut resolver = RestrictedResolver::new(inner);

        // Set allowed hosts to only allow localhost
        resolver.set_allowed_hosts(Some(vec!["127.0.0.1".into()]));

        // Request to localhost should work (though it will fail to connect in this test)
        let request = http::Request::get("http://127.0.0.1/test")
            .body(vec![])
            .unwrap();
        let result = resolver.http_resolve(request);
        // We expect a connection error, not a UriDisallowed error
        assert!(!matches!(
            result,
            Err(HttpResolverError::UriDisallowed { .. })
        ));

        // Request to external host should be blocked
        let request = http::Request::get("http://example.com/test")
            .body(vec![])
            .unwrap();
        let result = resolver.http_resolve(request);
        assert!(matches!(
            result,
            Err(HttpResolverError::UriDisallowed { .. })
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_restricted_async_generic_resolver() {
        use crate::http::{AsyncGenericResolver, AsyncHttpResolver, HttpResolverError};

        let inner = AsyncGenericResolver::new();
        let mut resolver = RestrictedResolver::new(inner);

        // Set allowed hosts to only allow localhost
        resolver.set_allowed_hosts(Some(vec!["127.0.0.1".into()]));

        // Request to localhost should work (though it will fail to connect in this test)
        let request = http::Request::get("http://127.0.0.1/test")
            .body(vec![])
            .unwrap();
        let result = resolver.http_resolve_async(request).await;
        // We expect a connection error, not a UriDisallowed error
        assert!(!matches!(
            result,
            Err(HttpResolverError::UriDisallowed { .. })
        ));

        // Request to external host should be blocked
        let request = http::Request::get("http://example.com/test")
            .body(vec![])
            .unwrap();
        let result = resolver.http_resolve_async(request).await;
        assert!(matches!(
            result,
            Err(HttpResolverError::UriDisallowed { .. })
        ));
    }

    #[test]
    fn strict_policy_blocks_non_global_hosts() {
        for uri in [
            "http://169.254.169.254/latest/meta-data/", // link-local / cloud metadata
            "http://127.0.0.1/",                        // IPv4 loopback
            "http://127.1.2.3/",                        // IPv4 loopback (whole /8)
            "http://10.0.0.1/",                         // RFC1918
            "http://172.16.5.4/",                       // RFC1918
            "http://192.168.1.1/",                      // RFC1918
            "http://100.64.0.1/",                       // CGNAT / shared
            "http://0.0.0.0/",                          // unspecified
            "http://[::1]/",                            // IPv6 loopback
            "http://[fe80::1]/",                        // IPv6 link-local
            "http://[fc00::1]/",                        // IPv6 unique-local
            "http://[::ffff:169.254.169.254]/",         // IPv4-mapped link-local
            "http://localhost/",                        // loopback host name
            "http://api.localhost/",                    // loopback host name suffix
            "http://LOCALHOST/",                        // case-insensitive host name
            "http://127.0.0.1./",                       // trailing-dot FQDN form of loopback
            "http://2130706433/",                       // obfuscated decimal 127.0.0.1
            "http://0x7f000001/",                       // obfuscated hex 127.0.0.1
            "http://127.1/",                            // short-form IPv4 loopback
        ] {
            assert!(
                host_is_non_global(&Uri::from_static(uri)),
                "expected {uri} to be denied"
            );
        }
    }

    #[test]
    fn strict_policy_allows_global_hosts() {
        for uri in [
            "http://93.184.216.34/",            // public IPv4 literal
            "https://contentauthenticity.org/", // public host name
            "https://sub.example.com/path",
            "http://[2606:2800:220:1:248:1893:25c8:1946]/", // public IPv6 literal
            "http://cafe.example.com/", // hex-looking label is a normal host name
        ] {
            assert!(
                !host_is_non_global(&Uri::from_static(uri)),
                "expected {uri} to be allowed"
            );
        }
    }
}
