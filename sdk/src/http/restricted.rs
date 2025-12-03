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
//! or [`AsyncHttpResolver`]. The SDK can also manage an allowed list for you via the
//! [`Core::allowed_network_hosts`] setting.
//!
//! # Why restrict network requests?
//! In some environments, you may not want the SDK to talk to arbitrary hosts. Restricting
//! network requests help to:
//! - Reduce SSRF-style risks (e.g. requests to internal services).
//! - Constrain requests to a small, trusted set of domains.
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

use std::io::Read;

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
    #[allow(dead_code)] // TODO: temp until http module is public
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
    pub fn allowed_hosts(&self) -> Option<&[HostPattern]> {
        self.allowed_hosts.as_deref()
    }
}

impl<T: SyncHttpResolver> SyncHttpResolver for RestrictedResolver<T> {
    fn http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        if self
            .allowed_hosts()
            .is_none_or(|hosts| is_uri_allowed(hosts, request.uri()))
        {
            self.inner.http_resolve(request)
        } else {
            Err(HttpResolverError::UriDisallowed {
                uri: request.uri().to_string(),
            })
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<T: AsyncHttpResolver + Sync> AsyncHttpResolver for RestrictedResolver<T> {
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        if self
            .allowed_hosts()
            .is_none_or(|hosts| is_uri_allowed(hosts, request.uri()))
        {
            self.inner.http_resolve_async(request).await
        } else {
            Err(HttpResolverError::UriDisallowed {
                uri: request.uri().to_string(),
            })
        }
    }
}

/// A host/scheme pattern used to restrict network requests.
///
/// Each pattern may include:
/// - A scheme (e.g. `https://` or `http://`)
/// - A hostname, which may have a single leading wildcard (e.g. `*.contentauthenticity.org`)
///
/// Matching is case-insensitive. A wildcard pattern such as `*.contentauthenticity.org` matches
/// `sub.contentauthenticity.org`, but does not match `contentauthenticity.org` or `fakecontentauthenticity.org`.
/// If a scheme is present in the pattern, only URIs using the same scheme are considered a match. If the scheme
/// is omitted, any scheme is allowed as long as the host matches.
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
}

impl HostPattern {
    /// Creates a new `HostPattern` with the given pattern.
    pub fn new(pattern: &str) -> Self {
        let pattern = pattern.to_ascii_lowercase();
        let (scheme, host): (Option<String>, Option<String>) =
            if let Some(host) = pattern.strip_prefix("https://") {
                (Some("https".to_owned()), Some(host.to_owned()))
            } else if let Some(host) = pattern.strip_prefix("http://") {
                (Some("http".to_owned()), Some(host.to_owned()))
            } else {
                (None, Some(pattern.clone()))
            };

        Self {
            pattern,
            scheme,
            host,
        }
    }

    /// Returns true if the given URI matches the `HostPattern`.
    pub fn matches(&self, uri: &Uri) -> bool {
        if let Some(allowed_host_pattern) = &self.host {
            if let Some(host) = uri.host() {
                // If there's a wildcard, do an suffix match, otherwise do an exact match.
                let host_allowed = if let Some(suffix) = allowed_host_pattern.strip_prefix("*.") {
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

                if host_allowed {
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
fn is_uri_allowed(patterns: &[HostPattern], uri: &Uri) -> bool {
    for pattern in patterns {
        if pattern.matches(uri) {
            return true;
        }
    }

    false
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
}
