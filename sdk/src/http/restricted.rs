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

use std::io::Read;

use async_trait::async_trait;
use http::{Request, Response, Uri};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    http::{
        AsyncGenericResolver, AsyncHttpResolver, HttpResolverError, SyncGenericResolver,
        SyncHttpResolver,
    },
    Result,
};

#[derive(Debug)]
pub struct RestrictedResolver<T> {
    inner: T,
    allowed_hosts: Vec<HostPattern>,
}

impl<T> RestrictedResolver<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            allowed_hosts: Vec::new(),
        }
    }

    pub fn with_allowed_hosts(inner: T, allowed_hosts: Vec<HostPattern>) -> Self {
        Self {
            inner,
            allowed_hosts,
        }
    }

    pub fn allowed_hosts(&self) -> &[HostPattern] {
        &self.allowed_hosts
    }
}

impl Default for RestrictedResolver<SyncGenericResolver> {
    fn default() -> Self {
        Self {
            inner: SyncGenericResolver::new(),
            allowed_hosts: Vec::new(),
        }
    }
}

impl Default for RestrictedResolver<AsyncGenericResolver> {
    fn default() -> Self {
        Self {
            inner: AsyncGenericResolver::new(),
            allowed_hosts: Vec::new(),
        }
    }
}

impl<T: SyncHttpResolver> SyncHttpResolver for RestrictedResolver<T> {
    fn http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
        match is_uri_allowed(self.allowed_hosts(), request.uri()) {
            true => self.inner.http_resolve(request),
            false => Err(HttpResolverError::UriDisallowed {
                uri: request.uri().to_string(),
            }),
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
        match is_uri_allowed(self.allowed_hosts(), request.uri()) {
            true => self.inner.http_resolve_async(request).await,
            false => Err(HttpResolverError::UriDisallowed {
                uri: request.uri().to_string(),
            }),
        }
    }
}

#[cfg_attr(
    feature = "json_schema",
    derive(schemars::JsonSchema),
    schemars(with = "String")
)]
#[derive(Debug, Clone, PartialEq)]
pub struct HostPattern {
    uri: Uri,
}

impl HostPattern {
    // TODO: validate it doesn't have more than a scheme and a host and that it has at least 1
    pub fn new(uri: Uri) -> Self {
        Self { uri }
    }

    pub fn matches(&self, uri: &Uri) -> bool {
        if let Some(allowed_host_pattern) = self.uri.host() {
            if let Some(host) = uri.host() {
                // If there's a wildcard, do an suffix match, otherwise do an exact match.
                let host_allowed = if let Some(suffix) = allowed_host_pattern.strip_prefix("*.") {
                    let host = host.to_ascii_lowercase();
                    let suffix = suffix.to_ascii_lowercase();

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
                    if let Some(allowed_scheme) = self.uri.scheme() {
                        if let Some(scheme) = uri.scheme() {
                            return scheme == allowed_scheme;
                        }
                    } else {
                        return true;
                    }
                }
            }
        } else if let Some(allowed_scheme) = self.uri.scheme() {
            if let Some(scheme) = uri.scheme() {
                return scheme == allowed_scheme;
            }
        }

        false
    }
}

impl Serialize for HostPattern {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.uri.to_string())
    }
}

impl<'de> Deserialize<'de> for HostPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        let uri = string.parse::<Uri>().map_err(serde::de::Error::custom)?;
        Ok(HostPattern::new(uri))
    }
}

fn is_uri_allowed(patterns: &[HostPattern], uri: &Uri) -> bool {
    if patterns.is_empty() {
        return true;
    }

    for pattern in patterns {
        if pattern.matches(uri) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic_wildcard_pattern() {
        let pattern = HostPattern::new(Uri::from_static("*.contentauthenticity.org"));

        let uri = Uri::from_static("test.contentauthenticity.org");
        assert!(pattern.matches(&uri));

        let uri = Uri::from_static("contentauthenticity.org");
        assert!(!pattern.matches(&uri));

        let uri = Uri::from_static("fakecontentauthenticity.org");
        assert!(!pattern.matches(&uri));
    }

    #[test]
    fn wildcard_pattern_with_scheme() {
        let pattern = HostPattern::new(Uri::from_static("https://*.contentauthenticity.org"));

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
    fn pattern_case_insensitive() {
        let pattern = HostPattern::new(Uri::from_static("*.contentAuthenticity.org"));

        let uri = Uri::from_static("tEst.conTentauthenticity.orG");
        assert!(pattern.matches(&uri));
    }

    #[test]
    fn pattern_exact() {
        let pattern = HostPattern::new(Uri::from_static("contentauthenticity.org"));

        let uri = Uri::from_static("contentauthenticity.org");
        assert!(pattern.matches(&uri));

        let uri = Uri::from_static("https://contentauthenticity.org");
        assert!(pattern.matches(&uri));

        let uri = Uri::from_static("http://contentauthenticity.org");
        assert!(pattern.matches(&uri));
    }

    #[test]
    fn pattern_exact_with_schema() {
        let pattern = HostPattern::new(Uri::from_static("https://contentauthenticity.org"));

        let uri = Uri::from_static("https://contentauthenticity.org");
        assert!(pattern.matches(&uri));

        let uri = Uri::from_static("http://contentauthenticity.org");
        assert!(!pattern.matches(&uri));

        let uri = Uri::from_static("contentauthenticity.org");
        assert!(!pattern.matches(&uri));
    }
}
