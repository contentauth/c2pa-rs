// Copyright 2022 Adobe. All rights reserved.
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

use std::{path::PathBuf, str::FromStr};

use anyhow::{Context, Result};
use c2pa::settings::Settings;
use log::debug;
use url::Url;

/// A trust resource that can be either a local file or a remote URL.
#[derive(Clone, Debug)]
pub enum TrustResource {
    File(PathBuf),
    Url(Url),
}

pub fn parse_resource_string(s: &str) -> Result<TrustResource> {
    if let Ok(url) = s.parse::<Url>() {
        Ok(TrustResource::Url(url))
    } else {
        Ok(TrustResource::File(PathBuf::from_str(s)?))
    }
}

pub fn load_trust_resource(resource: &TrustResource) -> Result<String> {
    match resource {
        TrustResource::File(path) => std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read trust resource from path: {path:?}")),
        TrustResource::Url(url) => {
            #[cfg(not(target_os = "wasi"))]
            let data = reqwest::blocking::get(url.to_string())?
                .text()
                .with_context(|| format!("Failed to read trust resource from URL: {url}"))?;

            #[cfg(target_os = "wasi")]
            let data = wasi_blocking_get(&url.to_string())?;

            Ok(data)
        }
    }
}

/// Apply trust anchor, allowed list, and trust config resources to a Settings object.
/// Returns true if any trust resource was applied (which enables trust verification).
pub fn apply_trust_settings(
    settings: &mut Settings,
    trust_anchors: Option<&TrustResource>,
    allowed_list: Option<&TrustResource>,
    trust_config: Option<&TrustResource>,
) -> Result<bool> {
    let mut enabled = false;

    if let Some(trust_list) = trust_anchors {
        debug!("Using trust anchors from {trust_list:?}");
        let data = load_trust_resource(trust_list)?;
        settings.update_from_str(
            &toml::toml! {
                [trust]
                trust_anchors = data
            }
            .to_string(),
            "toml",
        )?;
        enabled = true;
    }

    if let Some(list) = allowed_list {
        debug!("Using allowed list from {list:?}");
        let data = load_trust_resource(list)?;
        settings.update_from_str(
            &toml::toml! {
                [trust]
                allowed_list = data
            }
            .to_string(),
            "toml",
        )?;
        enabled = true;
    }

    if let Some(cfg) = trust_config {
        debug!("Using trust config from {cfg:?}");
        let data = load_trust_resource(cfg)?;
        settings.update_from_str(
            &toml::toml! {
                [trust]
                trust_config = data
            }
            .to_string(),
            "toml",
        )?;
        enabled = true;
    }

    if enabled {
        settings.update_from_str(
            &toml::toml! {
                [verify]
                verify_trust = true
            }
            .to_string(),
            "toml",
        )?;
    }

    Ok(enabled)
}

#[cfg(target_os = "wasi")]
fn wasi_blocking_get(url: &str) -> Result<String> {
    use std::io::Read;

    use url::Url;
    use wasi::http::{
        outgoing_handler,
        types::{Fields, OutgoingRequest, Scheme},
    };

    let parsed_url =
        Url::parse(url).map_err(|e| c2pa::Error::ResourceNotFound(format!("invalid URL: {e}")))?;
    let path_with_query = parsed_url[url::Position::BeforeHost..].to_string();
    let request = OutgoingRequest::new(Fields::new());
    request.set_path_with_query(Some(&path_with_query)).unwrap();

    let scheme = match parsed_url.scheme() {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        _ => return Err(anyhow!("unsupported URL scheme")),
    };
    request.set_scheme(Some(&scheme)).unwrap();

    match outgoing_handler::handle(request, None) {
        Ok(resp) => {
            resp.subscribe().block();
            let response = resp
                .get()
                .expect("HTTP request response missing")
                .expect("HTTP request response requested more than once")
                .expect("HTTP request failed");

            if response.status() == 200 {
                let raw_header = response.headers().get("Content-Length");
                if raw_header.first().map(|val| val.is_empty()).unwrap_or(true) {
                    return Err(anyhow!("url returned no content length"));
                }
                let str_header = std::str::from_utf8(raw_header.first().unwrap())
                    .map_err(|e| anyhow!("error parsing content length header: {e}"))?;
                let content_length: usize = str_header
                    .parse()
                    .map_err(|e| anyhow!("error parsing content length header: {e}"))?;

                let body = {
                    let mut buf = Vec::with_capacity(content_length);
                    let response_body = response.consume().expect("failed to get response body");
                    let mut stream = response_body
                        .stream()
                        .expect("failed to get response body stream");
                    stream
                        .read_to_end(&mut buf)
                        .expect("failed to read response body");
                    buf
                };
                std::str::from_utf8(&body)
                    .map(|s| s.to_string())
                    .map_err(|e| anyhow!("invalid UTF-8: {e}"))
            } else {
                Err(anyhow!("fetch failed: code: {}", response.status()))
            }
        }
        Err(e) => Err(anyhow!(e.to_string())),
    }
}
