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

// When at least one integration test doesn't use all of the exported methods, there are
// dead code warnings causing clippy CI to fail.
#![allow(dead_code)]

use std::{path::PathBuf, process::Command};

use anyhow::Result;
use httpmock::{Method, Mock, MockServer};
use insta_cmd::get_cargo_bin;
use serde_json::Value;

pub const TEST_IMAGE_WITH_MANIFEST: &str = "C.jpg";
pub const TEST_IMAGE_WITH_MANIFEST_FORMAT: &str = "image/jpeg";

pub fn fixture_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures");
    path.push(name);
    path
}

pub fn test_img_path() -> PathBuf {
    fixture_path(TEST_IMAGE_WITH_MANIFEST)
}

pub fn cli() -> Command {
    Command::new(get_cargo_bin("c2patool"))
}

pub fn create_mock_server<'a>(
    server: &'a MockServer,
    anchor_source: &str,
    config_source: &str,
) -> Vec<Mock<'a>> {
    let anchor_path = fixture_path(anchor_source).to_str().unwrap().to_owned();
    let trust_mock = server.mock(|when, then| {
        when.method(Method::GET).path("/trust/anchors.pem");
        then.status(200)
            .header("content-type", "text/plain")
            .body_from_file(anchor_path);
    });
    let config_path = fixture_path(config_source).to_str().unwrap().to_owned();
    let config_mock = server.mock(|when, then| {
        when.method(Method::GET).path("/trust/store.cfg");
        then.status(200)
            .header("content-type", "text/plain")
            .body_from_file(config_path);
    });

    vec![trust_mock, config_mock]
}

pub fn unescape_json(str: &str) -> Result<Value> {
    Ok(serde_json::from_str(str)?)
}

// This macro filters unstable snapshot output values so that we can properly diff changes.
#[macro_export]
macro_rules! apply_filters {
    {} => {
        // TODO: c2pa regex patterns can be more strict and granular
        let mut settings = insta::Settings::clone_current();
        // macOS temp folder
        settings.add_filter(r"/var/folders/\S+?/T/\S+", "[TEMP_FILE]");
        // Linux temp folder
        settings.add_filter(r"/tmp/\.tmp\S+", "[TEMP_FILE]");
        // Windows temp folder
        settings.add_filter(r"\b[A-Z]:\\.*\\Local\\Temp\\\S+", "[TEMP_FILE]");
        // Convert Windows paths to Unix Paths
        settings.add_filter(r"\\\\?([\w\d.])", "/$1");
        // Jumbf URI
        settings.add_filter(r#""self#jumbf=.*""#, r#""[JUMBF_URI]""#);
        // Xmp id
        settings.add_filter(r#""xmp:iid:.*""#, r#"[XMP_ID]""#);
        // Manifest URN
        settings.add_filter(r#""(?:contentauth:)?urn:uuid:.*""#, r#""[MANIFEST_URN]""#);
        // Timestamp1
        settings.add_filter(r#""\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}""#, r#""[TIMESTAMP1]""#);
        // Timestamp2
        settings.add_filter(r#"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6} UTC"#, r#""[TIMESTAMP2]""#);
        let _guard = settings.bind_to_scope();
    }
}

// When using assert_cmd_snapshot! with absolute file paths, it will include local filesystem structure and account
// username. Ideally we'd be able to filter this information, but that's currently not supported: https://github.com/mitsuhiko/insta/issues/500
#[macro_export]
macro_rules! hide_info {
    {} => {
        let mut settings = insta::Settings::clone_current();
        settings.remove_description();
        let _guard = settings.bind_to_scope();
    }
}
