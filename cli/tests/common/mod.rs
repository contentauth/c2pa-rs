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

pub fn cmd() -> Command {
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

// Taken from: https://insta.rs/docs/cmd/
#[macro_export]
macro_rules! apply_path_filters {
    {} => {
        let mut settings = insta::Settings::clone_current();
        // Macos Temp Folder
        settings.add_filter(r"/var/folders/\S+?/T/\S+", "[TEMP_FILE]");
        // Linux Temp Folder
        settings.add_filter(r"/tmp/\.tmp\S+", "[TEMP_FILE]");
        // Windows Temp folder
        settings.add_filter(r"\b[A-Z]:\\.*\\Local\\Temp\\\S+", "[TEMP_FILE]");
        // Convert windows paths to Unix Paths.
        settings.add_filter(r"\\\\?([\w\d.])", "/$1");
        let _bound = settings.bind_to_scope();
    }
}

#[macro_export]
macro_rules! apply_manifest_filters {
    {} => {
        let mut settings = insta::Settings::clone_current();
        // jumbf uri
        settings.add_filter(r#""self#jumbf=.*""#, r#""[JUMBF_URI]""#);
        // xmp id
        settings.add_filter(r#""xmp:iid:.*""#, r#"[XMP_ID]""#);
        // manifest urn
        settings.add_filter(r#""(?:contentauth:)?urn:uuid:.*""#, r#""[MANIFEST_URN]""#);
        // timestamp
        settings.add_filter(r#""\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}""#, r#""[TIMESTAMP]""#);
        let _bound = settings.bind_to_scope();
    }
}
