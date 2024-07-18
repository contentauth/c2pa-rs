// Copyright 2024 Adobe. All rights reserved.
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

pub mod asset;
mod test_signer;

use std::{fs, path::Path};

use c2pa::{format_from_path, Reader, Result};
#[allow(unused)]
pub use test_signer::test_signer;

#[allow(unused_macros)]
macro_rules! assert_err {
    ($expression:expr, $($pattern:tt)+) => {
        match $expression {
            $($pattern)+ => (),
            ref e => panic!("expected `{}` but got `{:?}`", stringify!($($pattern)+), e),
        }
    }
}
#[allow(unused_imports)]
pub(super) use assert_err;

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
        settings.add_filter(r#""(?:[^:]+:)?urn:uuid:.*""#, r#""[MANIFEST_URN]""#);
        // Timestamp1
        settings.add_filter(r#""\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}""#, r#""[TIMESTAMP1]""#);
        // Timestamp2
        settings.add_filter(r#"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ UTC"#, r#""[TIMESTAMP2]""#);
        let _guard = settings.bind_to_scope();
    }
}

// The order of the output in some scenarios can be arbitrary, so we sort it beforehand
// as to not affect the diff.
#[macro_export]
macro_rules! apply_sorted_output {
    {} => {
    let mut settings = Settings::clone_current();
    settings.set_sort_maps(true);
    let _guard = settings.bind_to_scope();
    }
}

pub fn unescape_json(str: &str) -> Result<serde_json::Value> {
    Ok(serde_json::from_str(str)?)
}

#[allow(unused)]
pub fn check_validation_status(reader: &Reader, code: &str) {
    if let Some(validation_statuses) = reader.validation_status() {
        assert!(
            validation_statuses
                .iter()
                .any(|status| status.code() == code),
            "Expected to find {code} in validation status"
        );
    } else {
        panic!("Expected to find validation status");
    }
}
