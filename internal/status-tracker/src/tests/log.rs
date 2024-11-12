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

use crate::{log_item, LogItem};

#[test]
fn new() {
    let log_item = LogItem::new("test1", "test item 1", "test func", "src/test.rs", 42);

    assert_eq!(
        log_item,
        LogItem {
            label: "test1".to_string(),
            description: "test item 1".to_string(),
            file: "src/test.rs".to_string(),
            function: "test func".to_string(),
            line: 42u32,
            err_val: None,
            validation_status: None,
        }
    );
}

#[test]
fn error() {
    let log_item = LogItem::new("test1", "test item 1", "test func", "src/test.rs", 42)
        .error("sample error message");

    assert_eq!(
        log_item,
        LogItem {
            label: "test1".to_string(),
            description: "test item 1".to_string(),
            file: "src/test.rs".to_string(),
            function: "test func".to_string(),
            line: 42u32,
            err_val: Some("\"sample error message\"".to_string()),
            validation_status: None,
        }
    );
}

#[test]
fn validation_status() {
    let log_item = LogItem::new("test1", "test item 1", "test func", "src/test.rs", 42)
        .validation_status("claim.missing");

    assert_eq!(
        log_item,
        LogItem {
            label: "test1".to_string(),
            description: "test item 1".to_string(),
            file: "src/test.rs".to_string(),
            function: "test func".to_string(),
            line: 42u32,
            err_val: None,
            validation_status: Some("claim.missing".to_string()),
        }
    );
}

#[test]
fn r#macro() {
    let log_item: LogItem = log_item!("test1", "test item 1", "test func");

    assert_eq!(
        log_item,
        LogItem {
            label: "test1".to_string(),
            description: "test item 1".to_string(),
            file: file!().to_string(),
            function: "test func".to_string(),
            line: log_item.line,
            err_val: None,
            validation_status: None,
        }
    );

    assert!(log_item.line > 2);
}

#[test]
fn impl_clone() {
    // Generate coverage for the #[derive(...)] line.
    let log_item: LogItem = log_item!("test1", "test item 1", "test func");
    let li2 = log_item.clone();

    assert_eq!(log_item, li2);
}
