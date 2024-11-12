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

use std::borrow::Cow;

use crate::{log_item, LogItem};

#[test]
fn new() {
    let log_item = LogItem::new("test1", "test item 1", "test func", "src/test.rs", 42);

    assert_eq!(
        log_item,
        LogItem {
            label: Cow::Borrowed("test1"),
            description: Cow::Borrowed("test item 1"),
            file: Cow::Borrowed("src/test.rs"),
            function: Cow::Borrowed("test func"),
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
            label: Cow::Borrowed("test1"),
            description: Cow::Borrowed("test item 1"),
            file: Cow::Borrowed("src/test.rs"),
            function: Cow::Borrowed("test func"),
            line: 42u32,
            err_val: Some(Cow::Borrowed("\"sample error message\"")),
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
            label: Cow::Borrowed("test1"),
            description: Cow::Borrowed("test item 1"),
            file: Cow::Borrowed("src/test.rs"),
            function: Cow::Borrowed("test func"),
            line: 42u32,
            err_val: None,
            validation_status: Some(Cow::Borrowed("claim.missing")),
        }
    );
}

#[test]
fn r#macro() {
    let log = log_item!("test1", "test item 1", "test func");

    assert_eq!(
        log,
        LogItem {
            label: Cow::Borrowed("test1"),
            description: Cow::Borrowed("test item 1"),
            file: Cow::Borrowed(file!()),
            function: Cow::Borrowed("test func"),
            line: log.line,
            err_val: None,
            validation_status: None,
        }
    );

    assert!(log.line > 2);
}

#[test]
fn impl_clone() {
    // Generate coverage for the #[derive(...)] line.
    let li1 = log_item!("test1", "test item 1", "test func");
    let li2 = li1.clone();

    assert_eq!(li1, li2);
}
