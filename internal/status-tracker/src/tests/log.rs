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

use crate::{log_item, DetailedStatusTracker, LogItem, LogKind, StatusTracker};

#[test]
fn r#macro() {
    let log = log_item!("test1", "test item 1", "test func");

    assert_eq!(
        log,
        LogItem {
            kind: LogKind::Informational,
            label: Cow::Borrowed("test1"),
            description: Cow::Borrowed("test item 1"),
            crate_name: env!("CARGO_PKG_NAME").into(),
            crate_version: env!("CARGO_PKG_VERSION").into(),
            file: Cow::Borrowed(file!()),
            function: Cow::Borrowed("test func"),
            line: log.line,
            err_val: None,
            validation_status: None,
            ..Default::default()
        }
    );

    assert!(log.line > 2);
}

#[test]
fn macro_from_string() {
    let desc = "test item 1".to_string();
    let log = log_item!("test1", desc, "test func");

    assert_eq!(
        log,
        LogItem {
            kind: crate::LogKind::Informational,
            label: Cow::Borrowed("test1"),
            description: Cow::Owned("test item 1".to_string()),
            crate_name: env!("CARGO_PKG_NAME").into(),
            crate_version: env!("CARGO_PKG_VERSION").into(),
            file: Cow::Borrowed(file!()),
            function: Cow::Borrowed("test func"),
            line: log.line,
            err_val: None,
            validation_status: None,
            ..Default::default()
        }
    );

    assert!(log.line > 2);
}

#[test]
fn success() {
    let mut tracker = DetailedStatusTracker::default();
    log_item!("test1", "test item 1", "test func").success(&mut tracker);

    let log_item = tracker.logged_items().first().unwrap();

    assert_eq!(
        log_item,
        &LogItem {
            kind: LogKind::Success,
            label: Cow::Borrowed("test1"),
            description: Cow::Borrowed("test item 1"),
            crate_name: env!("CARGO_PKG_NAME").into(),
            crate_version: env!("CARGO_PKG_VERSION").into(),
            file: Cow::Borrowed(file!()),
            function: Cow::Borrowed("test func"),
            line: log_item.line,
            err_val: None,
            validation_status: None,
            ingredient_uri: None,
        }
    );
}

#[test]
fn informational() {
    let mut tracker = DetailedStatusTracker::default();
    log_item!("test1", "test item 1", "test func").informational(&mut tracker);

    let log_item = tracker.logged_items().first().unwrap();

    assert_eq!(
        log_item,
        &LogItem {
            kind: LogKind::Informational,
            label: Cow::Borrowed("test1"),
            description: Cow::Borrowed("test item 1"),
            crate_name: env!("CARGO_PKG_NAME").into(),
            crate_version: env!("CARGO_PKG_VERSION").into(),
            file: Cow::Borrowed(file!()),
            function: Cow::Borrowed("test func"),
            line: log_item.line,
            err_val: None,
            validation_status: None,
            ..Default::default()
        }
    );
}

#[test]
fn failure() {
    let mut tracker = DetailedStatusTracker::default();
    log_item!("test1", "test item 1", "test func")
        .failure(&mut tracker, "sample error message")
        .unwrap();

    let log_item = tracker.logged_items().first().unwrap();

    assert_eq!(
        log_item,
        &LogItem {
            kind: LogKind::Failure,
            label: Cow::Borrowed("test1"),
            description: Cow::Borrowed("test item 1"),
            crate_name: env!("CARGO_PKG_NAME").into(),
            crate_version: env!("CARGO_PKG_VERSION").into(),
            file: Cow::Borrowed(file!()),
            function: Cow::Borrowed("test func"),
            line: log_item.line,
            err_val: Some(Cow::Borrowed("\"sample error message\"")),
            validation_status: None,
            ..Default::default()
        }
    );
}

#[test]
fn failure_no_throw() {
    let mut tracker = DetailedStatusTracker::default();
    log_item!("test1", "test item 1", "test func")
        .failure_no_throw(&mut tracker, "sample error message");

    let log_item = tracker.logged_items().first().unwrap();

    assert_eq!(
        log_item,
        &LogItem {
            kind: LogKind::Failure,
            label: Cow::Borrowed("test1"),
            description: Cow::Borrowed("test item 1"),
            crate_name: env!("CARGO_PKG_NAME").into(),
            crate_version: env!("CARGO_PKG_VERSION").into(),
            file: Cow::Borrowed(file!()),
            function: Cow::Borrowed("test func"),
            line: log_item.line,
            err_val: Some(Cow::Borrowed("\"sample error message\"")),
            ..Default::default()
        }
    );
}

#[test]
fn validation_status() {
    let log_item =
        log_item!("test1", "test item 1", "test func").validation_status("claim.missing");

    assert_eq!(
        log_item,
        LogItem {
            kind: LogKind::Informational,
            label: Cow::Borrowed("test1"),
            description: Cow::Borrowed("test item 1"),
            crate_name: env!("CARGO_PKG_NAME").into(),
            crate_version: env!("CARGO_PKG_VERSION").into(),
            file: Cow::Borrowed(file!()),
            function: Cow::Borrowed("test func"),
            line: log_item.line,
            err_val: None,
            validation_status: Some(Cow::Borrowed("claim.missing")),
            ..Default::default()
        }
    );
}

#[test]
fn impl_clone() {
    // Generate coverage for the #[derive(...)] line.
    let li1 = log_item!("test1", "test item 1", "test func");
    let li2 = li1.clone();

    assert_eq!(li1, li2);
}
