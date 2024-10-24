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

use crate::{
    status_tracker::{
        log_item, report_split_errors, DetailedStatusTracker, LogItem, OneShotStatusTracker,
        StatusTracker,
    },
    validation_status, Error,
};

#[test]
fn test_standard_tracker_stopping_for_error() {
    let mut tracker = OneShotStatusTracker::new();

    // item without error
    let item1 = LogItem::new("test1", "test item 1", "test func", file!(), line!());
    assert!(tracker.log(item1, None).is_ok());

    // item with an error
    let item2 =
        LogItem::new("test2", "test item 1", "test func", file!(), line!()).error(Error::NotFound); // add arbitrary error
    assert!(tracker.log(item2, None).is_err());

    // item with error with caller specified error response, testing macro for
    // generation
    let item3 = log_item!("test3", "test item 3 from macro", "test func")
        .error(Error::UnsupportedType)
        .validation_status(validation_status::ALGORITHM_UNSUPPORTED);
    assert!(matches!(
        tracker.log(item3, Some(Error::NotFound)),
        Err(Error::NotFound)
    ));
}

#[test]
fn test_standard_tracker_no_stopping_for_error() {
    let mut tracker = DetailedStatusTracker::new();

    // item without error
    let item1 = LogItem::new("test1", "test item 1", "test func", file!(), line!());
    assert!(tracker.log(item1, None).is_ok());

    // item with an error
    let item2 =
        LogItem::new("test2", "test item 1", "test func", file!(), line!()).error(Error::NotFound); // add arbitrary error
    assert!(tracker.log(item2, None).is_ok());

    // item with error with caller specified error response, testing macro for
    // generation
    let item3 =
        log_item!("test3", "test item 3 from macro", "test func").error(Error::UnsupportedType);
    assert!(tracker.log(item3, Some(Error::NotFound)).is_ok());

    // item with error with caller specified error response, testing macro for
    // generation, test validation_status
    let item4 = log_item!("test3", "test item 3 from macro", "test func")
        .error(Error::UnsupportedType)
        .validation_status(validation_status::ALGORITHM_UNSUPPORTED);
    assert!(tracker.log(item4, None).is_ok());

    // there should be two items with error
    let errors = report_split_errors(tracker.get_log_mut());
    assert_eq!(errors.len(), 3);
}
