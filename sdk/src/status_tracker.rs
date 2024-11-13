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

use std::fmt::{self, Display, Formatter};

use c2pa_status_tracker::LogItem;
pub use c2pa_status_tracker::{DetailedStatusTracker, StatusTracker};

use crate::error::Error;

// Logger that will returns error values on LogItems with error
#[derive(Default, Debug)]
pub struct OneShotStatusTracker {
    logged_items: Vec<LogItem>,
}

impl OneShotStatusTracker {
    pub fn new() -> Self {
        OneShotStatusTracker {
            logged_items: Vec::new(),
        }
    }
}

impl StatusTracker for OneShotStatusTracker {
    fn get_log(&self) -> &[LogItem] {
        &self.logged_items
    }

    fn get_log_mut(&mut self) -> &mut Vec<LogItem> {
        &mut self.logged_items
    }

    fn add_non_error(&mut self, log_item: LogItem) {
        self.logged_items.push(log_item);
    }

    fn add_error<E>(&mut self, log_item: LogItem, err: E) -> std::result::Result<(), E> {
        let item_has_err = log_item.err_val.is_some();
        self.logged_items.push(log_item);
        if item_has_err {
            Err(err)
        } else {
            Ok(())
        }
    }
}

impl Display for OneShotStatusTracker {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self.logged_items)
    }
}

/// Check to see if report contains a specific C2PA status code
#[allow(dead_code)] // in case we make use of these or export this
pub fn report_has_status(report: &[LogItem], val: &str) -> bool {
    report.iter().any(|vi| {
        if let Some(vs) = &vi.validation_status {
            vs == val
        } else {
            false
        }
    })
}

/// Check to see if report contains a specific error
#[allow(dead_code)] // in case we make use of these or export this
pub fn report_has_err(report: &[LogItem], err: Error) -> bool {
    let err_type = format!("{:?}", &err);
    report.iter().any(|vi| {
        if let Some(e) = &vi.err_val {
            e == &err_type
        } else {
            false
        }
    })
}

/// Split Errors off from rest of report
#[allow(dead_code)] // in case we make use of these or export this
pub fn report_split_errors(report: &mut Vec<LogItem>) -> Vec<LogItem> {
    let mut output: Vec<LogItem> = Vec::new();

    let mut i = 0;
    while i < report.len() {
        if report[i].err_val.is_some() {
            output.push(report.remove(i));
        } else {
            i += 1;
        }
    }
    output
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use c2pa_status_tracker::log_item;

    use super::*;
    use crate::validation_status;

    #[test]
    fn test_standard_tracker_stopping_for_error() {
        let mut tracker = OneShotStatusTracker::new();

        // item without error
        log_item!("test1", "test item 1", "test func").success(&mut tracker);

        // item with an error
        // let item2 = log_item!("test2", "test item 1", "test func").error(Error::NotFound); // add arbitrary error
        // HMMM ... I didn't know log_silent would error out.
        // assert!(tracker.log_silent(item2).is_err());

        // item with error with caller specified error response, testing macro for generation
        let err = log_item!("test3", "test item 3 from macro", "test func")
            .validation_status(validation_status::ALGORITHM_UNSUPPORTED)
            .failure(&mut tracker, Error::NotFound)
            .unwrap_err();

        assert!(matches!(err, Error::NotFound));
    }

    #[test]
    fn test_standard_tracker_no_stopping_for_error() {
        let mut tracker = DetailedStatusTracker::default();

        // item without error
        log_item!("test1", "test item 1", "test func").success(&mut tracker);

        // item with an error
        log_item!("test2", "test item 1", "test func")
            .failure_no_throw(&mut tracker, Error::NotFound);

        // item with error with caller specified error response, testing macro for generation
        log_item!("test3", "test item 3 from macro", "test func")
            .failure(&mut tracker, Error::UnsupportedType)
            .unwrap();

        // item with error with caller specified error response, testing macro for generation, test validation_status
        log_item!("test3", "test item 3 from macro", "test func")
            .validation_status(validation_status::ALGORITHM_UNSUPPORTED)
            .failure_no_throw(&mut tracker, Error::UnsupportedType);

        // there should be two items with error
        let errors = report_split_errors(tracker.get_log_mut());
        assert_eq!(errors.len(), 3);
    }
}
