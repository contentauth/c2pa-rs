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

use std::fmt;

use c2pa_status_tracker::LogItem;

use crate::error::{Error, Result};

pub trait StatusTracker: Send {
    // should we stop on the first error
    fn stop_on_error(&self) -> bool;

    // return reference to current set of validation items
    fn get_log(&self) -> &Vec<LogItem>;

    // return mutable reference to current set of validation items
    fn get_log_mut(&mut self) -> &mut Vec<LogItem>;

    // Log an item.  Returns err if available
    // and stop_on_error is true.  Otherwise success OK(())
    // log_item - LogItem to be recorded
    // err - optional Error value to be returned if stop_on_error is true and item contain an error,
    // otherwise if None, Error:LogStop will be returned if stop_on_err is true.
    // The actual error is always available in the log_item.  This allows the caller
    // to return an error even when the error does not implement Clone.
    fn log(&mut self, log_item: LogItem, err: Option<Error>) -> Result<()>;

    // Log an item. No special consideration are given to the contents of the log item.
    fn log_silent(&mut self, log_item: LogItem);
}

impl fmt::Display for dyn StatusTracker {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.get_log())
    }
}

impl fmt::Debug for dyn StatusTracker {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.get_log())
    }
}

// Logger that returns success regardless of if LogItem was for an error condition
#[derive(Default, Debug)]
pub struct DetailedStatusTracker {
    logged_items: Vec<LogItem>,
    stop_on_error: bool,
}

impl DetailedStatusTracker {
    pub fn new() -> Self {
        DetailedStatusTracker {
            logged_items: Vec::new(),
            stop_on_error: false,
        }
    }
}

impl StatusTracker for DetailedStatusTracker {
    fn stop_on_error(&self) -> bool {
        self.stop_on_error
    }

    fn get_log(&self) -> &Vec<LogItem> {
        &self.logged_items
    }

    fn get_log_mut(&mut self) -> &mut Vec<LogItem> {
        &mut self.logged_items
    }

    fn log(&mut self, log_item: LogItem, err: Option<Error>) -> Result<()> {
        let item_has_err = log_item.err_val.is_some();
        self.logged_items.push(log_item);
        if self.stop_on_error && item_has_err {
            Err(err.unwrap_or(Error::LogStop))
        } else {
            Ok(())
        }
    }

    fn log_silent(&mut self, log_item: LogItem) {
        self.logged_items.push(log_item);
    }
}

// Logger that will returns error values on LogItems with error
#[derive(Default, Debug)]
pub struct OneShotStatusTracker {
    logged_items: Vec<LogItem>,
    stop_on_error: bool,
}

impl OneShotStatusTracker {
    pub fn new() -> Self {
        OneShotStatusTracker {
            logged_items: Vec::new(),
            stop_on_error: true,
        }
    }
}

impl StatusTracker for OneShotStatusTracker {
    fn stop_on_error(&self) -> bool {
        self.stop_on_error
    }

    fn get_log(&self) -> &Vec<LogItem> {
        &self.logged_items
    }

    fn get_log_mut(&mut self) -> &mut Vec<LogItem> {
        &mut self.logged_items
    }

    fn log(&mut self, log_item: LogItem, err: Option<Error>) -> Result<()> {
        let item_has_err = log_item.err_val.is_some();
        self.logged_items.push(log_item);
        if self.stop_on_error && item_has_err {
            Err(err.unwrap_or(Error::LogStop))
        } else {
            Ok(())
        }
    }

    fn log_silent(&mut self, log_item: LogItem) {
        self.logged_items.push(log_item);
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
        let item1 = log_item!("test1", "test item 1", "test func");
        assert!(tracker.log(item1, None).is_ok());

        // item with an error
        let item2 = log_item!("test2", "test item 1", "test func").error(Error::NotFound); // add arbitrary error
        assert!(tracker.log(item2, None).is_err());

        // item with error with caller specified error response, testing macro for generation
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
        let item1 = log_item!("test1", "test item 1", "test func");
        assert!(tracker.log(item1, None).is_ok());

        // item with an error
        let item2 = log_item!("test2", "test item 1", "test func").error(Error::NotFound); // add arbitrary error
        assert!(tracker.log(item2, None).is_ok());

        // item with error with caller specified error response, testing macro for generation
        let item3 =
            log_item!("test3", "test item 3 from macro", "test func").error(Error::UnsupportedType);
        assert!(tracker.log(item3, Some(Error::NotFound)).is_ok());

        // item with error with caller specified error response, testing macro for generation, test validation_status
        let item4 = log_item!("test3", "test item 3 from macro", "test func")
            .error(Error::UnsupportedType)
            .validation_status(validation_status::ALGORITHM_UNSUPPORTED);
        assert!(tracker.log(item4, None).is_ok());

        // there should be two items with error
        let errors = report_split_errors(tracker.get_log_mut());
        assert_eq!(errors.len(), 3);
    }
}
