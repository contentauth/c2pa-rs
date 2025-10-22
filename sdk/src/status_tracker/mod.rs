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

#![deny(missing_docs)]

use std::{fmt::Debug, iter::Iterator};

use log::info;

/// A `StatusTracker` is used in the validation logic of c2pa-rs and
/// related crates to control error-handling behavior and optionally
/// aggregate log messages as they are generated.
#[derive(Debug, Default)]
pub struct StatusTracker {
    error_behavior: ErrorBehavior,
    logged_items: Vec<LogItem>,
    ingredient_uris: Vec<String>,
    current_uri: Vec<String>,
}

impl StatusTracker {
    /// Returns a [`StatusTracker`] with the specified [`ErrorBehavior`].
    pub fn with_error_behavior(error_behavior: ErrorBehavior) -> Self {
        Self {
            error_behavior,
            logged_items: vec![],
            ingredient_uris: vec![],
            current_uri: vec![],
        }
    }

    /// Returns the current list of validation log items.
    pub fn logged_items(&self) -> &[LogItem] {
        &self.logged_items
    }

    /// Returns a list of validation log items that can be mutated if needed.
    pub fn logged_items_mut(&mut self) -> &mut [LogItem] {
        &mut self.logged_items
    }

    /// Appends the contents of another [`StatusTracker`] to this list of
    /// validation log items.
    pub fn append(&mut self, other: &StatusTracker) {
        for log_item in other.logged_items() {
            self.add_non_error(log_item.clone());
        }
    }

    /// Adds a non-error [`LogItem`] to this status tracker.
    ///
    /// Primarily intended for use by [`LogItem::success()`]
    /// or [`LogItem::informational()`].
    pub fn add_non_error(&mut self, mut log_item: LogItem) {
        if let Some(ingredient_uri) = self.ingredient_uris.last() {
            log_item.ingredient_uri = Some(ingredient_uri.to_string().into());
        }
        if log_item.label.is_empty() {
            if let Some(current_uri) = self.current_uri.last() {
                log_item.label = std::borrow::Cow::Owned(current_uri.to_string());
            }
        }
        info!("Validation info: {log_item:#?}");
        self.logged_items.push(log_item);
    }

    /// Adds an error-case [`LogItem`] to this status tracker.
    ///
    /// Will return `Err(err)` if configured to stop immediately on errors or
    /// `Ok(())` if configured to continue on errors. _(See [`ErrorBehavior`].)_
    ///
    /// Primarily intended for use by [`LogItem::failure()`]. The error value
    /// is available regardless of ErrorBehavior.
    pub fn add_error<E>(&mut self, mut log_item: LogItem, err: E) -> Result<E, E> {
        if let Some(ingredient_uri) = self.ingredient_uris.last() {
            log_item.ingredient_uri = Some(ingredient_uri.to_string().into());
        }
        if log_item.label.is_empty() {
            if let Some(current_uri) = self.current_uri.last() {
                log_item.label = std::borrow::Cow::Owned(current_uri.to_string());
            }
        }

        self.logged_items.push(log_item);

        match self.error_behavior {
            ErrorBehavior::StopOnFirstError => Err(err),
            ErrorBehavior::ContinueWhenPossible => Ok(err),
        }
    }

    /// Returns the [`LogItem`]s that have error conditions (`err_val` is
    /// populated).
    ///
    /// Removes matching items from the list of log items.
    pub fn filter_errors(&self) -> impl Iterator<Item = &LogItem> {
        self.logged_items()
            .iter()
            .filter(|item| item.err_val.is_some())
    }

    /// Returns `true` if the validation log contains a specific C2PA status
    /// code.
    pub fn has_status(&self, val: &str) -> bool {
        self.logged_items().iter().any(|vi| {
            if let Some(vs) = &vi.validation_status {
                vs == val
            } else {
                false
            }
        })
    }

    /// Returns `true` if the validation log contains a specific error.
    pub fn has_error<E: Debug>(&self, err: E) -> bool {
        let err_type = format!("{:?}", &err);
        self.logged_items().iter().any(|vi| {
            if let Some(e) = &vi.err_val {
                e == &err_type
            } else {
                false
            }
        })
    }

    /// Returns `true` if the validation log contains any error.
    pub fn has_any_error(&self) -> bool {
        self.filter_errors().next().is_some()
    }

    /// Keeps track of the current ingredient URI, if any.
    ///
    /// The current URI may be added to any log items that are created.
    pub fn push_ingredient_uri<S: Into<String>>(&mut self, uri: S) {
        self.ingredient_uris.push(uri.into());
    }

    /// Removes the current ingredient URI, if any.
    pub fn pop_ingredient_uri(&mut self) -> Option<String> {
        self.ingredient_uris.pop()
    }

    /// Returns the current ingredient URI, if any.
    pub fn ingredient_uri(&self) -> Option<&str> {
        self.ingredient_uris.last().map(|s| s.as_str())
    }

    /// Keeps track of the current URI, if any.
    ///
    /// The current URI may be added to any log items that are created.
    pub fn push_current_uri<S: Into<String>>(&mut self, uri: S) {
        self.current_uri.push(uri.into());
    }

    /// Removes the current URI, if any.
    pub fn pop_current_uri(&mut self) -> Option<String> {
        self.current_uri.pop()
    }

    /// Returns the current URI, if any.
    pub fn current_uri(&self) -> Option<&str> {
        self.current_uri.last().map(|s| s.as_str())
    }
}

/// `ErrorBehavior` configures the behavior of [`StatusTracker`] when its
/// [`add_error`] function is called.
///
/// [`add_error`]: StatusTracker::add_error
#[derive(Debug, Eq, PartialEq)]
pub enum ErrorBehavior {
    /// If an error is encountered, stop validation immediately.
    StopOnFirstError,

    /// If an error is encountered, log it and continue validation as much as
    /// possible.
    ContinueWhenPossible,
}

impl Default for ErrorBehavior {
    fn default() -> Self {
        Self::ContinueWhenPossible
    }
}

mod log_item;
pub use log_item::{LogItem, LogKind};

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use std::fmt::{self, Display, Formatter};

    mod detailed {
        use super::SampleError;
        use crate::{log_item, status_tracker::StatusTracker};

        #[test]
        fn aggregates_errors() {
            let mut tracker = StatusTracker::default();

            // Add an item without an error.
            log_item!("test1", "test item 1", "test func").success(&mut tracker);

            // Add another item with an error. Should not stop.
            log_item!("test2", "test item 1", "test func")
                .validation_status("foo.bar")
                .failure(&mut tracker, SampleError {})
                .unwrap();

            dbg!(&tracker);

            assert_eq!(tracker.logged_items().len(), 2);

            assert!(tracker.has_status("foo.bar"));
            assert!(!tracker.has_status("blah"));

            assert!(tracker.has_error(SampleError {}));
            assert!(!tracker.has_error("Something Else"));

            // Verify that one item with error was found.
            let errors: Vec<&crate::status_tracker::LogItem> = tracker.filter_errors().collect();
            assert_eq!(errors.len(), 1);
            assert_eq!(tracker.logged_items().len(), 2);
        }

        #[test]
        fn append() {
            let mut tracker1 = StatusTracker::default();
            let mut tracker2 = StatusTracker::default();

            log_item!("test1", "test item 1", "test func").success(&mut tracker1);

            log_item!("test2", "test item 1", "test func")
                .failure(&mut tracker2, SampleError {})
                .unwrap();

            assert_eq!(tracker1.logged_items().len(), 1);
            assert_eq!(tracker2.logged_items().len(), 1);

            tracker1.append(&tracker2);

            assert_eq!(tracker1.logged_items().len(), 2);
            assert_eq!(tracker2.logged_items().len(), 1);
        }
    }

    mod one_shot {
        use super::SampleError;
        use crate::{
            log_item,
            status_tracker::{ErrorBehavior, StatusTracker},
        };

        #[test]
        fn stops_on_first_error() {
            let mut tracker = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

            // Add an item without error.
            log_item!("test1", "test item 1", "test func").success(&mut tracker);

            // Adding an error item should trigger an abort.
            let err = log_item!("test2", "test item 2 from macro", "test func")
                .failure(&mut tracker, SampleError {})
                .unwrap_err();

            assert_eq!(err, SampleError {});
            assert_eq!(tracker.logged_items().len(), 2);
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct SampleError {}

    impl Display for SampleError {
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            write!(f, "SampleError")
        }
    }
}
