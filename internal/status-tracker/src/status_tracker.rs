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

use std::{fmt::Debug, iter::Iterator};

use crate::LogItem;

/// A `StatusTracker` is used in the validation logic of c2pa-rs and
/// related crates to control error-handling behavior and optionally
/// aggregate log messages as they are generated.
#[derive(Debug, Default)]
pub struct StatusTracker {
    error_behavior: ErrorBehavior,
    logged_items: Vec<LogItem>,
    ingredient_uris: Vec<String>,
}

impl StatusTracker {
    /// Returns a [`StatusTracker`] with the specified [`ErrorBehavior`].
    pub fn with_error_behavior(error_behavior: ErrorBehavior) -> Self {
        Self {
            error_behavior,
            logged_items: vec![],
            ingredient_uris: vec![],
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
        self.logged_items.push(log_item);
    }

    /// Adds an error-case [`LogItem`] to this status tracker.
    ///
    /// Will return `Err(err)` if configured to stop immediately on errors or
    /// `Ok(())` if configured to continue on errors. _(See [`ErrorBehavior`].)_
    ///
    /// Primarily intended for use by [`LogItem::failure()`].
    pub fn add_error<E>(&mut self, mut log_item: LogItem, err: E) -> Result<(), E> {
        if let Some(ingredient_uri) = self.ingredient_uris.last() {
            log_item.ingredient_uri = Some(ingredient_uri.to_string().into());
        }

        self.logged_items.push(log_item);

        match self.error_behavior {
            ErrorBehavior::StopOnFirstError => Err(err),
            ErrorBehavior::ContinueWhenPossible => Ok(()),
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
