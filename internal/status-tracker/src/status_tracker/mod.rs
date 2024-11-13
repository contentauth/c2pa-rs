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
pub trait StatusTracker: Debug + Send {
    /// Return the current list of validation log items.
    fn logged_items(&self) -> &[LogItem];

    /// Appends the contents of another [`StatusTracker`] to this list of
    /// validation log items.
    fn append(&mut self, other: &impl StatusTracker) {
        for log_item in other.logged_items() {
            self.add_non_error(log_item.clone());
        }
    }

    /// Add a non-error [`LogItem`] to this status tracker.
    ///
    /// Primarily intended for use by [`LogItem::success()`]
    /// or [`LogItem::informational()`].
    fn add_non_error(&mut self, log_item: LogItem);

    /// Add an error-case [`LogItem`] to this status tracker.
    ///
    /// Some implementations are configured to stop immediately on errors. If
    /// so, this function will return `Err(err)`.
    ///
    /// If the implementation is configured to aggregate all log
    /// messages, this function returns `Ok(())`.
    ///
    /// Primarily intended for use by [`LogItem::failure()`].
    fn add_error<E>(&mut self, log_item: LogItem, err: E) -> Result<(), E>;

    /// Return the [`LogItem`]s that have error conditions (`err_val` is
    /// populated).
    ///
    /// Removes matching items from the list of log items.
    fn filter_errors(&mut self) -> impl Iterator<Item = &LogItem> {
        self.logged_items().iter().filter(|item| item.err_val.is_some())
    }
}

pub(crate) mod detailed;
pub(crate) mod one_shot;
