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

use std::fmt::{Debug, Display};

use crate::LogItem;

/// A `StatusTracker` is used in the validation logic of c2pa-rs and
/// related crates to control error-handling behavior and optionally
/// aggregate log messages as they are generated.
pub trait StatusTracker: Debug + Display + Send {
    /// Return the current list of validation log items.
    fn get_log(&self) -> &[LogItem];

    /// Return a mutable reference to the list of validation log items.
    ///
    /// NOTE: I'm close to removing this function in favor of
    /// the new `DetailedStatusTracker::take_errors`.
    fn get_log_mut(&mut self) -> &mut Vec<LogItem>;

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
}

pub(crate) mod detailed;
pub(crate) mod one_shot;
