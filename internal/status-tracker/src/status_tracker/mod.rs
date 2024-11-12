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

    /// Record a validation log item.
    ///
    /// Some implementations are configured to stop immediately on errors. If
    /// so, and the [`LogItem`]'s `err_val` field is non-empty, this function
    /// will return `Err(err)`.
    ///
    /// If the implementation is configured to aggregate all log
    /// messages, this function returns `Ok(())`.
    fn log<E>(&mut self, log_item: LogItem, err: E) -> Result<(), E>;

    /// Record a validation log item without stopping.
    ///
    /// Unlike [`log()`], this does not return a [`Result`] type.
    ///
    /// [`log()`]: Self::log()
    fn log_silent(&mut self, log_item: LogItem);
}

pub(crate) mod detailed;
