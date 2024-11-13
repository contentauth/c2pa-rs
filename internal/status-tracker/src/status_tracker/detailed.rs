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

use crate::{LogItem, StatusTracker};

/// A `DetailedStatusTracker` aggregates all log conditions observed during a
/// validation pass.
///
/// When [`add_error()`] is called, it will not raise an error.
///
/// [`add_error()`]: Self::add_error()
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct DetailedStatusTracker {
    /// List of items that were logged during validation
    pub logged_items: Vec<LogItem>,
}

impl DetailedStatusTracker {
    /// Return the [`LogItem`]s that have error conditions (`err_val` is
    /// populated).
    ///
    /// Removes matching items from the list of log items.
    pub fn take_errors(&mut self) -> Vec<LogItem> {
        let mut output: Vec<LogItem> = Vec::new();

        let mut i = 0;
        while i < self.logged_items.len() {
            if self.logged_items[i].err_val.is_some() {
                output.push(self.logged_items.remove(i));
            } else {
                i += 1;
            }
        }
        output
    }
}

impl StatusTracker for DetailedStatusTracker {
    fn logged_items(&self) -> &[LogItem] {
        &self.logged_items
    }

    fn add_non_error(&mut self, log_item: LogItem) {
        self.logged_items.push(log_item);
    }

    fn add_error<E>(&mut self, log_item: LogItem, _err: E) -> Result<(), E> {
        self.logged_items.push(log_item);
        Ok(())
    }
}
