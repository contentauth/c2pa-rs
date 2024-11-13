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

/// A `OneShotStatusTracker` will trigger an error upon the first call to its
/// [`add_error`] function, which is designed to abort any unnecessary
/// computation if the overall result is unnecessary.
///
/// [`add_error`]: Self::add_error
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct OneShotStatusTracker {
    /// List of items that were logged during validation
    pub logged_items: Vec<LogItem>,
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
