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
pub struct DetailedStatusTracker {
    logged_items: Vec<LogItem>,
    ingredient_uris: Vec<String>,
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

    fn add_non_error(&mut self, mut log_item: LogItem) {
        if let Some(ingredient_uri) = self.ingredient_uris.last() {
            log_item.ingredient_uri = Some(ingredient_uri.to_string().into());
        }
        self.logged_items.push(log_item);
    }

    fn add_error<E>(&mut self, mut log_item: LogItem, _err: E) -> Result<(), E> {
        if let Some(ingredient_uri) = self.ingredient_uris.last() {
            log_item.ingredient_uri = Some(ingredient_uri.to_string().into());
        }
        self.logged_items.push(log_item);
        Ok(())
    }

    fn push_ingredient_uri<S: Into<String>>(&mut self, uri: S) {
        self.ingredient_uris.push(uri.into());
    }

    fn pop_ingredient_uri(&mut self) -> Option<String> {
        self.ingredient_uris.pop()
    }

    fn logged_items_mut(&mut self) -> &mut [LogItem] {
        &mut self.logged_items
    }
}
