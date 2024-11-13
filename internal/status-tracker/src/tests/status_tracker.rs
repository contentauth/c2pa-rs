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

mod detailed {
    use super::SampleError;
    use crate::{log_item, DetailedStatusTracker};

    #[test]
    fn aggregates_errors() {
        let mut tracker = DetailedStatusTracker::default();

        // Add an item without an error.
        log_item!("test1", "test item 1", "test func").success(&mut tracker);

        // Add another item with an error. Should not stop.
        log_item!("test2", "test item 1", "test func")
            .failure(&mut tracker, SampleError {})
            .unwrap();

        assert_eq!(tracker.logged_items.len(), 2);

        // Verify that one item with error was found.
        let errors = tracker.take_errors();
        assert_eq!(errors.len(), 1);
        assert_eq!(tracker.logged_items.len(), 1);
    }
}

#[derive(Debug)]
struct SampleError {}

impl Display for SampleError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "SampleError")
    }
}
