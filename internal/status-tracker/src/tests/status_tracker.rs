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
    use crate::{log_item, DetailedStatusTracker, StatusTracker};

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

    #[test]
    fn append() {
        let mut tracker1 = DetailedStatusTracker::default();
        let mut tracker2 = DetailedStatusTracker::default();

        log_item!("test1", "test item 1", "test func").success(&mut tracker1);

        log_item!("test2", "test item 1", "test func")
            .failure(&mut tracker2, SampleError {})
            .unwrap();

        assert_eq!(tracker1.logged_items.len(), 1);
        assert_eq!(tracker2.logged_items.len(), 1);

        tracker1.append(&tracker2);

        assert_eq!(tracker1.logged_items.len(), 2);
        assert_eq!(tracker2.logged_items.len(), 1);
    }
}

mod one_shot {
    use crate::{
        log_item, tests::status_tracker::SampleError, OneShotStatusTracker, StatusTracker,
    };

    #[test]
    fn stops_on_first_error() {
        let mut tracker = OneShotStatusTracker::default();

        // Add an item without error.
        log_item!("test1", "test item 1", "test func").success(&mut tracker);

        // Add another item with an error. Should not stop.
        // let item2 = log_item!("test2", "test item 1", "test
        // func").error(Error::NotFound); // add arbitrary error HMMM ... I
        // didn't know log_silent would error out. assert!(tracker.
        // log_silent(item2).is_err());

        // Adding an error item should trigger an abort.
        let err = log_item!("test3", "test item 3 from macro", "test func")
            .failure(&mut tracker, SampleError {})
            .unwrap_err();

        assert_eq!(err, SampleError {});

        assert_eq!(tracker.get_log().len(), 2);
        assert_eq!(tracker.get_log_mut().len(), 2);
    }
}

#[derive(Debug, Eq, PartialEq)]
struct SampleError {}

impl Display for SampleError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "SampleError")
    }
}
