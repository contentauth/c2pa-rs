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

use log::info;
use std::time::Instant;

// (Internal debugging tool.)
// Measure and log the time from the creation of this struct until it is dropped.
pub(crate) struct TimeIt {
    label: &'static str,
    start: Instant,
}

// Justification for dead_code: This is a debugging tool that is not always needed.
#[allow(dead_code)]
impl TimeIt {
    pub fn new(label: &'static str) -> Self {
        Self {
            label,
            start: Instant::now(),
        }
    }
}
impl Drop for TimeIt {
    fn drop(&mut self) {
        info!("timing for {}: {:.2?}", self.label, self.start.elapsed());
    }
}
