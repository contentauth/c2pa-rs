// Copyright 2024 Adobe. All rights reserved.
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

use crate::internal::time;

#[test]
fn now() {
    let time_now = time::utc_now();
    let unix_ts = time_now.timestamp();
    dbg!(&unix_ts);

    assert!(unix_ts > 1731560000); // 2024-11-14T04:53:00Z
    assert!(unix_ts > 1731561000); // 2024-11-14T04:53:00Z (later ... delete!)
}
