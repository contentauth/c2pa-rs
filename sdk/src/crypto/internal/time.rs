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

use chrono::{DateTime, Utc};

/// Return the current time in UTC.
pub(crate) fn utc_now() -> DateTime<Utc> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        Utc::now()
    }

    #[cfg(target_arch = "wasm32")]
    {
        // Very unlikely that SystemTime would be before Unix epoch, but if so, cap it
        // at 0.
        let utc_duration = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO);

        let mut utc_now = chrono::DateTime::UNIX_EPOCH;
        utc_now += utc_duration;

        utc_now
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::crypto::internal::time;

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn now() {
        let time_now = time::utc_now();
        let unix_ts = time_now.timestamp();
        dbg!(&unix_ts);

        assert!(unix_ts > 1731560000); // 2024-11-14T04:53:00Z
    }
}
