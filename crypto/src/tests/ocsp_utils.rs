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

use chrono::{TimeZone, Utc};

use crate::{
    ocsp_utils::check_ocsp_response,
    status_tracker::{report_split_errors, DetailedStatusTracker, StatusTracker},
};

#[test]
fn test_good_response() {
    let rsp_data = include_bytes!("fixtures/ocsp/ocsp_good.data");

    let mut validation_log = DetailedStatusTracker::default();

    let test_time = Utc.with_ymd_and_hms(2023, 2, 1, 8, 0, 0).unwrap();

    let ocsp_data = check_ocsp_response(rsp_data, Some(test_time), &mut validation_log).unwrap();

    assert!(ocsp_data.revoked_at.is_none());
    assert!(ocsp_data.ocsp_certs.is_some());
}

#[test]
fn test_revoked_response() {
    let rsp_data = include_bytes!("fixtures/ocsp/ocsp_revoked.data");

    let mut validation_log = DetailedStatusTracker::default();

    let test_time = Utc.with_ymd_and_hms(2024, 2, 1, 8, 0, 0).unwrap();

    let ocsp_data = check_ocsp_response(rsp_data, Some(test_time), &mut validation_log).unwrap();

    let errors = report_split_errors(validation_log.get_log_mut());

    assert!(ocsp_data.revoked_at.is_some());
    assert!(!errors.is_empty());
}
