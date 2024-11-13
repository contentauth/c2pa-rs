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

use c2pa_status_tracker::LogItem;

use crate::error::Error;

/// Check to see if report contains a specific C2PA status code
#[allow(dead_code)] // in case we make use of these or export this
pub fn report_has_status(report: &[LogItem], val: &str) -> bool {
    report.iter().any(|vi| {
        if let Some(vs) = &vi.validation_status {
            vs == val
        } else {
            false
        }
    })
}

/// Check to see if report contains a specific error
#[allow(dead_code)] // in case we make use of these or export this
pub fn report_has_err(report: &[LogItem], err: Error) -> bool {
    let err_type = format!("{:?}", &err);
    report.iter().any(|vi| {
        if let Some(e) = &vi.err_val {
            e == &err_type
        } else {
            false
        }
    })
}
