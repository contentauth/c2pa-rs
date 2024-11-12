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

use std::fmt::Debug;

/// Detailed information about an error or other noteworthy condition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogItem {
    /// JUBMF label of the item (if available), or other descriptive label
    pub label: String,

    /// Description of the error
    pub description: String,

    /// Source file where error was detected
    pub file: String,

    /// Function where error was detected
    pub function: String,

    /// Source line number where error was detected
    pub line: u32,

    /// Error code as string
    pub err_val: Option<String>,
    // NOTE: This was not public in the c2pa-rs version. Why not?
    /// C2PA validation status code
    pub validation_status: Option<String>,
}

impl LogItem {
    /// Create a new `LogItem`.
    ///
    /// ## Example
    ///
    /// ```
    /// # use c2pa_status_tracker::LogItem;
    /// let log_item = LogItem::new("test1", "test item 1", "test func", "src/test.rs", 42);
    ///
    /// assert_eq!(
    ///     log_item,
    ///     LogItem {
    ///         label: "test1".to_string(),
    ///         description: "test item 1".to_string(),
    ///         file: "src/test.rs".to_string(),
    ///         function: "test func".to_string(),
    ///         line: 42u32,
    ///         err_val: None,
    ///         validation_status: None,
    ///     }
    /// );
    /// ```
    pub fn new(label: &str, description: &str, function: &str, file: &str, line: u32) -> Self {
        LogItem {
            label: label.to_string(),
            file: file.to_string(),
            function: function.to_string(),
            line,
            description: description.to_string(),
            err_val: None,
            validation_status: None,
        }
    }

    /// Captures the description from the value (typically an `Error` enum) as
    /// additional information for this `LogItem` struct.
    ///
    /// IMPORTANT: This is implemented using the [`Debug`](std::fmt::Debug)
    /// trait, but in common practice, the `Error` enum from any crate is likely
    /// to fulfill this requirement.     
    /// ## Example
    ///
    /// ```
    /// # use c2pa_status_tracker::LogItem;
    /// let log_item = LogItem::new("test1", "test item 1", "test func", "src/test.rs", 42)
    ///     .error("sample error message");
    ///
    /// assert_eq!(
    ///     log_item,
    ///     LogItem {
    ///         label: "test1".to_string(),
    ///         description: "test item 1".to_string(),
    ///         file: "src/test.rs".to_string(),
    ///         function: "test func".to_string(),
    ///         line: 42u32,
    ///         err_val: Some("\"sample error message\"".to_string()),
    ///         validation_status: None,
    ///     }
    /// );
    /// ```
    pub fn error<E: std::fmt::Debug>(self, err: E) -> Self {
        LogItem {
            err_val: Some(format!("{err:?}")),
            ..self
        }
    }

    // MIGRATION NOTE: This looks a lot like `error` above. Can we coalesce?

    // // add an error value
    // pub fn set_error<E: std::fmt::Debug>(self, err: &E) -> Self {
    //     LogItem {
    //         err_val: Some(format!("{err:?}")),
    //         ..self
    //     }
    // }

    // MIGRATION NOTE: Made err_val public. Don't think we need the accessor any
    // more. /// Returns a reference to the error string if there is one
    // pub fn error_str(&self) -> Option<&str> {
    //     self.err_val.as_deref()
    // }

    /// Add a C2PA validation status code.
    ///
    /// ## Example
    ///
    /// ```
    /// # use c2pa_status_tracker::LogItem;
    /// let log_item = LogItem::new("test1", "test item 1", "test func", "src/test.rs", 42)
    ///     .validation_status("claim.missing");
    ///
    /// assert_eq!(
    ///     log_item,
    ///     LogItem {
    ///         label: "test1".to_string(),
    ///         description: "test item 1".to_string(),
    ///         file: "src/test.rs".to_string(),
    ///         function: "test func".to_string(),
    ///         line: 42u32,
    ///         err_val: None,
    ///         validation_status: Some("claim.missing".to_string()),
    ///     }
    /// );
    /// ```
    pub fn validation_status(self, status: &str) -> Self {
        LogItem {
            validation_status: Some(status.to_string()),
            ..self
        }
    }
}

/// Creates a [`LogItem`] struct that is annotated with the source file and line
/// number where the log condition was discovered.
///
/// Takes three parameters:
///
/// * `label`: name of object this LogItem references (typically a JUMBF path
///   reference)
/// * `description`: human-readable reason for this `LogItem` to have been
///   generated
/// * `function`: name of the function generating this `LogItem`
///
/// ## Example
///
/// ```
/// # use c2pa_status_tracker::{log_item, LogItem};
/// let log_item = log_item!("test1", "test item 1", "test func");
///
/// assert_eq!(
///     log_item,
///     LogItem {
///         label: "test1".to_string(),
///         description: "test item 1".to_string(),
///         file: "internal/status-tracker/src/log.rs".to_string(),
///         function: "test func".to_string(),
///         line: log_item.line,
///         err_val: None,
///         validation_status: None,
///     }
/// );
/// #
/// # assert!(log_item.line > 2);
/// ```
#[macro_export]
macro_rules! log_item {
    ($label:expr, $description:expr, $function:expr) => {{
        use c2pa_status_tracker::LogItem;
        LogItem::new(
            &$label.to_string(),
            &$description.to_string(),
            &$function.to_string(),
            file!(),
            line!(),
        )
    }};
}
