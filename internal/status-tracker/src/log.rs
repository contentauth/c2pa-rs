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

use std::{borrow::Cow, fmt::Debug};

/// Detailed information about an error or other noteworthy condition.
///
/// Use the [`log_item`](crate::log_item) macro to create a `LogItem`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogItem {
    /// JUBMF label of the item (if available), or other descriptive label
    pub label: Cow<'static, str>,

    /// Description of the error
    pub description: Cow<'static, str>,

    /// Source file where error was detected
    pub file: Cow<'static, str>,

    /// Function where error was detected
    pub function: Cow<'static, str>,

    /// Source line number where error was detected
    pub line: u32,

    /// Error code as string
    pub err_val: Option<Cow<'static, str>>,

    /// C2PA validation status code
    pub validation_status: Option<Cow<'static, str>>,
}

impl LogItem {
    /// Captures the description from the value (typically an `Error` enum) as
    /// additional information for this `LogItem` struct.
    ///
    /// IMPORTANT: This is implemented using the [`Debug`](std::fmt::Debug)
    /// trait, but in common practice, the `Error` enum from any crate is likely
    /// to fulfill this requirement.     
    /// ## Example
    ///
    /// ```
    /// # use std::borrow::Cow;
    /// # use c2pa_status_tracker::{log_item, LogItem};
    /// let log = log_item!("test1", "test item 1", "test func").error("sample error message");
    ///
    /// assert_eq!(
    ///     log,
    ///     LogItem {
    ///         label: Cow::Borrowed("test1"),
    ///         description: Cow::Borrowed("test item 1"),
    ///         file: Cow::Borrowed("internal/status-tracker/src/log.rs"),
    ///         function: Cow::Borrowed("test func"),
    ///         line: 7,
    ///         err_val: Some(Cow::Borrowed("\"sample error message\"")),
    ///         validation_status: None,
    ///     }
    /// );
    /// ```
    pub fn error<E: std::fmt::Debug>(self, err: E) -> Self {
        LogItem {
            err_val: Some(format!("{err:?}").into()),
            ..self
        }
    }

    /// Add a C2PA validation status code.
    ///
    /// ## Example
    ///
    /// ```
    /// # use std::borrow::Cow;
    /// # use c2pa_status_tracker::{log_item, LogItem};
    /// let log = log_item!("test1", "test item 1", "test func").validation_status("claim.missing");
    ///
    /// assert_eq!(
    ///     log,
    ///     LogItem {
    ///         label: Cow::Borrowed("test1"),
    ///         description: Cow::Borrowed("test item 1"),
    ///         file: Cow::Borrowed("internal/status-tracker/src/log.rs"),
    ///         function: Cow::Borrowed("test func"),
    ///         line: 7,
    ///         err_val: None,
    ///         validation_status: Some(Cow::Borrowed("claim.missing")),
    ///     }
    /// );
    /// ```
    pub fn validation_status(self, status: &'static str) -> Self {
        LogItem {
            validation_status: Some(status.into()),
            ..self
        }
    }
}

/// Creates a [`LogItem`] struct that is annotated with the source file and line
/// number where the log condition was discovered.
///
/// Takes three parameters, each of which may be a `'static str` or `String`:
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
/// # use std::borrow::Cow;
/// # use c2pa_status_tracker::{log_item, LogItem};
/// let log = log_item!("test1", "test item 1", "test func");
///
/// assert_eq!(
///     log,
///     LogItem {
///         label: Cow::Borrowed("test1"),
///         description: Cow::Borrowed("test item 1"),
///         file: Cow::Borrowed(file!()),
///         function: Cow::Borrowed("test func"),
///         line: log.line,
///         err_val: None,
///         validation_status: None,
///     }
/// );
/// #
/// # assert!(log.line > 2);
/// ```
#[macro_export]
macro_rules! log_item {
    ($label:expr, $description:expr, $function:expr) => {{
        $crate::LogItem {
            label: $label.into(),
            file: file!().into(),
            function: $function.into(),
            line: line!(),
            description: $description.into(),
            err_val: None,
            validation_status: None,
        }
    }};
}
