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

use crate::StatusTracker;

/// Creates a [`LogItem`] struct that is annotated with the source file and line
/// number where the log condition was discovered.
///
/// Takes three parameters, each of which may be a `&'static str` or `String`:
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
/// # use c2pa_status_tracker::{log_item, LogKind, LogItem};
/// let log = log_item!("test1", "test item 1", "test func");
///
/// assert_eq!(
///     log,
///     LogItem {
///         kind: LogKind::Informational,
///         label: Cow::Borrowed("test1"),
///         crate_name: Cow::Borrowed(env!("CARGO_PKG_NAME")),
///         crate_version: Cow::Borrowed(env!("CARGO_PKG_VERSION")),
///         description: Cow::Borrowed("test item 1"),
///         file: Cow::Borrowed(file!()),
///         function: Cow::Borrowed("test func"),
///         line: log.line,
///         ..Default::default()
///     }
/// );
/// #
/// # assert!(log.line > 2);
/// ```
#[macro_export]
macro_rules! log_item {
    ($label:expr, $description:expr, $function:expr) => {{
        $crate::LogItem {
            kind: $crate::LogKind::Informational,
            label: $label.into(),
            crate_name: env!("CARGO_PKG_NAME").into(),
            crate_version: env!("CARGO_PKG_VERSION").into(),
            file: file!().into(),
            function: $function.into(),
            line: line!(),
            description: $description.into(),
            ..Default::default()
        }
    }};
}

/// Creates a [`LogItem`] struct that is annotated with the source file and line
/// number where the log condition was discovered.
///
/// Takes two parameters, each of which may be a `&'static str` or `String`:
///
/// * `description`: human-readable reason for this `LogItem` to have been
///   generated
/// * `function`: name of the function generating this `LogItem`
///
/// ## Example
///
/// ```
/// # use c2pa_status_tracker::{log_current_item, LogKind, LogItem};
/// let log = log_current_item!("test item 1", "test func");
/// ```
#[macro_export]
macro_rules! log_current_item {
    ($description:expr, $function:expr) => {{
        $crate::LogItem {
            kind: $crate::LogKind::Informational,
            label: "".to_owned().into(), // will be set to the current status tracker uri
            crate_name: env!("CARGO_PKG_NAME").into(),
            crate_version: env!("CARGO_PKG_VERSION").into(),
            file: file!().into(),
            function: $function.into(),
            line: line!(),
            description: $description.into(),
            ..Default::default()
        }
    }};
}

/// Detailed information about an error or other noteworthy condition.
///
/// Use the [`log_item`](crate::log_item) macro to create a `LogItem`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogItem {
    /// Kind of log item.
    pub kind: LogKind,

    /// JUBMF label of the item (if available), or other descriptive label
    pub label: Cow<'static, str>,

    /// Description of the error
    pub description: Cow<'static, str>,

    /// Crate where error was detected
    pub crate_name: Cow<'static, str>,

    /// Version of the crate
    pub crate_version: Cow<'static, str>,

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

    /// Ingredient URI (for ingredient-related logs)
    pub ingredient_uri: Option<Cow<'static, str>>,
}

impl Default for LogItem {
    fn default() -> Self {
        LogItem {
            kind: LogKind::Success,
            label: Cow::Borrowed(""),
            description: Cow::Borrowed(""),
            crate_name: env!("CARGO_PKG_NAME").into(),
            crate_version: env!("CARGO_PKG_VERSION").into(),
            file: Cow::Borrowed(""),
            function: Cow::Borrowed(""),
            line: 0,
            err_val: None,
            validation_status: None,
            ingredient_uri: None,
        }
    }
}

impl LogItem {
    /// Add a C2PA validation status code.
    ///
    /// ## Example
    ///
    /// ```
    /// # use std::borrow::Cow;
    /// # use c2pa_status_tracker::{log_item, LogKind, LogItem};
    /// let log = log_item!("test1", "test item 1", "test func").validation_status("claim.missing");
    ///
    /// assert_eq!(
    ///     log,
    ///     LogItem {
    ///         kind: LogKind::Informational,
    ///         label: Cow::Borrowed("test1"),
    ///         description: Cow::Borrowed("test item 1"),
    ///         crate_name: Cow::Borrowed(env!("CARGO_PKG_NAME")),
    ///         crate_version: Cow::Borrowed(env!("CARGO_PKG_VERSION")),
    ///         file: Cow::Borrowed(file!()),
    ///         function: Cow::Borrowed("test func"),
    ///         line: 7,
    ///         validation_status: Some(Cow::Borrowed("claim.missing")),
    ///         ..Default::default()
    ///     }
    /// );
    /// ```
    #[must_use]
    pub fn validation_status(self, status: &'static str) -> Self {
        LogItem {
            validation_status: Some(status.into()),
            ..self
        }
    }

    /// Add an ingredient URI.
    ///
    /// ## Example
    ///
    /// ```
    /// # use std::borrow::Cow;
    /// # use c2pa_status_tracker::{log_item, LogKind, LogItem};
    /// let log = log_item!("test1", "test item 1", "test func")
    ///     .set_ingredient_uri("self#jumbf=/c2pa/contentauth:urn:uuid:bef41f24-13aa-4040-8efa-08e5e85c4a00/c2pa.assertions/c2pa.ingredient__1");
    /// ```
    pub fn set_ingredient_uri<S: Into<String>>(self, uri: S) -> Self {
        LogItem {
            ingredient_uri: Some(uri.into().into()),
            ..self
        }
    }

    /// Set the log item kind to [`LogKind::Success`] and add it to the
    /// [`StatusTracker`].
    pub fn success(mut self, tracker: &mut StatusTracker) {
        self.kind = LogKind::Success;
        tracker.add_non_error(self);
    }

    /// Set the log item kind to [`LogKind::Informational`] and add it to the
    /// [`StatusTracker`].
    pub fn informational(mut self, tracker: &mut StatusTracker) {
        self.kind = LogKind::Informational;
        tracker.add_non_error(self);
    }

    /// Set the log item kind to [`LogKind::Failure`] and add it to the
    /// [`StatusTracker`].
    ///
    /// Some implementations are configured to stop immediately on errors. If
    /// so, this function will return `Err(err)`.
    ///
    /// If the implementation is configured to aggregate all log messages, this
    /// function will return `Ok(())`.
    pub fn failure<E: Debug>(mut self, tracker: &mut StatusTracker, err: E) -> Result<(), E> {
        self.kind = LogKind::Failure;
        self.err_val = Some(format!("{err:?}").into());
        tracker.add_error(self, err)
    }

    /// Set the log item kind to [`LogKind::Failure`] and add it to the
    /// [`StatusTracker`].
    ///
    /// Does not return a [`Result`] and thus ignores the [`StatusTracker`]
    /// error-handling configuration.
    pub fn failure_no_throw<E: Debug>(mut self, tracker: &mut StatusTracker, err: E) {
        self.kind = LogKind::Failure;
        self.err_val = Some(format!("{err:?}").into());

        tracker.add_non_error(self);
    }
}

/// Descriptive nature of this [`LogItem`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogKind {
    /// This [`LogItem`] describes a success condition.
    Success,

    /// This [`LogItem`] describes an informational condition.
    Informational,

    /// This [`LogItem`] describes a failure or error condition.
    Failure,
}
