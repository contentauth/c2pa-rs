// Copyright 2026 Adobe. All rights reserved.
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

use std::path::{Component, Path};

use crate::{Error, Result};

/// Validate and canonicalize an archive entry path.
///
/// Used to harden archive ingestion (Builder archives, resource store) against
/// zip-slip path-traversal attacks. Returns the normalized,
/// forward-slash-separated path (`.` components are stripped), or an error if
/// the path is empty, absolute, contains a `..` traversal, contains a
/// backslash, or includes a Windows drive/UNC prefix.
///
/// Backslash is explicitly rejected because archives are portable: a zip
/// authored on Windows may use `\` as a path separator, but on Linux
/// [`Path::components`] treats `\` as part of a filename. Without this check,
/// a payload like `..\..\etc\passwd` would slip past traversal checks on
/// non-Windows hosts.
pub(crate) fn sanitize_archive_path(path: &str) -> Result<String> {
    if path.is_empty() {
        return Err(Error::BadParam("Empty path not allowed".to_string()));
    }

    // Reject backslash on all platforms (see doc comment).
    if path.contains('\\') {
        return Err(Error::BadParam(format!(
            "Backslash not allowed in archive path: {path}"
        )));
    }

    let mut sanitized = String::new();

    for component in Path::new(path).components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str().ok_or_else(|| {
                    Error::BadParam(format!("Non-UTF-8 path component in: {path}"))
                })?;
                if !sanitized.is_empty() {
                    sanitized.push('/');
                }
                sanitized.push_str(part);
            }
            // Silently drop current-directory markers (`.`).
            Component::CurDir => {}
            // Absolute paths (`/`), Windows drive/UNC prefixes, and `..` are all rejected.
            Component::RootDir | Component::Prefix(_) | Component::ParentDir => {
                return Err(Error::BadParam(format!(
                    "Path traversal not allowed: {path}"
                )));
            }
        }
    }

    if sanitized.is_empty() {
        return Err(Error::BadParam("Empty path not allowed".to_string()));
    }

    Ok(sanitized)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::sanitize_archive_path;

    #[test]
    fn normal_path_accepted() {
        assert_eq!(
            sanitize_archive_path("resources/thumbnail.jpg").unwrap(),
            "resources/thumbnail.jpg"
        );
    }

    #[test]
    fn dot_stripped() {
        assert_eq!(
            sanitize_archive_path("./resources/thumb.jpg").unwrap(),
            "resources/thumb.jpg"
        );
    }

    #[test]
    fn parent_dir_rejected() {
        assert!(sanitize_archive_path("../etc/passwd").is_err());
    }

    #[test]
    fn inner_parent_dir_rejected() {
        assert!(sanitize_archive_path("resources/../../../etc/passwd").is_err());
    }

    #[test]
    fn absolute_rejected() {
        assert!(sanitize_archive_path("/etc/passwd").is_err());
    }

    #[test]
    fn empty_rejected() {
        assert!(sanitize_archive_path("").is_err());
    }

    #[test]
    fn dot_only_rejected() {
        // "." normalises to no Normal components → empty result → error
        assert!(sanitize_archive_path(".").is_err());
    }

    #[test]
    fn backslash_separator_rejected() {
        // On Linux, Path::components() does not treat `\` as a separator, so
        // this must be rejected explicitly to prevent Windows-authored zips
        // from slipping traversal payloads through.
        assert!(sanitize_archive_path("resources\\thumb.jpg").is_err());
    }

    #[test]
    fn backslash_traversal_rejected() {
        assert!(sanitize_archive_path("..\\..\\etc\\passwd").is_err());
    }

    #[test]
    fn mixed_slash_traversal_rejected() {
        assert!(sanitize_archive_path("resources/..\\..\\etc/passwd").is_err());
    }
}
