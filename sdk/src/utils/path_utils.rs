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

#[cfg(feature = "file_io")]
use std::path::PathBuf;
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

/// Lexically normalize a path by resolving `.` and `..` components without
/// touching the filesystem.
///
/// Leading `..` components that cannot be popped (they would climb above the
/// path's start, or the path is rooted) are preserved so that an escape above a
/// relative base remains detectable by a later `starts_with` check.
#[cfg(feature = "file_io")]
pub(crate) fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                // Pop a preceding normal segment.
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                // Cannot climb above a filesystem/drive root: drop the `..`.
                Some(Component::RootDir | Component::Prefix(_)) => {}
                // Nothing to pop (empty, or tail is already `..`): keep it so the
                // escape stays visible.
                _ => out.push(".."),
            },
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Resolve a resource `path` (an attacker-influenced identifier) against `base`,
/// confining the result to `root` (the manifest tree). Returns the resolved
/// path, or an error if the identifier would escape `root`.
///
/// Relative identifiers — including `..` — are permitted: a nested ingredient
/// (whose `base` is a subdirectory) may reference sibling resources one or more
/// levels up, as long as the resolved path stays inside `root`. What is rejected
/// is anything that escapes `root`:
///
/// 1. Backslashes and absolute paths are refused up front by
///    [`reject_unsafe_identifier`]. Archives are portable, so a Windows-authored
///    `\` separator would otherwise be treated as a filename on Linux; absolute
///    identifiers are never legitimate.
/// 2. Containment within `root` is enforced by [`ensure_within_root`], lexically
///    and then against symlinks.
///
/// A non-existent target has nothing to canonicalize and is returned as the
/// joined path; the caller's own read/open then surfaces the not-found error.
#[cfg(feature = "file_io")]
pub(crate) fn resolve_within_root(base: &Path, root: &Path, path: &str) -> Result<PathBuf> {
    reject_unsafe_identifier(path)?;

    let joined = base.join(path);
    ensure_within_root(&joined, root)
        .map_err(|_| Error::BadParam(format!("Resource path escapes manifest root: {path}")))?;

    Ok(joined)
}

/// Reject an identifier that can never be legitimate: empty, backslash-separated,
/// or absolute. Split out of [`resolve_within_root`] so a caller that builds its
/// own candidate path can apply the same check without the join.
#[cfg(feature = "file_io")]
pub(crate) fn reject_unsafe_identifier(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(Error::BadParam(
            "Empty resource path not allowed".to_string(),
        ));
    }
    if path.contains('\\') {
        return Err(Error::BadParam(format!(
            "Backslash not allowed in resource path: {path}"
        )));
    }
    if Path::new(path).is_absolute() {
        return Err(Error::BadParam(format!(
            "Absolute resource path not allowed: {path}"
        )));
    }
    Ok(())
}

/// Confine an already-joined `candidate` to `root`, rejecting anything that escapes it.
///
/// Two checks, either of which can accept:
///
/// 1. Lexical containment: `candidate` is normalized (resolving `.`/`..` without
///    filesystem access) and must remain within the normalized `root`. This
///    catches escapes even when the target does not exist.
/// 2. Symlink containment: if the target exists, it is canonicalized (following
///    symlinks) and re-checked against the canonicalized `root`. A hostile bundle
///    could ship an innocuously-named symlink pointing outside the manifest tree;
///    lexical checks alone would not catch that. Both sides are canonicalized so a
///    legitimately symlinked `root` (e.g. `/tmp` -> `/private/tmp` on macOS) is
///    not falsely rejected — which is also why a lexical failure falls through to
///    this check rather than rejecting outright.
///
/// Returns the **validated** path the caller should open: the canonicalized target
/// when it exists, or the joined candidate when it does not (so the caller's own
/// open surfaces the not-found error).
#[cfg(feature = "file_io")]
pub(crate) fn ensure_within_root(candidate: &Path, root: &Path) -> Result<PathBuf> {
    // Lexical containment (works whether or not the target exists).
    if normalize_lexically(candidate).starts_with(normalize_lexically(root)) {
        // Symlink containment for targets that exist.
        // Returns the canonical validated path to be opened.
        match candidate.canonicalize() {
            Ok(canonical_target) => {
                let canonical_root = root.canonicalize()?;
                if !canonical_target.starts_with(&canonical_root) {
                    return Err(escaped_root(candidate));
                }
                Ok(canonical_target)
            }
            // Non-existent target, return the candidate.
            Err(_) => Ok(candidate.to_path_buf()),
        }
    } else {
        // A symlinked prefix can still make the two canonicalize to the same place.
        match (candidate.canonicalize(), root.canonicalize()) {
            (Ok(target), Ok(canonical_root)) if target.starts_with(&canonical_root) => Ok(target),
            _ => Err(escaped_root(candidate)),
        }
    }
}

#[cfg(feature = "file_io")]
fn escaped_root(candidate: &Path) -> Error {
    Error::BadParam(format!(
        "Path escapes the configured root: {}",
        candidate.display()
    ))
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

#[cfg(all(test, feature = "file_io"))]
mod within_root_tests {
    #![allow(clippy::unwrap_used)]

    use super::{ensure_within_root, resolve_within_root};
    use crate::utils::io_utils::tempdirectory;

    #[test]
    fn resolve_within_root_returns_the_joined_identifier_not_the_canonical_path() {
        // The resource store surfaces this path in `path_for_id` and error strings,
        // so it must stay the joined identifier path.
        let root = tempdirectory().unwrap();
        std::fs::write(root.path().join("asset.jpg"), b"\xff\xd8").unwrap();

        let resolved = resolve_within_root(root.path(), root.path(), "asset.jpg").unwrap();
        assert_eq!(resolved, root.path().join("asset.jpg"));
    }

    #[test]
    fn existing_target_inside_root_returns_canonical_path() {
        let root = tempdirectory().unwrap();
        let target = root.path().join("asset.jpg");
        std::fs::write(&target, b"\xff\xd8").unwrap();

        let resolved = ensure_within_root(&target, root.path()).unwrap();
        assert_eq!(resolved, target.canonicalize().unwrap());
        assert!(resolved.starts_with(root.path().canonicalize().unwrap()));
    }

    #[test]
    fn nonexistent_target_inside_root_returns_joined_candidate() {
        let root = tempdirectory().unwrap();
        let candidate = root.path().join("missing.jpg");

        // Nothing to canonicalize; the caller's open surfaces the not-found error.
        let resolved = ensure_within_root(&candidate, root.path()).unwrap();
        assert_eq!(resolved, candidate);
    }

    #[test]
    fn existing_target_outside_root_is_rejected() {
        let outside = tempdirectory().unwrap();
        let secret = outside.path().join("secret.jpg");
        std::fs::write(&secret, b"\xff\xd8").unwrap();

        let root = tempdirectory().unwrap();
        assert!(ensure_within_root(&secret, root.path()).is_err());
    }

    #[test]
    fn nonexistent_target_escaping_root_is_rejected() {
        let root = tempdirectory().unwrap();
        // Lexical escape to a path that does not exist: rejected without touching disk.
        let candidate = root.path().join("../elsewhere/missing.jpg");
        assert!(ensure_within_root(&candidate, root.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_root_is_not_falsely_rejected() {
        // A symlinked root (e.g. /tmp -> /private/tmp on macOS) must still accept
        // its own contents; both sides are canonicalized before comparison.
        let real = tempdirectory().unwrap();
        let target = real.path().join("asset.jpg");
        std::fs::write(&target, b"\xff\xd8").unwrap();

        let link_parent = tempdirectory().unwrap();
        let link_root = link_parent.path().join("link");
        std::os::unix::fs::symlink(real.path(), &link_root).unwrap();

        let resolved = ensure_within_root(&link_root.join("asset.jpg"), &link_root).unwrap();
        assert_eq!(resolved, target.canonicalize().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inside_root_pointing_outside_is_rejected() {
        let outside = tempdirectory().unwrap();
        let secret = outside.path().join("secret.jpg");
        std::fs::write(&secret, b"\xff\xd8").unwrap();

        let root = tempdirectory().unwrap();
        let innocent = root.path().join("innocent.jpg");
        std::os::unix::fs::symlink(&secret, &innocent).unwrap();

        assert!(ensure_within_root(&innocent, root.path()).is_err());
    }
}
