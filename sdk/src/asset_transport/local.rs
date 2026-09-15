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

//! Default asset transport: the local filesystem (needs the `file_io` feature).

#[cfg(feature = "file_io")]
use std::{
    borrow::Cow,
    path::{Component, Path},
};

#[cfg(feature = "file_io")]
use super::AssetRef;
use super::{AssetRequest, AssetTransportError, ResolvedAsset, SyncAssetTransport};
#[cfg(feature = "file_io")]
use crate::utils::path_utils::{ensure_within_root, reject_unsafe_identifier};

/// Default asset transport: the local filesystem.
/// Accepts:
/// - [`AssetRef::Path`] (filesystem path).
/// - [`AssetRef::Custom`] (treated as a path).
/// - [`AssetRef::Uri`] (file URI).
///
/// Anything else is rejected with [`AssetTransportError::UnsupportedReference`].
///
/// If a root is set, references are sandboxed to it (see [`Self::rooted_at`]).
#[cfg(feature = "file_io")]
#[derive(Debug, Default, Clone)]
pub struct LocalAssetTransport {
    root: Option<std::path::PathBuf>,
}

#[cfg(feature = "file_io")]
impl LocalAssetTransport {
    /// Confines references to `root`. Anything outside it is rejected with
    /// [`AssetTransportError::OutsideRoot`].
    pub fn rooted_at(root: impl Into<std::path::PathBuf>) -> Self {
        let root = root.into();
        let root = root
            .canonicalize()
            .or_else(|_| std::path::absolute(&root))
            .unwrap_or(root);
        Self { root: Some(root) }
    }
}

#[cfg(feature = "file_io")]
impl SyncAssetTransport for LocalAssetTransport {
    /// Request to open an asset (and read its bytes).
    fn open(&self, request: AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError> {
        // Built only on error paths.
        let outside = || AssetTransportError::OutsideRoot {
            reference: request.reference.to_string(),
        };

        // Candidate path resolution.
        let candidate: Cow<'_, Path> = match request.reference {
            AssetRef::Path(p) => match &self.root {
                Some(root) if p.is_relative() => Cow::Owned(root.join(p)),
                _ => Cow::Borrowed(p),
            },
            AssetRef::Custom(s) => match &self.root {
                Some(root) => {
                    reject_unsafe_identifier(s).map_err(|_| outside())?;
                    Cow::Owned(root.join(s))
                }
                None => {
                    let candidate = Path::new(s);
                    if candidate
                        .components()
                        .any(|c| matches!(c, Component::ParentDir))
                    {
                        return Err(outside());
                    }
                    Cow::Borrowed(candidate)
                }
            },
            AssetRef::Uri(u) => {
                let url =
                    url::Url::parse(u).map_err(|_| AssetTransportError::UnsupportedReference)?;
                if url.scheme() != "file" {
                    return Err(AssetTransportError::UnsupportedReference);
                }
                Cow::Owned(
                    url.to_file_path()
                        .map_err(|()| AssetTransportError::UnsupportedReference)?,
                )
            }
        };

        // When a root is configured, open the canonicalized path.
        let to_open: Cow<'_, Path> = match &self.root {
            Some(root) => Cow::Owned(ensure_within_root(&candidate, root).map_err(|_| outside())?),
            None => candidate,
        };

        let file = std::fs::File::open(&to_open)
            .map_err(|e| AssetTransportError::from_io(e, &request.reference.to_string()))?;
        Ok(ResolvedAsset::new(file))
    }
}

/// Refuses every read with [`AssetTransportError::NotConfigured`]. Used when `file_io` is off,
/// or registered on a `Context` to disable sync filesystem reads on purpose.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnconfiguredAssetTransport;

impl SyncAssetTransport for UnconfiguredAssetTransport {
    fn open(&self, _request: AssetRequest<'_>) -> Result<ResolvedAsset, AssetTransportError> {
        Err(AssetTransportError::NotConfigured)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::asset_transport::AssetRef;
    #[cfg(feature = "file_io")]
    use crate::utils::io_utils::tempdirectory;

    #[cfg(feature = "file_io")]
    #[test]
    fn default_filesystem_transport_can_open_filesystem_path() {
        use std::io::Read;

        let path = std::path::Path::new("tests/fixtures/C.jpg");
        let request = AssetRequest::new(AssetRef::Path(path));

        let mut stream = LocalAssetTransport::default()
            .open(request)
            .unwrap()
            .try_into_read_seek()
            .unwrap();

        let mut magic = [0u8; 2];
        stream.read_exact(&mut magic).unwrap();
        assert_eq!(magic, [0xff, 0xd8], "expected JPEG marker");
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn default_filesystem_transport_handles_custom_reference_as_path() {
        let request = AssetRequest::from_reference("tests/fixtures/C.jpg");
        assert!(matches!(request.reference, AssetRef::Custom(_)));
        assert!(LocalAssetTransport::default().open(request).is_ok());
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn default_filesystem_transport_can_open_file_uris() {
        let absolute = std::path::Path::new("tests/fixtures/C.jpg")
            .canonicalize()
            .unwrap();
        let uri = url::Url::from_file_path(&absolute).unwrap().to_string();

        let request = AssetRequest::from_reference(&uri);
        assert!(matches!(request.reference, AssetRef::Uri(_)));
        assert!(LocalAssetTransport::default().open(request).is_ok());
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn default_filesystem_transport_refuses_requests_outside_sandbox_root() {
        let request = AssetRequest::from_reference("../../etc/passwd");
        assert!(matches!(request.reference, AssetRef::Custom(_)));
        assert!(matches!(
            LocalAssetTransport::default().open(request),
            Err(AssetTransportError::OutsideRoot { .. })
        ));
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn default_filesystem_transport_accepts_absolute_custom_asset_references() {
        let absolute = std::path::Path::new("tests/fixtures/C.jpg")
            .canonicalize()
            .unwrap();

        let request = AssetRequest::from_reference(absolute.to_str().unwrap());
        assert!(matches!(request.reference, AssetRef::Custom(_)));
        assert!(LocalAssetTransport::default().open(request).is_ok());
    }
    #[cfg(feature = "file_io")]
    #[test]
    fn default_filesystem_transport_allows_relative_paths_kept_inside_rooted_sandbox() {
        let dir = tempdirectory().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("asset.jpg"), b"\xff\xd8 test").unwrap();

        let transport = LocalAssetTransport::rooted_at(dir.path());
        let request = AssetRequest::from_reference("sub/../asset.jpg");

        assert!(transport.open(request).is_ok());
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn rooted_transport_rejects_an_escape_beyond_the_root() {
        let dir = tempdirectory().unwrap();
        let transport = LocalAssetTransport::rooted_at(dir.path());

        let request = AssetRequest::from_reference("../../etc/passwd");
        assert!(matches!(
            transport.open(request),
            Err(AssetTransportError::OutsideRoot { .. })
        ));
    }

    #[cfg(all(feature = "file_io", unix))]
    #[test]
    fn default_rooted_filesystem_transport_rejects_outside_symlinks() {
        let outside = tempdirectory().unwrap();
        let secret = outside.path().join("secret.jpg");
        std::fs::write(&secret, b"\xff\xd8 secret").unwrap();

        let root = tempdirectory().unwrap();
        std::os::unix::fs::symlink(&secret, root.path().join("innocent.jpg")).unwrap();

        let transport = LocalAssetTransport::rooted_at(root.path());
        let request = AssetRequest::from_reference("innocent.jpg");

        assert!(matches!(
            transport.open(request),
            Err(AssetTransportError::OutsideRoot { .. })
        ));
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn default_filesystem_transport_confines_to_an_absolute_root() {
        // Fixture must be accessible in test env on any platform...
        let parent = tempfile::Builder::new()
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let root = parent.path().join("assets");
        std::fs::create_dir(&root).unwrap();
        let asset = root.join("photo.jpg");
        std::fs::write(&asset, b"\xff\xd8 test").unwrap();

        let relative_root = pathdiff_to_cwd(&root);
        let transport = LocalAssetTransport::rooted_at(&relative_root);
        assert!(
            relative_root.is_relative(),
            "fixture must exercise a relative root, got {}",
            relative_root.display()
        );

        assert!(
            transport
                .open(AssetRequest::new(AssetRef::Path(&asset)))
                .is_ok(),
            "an absolute path inside a relative root should open"
        );
    }

    #[cfg(feature = "file_io")]
    fn pathdiff_to_cwd(path: &std::path::Path) -> std::path::PathBuf {
        let cwd = std::env::current_dir().unwrap();
        let cwd = cwd.canonicalize().unwrap_or(cwd);
        let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

        let mut up = std::path::PathBuf::new();
        let mut base = cwd.as_path();
        loop {
            if let Ok(rest) = path.strip_prefix(base) {
                return up.join(rest);
            }
            match base.parent() {
                Some(parent) => {
                    up.push("..");
                    base = parent;
                }
                None => return path,
            }
        }
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn default_filesystem_transport_rejects_paths_outside_rooted_sandbox() {
        let outside = tempdirectory().unwrap();
        let secret = outside.path().join("secret.jpg");
        std::fs::write(&secret, b"\xff\xd8 secret").unwrap();

        let root = tempdirectory().unwrap();
        let transport = LocalAssetTransport::rooted_at(root.path());

        let request = AssetRequest::new(AssetRef::Path(&secret));
        assert!(matches!(
            transport.open(request),
            Err(AssetTransportError::OutsideRoot { .. })
        ));
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn default_unrooted_filesystem_transport_can_open_paths() {
        let dir = tempdirectory().unwrap();
        let asset = dir.path().join("asset.jpg");
        std::fs::write(&asset, b"\xff\xd8 test").unwrap();

        let request = AssetRequest::new(AssetRef::Path(&asset));
        assert!(
            LocalAssetTransport::default().open(request).is_ok(),
            "an unrooted transport has no root to confine against"
        );
    }

    #[test]
    fn default_filesystem_transport_recognizes_leading_uri_schemes() {
        for reference in ["file:///tmp/a.jpg", "https://example.com/a.jpg", "s3://b/k"] {
            let request = AssetRequest::from_reference(reference);
            assert!(
                matches!(request.reference, AssetRef::Uri(_)),
                "a leading scheme is a URI: {reference}"
            );
        }
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn default_rooted_filesystem_transport_contains_file_uris_to_sandbox() {
        let outside = tempdirectory().unwrap();
        let secret = outside.path().join("secret.jpg");
        std::fs::write(&secret, b"\xff\xd8 secret").unwrap();
        let uri = url::Url::from_file_path(&secret).unwrap().to_string();

        let root = tempdirectory().unwrap();
        let transport = LocalAssetTransport::rooted_at(root.path());

        let request = AssetRequest::new(AssetRef::Uri(&uri));
        assert!(
            matches!(
                transport.open(request),
                Err(AssetTransportError::OutsideRoot { .. })
            ),
            "a file: URI outside the root must not be readable from a rooted transport"
        );
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn default_filesystem_transport_rejects_non_file_uris() {
        let request = AssetRequest::new(AssetRef::Uri("https://example.com/a.jpg"));
        assert!(matches!(
            LocalAssetTransport::default().open(request),
            Err(AssetTransportError::UnsupportedReference)
        ));
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn default_filesystem_transport_reports_missing_paths_as_not_found() {
        let path = std::path::Path::new("tests/fixtures/does-not-exist.jpg");
        let request = AssetRequest::new(AssetRef::Path(path));

        let err = LocalAssetTransport::default().open(request).err();
        let Some(AssetTransportError::NotFound { reference }) = err else {
            unreachable!("expected NotFound, got {err:?}");
        };
        assert!(
            reference.contains("does-not-exist.jpg"),
            "error should name the reference, got {reference}"
        );
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn rooted_missing_file_names_reference() {
        // Avoid leaking which paths exist on the host.
        let root = tempdirectory().unwrap();
        let transport = LocalAssetTransport::rooted_at(root.path());

        let request = AssetRequest::from_reference("missing.jpg");
        let err = transport.open(request).err();
        let Some(AssetTransportError::NotFound { reference }) = err else {
            unreachable!("expected NotFound, got {err:?}");
        };

        assert_eq!(reference, "missing.jpg");
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn rooted_outside_root_names_reference() {
        let root = tempdirectory().unwrap();
        let transport = LocalAssetTransport::rooted_at(root.path());

        // A reference that escapes the root once joined.
        let request = AssetRequest::from_reference("../outside.jpg");
        let err = transport.open(request).err();
        let Some(AssetTransportError::OutsideRoot { reference }) = err else {
            unreachable!("expected OutsideRoot, got {err:?}");
        };
        // The caller's own reference, not the joined absolute root path.
        assert_eq!(reference, "../outside.jpg");
    }
}
