// Copyright 2023 Adobe. All rights reserved.
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

use std::{
    borrow::Cow,
    collections::HashMap,
    io::{Read, Seek, Write},
    sync::Arc,
};

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[cfg(feature = "file_io")]
use {
    crate::utils::path_utils::sanitize_archive_path,
    std::{
        fs::{create_dir_all, read, write},
        path::{Component, Path, PathBuf},
    },
};

use crate::{
    assertions::{labels, AssetType, EmbeddedData},
    asset_io::CAIRead,
    claim::Claim,
    error::Error,
    hashed_uri::HashedUri,
    jumbf::labels::{to_absolute_uri, DATABOXES},
    maybe_send_sync::{MaybeSend, MaybeSync},
    utils::mime::format_to_mime,
    Result,
};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[serde(untagged)]
pub enum UriOrResource {
    ResourceRef(ResourceRef),
    HashedUri(HashedUri),
}
impl UriOrResource {
    pub fn to_hashed_uri(
        &self,
        resources: &ResourceStore,
        claim: &mut Claim,
    ) -> Result<UriOrResource> {
        match self {
            UriOrResource::ResourceRef(r) => {
                let data = resources.get(&r.identifier)?;
                let hash_uri = match claim.version() {
                    1 => claim.add_databox(&r.format, data.to_vec(), None)?,
                    _ => {
                        let icon_assertion = EmbeddedData::new(
                            labels::ICON,
                            format_to_mime(&r.format),
                            data.to_vec(),
                        );
                        claim.add_assertion(&icon_assertion)?
                    }
                };
                Ok(UriOrResource::HashedUri(hash_uri))
            }
            UriOrResource::HashedUri(h) => Ok(UriOrResource::HashedUri(h.clone())),
        }
    }

    pub fn to_resource_ref(&self, claim: &Claim) -> Result<UriOrResource> {
        match self {
            UriOrResource::ResourceRef(r) => Ok(UriOrResource::ResourceRef(r.clone())),
            UriOrResource::HashedUri(h) => {
                let url = to_absolute_uri(claim.label(), &h.url());
                let format = if h.url().contains(DATABOXES) {
                    let data_box = claim.get_databox(h).ok_or(Error::MissingDataBox)?;
                    data_box.format.clone()
                } else {
                    let (label, instance) = Claim::assertion_label_from_link(&h.url());
                    let assertion =
                        claim
                            .get_assertion(&label, instance)
                            .ok_or(Error::AssertionMissing {
                                url: h.url().to_string(),
                            })?;
                    assertion.content_type().to_string()
                };
                Ok(UriOrResource::ResourceRef(ResourceRef::new(format, url)))
            }
        }
    }
}

impl From<ResourceRef> for UriOrResource {
    fn from(r: ResourceRef) -> Self {
        Self::ResourceRef(r)
    }
}

impl From<HashedUri> for UriOrResource {
    fn from(h: HashedUri) -> Self {
        Self::HashedUri(h)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
/// A reference to a resource to be used in JSON serialization.
///
/// The underlying data can be read as a stream via [`Reader::resource_to_stream`][crate::Reader::resource_to_stream].
pub struct ResourceRef {
    /// The mime type of the referenced resource.
    pub format: String,

    /// A URI that identifies the resource as referenced from the manifest.
    ///
    /// This may be a JUMBF URI, a file path, a URL or any other string.
    /// Relative JUMBF URIs will be resolved with the manifest label.
    /// Relative file paths will be resolved with the base path if provided.
    pub identifier: String,

    /// More detailed data types as defined in the C2PA spec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_types: Option<Vec<AssetType>>,

    /// The algorithm used to hash the resource (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// The hash of the resource (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl ResourceRef {
    pub fn new<S: Into<String>, I: Into<String>>(format: S, identifier: I) -> Self {
        Self {
            format: format.into(),
            identifier: identifier.into(),
            data_types: None,
            alg: None,
            hash: None,
        }
    }
}

/// Resource store to contain binary objects referenced from JSON serializable structures
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[doc(hidden)]
pub struct ResourceStore {
    resources: HashMap<String, Vec<u8>>,
    #[cfg(feature = "file_io")]
    #[serde(skip_serializing_if = "Option::is_none")]
    base_path: Option<PathBuf>,
    /// Directory that disk-backed resources must resolve within.
    ///
    /// Relative identifiers (including `..`) are resolved against
    /// [`base_path`](Self::base_path) but the final path is confined to this
    /// root, so an attacker-supplied identifier cannot escape the manifest tree
    /// to read arbitrary files. When unset it defaults to `base_path`. Never
    /// serialized — it is a runtime security boundary set by the caller, never
    /// taken from (untrusted) manifest/archive data.
    #[cfg(feature = "file_io")]
    #[serde(skip)]
    resource_root: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    /// Optional resolver that can look up resource bytes by URI from an external source
    /// (e.g. a `Store`). Used to defer materialization of bytes during reading.
    #[serde(skip)]
    resolver: Option<Arc<dyn StoreResolver>>,
}

/// A pluggable resolver that lets [`ResourceStore`] look up resource bytes from an
/// external source (e.g. a parsed [`Store`][crate::store::Store]) without eagerly copying them.
///
/// - [`get`][StoreResolver::get]: Returns `None` for unknown URIs, `Some(Err)` for known-but-failed.
/// - [`has`][StoreResolver::has]: O(1) existence check — `true` only for binary resources.
/// - [`keys`][StoreResolver::keys]: Enumerates binary resource URIs visible through this resolver.
pub(crate) trait StoreResolver: std::fmt::Debug + MaybeSend + MaybeSync {
    fn get(&self, uri: &str) -> Option<crate::Result<Vec<u8>>>;
    fn has(&self, uri: &str) -> bool;
    fn keys(&self) -> Vec<String>;
}

/// Chains two resolvers: tries `primary` first, falls back to `fallback`.
#[derive(Debug)]
struct ChainedResolver {
    primary: Arc<dyn StoreResolver>,
    fallback: Arc<dyn StoreResolver>,
}

impl StoreResolver for ChainedResolver {
    fn get(&self, uri: &str) -> Option<crate::Result<Vec<u8>>> {
        self.primary.get(uri).or_else(|| self.fallback.get(uri))
    }

    fn has(&self, uri: &str) -> bool {
        self.primary.has(uri) || self.fallback.has(uri)
    }

    fn keys(&self) -> Vec<String> {
        let mut ids = self.primary.keys();
        ids.extend(self.fallback.keys());
        ids
    }
}

impl ResourceStore {
    /// Create a new resource reference.
    pub fn new() -> Self {
        ResourceStore {
            resources: HashMap::new(),
            #[cfg(feature = "file_io")]
            base_path: None,
            #[cfg(feature = "file_io")]
            resource_root: None,
            label: None,
            resolver: None,
        }
    }

    /// Sets the resolver used to lazily look up resource bytes by URI.
    ///
    /// The resolver is called as a fallback when a resource is not present in
    /// memory or on disk.
    pub(crate) fn set_resolver(&mut self, resolver: Arc<dyn StoreResolver>) {
        self.resolver = Some(resolver);
    }

    /// Chains the resolver from `other` as an additional fallback on this store.
    ///
    /// When [`get`](Self::get) finds no local match it tries the existing resolver
    /// chain first, then falls through to `other`'s resolver.  This allows a
    /// builder's resource store to transparently serve bytes that live in an
    /// ingredient's manifest store without eagerly copying them.
    pub(crate) fn chain_resolver_from(&mut self, other: &ResourceStore) {
        if let Some(new_resolver) = other.resolver.clone() {
            if let Some(existing) = self.resolver.take() {
                self.set_resolver(Arc::new(ChainedResolver {
                    primary: existing,
                    fallback: new_resolver,
                }));
            } else {
                self.set_resolver(new_resolver);
            }
        }
    }

    /// Set a manifest label for this store used to resolve relative JUMBF URIs.
    pub fn set_label<S: Into<String>>(&mut self, label: S) -> &Self {
        self.label = Some(label.into());
        self
    }

    #[cfg(feature = "file_io")]
    // Returns the base path for relative file paths if it is set.
    pub fn base_path(&self) -> Option<&Path> {
        self.base_path.as_deref()
    }

    #[cfg(feature = "file_io")]
    /// Sets a base path for relative file paths.
    ///
    /// Identifiers will be interpreted as file paths and resources will be written to files if this is set.
    pub fn set_base_path<P: Into<PathBuf>>(&mut self, base_path: P) {
        self.base_path = Some(base_path.into());
    }

    #[cfg(feature = "file_io")]
    /// Returns and removes the base path.
    pub fn take_base_path(&mut self) -> Option<PathBuf> {
        self.base_path.take()
    }

    #[cfg(feature = "file_io")]
    /// Sets the containment root that disk-backed resources must resolve within.
    ///
    /// Relative identifiers are still resolved against [`base_path`](Self::base_path),
    /// but the resolved path may not escape this root. Set this to the top-level
    /// manifest directory so a nested ingredient (whose `base_path` is a
    /// subdirectory) can still reference sibling resources via `..` while
    /// attacker-supplied traversal that escapes the manifest tree is rejected.
    pub fn set_resource_root<P: Into<PathBuf>>(&mut self, resource_root: P) {
        self.resource_root = Some(resource_root.into());
    }

    /// Generates a unique ID for a given content type (adds a file extension).
    pub fn id_from(&self, key: &str, format: &str) -> String {
        let ext = match format {
            "jpg" | "jpeg" | "image/jpeg" => ".jpg",
            "png" | "image/png" => ".png",
            //make "svg" | "image/svg+xml" => ".svg",
            "c2pa" | "application/x-c2pa-manifest-store" | "application/c2pa" => ".c2pa",
            "ocsp" => ".ocsp",
            _ => "",
        };
        // clean string for possible filesystem use
        let id_base = key.replace(['/', ':'], "-");

        // ensure it is unique in this store
        let mut count = 1;
        let mut id = format!("{id_base}{ext}");
        while self.exists(&id) {
            id = format!("{id_base}-{count}{ext}");
            count += 1;
        }
        id
    }

    /// Adds a resource, generating a [`ResourceRef`] from a key and format.
    ///
    /// The generated identifier may be different from the key.
    pub fn add_with<R>(&mut self, key: &str, format: &str, value: R) -> crate::Result<ResourceRef>
    where
        R: Into<Vec<u8>>,
    {
        let id = self.id_from(key, format);
        self.add(&id, value)?;
        Ok(ResourceRef::new(format, id))
    }

    /// Adds a resource, using a given id value.
    pub fn add<S, R>(&mut self, id: S, value: R) -> crate::Result<&mut Self>
    where
        S: Into<String>,
        R: Into<Vec<u8>>,
    {
        #[cfg(feature = "file_io")]
        if let Some(base) = self.base_path.as_ref() {
            let sanitized_id = sanitize_archive_path(&id.into())?;
            let path = base.join(&sanitized_id);
            create_dir_all(path.parent().unwrap_or(Path::new("")))?;
            write(path, value.into())?;
            return Ok(self);
        }
        self.resources.insert(id.into(), value.into());
        Ok(self)
    }

    /// Returns a [`HashMap`] of internal resources.
    pub fn resources(&self) -> &HashMap<String, Vec<u8>> {
        &self.resources
    }

    /// Returns a copy on write reference to the resource if found.
    ///
    /// Returns [`Error::ResourceNotFound`] if it cannot find a resource matching that ID.
    pub fn get(&self, id: &str) -> Result<Cow<'_, Vec<u8>>> {
        #[cfg(feature = "file_io")]
        if !self.resources.contains_key(id) {
            match self.base_path.as_ref() {
                Some(base) => {
                    // Confine the identifier to the manifest root (defaults to
                    // base_path). Relative `..` is allowed as long as it stays
                    // within the manifest tree; absolute paths, escapes, and
                    // escaping symlinks are rejected. Prevents attacker-supplied
                    // manifest definitions from exfiltrating files outside the
                    // manifest directory.
                    let root = self.resource_root.as_deref().unwrap_or(base);
                    let path = resolve_within_root(base, root, id)
                        .map_err(|_| Error::ResourceNotFound(id.to_string()))?;
                    // read the file, save in Map and then return a reference
                    let value = read(&path).map_err(|_| {
                        Error::ResourceNotFound(path.to_string_lossy().into_owned())
                    })?;
                    return Ok(Cow::Owned(value));
                }
                None => {
                    if let Some(result) = self.resolver.as_ref().and_then(|r| r.get(id)) {
                        return result.map(Cow::Owned);
                    }
                    return Err(Error::ResourceNotFound(id.to_string()));
                }
            }
        }
        self.resources.get(id).map_or_else(
            || {
                self.resolver
                    .as_ref()
                    .and_then(|r| r.get(id))
                    .map_or(Err(Error::ResourceNotFound(id.to_string())), |r| {
                        r.map(Cow::Owned)
                    })
            },
            |v| Ok(Cow::Borrowed(v)),
        )
    }

    pub fn write_stream(
        &self,
        id: &str,
        mut stream: impl Write + Read + Seek + MaybeSend,
    ) -> Result<u64> {
        #[cfg(feature = "file_io")]
        if !self.resources.contains_key(id) {
            match self.base_path.as_ref() {
                Some(base) => {
                    // Confine the identifier to the manifest root (see get()).
                    let root = self.resource_root.as_deref().unwrap_or(base);
                    let path = resolve_within_root(base, root, id)
                        .map_err(|_| Error::ResourceNotFound(id.to_string()))?;
                    // read from, the file to stream
                    let mut file = std::fs::File::open(path)?;
                    return std::io::copy(&mut file, &mut stream).map_err(Error::IoError);
                }
                None => {
                    if let Some(result) = self.resolver.as_ref().and_then(|r| r.get(id)) {
                        let data = result?;
                        stream.write_all(&data).map_err(Error::IoError)?;
                        return Ok(data.len() as u64);
                    }
                    return Err(Error::ResourceNotFound(id.to_string()));
                }
            }
        }
        match self.resources().get(id) {
            Some(data) => {
                stream.write_all(data).map_err(Error::IoError)?;
                Ok(data.len() as u64)
            }
            None => {
                if let Some(result) = self.resolver.as_ref().and_then(|r| r.get(id)) {
                    let data = result?;
                    stream.write_all(&data).map_err(Error::IoError)?;
                    return Ok(data.len() as u64);
                }
                Err(Error::ResourceNotFound(id.to_string()))
            }
        }
    }

    /// Returns `true` if the resource has been added or exists as a file or in the resolver.
    pub fn exists(&self, path: &str) -> bool {
        if self.resources.contains_key(path) {
            return true;
        }

        #[cfg(feature = "file_io")]
        if let Some(base) = self.base_path.as_ref() {
            // Skip disk probes for identifiers that would escape the manifest
            // root — a hostile id like `../../etc/passwd`, or a symlink pointing
            // outside the manifest tree, must not leak existence via this API.
            let root = self.resource_root.as_deref().unwrap_or(base);
            if let Ok(resolved) = resolve_within_root(base, root, path) {
                if resolved.exists() {
                    return true;
                }
            }
        }

        if let Some(resolver) = &self.resolver {
            if resolver.has(path) {
                return true;
            }
        }

        false
    }

    /// Returns all resource IDs — both in-memory keys and those enumerated by the resolver.
    ///
    /// Only binary resources are enumerated from the resolver (EmbeddedData assertions,
    /// databoxes, and manifest bytes).
    pub fn iter_resource_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.resources.keys().cloned().collect();
        if let Some(resolver) = &self.resolver {
            ids.extend(resolver.keys());
        }
        ids
    }

    #[cfg(feature = "file_io")]
    // Returns the full path for an ID.
    pub fn path_for_id(&self, id: &str) -> Option<PathBuf> {
        let base = self.base_path.as_ref()?;
        let root = self.resource_root.as_deref().unwrap_or(base);
        resolve_within_root(base, root, id).ok()
    }
}

impl Default for ResourceStore {
    fn default() -> Self {
        ResourceStore::new()
    }
}

/// Lexically normalize a path by resolving `.` and `..` components without
/// touching the filesystem.
///
/// Leading `..` components that cannot be popped (they would climb above the
/// path's start, or the path is rooted) are preserved so that an escape above a
/// relative base remains detectable by a later `starts_with` check.
#[cfg(feature = "file_io")]
fn normalize_lexically(path: &Path) -> PathBuf {
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
/// 1. Backslashes and absolute paths are refused up front. Archives are
///    portable, so a Windows-authored `\` separator would otherwise be treated
///    as a filename on Linux; absolute identifiers are never legitimate.
/// 2. Lexical containment: `base.join(path)` is normalized (resolving `.`/`..`
///    without filesystem access) and must remain within the normalized `root`.
///    This catches escapes even when the target does not exist.
/// 3. Symlink containment: if the resolved target exists, it is canonicalized
///    (following symlinks) and re-checked against the canonicalized `root`. A
///    hostile bundle could ship an innocuously-named symlink pointing outside
///    the manifest tree; lexical checks alone would not catch that. Both sides
///    are canonicalized so a legitimately symlinked `root` (e.g. `/tmp` ->
///    `/private/tmp` on macOS) is not falsely rejected.
///
/// A non-existent target passes step 3 (nothing to canonicalize) and is returned
/// as the joined path; the caller's own read/open then surfaces the not-found
/// error.
#[cfg(feature = "file_io")]
fn resolve_within_root(base: &Path, root: &Path, path: &str) -> Result<PathBuf> {
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

    let joined = base.join(path);

    // Lexical containment (works whether or not the target exists).
    if !normalize_lexically(&joined).starts_with(normalize_lexically(root)) {
        return Err(Error::BadParam(format!(
            "Resource path escapes manifest root: {path}"
        )));
    }

    // Symlink containment for targets that exist.
    if let Ok(canonical_target) = joined.canonicalize() {
        let canonical_root = root.canonicalize()?;
        if !canonical_target.starts_with(&canonical_root) {
            return Err(Error::BadParam(format!(
                "Resource path escapes manifest root: {path}"
            )));
        }
    }

    Ok(joined)
}

pub trait ResourceResolver {
    /// Read the data in a [`ResourceRef`] via a stream.
    fn open(&self, reference: &ResourceRef) -> Result<Box<dyn CAIRead>>;
}

impl ResourceResolver for ResourceStore {
    fn open(&self, reference: &ResourceRef) -> Result<Box<dyn CAIRead>> {
        let data = self.get(&reference.identifier)?.into_owned();
        let cursor = std::io::Cursor::new(data);
        Ok(Box::new(cursor))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;
    use crate::{
        crypto::raw_signature::SigningAlg, utils::test_signer::test_signer, Builder, Reader,
    };

    #[test]
    fn resource_store() {
        let mut c = ResourceStore::new();
        let value = b"my value";
        c.add("abc123.jpg", value.to_vec()).expect("add");
        let v = c.get("abc123.jpg").unwrap();
        assert_eq!(v.to_vec(), b"my value");
        c.add("cba321.jpg", value.to_vec()).expect("add");
        assert!(c.exists("cba321.jpg"));
        assert!(!c.exists("foo"));

        let json = r#"{
            "claim_generator": "test",
            "format" : "image/jpeg",
            "instance_id": "12345",
            "thumbnail": {
                "format": "image/jpeg",
                "identifier": "abc123"
            },
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty"
                            }
                        ]
                    }
                }
            ],
            "ingredients": [{
                "title": "A.jpg",
                "format": "image/jpeg",
                "document_id": "xmp.did:813ee422-9736-4cdc-9be6-4e35ed8e41cb",
                "instance_id": "xmp.iid:813ee422-9736-4cdc-9be6-4e35ed8e41cb",
                "relationship": "parentOf",
                "thumbnail": {
                    "format": "image/jpeg",
                    "identifier": "cba321"
                }
            }]
        }"#;

        let mut builder = Builder::default().with_definition(json).expect("from json");
        builder
            .add_resource("abc123", Cursor::new(value))
            .expect("add_resource");
        builder
            .add_resource("cba321", Cursor::new(value))
            .expect("add_resource");

        let image = include_bytes!("../tests/fixtures/earth_apollo17.jpg");

        let signer = test_signer(SigningAlg::Ps256);

        // Embed a manifest using the signer.
        let mut output_image = Cursor::new(Vec::new());
        builder
            .sign(
                &*signer,
                "image/jpeg",
                &mut Cursor::new(image),
                &mut output_image,
            )
            .expect("sign");

        output_image.set_position(0);
        let reader = Reader::default()
            .with_stream("jpeg", &mut output_image)
            .expect("from_bytes");
        let _json = reader.json();
        println!("{_json}");
    }

    #[cfg(all(feature = "file_io", not(target_arch = "wasm32")))]
    mod zip_slip_tests {
        use tempfile::tempdir;

        use super::*;

        #[test]
        fn add_with_base_path_rejects_parent_dir_traversal() {
            let temp = tempdir().unwrap();
            let mut store = ResourceStore::new();
            store.set_base_path(temp.path().to_path_buf());

            let result = store.add("../outside_evil.txt", b"attacker data".to_vec());
            assert!(result.is_err());

            let escaped = temp.path().parent().unwrap().join("outside_evil.txt");
            assert!(!escaped.exists());
        }

        #[test]
        fn add_with_base_path_rejects_absolute_path() {
            let temp = tempdir().unwrap();
            let mut store = ResourceStore::new();
            store.set_base_path(temp.path().to_path_buf());

            let result = store.add("/etc/passwd", b"attacker data".to_vec());
            assert!(result.is_err());
        }

        #[test]
        fn add_with_base_path_accepts_normal_resource() {
            let temp = tempdir().unwrap();
            let mut store = ResourceStore::new();
            store.set_base_path(temp.path().to_path_buf());

            store.add("thumbnail.jpg", b"image data".to_vec()).unwrap();
            assert!(temp.path().join("thumbnail.jpg").exists());
        }

        #[test]
        fn add_with_base_path_accepts_subdir_resource() {
            let temp = tempdir().unwrap();
            let mut store = ResourceStore::new();
            store.set_base_path(temp.path().to_path_buf());

            store
                .add("subdir/thumbnail.jpg", b"image data".to_vec())
                .unwrap();
            assert!(temp.path().join("subdir/thumbnail.jpg").exists());
        }

        #[test]
        fn add_with_base_path_rejects_backslash_traversal() {
            // Cross-platform regression: a Windows-authored archive can carry
            // entry IDs that use `\` as a path separator. On Linux those would
            // appear as a single Normal component to Path::components() and
            // would slip past the traversal check unless we reject backslash
            // explicitly.
            let temp = tempdir().unwrap();
            let mut store = ResourceStore::new();
            store.set_base_path(temp.path().to_path_buf());

            let result = store.add("..\\..\\etc\\passwd", b"attacker data".to_vec());
            assert!(result.is_err());
        }

        // Regression: an attacker-supplied manifest.json with an ingredient
        // `data.identifier` containing a traversal payload must not read files
        // outside base_path (the manifest directory) when Builder::sign reaches
        // ResourceStore::get on the disk-fallback path.
        #[test]
        fn get_with_base_path_rejects_parent_dir_traversal() {
            let temp = tempdir().unwrap();
            let base = temp.path().join("manifest_dir");
            std::fs::create_dir_all(&base).unwrap();
            // A "secret" file outside the manifest dir the attacker wants to exfiltrate.
            let secret = temp.path().join("secret.txt");
            std::fs::write(&secret, b"SUPER SECRET").unwrap();

            let mut store = ResourceStore::new();
            store.set_base_path(base);

            let result = store.get("../secret.txt");
            assert!(
                matches!(result, Err(Error::ResourceNotFound(_))),
                "expected ResourceNotFound, got {result:?}"
            );
        }

        #[test]
        fn get_with_base_path_rejects_absolute_path() {
            let temp = tempdir().unwrap();
            let mut store = ResourceStore::new();
            store.set_base_path(temp.path().to_path_buf());

            let result = store.get("/etc/passwd");
            assert!(matches!(result, Err(Error::ResourceNotFound(_))));
        }

        #[test]
        fn get_with_base_path_rejects_backslash_traversal() {
            // A Windows-style backslash traversal must be blocked on all platforms —
            // on Linux it would otherwise be joined verbatim into a filename lookup
            // relative to base_path, but a malicious manifest with `..\` intent must
            // never reach disk regardless of host separator conventions.
            let temp = tempdir().unwrap();
            let mut store = ResourceStore::new();
            store.set_base_path(temp.path().to_path_buf());

            let result = store.get("..\\secrets\\password.txt");
            assert!(matches!(result, Err(Error::ResourceNotFound(_))));
        }

        #[test]
        fn get_with_base_path_accepts_normal_resource() {
            let temp = tempdir().unwrap();
            std::fs::write(temp.path().join("thumb.jpg"), b"image data").unwrap();
            let mut store = ResourceStore::new();
            store.set_base_path(temp.path().to_path_buf());

            let data = store.get("thumb.jpg").expect("get should succeed");
            assert_eq!(data.as_slice(), b"image data");
        }

        #[test]
        fn write_stream_with_base_path_rejects_parent_dir_traversal() {
            let temp = tempdir().unwrap();
            let base = temp.path().join("manifest_dir");
            std::fs::create_dir_all(&base).unwrap();
            std::fs::write(temp.path().join("secret.txt"), b"SUPER SECRET").unwrap();

            let mut store = ResourceStore::new();
            store.set_base_path(base);

            let mut out = std::io::Cursor::new(Vec::<u8>::new());
            let result = store.write_stream("../secret.txt", &mut out);
            assert!(matches!(result, Err(Error::ResourceNotFound(_))));
            assert!(out.get_ref().is_empty());
        }

        #[test]
        fn exists_with_base_path_rejects_parent_dir_traversal() {
            let temp = tempdir().unwrap();
            let base = temp.path().join("manifest_dir");
            std::fs::create_dir_all(&base).unwrap();
            std::fs::write(temp.path().join("secret.txt"), b"SUPER SECRET").unwrap();

            let mut store = ResourceStore::new();
            store.set_base_path(base);

            assert!(!store.exists("../secret.txt"));
            assert!(!store.exists("..\\secret.txt"));
            assert!(!store.exists("/etc/passwd"));
        }

        #[test]
        fn path_for_id_rejects_traversal() {
            let temp = tempdir().unwrap();
            let mut store = ResourceStore::new();
            store.set_base_path(temp.path().to_path_buf());

            assert!(store.path_for_id("../secret.txt").is_none());
            assert!(store.path_for_id("..\\secret.txt").is_none());
            assert!(store.path_for_id("/etc/passwd").is_none());
            assert!(store.path_for_id("thumb.jpg").is_some());
        }

        // A legitimate nested resource (e.g. `resources/thumb.jpg`) must still be
        // readable — sanitization must not over-block ordinary subdirectories.
        #[test]
        fn get_with_base_path_accepts_nested_resource() {
            let temp = tempdir().unwrap();
            std::fs::create_dir_all(temp.path().join("resources/thumbs")).unwrap();
            std::fs::write(
                temp.path().join("resources/thumbs/thumb.jpg"),
                b"nested image data",
            )
            .unwrap();

            let mut store = ResourceStore::new();
            store.set_base_path(temp.path().to_path_buf());

            let data = store
                .get("resources/thumbs/thumb.jpg")
                .expect("nested get should succeed");
            assert_eq!(data.as_slice(), b"nested image data");
        }

        // A `..` buried inside an otherwise-legitimate nested path must be caught
        // (the whole path is rejected, not just a leading `..`).
        #[test]
        fn get_with_base_path_rejects_nested_traversal() {
            let temp = tempdir().unwrap();
            let base = temp.path().join("manifest_dir");
            std::fs::create_dir_all(base.join("resources")).unwrap();
            std::fs::write(temp.path().join("secret.txt"), b"SUPER SECRET").unwrap();

            let mut store = ResourceStore::new();
            store.set_base_path(base);

            let result = store.get("resources/../../secret.txt");
            assert!(
                matches!(result, Err(Error::ResourceNotFound(_))),
                "expected ResourceNotFound, got {result:?}"
            );
        }

        // Symlink defense-in-depth: a symlink planted inside base_path (e.g. by
        // an extracted manifest bundle) that points to a file *outside* base_path
        // must not be read, even though its name contains no traversal sequence.
        #[cfg(unix)]
        #[test]
        fn get_with_base_path_rejects_escaping_symlink() {
            let temp = tempdir().unwrap();
            let base = temp.path().join("manifest_dir");
            std::fs::create_dir_all(&base).unwrap();
            let secret = temp.path().join("secret.txt");
            std::fs::write(&secret, b"SUPER SECRET").unwrap();
            // An innocuously-named link inside base_path pointing outside it.
            std::os::unix::fs::symlink(&secret, base.join("thumb.jpg")).unwrap();

            let mut store = ResourceStore::new();
            store.set_base_path(base);

            let result = store.get("thumb.jpg");
            assert!(
                matches!(result, Err(Error::ResourceNotFound(_))),
                "escaping symlink must not be readable, got {result:?}"
            );
        }

        // The containment check follows symlinks but only rejects those that
        // escape base_path — a symlink pointing at a sibling *inside* base_path
        // is still a valid resource and must resolve.
        #[cfg(unix)]
        #[test]
        fn get_with_base_path_allows_internal_symlink() {
            let temp = tempdir().unwrap();
            let base = temp.path().join("manifest_dir");
            std::fs::create_dir_all(&base).unwrap();
            std::fs::write(base.join("real.jpg"), b"image data").unwrap();
            std::os::unix::fs::symlink(base.join("real.jpg"), base.join("alias.jpg")).unwrap();

            let mut store = ResourceStore::new();
            store.set_base_path(base);

            let data = store
                .get("alias.jpg")
                .expect("in-directory symlink should resolve");
            assert_eq!(data.as_slice(), b"image data");
        }

        // `exists` must not confirm the presence of an escaping-symlink target.
        #[cfg(unix)]
        #[test]
        fn exists_with_base_path_rejects_escaping_symlink() {
            let temp = tempdir().unwrap();
            let base = temp.path().join("manifest_dir");
            std::fs::create_dir_all(&base).unwrap();
            let secret = temp.path().join("secret.txt");
            std::fs::write(&secret, b"SUPER SECRET").unwrap();
            std::os::unix::fs::symlink(&secret, base.join("thumb.jpg")).unwrap();

            let mut store = ResourceStore::new();
            store.set_base_path(base);

            assert!(!store.exists("thumb.jpg"));
        }

        // `write_stream` must not stream out the contents of an escaping symlink.
        #[cfg(unix)]
        #[test]
        fn write_stream_with_base_path_rejects_escaping_symlink() {
            let temp = tempdir().unwrap();
            let base = temp.path().join("manifest_dir");
            std::fs::create_dir_all(&base).unwrap();
            let secret = temp.path().join("secret.txt");
            std::fs::write(&secret, b"SUPER SECRET").unwrap();
            std::os::unix::fs::symlink(&secret, base.join("thumb.jpg")).unwrap();

            let mut store = ResourceStore::new();
            store.set_base_path(base);

            let mut out = std::io::Cursor::new(Vec::<u8>::new());
            let result = store.write_stream("thumb.jpg", &mut out);
            assert!(matches!(result, Err(Error::ResourceNotFound(_))));
            assert!(out.get_ref().is_empty());
        }

        // Windows equivalents of the symlink tests above. The containment fix is
        // cross-platform (Path::canonicalize resolves symlinks on Windows too),
        // but creating a symlink on Windows requires Administrator rights or
        // Developer Mode, which unprivileged CI runners lack. These tests skip
        // (rather than fail) when symlink creation is not permitted.
        #[cfg(windows)]
        #[test]
        fn get_with_base_path_rejects_escaping_symlink_windows() {
            let temp = tempdir().unwrap();
            let base = temp.path().join("manifest_dir");
            std::fs::create_dir_all(&base).unwrap();
            let secret = temp.path().join("secret.txt");
            std::fs::write(&secret, b"SUPER SECRET").unwrap();
            // An innocuously-named link inside base_path pointing outside it.
            if std::os::windows::fs::symlink_file(&secret, base.join("thumb.jpg")).is_err() {
                return; // no symlink privilege on this runner
            }

            let mut store = ResourceStore::new();
            store.set_base_path(base);

            let result = store.get("thumb.jpg");
            assert!(
                matches!(result, Err(Error::ResourceNotFound(_))),
                "escaping symlink must not be readable, got {result:?}"
            );
        }

        #[cfg(windows)]
        #[test]
        fn get_with_base_path_allows_internal_symlink_windows() {
            let temp = tempdir().unwrap();
            let base = temp.path().join("manifest_dir");
            std::fs::create_dir_all(&base).unwrap();
            std::fs::write(base.join("real.jpg"), b"image data").unwrap();
            if std::os::windows::fs::symlink_file(base.join("real.jpg"), base.join("alias.jpg"))
                .is_err()
            {
                return; // no symlink privilege on this runner
            }

            let mut store = ResourceStore::new();
            store.set_base_path(base);

            let data = store
                .get("alias.jpg")
                .expect("in-directory symlink should resolve");
            assert_eq!(data.as_slice(), b"image data");
        }

        #[cfg(windows)]
        #[test]
        fn exists_with_base_path_rejects_escaping_symlink_windows() {
            let temp = tempdir().unwrap();
            let base = temp.path().join("manifest_dir");
            std::fs::create_dir_all(&base).unwrap();
            let secret = temp.path().join("secret.txt");
            std::fs::write(&secret, b"SUPER SECRET").unwrap();
            if std::os::windows::fs::symlink_file(&secret, base.join("thumb.jpg")).is_err() {
                return; // no symlink privilege on this runner
            }

            let mut store = ResourceStore::new();
            store.set_base_path(base);

            assert!(!store.exists("thumb.jpg"));
        }

        #[cfg(windows)]
        #[test]
        fn write_stream_with_base_path_rejects_escaping_symlink_windows() {
            let temp = tempdir().unwrap();
            let base = temp.path().join("manifest_dir");
            std::fs::create_dir_all(&base).unwrap();
            let secret = temp.path().join("secret.txt");
            std::fs::write(&secret, b"SUPER SECRET").unwrap();
            if std::os::windows::fs::symlink_file(&secret, base.join("thumb.jpg")).is_err() {
                return; // no symlink privilege on this runner
            }

            let mut store = ResourceStore::new();
            store.set_base_path(base);

            let mut out = std::io::Cursor::new(Vec::<u8>::new());
            let result = store.write_stream("thumb.jpg", &mut out);
            assert!(matches!(result, Err(Error::ResourceNotFound(_))));
            assert!(out.get_ref().is_empty());
        }

        // Regression for the nested-ingredient case (c2patool ingredient_paths):
        // a store whose base_path is a subdirectory of the manifest root may
        // reference a sibling resource one level up via `..`, as long as the
        // resolved path stays within the manifest root.
        #[test]
        fn get_with_resource_root_allows_parent_relative_within_root() {
            let temp = tempdir().unwrap();
            let root = temp.path().join("manifest");
            let ingredient_dir = root.join("ingredient");
            std::fs::create_dir_all(&ingredient_dir).unwrap();
            // Sibling resource lives in the manifest root, referenced from the
            // ingredient subdirectory as `../thumb.png`.
            std::fs::write(root.join("thumb.png"), b"thumb data").unwrap();

            let mut store = ResourceStore::new();
            store.set_base_path(&ingredient_dir);
            store.set_resource_root(&root);

            let data = store
                .get("../thumb.png")
                .expect("parent-relative resource within root should resolve");
            assert_eq!(data.as_slice(), b"thumb data");
        }

        // But `..` may not climb above the manifest root, even from a nested base.
        #[test]
        fn get_with_resource_root_rejects_escape_beyond_root() {
            let temp = tempdir().unwrap();
            let root = temp.path().join("manifest");
            let ingredient_dir = root.join("ingredient");
            std::fs::create_dir_all(&ingredient_dir).unwrap();
            // Secret lives outside the manifest root entirely.
            std::fs::write(temp.path().join("secret.txt"), b"SUPER SECRET").unwrap();

            let mut store = ResourceStore::new();
            store.set_base_path(&ingredient_dir);
            store.set_resource_root(&root);

            // `ingredient/../../secret.txt` -> temp/secret.txt, outside the root.
            let result = store.get("../../secret.txt");
            assert!(
                matches!(result, Err(Error::ResourceNotFound(_))),
                "escape above manifest root must be rejected, got {result:?}"
            );
        }
    }
}
