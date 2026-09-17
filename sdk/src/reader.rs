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

//! The Reader provides a way to read a manifest store from an asset.
//! It also performs validation on the manifest store.

use std::{
    collections::{HashMap, HashSet},
    io::{Read, Seek, Write},
    sync::Arc,
};

use async_generic::async_generic;
use async_trait::async_trait;
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;

use crate::asset_transport::{
    AssetRef, AssetRequest, AssetRequestKind, AssetTransportError, OwnedAssetRef, ResolvedAsset,
};
use crate::asset_transport::{drive_async, read_whole_async, ReadTarget};
#[cfg(feature = "file_io")]
use crate::utils::io_utils::uri_to_path;
use crate::{
    assertions::Metadata,
    context::{Context, ProgressPhase},
    dynamic_assertion::PartialClaim,
    error::{Error, Result},
    jumbf::labels::{manifest_label_from_uri, to_absolute_uri, to_relative_uri},
    log_item,
    manifest::StoreOptions,
    manifest_store_report::ManifestStoreReport,
    status_tracker::StatusTracker,
    store::Store,
    utils::hash_utils::hash_to_b64,
    validation_results::{ValidationResults, ValidationState},
    validation_status::{ValidationStatus, ASSERTION_MISSING},
    Ingredient, Manifest, ManifestAssertion, ManifestAssertionKind,
};

/// MaybeSend allows for no Send bound on wasm32 targets
/// todo: move this to a common module
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> MaybeSend for T {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}

/// A trait for post-validation of manifest assertions.
pub trait PostValidator {
    fn validate(
        &self,
        label: &str,
        assertion: &ManifestAssertion,
        uri: &str,
        preliminary_claim: &PartialClaim,
        tracker: &mut StatusTracker,
    ) -> Result<Option<Value>>;
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait AsyncPostValidator {
    async fn validate(
        &self,
        label: &str,
        assertion: &ManifestAssertion,
        uri: &str,
        preliminary_claim: &PartialClaim,
        tracker: &mut StatusTracker,
    ) -> Result<Option<Value>>;
}

/// Use a Reader to read and validate a manifest store.
#[skip_serializing_none]
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema), schemars(default))]
pub struct Reader {
    /// A label for the active (most recent) manifest in the store
    active_manifest: Option<String>,

    /// A HashMap of Manifests
    manifests: HashMap<String, Manifest>,

    /// ValidationStatus generated when loading the ManifestStore from an asset
    validation_status: Option<Vec<ValidationStatus>>,

    /// ValidationStatus generated when loading the ManifestStore from an asset
    validation_results: Option<ValidationResults>,

    /// The validation state of the manifest store
    validation_state: Option<ValidationState>,

    #[serde(skip)]
    /// We keep this around so we can generate a detailed report if needed
    pub(crate) store: Arc<Store>,

    #[serde(skip)]
    /// Map to hold post-validation assertion values for reports
    /// the key is an assertion uri and the value is the assertion value
    assertion_values: HashMap<String, Value>,

    #[serde(skip)]
    context: Arc<Context>,
}

impl Default for Reader {
    fn default() -> Self {
        Self {
            active_manifest: None,
            manifests: HashMap::new(),
            validation_status: None,
            validation_results: None,
            validation_state: None,
            store: Arc::new(Store::new()),
            assertion_values: HashMap::new(),
            context: Arc::new(Context::default()),
        }
    }
}

impl Reader {
    /// Create a new Reader with the given [`Context`].
    ///
    /// This method takes ownership of the [`Context`] and wraps it in an [`Arc`] internally.
    /// Use this for single-use contexts where you don't need to share the context.
    ///
    /// Use [`Reader::default()`] when no special configuration is needed.
    /// Use [`Reader::from_shared_context`] to share a context across multiple readers.
    ///
    /// # Arguments
    /// * `context` - The [`Context`] to use for the Reader
    ///
    /// # Returns
    /// A new Reader
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::{Context, Reader, Result};
    /// # fn main() -> Result<()> {
    /// // With default settings (no explicit context needed):
    /// let reader = Reader::default();
    ///
    /// // With custom settings:
    /// let context = Context::new().with_settings(r#"{"verify": {"verify_after_sign": true}}"#)?;
    /// let reader = Reader::from_context(context);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_context(context: Context) -> Self {
        Self {
            context: Arc::new(context),
            store: Arc::new(Store::new()),
            assertion_values: HashMap::new(),
            ..Default::default()
        }
    }

    /// Create a new Reader with a shared [`Context`].
    ///
    /// This method allows sharing a single [`Context`] across multiple builders or readers,
    /// even across threads. The [`Arc`] is cloned internally, so you pass a reference.
    ///
    /// # Arguments
    /// * `context` - A reference to an [`Arc<Context>`] to share.
    ///
    /// # Returns
    /// A new [`Reader`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::{Context, Reader, Result, Settings};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<()> {
    /// // Create a shared Context once
    /// let ctx = Context::new().with_settings(Settings::new())?.into_shared();
    ///
    /// // Share it across multiple Readers (even across threads!)
    /// let reader1 = Reader::from_shared_context(&ctx);
    /// let reader2 = Reader::from_shared_context(&ctx);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_shared_context(context: &Arc<Context>) -> Self {
        Self {
            context: Arc::clone(context),
            store: Arc::new(Store::new()),
            assertion_values: HashMap::new(),
            ..Default::default()
        }
    }

    /// Add manifest store from a stream to the [`Reader`].
    ///
    /// # Arguments
    /// * `format` - The MIME type or file extension of the stream, used as a fallback when
    ///   content-based format detection cannot determine the format from the stream's leading
    ///   bytes.  Detection is attempted first; `format` is only used when detection returns
    ///   no result.
    /// * `stream` - The stream to read from.  Must implement the Read and Seek traits.
    /// # Returns
    /// The updated [`Reader`] with the added manifest store.
    #[async_generic]
    pub fn with_stream(
        mut self,
        format: &str,
        mut stream: impl Read + Seek + MaybeSend,
    ) -> Result<Self> {
        let mut validation_log = StatusTracker::default();
        stream.rewind()?; // Ensure stream is at the start

        // Prefer the caller's format hint when it identifies the same container as the
        // stream bytes (e.g. "dng" stays "dng" rather than being widened to "image/tiff").
        let format_owned = self.context.io().format_from_stream(format, &mut stream);
        let format = format_owned.as_str();

        self.context.check_progress(ProgressPhase::Reading, 1, 1)?;

        let store = if _sync {
            Store::from_stream(format, stream, &mut validation_log, &self.context)
        } else {
            Store::from_stream_async(format, stream, &mut validation_log, &self.context).await
        }?;

        if _sync {
            self.with_store(store, &mut validation_log)
        } else {
            self.with_store_async(store, &mut validation_log).await
        }?;
        Ok(self)
    }

    /// Create a manifest store [`Reader`] from a stream.  A Reader is used to validate C2PA data from an asset.
    ///
    /// # Arguments
    /// * `format` - The format of the stream.  MIME type or extension that maps to a MIME type.
    /// * `stream` - The stream to read from.  Must implement the Read and Seek traits.
    ///   Send trait is required for sync operations and Sync trait is required for async operations.
    /// # Returns
    /// A [`Reader`] for the manifest store.
    /// # Note
    /// [CAWG identity assertions](https://cawg.io/identity/) require async calls for validation.
    #[deprecated(
        since = "0.79.4",
        note = "Use `Reader::from_context(context).with_stream(format, stream)` instead, passing a `Context` explicitly rather than relying on thread-local settings. Will be removed in 0.92.0 (scheduled for mid-November 2026)."
    )]
    #[async_generic]
    pub fn from_stream(format: &str, stream: impl Read + Seek + MaybeSend) -> Result<Reader> {
        // Legacy behavior: explicitly get global settings for backward compatibility
        let settings = crate::settings::get_thread_local_settings();
        let context = Context::new().with_settings(settings)?;

        if _sync {
            Reader::from_context(context).with_stream(format, stream)
        } else {
            Reader::from_context(context)
                .with_stream_async(format, stream)
                .await
        }
    }

    /// Open an asset through the configured transport. Async prefers the async
    /// transport, falling back to sync when none is registered.
    #[async_generic]
    fn open_asset(
        &self,
        request: AssetRequest<'_>,
    ) -> std::result::Result<ResolvedAsset, AssetTransportError> {
        if _sync {
            self.context.asset_transport()?.open(request)
        } else {
            match self.context.asset_transport_async() {
                Some(transport) => transport.open_async(request).await,
                None => self.context.asset_transport()?.open(request),
            }
        }
    }

    /// Add manifest store from a file to the [`Reader`].
    /// If the `fetch_remote_manifests` feature is enabled, and the asset refers to a remote manifest, the function fetches a remote manifest.
    ///
    /// NOTE: If the file does not have a manifest store, the function will check for a sidecar manifest with the same base file name and a .c2pa extension.
    ///
    /// # Arguments
    /// * `path` - The path to the file.
    ///
    /// # Returns
    /// The updated [`Reader`] with the added manifest store.
    ///
    /// # Errors
    /// Returns an [`Error`] when the manifest data cannot be read from the specified file.
    /// A missing or refused file arrives as [`Error::AssetTransport`], not [`Error::IoError`].
    /// Even without a read error, check validation status.
    /// The data may still be invalid.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use c2pa::{Context, Reader};
    /// # fn main() -> c2pa::Result<()> {
    /// let reader = Reader::default().with_file("path/to/file.jpg")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Note
    /// [CAWG identity assertions](https://cawg.io/identity/) require async calls for validation.
    #[cfg(feature = "file_io")]
    #[async_generic]
    pub fn with_file<P: AsRef<std::path::Path>>(self, path: P) -> Result<Self> {
        let reference = AssetRef::Path(path.as_ref());
        if _sync {
            self.with_asset(reference, None)
        } else {
            self.with_asset_async(reference, None).await
        }
    }

    /// Add a manifest store read through the [`Context`]'s asset transport.
    ///
    /// Available without `file_io`: the transport interprets the reference.
    ///
    /// # Arguments
    /// * `reference` - What to open: a path, a URI, or a transport-defined reference.
    /// * `format` - MIME type or extension. Precedence is detected magic bytes, then a
    ///   path extension, then `format`, then the transport's `format_hint()`.
    ///
    /// # Sidecar
    /// When no embedded manifest is found, a second request goes out with
    /// [`AssetRequestKind::Sidecar`]. A path targets `<asset>.c2pa`. Any other reference
    /// is re-sent unchanged, so the transport decides what its sidecar is. A transport
    /// that serves no sidecar returns [`AssetTransportError::UnsupportedReference`],
    /// read here as "no manifest".
    #[async_generic]
    pub fn with_asset(mut self, reference: AssetRef<'_>, format: Option<&str>) -> Result<Self> {
        let request = AssetRequest::new(reference);

        self.context.check_progress(ProgressPhase::Reading, 1, 0)?;
        let resolved = if _sync {
            self.open_asset(request)?
        } else {
            self.open_asset_async(request).await?
        };
        self.context.check_progress(ProgressPhase::Reading, 2, 0)?;

        // A path extension outranks the argument, which outranks the transport hint.
        // `format_from_stream` then lets detected magic bytes win over all three.
        let path_fmt = match reference {
            AssetRef::Path(p) => self.context.io().format_from_path(p),
            _ => None,
        }
        .or_else(|| format.map(str::to_owned))
        .or_else(|| resolved.format_hint().map(str::to_owned))
        .unwrap_or_default();
        // An async range transport has no blocking view, so the parse is driven: run
        // over cached bytes, fetch what it misses, run again. Only the async twin can
        // await, so the sync path reports `AsyncOnlyAsset` through the same open call.
        let mut file = if _sync {
            resolved.try_into_read_seek()?
        } else {
            match resolved.into_read_target() {
                ReadTarget::Stream(stream) => stream,
                ReadTarget::AsyncRanges { transport, config } => {
                    return self
                        .with_driven_asset_async(&path_fmt, transport.as_ref(), config, reference)
                        .await
                }
            }
        };
        // Enforce stream at position 0.
        file.rewind()?;
        let format = self.context.io().format_from_stream(&path_fmt, &mut file);

        // Try loading from stream first
        let mut validation_log = StatusTracker::default();
        let store = if _sync {
            Store::from_stream(&format, &mut file, &mut validation_log, &self.context)
        } else {
            Store::from_stream_async(&format, &mut file, &mut validation_log, &self.context).await
        };

        let store = match store {
            Err(Error::JumbfNotFound) => {
                // No embedded manifest: try a sidecar via the same transport.
                let sidecar_ref = sidecar_reference(reference);
                let sidecar_request = AssetRequest::new(sidecar_ref.as_asset_ref())
                    .with_kind(AssetRequestKind::Sidecar);
                // Cancellation checkpoint between the asset read and the sidecar read.
                self.context.check_progress(ProgressPhase::Reading, 3, 0)?;
                let sidecar = if _sync {
                    self.open_asset(sidecar_request)
                } else {
                    self.open_asset_async(sidecar_request).await
                };

                let mut manifest_data = Vec::new();
                match sidecar {
                    Ok(resolved) => {
                        let mut sidecar_stream = resolved.try_into_read_seek()?;
                        // Enforce stream at position 0.
                        sidecar_stream.rewind()?;
                        sidecar_stream.read_to_end(&mut manifest_data)?;
                    }
                    // No sidecar, or a transport that does not serve sidecars: no manifest.
                    Err(AssetTransportError::NotFound { .. })
                    | Err(AssetTransportError::UnsupportedReference) => {
                        return Err(Error::JumbfNotFound)
                    }
                    Err(e) => return Err(e.into()),
                }

                // A transport that ignores the reference may answer with the asset
                // bytes again. A non-superbox means there is no manifest here.
                if !crate::jumbf::starts_with_superbox(&manifest_data) {
                    return Err(Error::JumbfNotFound);
                }

                validation_log = StatusTracker::default();
                if _sync {
                    Store::from_manifest_data_and_stream(
                        &manifest_data,
                        &format,
                        &mut file,
                        &mut validation_log,
                        &self.context,
                    )
                } else {
                    Store::from_manifest_data_and_stream_async(
                        &manifest_data,
                        &format,
                        &mut file,
                        &mut validation_log,
                        &self.context,
                    )
                    .await
                }?
            }
            Ok(store) => store,
            Err(e) => return Err(e),
        };

        if _sync {
            self.with_store(store, &mut validation_log)
        } else {
            self.with_store_async(store, &mut validation_log).await
        }?;
        Ok(self)
    }

    /// [`with_asset`](Self::with_asset), addressing the asset by string.
    ///
    /// A recognized URI scheme becomes [`AssetRef::Uri`]. Anything else becomes
    /// [`AssetRef::Custom`], which the transport treats as untrusted.
    ///
    /// # Arguments
    /// * `format` - MIME type or extension. `None` leaves the format to detection and the
    ///   transport's `format_hint()`.
    /// * `reference` - The asset reference to resolve.
    ///
    /// # Filesystem access
    /// A string is never an [`AssetRef::Path`], and the default
    /// [`LocalAssetTransport`](crate::asset_transport::LocalAssetTransport) opens
    /// `Custom` as a path. So under `file_io` a bare path here still reads a local file.
    /// Build the transport with `LocalAssetTransport::rooted_at` to confine it.
    #[async_generic]
    pub fn with_reference(self, format: Option<&str>, reference: &str) -> Result<Self> {
        let request = AssetRequest::from_reference(reference);
        if _sync {
            self.with_asset(request.reference, format)
        } else {
            self.with_asset_async(request.reference, format).await
        }
    }

    /// Create a manifest store [`Reader`] from a file.
    /// If the `fetch_remote_manifests` feature is enabled, and the asset refers to a remote manifest, the function fetches a remote manifest.
    ///
    /// NOTE: If the file does not have a manifest store, the function will check for a sidecar manifest with the same base file name and a .c2pa extension.
    ///
    /// # Arguments
    /// * `path` - The path to the file.
    ///
    /// # Returns
    /// A [`Reader`] for the manifest store.
    ///
    /// # Errors
    /// Same as [`Reader::with_file`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use c2pa::Reader;
    /// let reader = Reader::from_file("path/to/file.jpg").unwrap();
    /// ```
    ///
    /// # Note
    /// [CAWG identity assertions](https://cawg.io/identity/) require async calls for validation.
    #[cfg(feature = "file_io")]
    #[deprecated(
        since = "0.79.4",
        note = "Use `Reader::from_context(context).with_file(path)` instead, passing a `Context` explicitly rather than relying on thread-local settings. Will be removed in 0.92.0 (scheduled for mid-November 2026)."
    )]
    #[async_generic]
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Reader> {
        // Legacy behavior: explicitly get thread-local settings for backward compatibility
        let settings = crate::settings::get_thread_local_settings();
        let context = Context::new().with_settings(settings)?;

        if _sync {
            Reader::from_context(context).with_file(path)
        } else {
            Reader::from_context(context).with_file_async(path).await
        }
    }

    /// Create a manifest store [`Reader`] from a JSON string.
    /// # Arguments
    /// * `json` - A JSON string containing a manifest store definition.
    /// # Returns
    /// A [`Reader`] for the manifest store.
    /// # WARNING
    /// This function is intended for use in testing. Don't use it in an implementation.
    pub fn from_json(json: &str) -> Result<Reader> {
        serde_json::from_str(json).map_err(crate::Error::JsonError)
    }

    /// Add manifest store from existing `c2pa_data` and a stream to the [`Reader`].
    /// Use this to validate a remote manifest or a sidecar manifest.
    /// # Arguments
    /// * `c2pa_data` - A C2PA manifest store in JUMBF format.
    /// * `format` - The format of the stream.
    /// * `stream` - The stream to verify the store against.
    /// # Returns
    /// The updated [`Reader`] with the added manifest store.
    /// # Errors
    /// This function returns an [`Error`] if the c2pa_data is not valid, or severe errors occur in validation.
    /// You must check validation status for non-severe errors.
    #[async_generic]
    pub fn with_manifest_data_and_stream(
        mut self,
        c2pa_data: &[u8],
        format: &str,
        stream: impl Read + Seek + MaybeSend,
    ) -> Result<Self> {
        let mut validation_log = StatusTracker::default();

        let store = if _sync {
            Store::from_manifest_data_and_stream(
                c2pa_data,
                format,
                stream,
                &mut validation_log,
                &self.context,
            )
        } else {
            Store::from_manifest_data_and_stream_async(
                c2pa_data,
                format,
                stream,
                &mut validation_log,
                &self.context,
            )
            .await
        }?;
        if _sync {
            self.with_store(store, &mut validation_log)
        } else {
            self.with_store_async(store, &mut validation_log).await
        }?;
        Ok(self)
    }

    /// Create a manifest store [`Reader`] from existing `c2pa_data` and a stream.
    /// Use this to validate a remote manifest or a sidecar manifest.
    /// # Arguments
    /// * `c2pa_data` - A C2PA manifest store in JUMBF format.
    /// * `format` - The format of the stream.
    /// * `stream` - The stream to verify the store against.
    /// # Returns
    /// A [`Reader`] for the manifest store.
    /// # Errors
    /// This function returns an [`Error`] ef the c2pa_data is not valid, or severe errors occur in validation.
    /// You must check validation status for non-severe errors.
    #[deprecated(
        since = "0.79.4",
        note = "Use `Reader::from_context(context).with_manifest_data_and_stream(c2pa_data, format, stream)` instead, passing a `Context` explicitly rather than relying on thread-local settings. Will be removed in 0.92.0 (scheduled for mid-November 2026)."
    )]
    #[async_generic]
    pub fn from_manifest_data_and_stream(
        c2pa_data: &[u8],
        format: &str,
        stream: impl Read + Seek + MaybeSend,
    ) -> Result<Reader> {
        // Get thread-local settings (if any) for backward compatibility
        let settings = crate::settings::get_thread_local_settings();
        let context = Context::new().with_settings(settings).unwrap_or_default();
        if _sync {
            Reader::from_context(context).with_manifest_data_and_stream(c2pa_data, format, stream)
        } else {
            Reader::from_context(context)
                .with_manifest_data_and_stream_async(c2pa_data, format, stream)
                .await
        }
    }

    /// Add manifest store from an initial segment and a fragment stream to the [`Reader`].
    /// This would be used to load and validate fragmented MP4 files that span multiple separate asset files.
    /// # Arguments
    /// * `format` - The format of the stream.
    /// * `stream` - The initial segment stream.
    /// * `fragment` - The fragment stream.
    /// # Returns
    /// The updated [`Reader`] with the added manifest store.
    /// # Errors
    /// This function returns an [`Error`] if the streams are not valid, or severe errors occur in validation.
    /// You must check validation status for non-severe errors.
    #[async_generic]
    pub fn with_fragment(
        mut self,
        format: &str,
        mut stream: impl Read + Seek + MaybeSend,
        mut fragment: impl Read + Seek + MaybeSend,
    ) -> Result<Self> {
        let mut validation_log = StatusTracker::default();

        let store = if _sync {
            Store::load_fragment_from_stream(
                format,
                &mut stream,
                &mut fragment,
                &mut validation_log,
                &self.context,
            )
        } else {
            Store::load_fragment_from_stream_async(
                format,
                &mut stream,
                &mut fragment,
                &mut validation_log,
                &self.context,
            )
            .await
        }?;

        if _sync {
            self.with_store(store, &mut validation_log)
        } else {
            self.with_store_async(store, &mut validation_log).await
        }?;
        Ok(self)
    }

    /// Create a [`Reader`] from an initial segment and a fragment stream.
    /// This would be used to load and validate fragmented MP4 files that span multiple separate asset files.
    /// # Arguments
    /// * `format` - The format of the stream.
    /// * `stream` - The initial segment stream.
    /// * `fragment` - The fragment stream.
    /// # Returns
    /// A [`Reader`] for the manifest store.
    /// # Errors
    /// This function returns an [`Error`] if the streams are not valid, or severe errors occur in validation.
    /// You must check validation status for non-severe errors.
    #[async_generic]
    pub fn from_fragment(
        format: &str,
        stream: impl Read + Seek + MaybeSend,
        fragment: impl Read + Seek + MaybeSend,
    ) -> Result<Self> {
        if _sync {
            Reader::default().with_fragment(format, stream, fragment)
        } else {
            Reader::default()
                .with_fragment_async(format, stream, fragment)
                .await
        }
    }

    /// Add manifest store from an initial segment and fragments to the [`Reader`].
    /// This would be used to load and validate fragmented MP4 files that span
    /// multiple separate asset files.
    /// # Arguments
    /// * `path` - The path to the initial segment file.
    /// * `fragments` - A vector of paths to fragment files.
    /// # Returns
    /// The updated [`Reader`] with the added manifest store.
    /// # Errors
    /// Returns an [`Error`] when the manifest data cannot be read from the specified files.
    #[cfg(feature = "file_io")]
    pub fn with_fragmented_files<P: AsRef<std::path::Path>>(
        self,
        path: P,
        fragments: &[std::path::PathBuf],
    ) -> Result<Self> {
        let asset_type = self
            .context
            .io()
            .supported_extension(path.as_ref())
            .ok_or(crate::Error::UnsupportedType)?;
        let fragment_refs: Vec<OwnedAssetRef> = fragments
            .iter()
            .map(|p| OwnedAssetRef::Path(p.clone()))
            .collect();

        self.with_fragment_refs(&asset_type, AssetRef::Path(path.as_ref()), &fragment_refs)
    }

    /// Add a manifest store from a fragmented asset addressed by references, read
    /// through the [`Context`]'s asset transport.
    ///
    /// Available without `file_io`. Each reference resolves the way
    /// [`with_reference`](Self::with_reference) resolves one.
    ///
    /// # Arguments
    /// * `format` - MIME type or extension of the initialization segment. `None` falls
    ///   back to the transport's `format_hint()`.
    /// * `init_reference` - Reference to the initialization segment.
    /// * `fragment_references` - Fragment references, in order.
    ///
    /// # Errors
    /// Fragment verification hashes through a blocking transport, so an async-only
    /// [`Context`] returns [`AssetTransportError::NoSyncTransport`] from both this method
    /// and its async twin.
    #[async_generic]
    pub fn with_fragment_references(
        self,
        format: Option<&str>,
        init_reference: &str,
        fragment_references: &[String],
    ) -> Result<Self> {
        // Fragments verify through the sync transport. Resolve it before any bytes move,
        // so an async-only Context fails here rather than mid-verification.
        self.context.asset_transport()?;

        let init_request = AssetRequest::from_reference(init_reference);
        let fragment_refs: Vec<OwnedAssetRef> = fragment_references
            .iter()
            .map(|r| AssetRequest::from_reference(r).reference.into_owned())
            .collect();

        let asset_type = match format {
            Some(format) => format.to_owned(),
            None => {
                let resolved = if _sync {
                    self.open_asset(init_request)?
                } else {
                    self.open_asset_async(init_request).await?
                };
                resolved
                    .format_hint()
                    .ok_or(crate::Error::UnsupportedType)?
                    .to_owned()
            }
        };

        if _sync {
            self.with_fragment_refs(&asset_type, init_request.reference, &fragment_refs)
        } else {
            self.with_fragment_refs_async(&asset_type, init_request.reference, &fragment_refs)
                .await
        }
    }

    /// Shared body of [`with_fragmented_files`](Self::with_fragmented_files) and
    /// [`with_fragment_references`](Self::with_fragment_references).
    ///
    /// Neither is defined over the other: `PathBuf` to `&str` is lossy on a non-UTF-8
    /// path, and a `&str` is never an [`AssetRef::Path`].
    #[async_generic]
    fn with_fragment_refs(
        mut self,
        asset_type: &str,
        init_reference: AssetRef<'_>,
        fragments: &[OwnedAssetRef],
    ) -> Result<Self> {
        let mut validation_log = StatusTracker::default();

        self.context.check_progress(ProgressPhase::Reading, 1, 0)?;

        let init_request = AssetRequest::new(init_reference);
        let resolved = if _sync {
            self.open_asset(init_request)?
        } else {
            self.open_asset_async(init_request).await?
        };
        let mut init_segment = resolved.try_into_read_seek()?;
        // Enforce stream at position 0.
        init_segment.rewind()?;

        self.context.check_progress(ProgressPhase::Reading, 2, 0)?;

        let store = if _sync {
            Store::load_from_stream_and_fragment_refs(
                asset_type,
                &mut init_segment,
                fragments,
                &mut validation_log,
                &self.context,
            )
        } else {
            Store::load_from_stream_and_fragment_refs_async(
                asset_type,
                &mut init_segment,
                fragments,
                &mut validation_log,
                &self.context,
            )
            .await
        }?;

        if _sync {
            self.with_store(store, &mut validation_log)
        } else {
            self.with_store_async(store, &mut validation_log).await
        }?;
        Ok(self)
    }

    /// Loads a [`Reader`]` from an initial segment and fragments.  This
    /// would be used to load and validate fragmented MP4 files that span
    /// multiple separate asset files.
    #[cfg(feature = "file_io")]
    #[deprecated(
        since = "0.79.4",
        note = "Use `Reader::from_context(context).with_fragmented_files(path, fragments)` instead, passing a `Context` explicitly rather than relying on thread-local settings. Will be removed in 0.92.0 (scheduled for mid-November 2026)."
    )]
    pub fn from_fragmented_files<P: AsRef<std::path::Path>>(
        path: P,
        fragments: &[std::path::PathBuf],
    ) -> Result<Reader> {
        let settings = crate::settings::get_thread_local_settings();
        let context = Context::new().with_settings(settings)?;
        Reader::from_context(context).with_fragmented_files(path, fragments)
    }

    /// Returns a [Vec] of mime types that [c2pa-rs] is able to read.
    pub fn supported_mime_types() -> Vec<String> {
        Context::default().io().reader_mime_types()
    }

    /// replace assertion values in the reader json with the values from the assertion_values map
    /// # Arguments
    /// * `reader_json` - The reader json to update
    /// # Returns
    /// The updated reader json
    fn to_json_formatted(&self) -> Result<Value> {
        let mut json = serde_json::to_value(self).map_err(Error::JsonError)?;

        // If we ran post-validation, we need to update the assertion values in the report
        if !self.assertion_values.is_empty() {
            if let Some(manifests) = json.get_mut("manifests").and_then(|m| m.as_object_mut()) {
                for (manifest_label, manifest) in manifests.iter_mut() {
                    // Get assertions array once instead of multiple lookups
                    if let Some(assertions) = manifest
                        .get_mut("assertions")
                        .and_then(|a| a.as_array_mut())
                    {
                        for assertion in assertions.iter_mut() {
                            // Get label once and reuse
                            if let Some(label) = assertion.get("label").and_then(|l| l.as_str()) {
                                let uri =
                                    crate::jumbf::labels::to_assertion_uri(manifest_label, label);
                                if let Some(value) = self.assertion_values.get(&uri) {
                                    // Only create new string if we need to insert
                                    if let Some(assertion_mut) = assertion.as_object_mut() {
                                        assertion_mut.insert("data".to_string(), value.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // Convert hash values to base64 strings
        Ok(hash_to_b64(json))
    }

    /// Convert the reader to a JSON value with detailed formatting.
    /// This view more closely resembles the original JUMBF manifest store.
    fn to_json_detailed_formatted(&self) -> Result<Value> {
        let report = match self.validation_results() {
            Some(results) => ManifestStoreReport::from_store_with_results(&self.store, results),
            None => ManifestStoreReport::from_store(&self.store),
        }?;

        let mut json = serde_json::to_value(report).map_err(Error::JsonError)?;

        // If we ran post-validation, we need to update the assertion values in the report
        if !self.assertion_values.is_empty() {
            if let Some(manifests) = json.get_mut("manifests").and_then(|m| m.as_object_mut()) {
                for (manifest_label, manifest) in manifests.iter_mut() {
                    if let Some(assertions) = manifest
                        .get_mut("assertion_store")
                        .and_then(|a| a.as_object_mut())
                    {
                        for (label, assertion) in assertions.iter_mut() {
                            let uri = crate::jumbf::labels::to_assertion_uri(manifest_label, label);
                            if let Some(value) = self.assertion_values.get(&uri) {
                                *assertion = value.clone();
                            }
                        }
                    }
                }
            }
        }
        // Convert hash values to base64 strings
        json = hash_to_b64(json);
        Ok(json)
    }

    /// Get the Reader as a JSON string
    /// This just calls to_json_formatted
    pub fn json(&self) -> String {
        self.json_checked().unwrap_or_else(|_| "{}".to_string())
    }

    /// Get the manifest store as a crJSON [`Value`](serde_json::Value).
    ///
    /// crJSON is a standardized JSON format for C2PA manifest data.
    /// Returns an error if conversion fails.
    pub fn to_crjson_value(&self) -> Result<Value> {
        crate::crjson::from_reader(self)
    }

    /// Get the manifest store as a pretty-printed crJSON string.
    ///
    /// crJSON is a standardized JSON format for C2PA manifest data.
    /// Returns empty valid JSON `"{}"` if conversion or formatting fails.
    pub fn crjson(&self) -> String {
        self.crjson_checked().unwrap_or_else(|_| "{}".to_string())
    }

    /// Get the manifest store as a pretty-printed crJSON string, returning an error if it fails.
    ///
    /// crJSON is a standardized JSON format for C2PA manifest data.
    pub fn crjson_checked(&self) -> Result<String> {
        self.to_crjson_value()
            .and_then(|v| serde_json::to_string_pretty(&v).map_err(Error::JsonError))
    }

    /// Get the Reader as a JSON string, returning an error if formatting fails
    ///
    /// This is useful when you need to handle errors from deeply nested or malformed structures.
    /// For a version that never fails, use [`Self::json()`].
    pub fn json_checked(&self) -> Result<String> {
        let value = self.to_json_formatted()?;
        serde_json::to_string_pretty(&value).map_err(Error::JsonError)
    }

    /// Get the Reader as a detailed JSON string
    /// This just calls to_json_detailed_formatted
    pub fn detailed_json(&self) -> String {
        self.detailed_json_checked()
            .unwrap_or_else(|_| "{}".to_string())
    }

    /// Get the Reader as a detailed JSON string, returning an error if formatting fails
    ///
    /// This is useful when you need to handle errors from deeply nested or malformed structures.
    /// For a version that never fails, use [`Self::detailed_json()`].
    pub fn detailed_json_checked(&self) -> Result<String> {
        let value = self.to_json_detailed_formatted()?;
        serde_json::to_string_pretty(&value).map_err(Error::JsonError)
    }

    /// Returns the remote url of the manifest if this [`Reader`] obtained the manifest remotely.
    pub fn remote_url(&self) -> Option<&str> {
        self.store.remote_url()
    }

    /// Returns if the [`Reader`] was created from an embedded manifest.
    pub fn is_embedded(&self) -> bool {
        self.store.is_embedded()
    }

    /// Get the [`ValidationStatus`] array of the manifest store if it exists.
    /// Call this method to check for validation errors.
    ///
    /// This validation report only includes error statuses applied to the active manifest
    /// and error statuses for ingredients that are not already reported by the ingredient status.
    /// Use the [`ValidationStatus`] `url` method to identify the associated manifest; this can be useful when a validation error does not refer to the active manifest.
    /// # Example
    /// ```no_run
    /// use c2pa::Reader;
    /// let stream = std::io::Cursor::new(include_bytes!("../tests/fixtures/CA.jpg"));
    /// let reader = Reader::from_stream("image/jpeg", stream).unwrap();
    /// let status = reader.validation_status();
    /// ```
    pub fn validation_status(&self) -> Option<&[ValidationStatus]> {
        self.validation_status.as_deref()
    }

    /// Get the [`ValidationResults`] map of an asset if it exists.
    ///
    /// Call this method to check for detailed validation results.
    /// The validation_state method should be used to determine the overall validation state.
    ///
    /// The results are divided between the active manifest and ingredient deltas.
    /// The deltas will only exist if there are validation errors not already reported in ingredients
    /// It is normal for there to be many success and information statuses.
    /// Any errors will be reported in the failure array.
    ///
    /// # Example
    /// ```no_run
    /// use c2pa::Reader;
    /// let stream = std::io::Cursor::new(include_bytes!("../tests/fixtures/CA.jpg"));
    /// let reader = Reader::from_stream("image/jpeg", stream).unwrap();
    /// let status = reader.validation_results();
    /// ```
    pub fn validation_results(&self) -> Option<&ValidationResults> {
        self.validation_results.as_ref()
    }

    /// Get the [`ValidationState`] of the manifest store.
    pub fn validation_state(&self) -> ValidationState {
        if let Some(validation_results) = self.validation_results() {
            return validation_results.validation_state();
        }

        let verify_trust = self.context.settings().verify.verify_trust;
        match self.validation_status() {
            Some(status) => {
                // if there are any errors, the state is invalid unless the only error is an untrusted credential
                let errs = status
                    .iter()
                    .any(|s| s.code() != crate::validation_status::SIGNING_CREDENTIAL_UNTRUSTED);
                if errs {
                    ValidationState::Invalid
                } else if verify_trust {
                    // If we verified trust and didn't get an error, we can assume it is trusted
                    ValidationState::Trusted
                } else {
                    ValidationState::Valid
                }
            }
            None => {
                if verify_trust {
                    // if we are verifying trust, and there is no validation status, we can assume it is trusted
                    ValidationState::Trusted
                } else {
                    ValidationState::Valid
                }
            }
        }
    }

    /// Return the active [`Manifest`], or `None` if there's no active manifest.
    pub fn active_manifest(&self) -> Option<&Manifest> {
        if let Some(label) = self.active_manifest.as_ref() {
            self.manifests.get(label)
        } else {
            None
        }
    }

    /// Return the active [`Manifest`], or `None` if there's no active manifest.
    pub fn active_label(&self) -> Option<&str> {
        self.active_manifest.as_deref()
    }

    /// Returns an iterator over a collection of [`Manifest`] structs.
    pub fn iter_manifests(&self) -> impl Iterator<Item = &Manifest> + '_ {
        self.manifests.values()
    }

    /// Returns a reference to the [`Manifest`] collection.
    pub fn manifests(&self) -> &HashMap<String, Manifest> {
        &self.manifests
    }

    /// Given a label, return the associated [`Manifest`], if it exists.
    /// # Arguments
    /// * `label` - The label of the requested [`Manifest`].
    pub fn get_manifest(&self, label: &str) -> Option<&Manifest> {
        self.manifests.get(label)
    }

    /// Write a resource identified by URI to the given stream.
    /// Use this function, for example, to get a thumbnail or icon image and write it to a stream.
    /// # Arguments
    /// * `uri` - The URI of the resource to write (from an identifier field).
    /// * `stream` - The stream to write to.
    /// # Returns
    /// The number of bytes written.
    /// # Errors
    /// Returns [`Error`] if the resource does not exist.
    /// # Example
    /// ```no_run
    /// use std::io::Cursor;
    ///
    /// use c2pa::{Context, Reader};
    /// // Create a Reader from an in-memory stream (placeholder bytes shown here).
    /// let input = Cursor::new(Vec::new());
    /// let reader = Reader::default().with_stream("image/jpeg", input).unwrap();
    ///
    /// // Get a resource identifier from the active manifest (e.g., a thumbnail).
    /// let manifest = reader.active_manifest().unwrap();
    /// let uri = &manifest.thumbnail_ref().unwrap().identifier;
    ///
    /// // Write that resource to an output stream.
    /// let out = Cursor::new(Vec::new());
    /// let bytes_written = reader.resource_to_stream(uri, out).unwrap();
    /// ```
    pub fn resource_to_stream(
        &self,
        uri: &str,
        mut stream: impl Write + Read + Seek + MaybeSend,
    ) -> Result<usize> {
        let explicit_label = manifest_label_from_uri(uri);
        let label = explicit_label
            .clone()
            .or_else(|| self.active_label().map(str::to_owned))
            .unwrap_or_default();
        let relative_uri = to_relative_uri(uri);
        let absolute_uri = to_absolute_uri(&label, uri);

        // Search the referenced manifest's own resource store, then each of its
        // ingredients' resource stores. Each store is resolver-backed, so this also
        // covers assertions/databoxes and lazily-materialized ingredient data — not
        // just resources that were added under an arbitrary identifier.
        if let Some(manifest) = self.manifests.get(&label) {
            for resources in std::iter::once(manifest.resources())
                .chain(manifest.ingredients().iter().map(Ingredient::resources))
            {
                for candidate in [relative_uri.as_str(), absolute_uri.as_str()] {
                    if resources.exists(candidate) {
                        return resources
                            .write_stream(candidate, &mut stream)
                            .map(|len| len as usize);
                    }
                }
            }
        }

        // The uri may itself name a manifest — either an explicit JUMBF manifest
        // reference, or the bare claim label of a manifest/ingredient — in which case
        // we stream that manifest's flattened JUMBF bytes.
        let manifest_label = explicit_label.unwrap_or_else(|| uri.to_owned());
        self.store
            .get_claim(&manifest_label)
            .ok_or_else(|| Error::ResourceNotFound(uri.to_owned()))
            .and_then(|claim| Store::build_flat_ingredient_store(&self.store, claim))
            .and_then(|s| s.to_jumbf_internal(0))
            .and_then(|bytes| {
                let len = bytes.len();
                stream.write_all(&bytes).map_err(Error::IoError)?;
                Ok(len)
            })
    }

    /// Write all resources to a folder.
    ///
    ///
    /// This function writes all resources to a folder.
    /// Resources are stored in sub-folders corresponding to manifest label.
    /// Conversions ensure the file paths are valid.
    ///
    /// # Arguments
    /// * `path` - The path to the folder to write to.
    /// # Errors
    /// Returns an [`Error`] if the resources cannot be written to the folder.
    /// # Example
    /// ```no_run
    /// use c2pa::Reader;
    /// let reader = Reader::from_file("path/to/file.jpg").unwrap();
    /// reader.to_folder("path/to/folder").unwrap();
    /// ```
    #[cfg(feature = "file_io")]
    pub fn to_folder<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        use crate::jumbf::labels::to_assertion_uri;

        std::fs::create_dir_all(&path)?;
        std::fs::write(path.as_ref().join("manifest_store.json"), self.json())?;
        let c2pa_data = self.store.to_jumbf_internal(0)?;
        std::fs::write(path.as_ref().join("manifest_data.c2pa"), c2pa_data)?;

        let write_bytes = |rel_path: std::path::PathBuf, data: &[u8]| -> Result<()> {
            let file_path = path.as_ref().join(rel_path);
            if let Some(parent) = file_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(file_path, data).map_err(Error::IoError)
        };

        for claim in self.store.claims() {
            let claim_label = claim.label();
            // Write binary (media) assertions — thumbnails, icons, embedded data
            for ca in claim.claim_assertion_store() {
                let assertion = ca.assertion();
                if !matches!(
                    assertion.content_type(),
                    "application/cbor" | "application/json" | "application/c2pa"
                ) {
                    let uri = to_assertion_uri(claim_label, &ca.label());
                    if let Some(a) = self.store.get_assertion_from_uri(&uri) {
                        write_bytes(uri_to_path(&uri, Some(claim_label))?, a.data())?;
                    }
                }
            }
            // Write databoxes
            for (hr, databox) in claim.databoxes() {
                write_bytes(uri_to_path(&hr.url(), Some(claim_label))?, &databox.data)?;
            }
        }
        Ok(())
    }

    #[async_generic()]
    pub(crate) fn with_store(
        &mut self,
        store: Store,
        validation_log: &mut StatusTracker,
    ) -> Result<&Self> {
        let active_manifest = store.provenance_label();
        let arc_store = Arc::new(store);
        let mut manifests = HashMap::new();
        let mut options = StoreOptions::default();

        for claim in arc_store.claims() {
            let manifest_label = claim.label();
            let result = if _sync {
                Manifest::from_store(
                    arc_store.as_ref(),
                    manifest_label,
                    &mut options,
                    validation_log,
                    &self.context,
                )
            } else {
                Manifest::from_store_async(
                    arc_store.as_ref(),
                    manifest_label,
                    &mut options,
                    validation_log,
                    &self.context,
                )
                .await
            };

            match result {
                Ok(mut manifest) => {
                    // Wire up the store resolver so manifest resources (e.g. claim
                    // thumbnails stored as JUMBF URIs) can be resolved lazily.
                    manifest.set_store_resolver(Arc::clone(&arc_store));
                    for ingredient in manifest.ingredients_mut() {
                        // Wire up the store resolver so ingredient resources can be
                        // resolved on demand from claims without eager byte copies.
                        // This also sets the deferred manifest_data ref when needed.
                        ingredient.set_store_resolver(Arc::clone(&arc_store));
                    }
                    manifests.insert(manifest_label.to_owned(), manifest);
                }
                Err(e) => {
                    let uri = crate::jumbf::labels::to_manifest_uri(manifest_label);
                    let code = ValidationStatus::code_from_error(&e);
                    log_item!(uri.clone(), "Failed to load manifest", "Reader::from_store")
                        .validation_status(code)
                        .failure(validation_log, Error::C2PAValidation(e.to_string()))?;
                }
            };
        }

        let validation_results = ValidationResults::from_store(arc_store.as_ref(), validation_log);

        // Report assertions the claim references but that aren't present, excluding any
        // that were redacted: a redacted assertion is expected to be absent (removed) or
        // zeroed, so it must not be reported as `assertion.missing`. Whether a redacted
        // box is validly zeroed or forged with non-zero content is `Store::verify_store`'s
        // concern (it raises `assertion.notRedacted`); here we only resolve missing vs. redacted.
        let mut missing = options.missing_assertions.clone();
        missing.retain(|item| !options.redacted_assertions.contains(item));

        for uri in &missing {
            log_item!(uri.clone(), "assertion missing", "Reader::from_store")
                .validation_status(ASSERTION_MISSING)
                .informational(validation_log);
        }

        let validation_state = validation_results.validation_state();

        self.active_manifest = active_manifest;
        self.manifests = manifests;
        self.validation_status = validation_results.validation_errors();
        self.validation_results = Some(validation_results);
        self.validation_state = Some(validation_state);
        self.store = arc_store;
        Ok(self)
    }

    /// Post-validate the reader. This function is called after the reader is created.
    #[async_generic(async_signature(
        &mut self,
        validator: &impl AsyncPostValidator
    ))]
    pub fn post_validate(&mut self, validator: &impl PostValidator) -> Result<()> {
        let mut validation_log = StatusTracker::default();
        let mut validation_results = self.validation_results.take().unwrap_or_default();
        let mut assertion_values = HashMap::new();
        if let Some(active_label) = self.active_label() {
            let values = if _sync {
                self.walk_manifest(active_label, validator, &mut validation_log)
            } else {
                self.walk_manifest_async(active_label, validator, &mut validation_log)
                    .await
            }?;
            assertion_values.extend(values);
            for log in validation_log.logged_items() {
                if let Some(status) = ValidationStatus::from_log_item(log) {
                    validation_results.add_status(status);
                } else {
                    eprintln!("Failed to create status from log item: {log:?}");
                }
            }
        }
        self.validation_results = Some(validation_results);
        self.assertion_values.extend(assertion_values);
        Ok(())
    }

    #[async_generic(async_signature(
        &self,
        manifest_label: &str,
        validator: &impl AsyncPostValidator,
        validation_log: &mut StatusTracker
    ))]
    fn walk_manifest(
        &self,
        manifest_label: &str,
        validator: &impl PostValidator,
        validation_log: &mut StatusTracker,
    ) -> Result<HashMap<String, Value>> {
        let mut assertion_values = HashMap::new();
        let mut stack: Vec<(String, Option<String>)> = vec![(manifest_label.to_string(), None)];
        let mut seen = HashSet::new();

        while let Some((current_label, parent_uri)) = stack.pop() {
            seen.insert(current_label.clone());

            // If we're processing an ingredient, push its URI to the validation log
            if let Some(uri) = &parent_uri {
                validation_log.push_ingredient_uri(uri.clone());
            }

            let manifest = match self.get_manifest(&current_label) {
                Some(m) => m,
                None => {
                    // skip this manifest if not found
                    continue;
                }
            };

            let mut partial_claim = crate::dynamic_assertion::PartialClaim::default();
            {
                if let Some(claim) = self.store.get_claim(&current_label) {
                    for assertion in claim.assertions() {
                        partial_claim.add_assertion(assertion);
                    }
                }
            }

            // Process assertions for current manifest
            for assertion in manifest.assertions().iter() {
                let assertion_uri =
                    crate::jumbf::labels::to_assertion_uri(&current_label, assertion.label());
                let result = if _sync {
                    validator.validate(
                        assertion.label(),
                        assertion,
                        &assertion_uri,
                        &partial_claim,
                        validation_log,
                    )
                } else {
                    validator
                        .validate(
                            assertion.label(),
                            assertion,
                            &assertion_uri,
                            &partial_claim,
                            validation_log,
                        )
                        .await
                }?;
                if let Some(value) = result {
                    assertion_values.insert(assertion_uri, value);
                }
            }

            // Add ingredients to stack for processing
            for ingredient in manifest.ingredients().iter() {
                if let Some(label) = ingredient.active_manifest() {
                    if !seen.contains(label) {
                        let ingredient_uri = crate::jumbf::labels::to_assertion_uri(
                            &current_label,
                            ingredient.label().unwrap_or("unknown"),
                        );
                        stack.push((label.to_string(), Some(ingredient_uri)));
                    }
                }
            }

            // If we're processing an ingredient, pop its URI from the validation log
            if parent_uri.is_some() {
                validation_log.pop_ingredient_uri();
            }
        }

        Ok(assertion_values)
    }

    /// Convert the Reader back into a Builder.
    /// This can be used to modify an existing manifest store.
    /// # Errors
    /// Returns an [`Error`] if there is no active manifest.
    pub fn into_builder(mut self) -> Result<crate::Builder> {
        // Preserve the Reader's context in the new Builder
        let context = self.context;
        let mut builder = crate::Builder::from_shared_context(&context);
        if let Some(label) = &self.active_manifest {
            if let Some(parts) = crate::jumbf::labels::manifest_label_to_parts(label) {
                builder.definition.vendor = parts.cgi.clone();
                if parts.is_v1 {
                    builder.definition.claim_version = Some(1);
                }
            }
            builder.definition.label = Some(label.to_string());
            if let Some(mut manifest) = self.manifests.remove(label) {
                builder.definition.claim_generator_info =
                    manifest.claim_generator_info.take().unwrap_or_default();
                builder.definition.format = manifest.format().unwrap_or_default().to_string();
                builder.definition.title = manifest.title().map(|s| s.to_owned());
                builder.definition.instance_id = manifest.instance_id().to_owned();
                builder.definition.thumbnail = manifest.thumbnail_ref().cloned();
                builder.definition.redactions = manifest.redactions.take();
                let ingredients = std::mem::take(&mut manifest.ingredients);
                for mut ingredient in ingredients {
                    ingredient.set_store_resolver(Arc::clone(&self.store));
                    builder.add_ingredient(ingredient);
                }
                for assertion in manifest.assertions.iter() {
                    // Archive bookkeeping, not part of the manifest being edited.
                    if assertion
                        .label()
                        .starts_with(crate::assertions::labels::ARCHIVE_METADATA)
                    {
                        continue;
                    }
                    // For archive roundtrip: keep created/gathered attribution and kind
                    let kind = match assertion.kind() {
                        ManifestAssertionKind::Json => Some(ManifestAssertionKind::Json),
                        _ => None,
                    };
                    builder.add_assertion_impl(
                        assertion.label(),
                        assertion.value()?,
                        kind,
                        assertion.created(),
                    )?;
                }
            }
        }
        Ok(builder)
    }

    /// Returns the archive kind from the active manifest's `org.contentauth.archive.metadata` assertion, when the archive was created by [`Builder::write_archive`].
    /// None if the assertion is missing or malformed.
    pub(crate) fn active_archive_kind(&self) -> Option<crate::builder::ArchiveKind> {
        let manifest = self.active_manifest()?;
        let metadata: Metadata = manifest
            .find_assertion(crate::assertions::labels::ARCHIVE_METADATA)
            .ok()?;
        crate::builder::ArchiveKind::from_metadata(&metadata)
    }

    /// Convert a Reader into an [`Ingredient`] using the parent ingredient from the active manifest.
    /// # Errors
    /// Returns an [`Error`] if there is no parent ingredient.
    pub(crate) fn to_ingredient(&self) -> Result<Ingredient> {
        let mut ingredient = self
            .active_manifest()
            .and_then(|m| m.ingredients().first())
            .ok_or_else(|| Error::IngredientNotFound)?
            .to_owned();

        // populate manifest_data on demand for ingredients with an active manifest
        ingredient.set_store_resolver(Arc::clone(&self.store));

        Ok(ingredient)
    }

    /// Reads an asset served by a non-blocking range transport.
    ///
    /// Discovery runs through the driver: the synchronous parser reads cached bytes,
    /// the driver fetches what it misses and runs it again. Verification then pulls the
    /// hashed ranges one hash buffer at a time, so peak memory is the buffer rather
    /// than the object.
    ///
    /// A handler that reads its input to end re-reads everything on each attempt, so
    /// driving it is quadratic for the same bytes. Those take the whole object instead,
    /// bounded by `max_whole_object`: above it this is an error, never a silent whole
    /// download.
    async fn with_driven_asset_async(
        mut self,
        path_fmt: &str,
        transport: &dyn crate::asset_transport::AsyncRangeTransport,
        config: crate::asset_transport::RangeConfig,
        reference: AssetRef<'_>,
    ) -> Result<Self> {
        let reference = reference.to_string();
        let verifying = self.context.settings().verify.verify_after_reading;

        if !supports_ranged_discovery(path_fmt) {
            // An asset that takes this rung on every read costs a full download each
            // time. Say so, or the cost is invisible to whoever tunes the knobs.
            log::debug!("range read took the whole object for {reference} ({path_fmt})");
            let mut file = read_whole_async(transport, &config, &reference).await?;
            let format = self.context.io().format_from_stream(path_fmt, &mut file);
            let mut validation_log = StatusTracker::default();
            let store =
                Store::from_stream_async(&format, &mut file, &mut validation_log, &self.context)
                    .await?;
            self.with_store_async(store, &mut validation_log).await?;
            return Ok(self);
        }

        // `load_jumbf_from_stream` touches no `StatusTracker`, so it is restartable by
        // construction and the "only side-effect-free work may be driven" rule is
        // structural here rather than a review criterion.
        let format = path_fmt.to_owned();
        let context = self.context.clone();
        let (manifest_bytes, report) = drive_async(transport, &config, &format, |stream| {
            Store::load_jumbf_from_stream(&format, stream, &context)
                .map(|(bytes, _)| bytes)
                .map_err(std::io::Error::other)
        })
        .await?;
        // Attempts, not wall time, are what a driven parse costs: a fast transport
        // hides a re-parse per miss.
        log::debug!(
            "drove {format} discovery in {} attempts, {} bytes fetched",
            report.attempts,
            report.bytes_fetched
        );

        // The tracker runs once, outside the driver, on the bytes it produced.
        let mut validation_log = StatusTracker::default();
        let store =
            Store::from_jumbf_with_context(&manifest_bytes, &mut validation_log, &self.context)?;

        if verifying {
            // The manifest range comes from a second driven walk. It is what
            // `get_store_validation_info` would compute from a seekable stream, which
            // it has no async twin to do here.
            let (locations, _) = drive_async(transport, &config, &format, |stream| {
                context
                    .io()
                    .object_locations(&format, stream)
                    .map_err(std::io::Error::other)
            })
            .await?;
            let manifest_range = locations
                .iter()
                .find(|o| o.htype == crate::asset_io::ObjectType::C2pa)
                .map(|o| crate::utils::hash_utils::HashRange::new(o.offset, o.length));

            let mut asset_data = crate::claim::ClaimAssetData::AsyncRanges {
                transport,
                config,
                format: &format,
                manifest_range,
            };
            Store::verify_store_async(
                &store,
                Some(&mut asset_data),
                &mut validation_log,
                &self.context,
            )
            .await?;
        }

        self.with_store_async(store, &mut validation_log).await?;
        Ok(self)
    }
}

/// Whether a format's handler can find its manifest by seeking, rather than by reading
/// the asset to end.
///
/// A handler that navigates (box headers, a central directory) discovers a manifest from
/// a few windows whatever the object's size, which is what ranges are for. A handler
/// whose `read_c2pa` consumes the stream re-reads everything on every driver attempt,
/// making discovery quadratic, so those take the whole-object rung instead.
///
/// The exclusions are `jpeg_io`, and `c2pa_io` for a bare manifest store read as the
/// primary asset. `zip_io` also reads to end, but only of the manifest entry it already
/// seeked to, so it stays on the ranged path.
fn supports_ranged_discovery(format: &str) -> bool {
    !matches!(
        format.rsplit('/').next().unwrap_or(format),
        "jpeg" | "jpg" | "c2pa" | "x-c2pa-manifest-store"
    )
}

/// The reference to request a sidecar manifest from.
///
/// A path gets the `.c2pa` sibling. Any other reference is returned unchanged: appending
/// `.c2pa` to something like `s3://bucket/key?signature=...` would address nothing, so the
/// transport derives its own sidecar instead.
fn sidecar_reference(reference: AssetRef<'_>) -> OwnedAssetRef {
    match reference {
        AssetRef::Path(p) => OwnedAssetRef::Path(p.with_extension("c2pa")),
        other => other.into_owned(),
    }
}

/// Convert the Reader to a JSON value.
impl TryFrom<Reader> for serde_json::Value {
    type Error = Error;

    fn try_from(reader: Reader) -> Result<Self> {
        reader.to_json_formatted()
    }
}
impl TryFrom<&Reader> for serde_json::Value {
    type Error = Error;

    fn try_from(reader: &Reader) -> Result<Self> {
        reader.to_json_formatted()
    }
}

/// Prints the JSON of the manifest data.
impl std::fmt::Display for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = self.json_checked().map_err(|_| std::fmt::Error)?;
        f.write_str(&json)
    }
}

/// Prints the full debug details of the manifest data.
impl std::fmt::Debug for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = self.detailed_json_checked().map_err(|_| std::fmt::Error)?;
        f.write_str(&json)
    }
}

impl TryInto<crate::Builder> for Reader {
    type Error = Error;

    fn try_into(self) -> Result<crate::Builder> {
        self.into_builder()
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]
    #![allow(deprecated)]
    use std::io::Cursor;

    use super::*;
    use crate::{
        assertions::DigitalSourceType,
        builder::BuilderIntent,
        utils::{test::test_context, test_signer::test_signer},
        Builder, SigningAlg,
    };

    const IMAGE_COMPLEX_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/CACAE-uri-CA.jpg");
    const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
    #[cfg(feature = "fetch_remote_manifests")]
    const IMAGE_WITH_REMOTE_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/cloud.jpg");
    const IMAGE_WITH_INGREDIENT_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/CACA.jpg");
    const SAMPLE1_HEIC: &[u8] = include_bytes!("../tests/fixtures/sample1.heic");

    // A handler whose `read_c2pa` consumes the stream must not be driven: the driver
    // restarts the parse on every miss, so it would re-read the object each time.
    // Wrongly reporting support is quadratic and silent, which is why both directions
    // are pinned here.
    #[test]
    fn only_navigating_handlers_support_ranged_discovery() {
        for format in [
            "image/jpeg",
            "jpeg",
            "jpg",
            "c2pa",
            "application/c2pa",
            "application/x-c2pa-manifest-store",
        ] {
            assert!(
                !supports_ranged_discovery(format),
                "{format} should not be driven"
            );
        }

        // Driven formats: discovery walks box headers, so ranges are the whole point.
        for format in ["video/mp4", "image/png", "application/pdf", "image/tiff"] {
            assert!(supports_ranged_discovery(format), "{format} should be driven");
        }
    }

    #[test]
    // Verify that we can convert a Reader back into a Builder re-sign and the read it back again
    fn test_into_builder() -> Result<()> {
        let context = test_context().into_shared();
        let mut source = Cursor::new(IMAGE_WITH_INGREDIENT_MANIFEST);
        let format = "image/jpeg";
        let reader = Reader::from_shared_context(&context).with_stream(format, &mut source)?;
        println!("{reader}");

        assert_eq!(reader.validation_state(), ValidationState::Trusted);
        let mut builder: crate::Builder = reader.try_into()?;
        println!("{builder}");

        source.set_position(0);
        let mut dest = Cursor::new(Vec::new());
        builder.save_to_stream(format, &mut source, &mut dest)?;

        dest.set_position(0);
        let reader2 = Reader::from_shared_context(&context).with_stream(format, &mut dest)?;
        println!("{reader2}");

        assert_eq!(reader2.validation_state(), ValidationState::Trusted);
        //std::fs::write("../target/CA-rebuilt.jpg", dest.get_ref())?;
        Ok(())
    }

    #[test]
    #[allow(deprecated)]
    fn test_detached_manifest_exclusion_hole_rejected() {
        use crate::{assertions::DataHash, Builder};

        // Sign a real asset (embedded); the attacker never holds this key.
        let victim_src = include_bytes!("../tests/fixtures/no_manifest.jpg");
        let signer = test_signer(SigningAlg::Ps256);
        let mut builder = Builder::from_context(test_context())
            .with_definition(r#"{"title": "victim"}"#)
            .unwrap();
        let mut source = Cursor::new(victim_src.to_vec());
        let mut dest = Cursor::new(Vec::new());
        builder
            .sign(signer.as_ref(), "image/jpeg", &mut source, &mut dest)
            .unwrap();
        let victim = dest.into_inner();

        // Attacker lifts the signed manifest store out, byte-verbatim, no re-signing.
        let context = test_context();
        let mut victim_stream = Cursor::new(victim.clone());
        let (jumbf, _remote) =
            crate::store::Store::load_jumbf_from_stream("image/jpeg", &mut victim_stream, &context)
                .unwrap();

        // Read the signed exclusion range straight off the claim.
        let store = crate::store::Store::from_stream(
            "image/jpeg",
            Cursor::new(victim.clone()),
            &mut StatusTracker::default(),
            &context,
        )
        .unwrap();
        let claim = store.provenance_claim().unwrap();
        let dh_assertion = claim
            .hash_assertions()
            .into_iter()
            .find(|a| a.label_raw().starts_with(DataHash::LABEL))
            .unwrap();
        let dh = DataHash::from_assertion(dh_assertion.assertion()).unwrap();
        let range = &dh.exclusions.unwrap()[0];
        let (excl_start, excl_len) = (range.start() as usize, range.length() as usize);

        // Overwrite exactly that range with unrelated content, keeping every byte
        // outside it untouched.
        let mut forged = victim.clone();
        for b in forged[excl_start..excl_start + excl_len].iter_mut() {
            *b = 0x41;
        }

        // Validate the forged pair through the detached-manifest path (c2patool
        // --external-manifest / a sidecar or remote manifest workflow).
        let result =
            Reader::from_manifest_data_and_stream(&jumbf, "image/jpeg", Cursor::new(forged));
        let state = result
            .map(|r| r.validation_state())
            .unwrap_or(ValidationState::Invalid);
        assert_ne!(
            state,
            ValidationState::Trusted,
            "a detached manifest's exclusion must not let unrelated content inside it pass validation"
        );
    }

    #[test]
    fn test_reader_embedded() -> Result<()> {
        let reader =
            Reader::default().with_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
        assert_eq!(reader.remote_url(), None);
        assert!(reader.is_embedded());

        Ok(())
    }

    #[test]
    fn test_reader_new_with_stream() -> Result<()> {
        let context = test_context();

        let mut source = Cursor::new(IMAGE_WITH_MANIFEST);

        let reader = Reader::from_context(context).with_stream("image/jpeg", &mut source)?;

        assert_eq!(reader.remote_url(), None);
        assert!(reader.is_embedded());
        assert_eq!(reader.validation_state(), ValidationState::Trusted);
        assert!(reader.active_manifest().is_some());

        Ok(())
    }

    #[test]
    #[cfg(feature = "fetch_remote_manifests")]
    fn test_reader_remote_url() -> Result<()> {
        let reader =
            Reader::default().with_stream("image/jpeg", Cursor::new(IMAGE_WITH_REMOTE_MANIFEST))?;
        let remote_url = reader.remote_url();
        assert_eq!(remote_url, Some("https://cai-manifests.adobe.com/manifests/adobe-urn-uuid-5f37e182-3687-462e-a7fb-573462780391"));
        assert!(!reader.is_embedded());

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_reader_from_file_no_manifest() -> Result<()> {
        let result = Reader::default().with_file("tests/fixtures/IMG_0003.jpg");
        assert!(matches!(result, Err(Error::JumbfNotFound)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_file_read_uses_transport() -> Result<()> {
        use crate::asset_transport::{
            AssetRequest, AssetTransportError, ResolvedAsset, SyncAssetTransport,
        };

        struct InMemorySource(Vec<u8>);
        impl SyncAssetTransport for InMemorySource {
            fn open(
                &self,
                _: AssetRequest<'_>,
            ) -> std::result::Result<ResolvedAsset, AssetTransportError> {
                Ok(ResolvedAsset::new(Cursor::new(self.0.clone())))
            }
        }

        let context =
            Context::new().with_asset_transport(InMemorySource(IMAGE_WITH_MANIFEST.to_vec()));

        let reader = Reader::from_context(context).with_file("no/such/file.jpg")?;
        assert!(reader.active_manifest().is_some());
        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_file_read_over_sync_ranges_matches_whole_object() -> Result<()> {
        // A synchronous range transport, wrapped in a `RangeStream`, is read by the
        // ordinary parse and reaches the same result as reading the whole object. This
        // proves discovery and hard-binding verification happen over ranges, not just
        // that a manifest was found.
        use crate::asset_transport::{
            AssetTransportError, ObjectVersion, RangeChunk, RangeInfo, SyncRangeAssetTransport,
            SyncRangeTransport,
        };

        struct InMemoryRanges(Vec<u8>);
        impl SyncRangeTransport for InMemoryRanges {
            fn info(&self) -> std::result::Result<RangeInfo, AssetTransportError> {
                Ok(RangeInfo::new(self.0.len() as u64))
            }

            fn read_range(
                &self,
                offset: u64,
                len: u64,
                _expect: Option<&ObjectVersion>,
            ) -> std::result::Result<RangeChunk, AssetTransportError> {
                let start = (offset as usize).min(self.0.len());
                let end = start.saturating_add(len as usize).min(self.0.len());
                Ok(RangeChunk::new(offset, self.0[start..end].to_vec()))
            }
        }

        // Whole-object read for the reference result.
        let whole = Reader::from_context(Context::new())
            .with_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;

        // Same bytes, served in ranges through a custom transport.
        let bytes = IMAGE_WITH_MANIFEST.to_vec();
        let context = Context::new().with_asset_transport(SyncRangeAssetTransport::new(move |_| {
            Ok(InMemoryRanges(bytes.clone()))
        }));
        let ranged = Reader::from_context(context).with_file("no/such/file.jpg")?;

        assert!(ranged.active_manifest().is_some());
        assert_eq!(
            ranged.validation_state(),
            whole.validation_state(),
            "ranged read disagreed with whole-object read: {:?}",
            ranged.validation_status()
        );
        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn a_small_hash_buffer_reaches_the_verifying_hasher() -> Result<()> {
        // `core.hash_buffer_size_in_kb` bounds the hasher's peak memory. The hasher
        // fires one `VerifyingAssetHash` tick per buffer, so the tick count is the only
        // in-process proof the setting travelled from `Settings` to the hash loop.
        use std::sync::{
            atomic::{AtomicU32, Ordering},
            Arc,
        };

        use crate::ProgressPhase;

        fn ticks_at(kb: usize) -> Result<u32> {
            let ticks = Arc::new(AtomicU32::new(0));
            let counter = ticks.clone();
            let context = Context::new()
                .with_settings(format!(
                    r#"{{"core": {{"hash_buffer_size_in_kb": {kb}}}}}"#
                ))?
                .with_progress_callback(move |phase, _step, _total| {
                    if phase == ProgressPhase::VerifyingAssetHash {
                        counter.fetch_add(1, Ordering::SeqCst);
                    }
                    true
                });

            Reader::from_context(context)
                .with_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
            Ok(ticks.load(Ordering::SeqCst))
        }

        // The binding hashes two ranges of `IMAGE_WITH_MANIFEST`, the larger about
        // 48 KiB, so the default gives one tick per range. A 16 KiB buffer splits the
        // larger range and ticks more often.
        let small = ticks_at(16)?;
        let default = ticks_at(256 * 1024)?;

        assert_eq!(default, 2, "one tick per hashed range at the default buffer");
        assert!(
            small > default,
            "a 16 KiB buffer should tick more often than the default: {small} vs {default}"
        );
        Ok(())
    }

    /// An async range transport with no blocking view, which the reader must drive.
    #[cfg(not(target_arch = "wasm32"))]
    struct InMemoryAsyncRanges {
        bytes: Vec<u8>,
        reads: std::sync::Arc<std::sync::atomic::AtomicU64>,
        /// Largest `len` any single request asked for. A chunked hash keeps this at or
        /// below the hash buffer, which is the only in-process proof of the bound.
        max_len: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl InMemoryAsyncRanges {
        fn new(bytes: Vec<u8>) -> (Self, InMemoryAsyncRangesStats) {
            let stats = InMemoryAsyncRangesStats {
                reads: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                max_len: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            };
            (
                Self {
                    bytes,
                    reads: stats.reads.clone(),
                    max_len: stats.max_len.clone(),
                },
                stats,
            )
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[derive(Clone)]
    struct InMemoryAsyncRangesStats {
        reads: std::sync::Arc<std::sync::atomic::AtomicU64>,
        max_len: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[async_trait::async_trait]
    impl crate::asset_transport::AsyncRangeTransport for InMemoryAsyncRanges {
        async fn info_async(
            &self,
        ) -> std::result::Result<crate::asset_transport::RangeInfo, AssetTransportError> {
            Ok(crate::asset_transport::RangeInfo::new(self.bytes.len() as u64))
        }

        async fn read_range_async(
            &self,
            offset: u64,
            len: u64,
            _expect: Option<&crate::asset_transport::ObjectVersion>,
        ) -> std::result::Result<crate::asset_transport::RangeChunk, AssetTransportError> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.max_len
                .fetch_max(len, std::sync::atomic::Ordering::SeqCst);
            let start = (offset as usize).min(self.bytes.len());
            let end = start.saturating_add(len as usize).min(self.bytes.len());
            Ok(crate::asset_transport::RangeChunk::new(
                offset,
                self.bytes[start..end].to_vec(),
            ))
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn async_ranges_are_driven_and_match_the_whole_object() -> Result<()> {
        // The async counterpart of the sync range test: the transport cannot block, so
        // the reader drives the parse over it. Before the driver this returned
        // `AsyncOnlyAsset`, which is what the c2pa-js `discover` and `verify-async`
        // modes hit.
        use crate::asset_transport::{AsyncRangeAssetTransport, RangeConfig};

        let whole = Reader::from_context(Context::new())
            .with_stream_async("image/jpeg", &mut Cursor::new(IMAGE_WITH_MANIFEST))
            .await?;

        let reads = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let bytes = IMAGE_WITH_MANIFEST.to_vec();
        let counter = reads.clone();
        // JPEG takes the whole-object rung, so the cap has to admit this object.
        let config = RangeConfig::default()
            .with_max_whole_object(Some(10 * 1024 * 1024));
        let context = Context::new().with_asset_transport_async(
            AsyncRangeAssetTransport::new(move |_| {
                Ok(InMemoryAsyncRanges {
                    bytes: bytes.clone(),
                    reads: counter.clone(),
                    max_len: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                })
            })
            .with_config(config),
        );

        let ranged = Reader::from_context(context)
            .with_asset_async(AssetRef::Uri("https://example.test/a.jpg"), Some("image/jpeg"))
            .await?;

        assert!(ranged.active_manifest().is_some());
        assert_eq!(
            ranged.validation_state(),
            whole.validation_state(),
            "driven async read disagreed with whole-object read: {:?}",
            ranged.validation_status()
        );
        assert!(
            reads.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "the transport was never read"
        );
        Ok(())
    }

    /// Discovery reads the manifest without checking the binding, so tampered bytes
    /// must not produce a data-hash failure. That is what separates `discover` from
    /// `verify-async`. A discovery path that verified anyway would make them identical.
    ///
    /// The assertion is on failure codes, not `validation_state`. With
    /// `verify_after_reading` off nothing populates `ValidationResults`, and
    /// `validation_state()` reports `Invalid` for an empty result set on every read
    /// path, ranges or not. That is pre-existing and not what this test is about.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn async_discovery_does_not_check_the_binding() -> Result<()> {
        use crate::asset_transport::{AsyncRangeAssetTransport, RangeConfig};

        let mut tampered = IMAGE_WITH_MANIFEST.to_vec();
        let last = tampered.len() - 64;
        tampered[last] ^= 0xff;

        let reads = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counter = reads.clone();
        let context = Context::new()
            .with_settings(r#"{"verify": {"verify_after_reading": false}}"#)?
            .with_asset_transport_async(
                AsyncRangeAssetTransport::new(move |_| {
                    Ok(InMemoryAsyncRanges {
                        bytes: tampered.clone(),
                        reads: counter.clone(),
                        max_len: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    })
                })
                .with_config(RangeConfig::default()),
            );

        let reader = Reader::from_context(context)
            .with_asset_async(AssetRef::Uri("https://example.test/d.jpg"), Some("image/jpeg"))
            .await?;

        assert!(reader.active_manifest().is_some());
        let codes: Vec<&str> = reader
            .validation_status()
            .unwrap_or_default()
            .iter()
            .map(|s| s.code())
            .collect();
        assert!(
            !codes.contains(&"assertion.dataHash.mismatch"),
            "discovery checked the binding: it must not. codes={codes:?}"
        );
        Ok(())
    }

    /// Verification over async ranges pulls one hash buffer at a time, so a 642 MB
    /// object costs the buffer rather than the object. `video1.mp4` carries a
    /// file-level BMFF hash and its handler navigates, so this is the driven path
    /// end to end: discovery, the exclusion walk, and the chunked hash.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn async_ranges_verify_bmff_in_chunks() -> Result<()> {
        use crate::asset_transport::{AsyncRangeAssetTransport, RangeConfig};

        let bytes = std::fs::read("tests/fixtures/video1.mp4")?;
        let whole = Reader::from_context(Context::new())
            .with_stream_async("video/mp4", &mut Cursor::new(bytes.clone()))
            .await?;

        // 64 KiB buffer against an 809 KB asset, so the hash runs in many chunks.
        let hash_buf_kb = 64usize;
        let (_, stats) = InMemoryAsyncRanges::new(Vec::new());
        let served = stats.clone();
        let source = std::sync::Arc::new(bytes);
        let context = Context::new()
            .with_settings(format!(
                r#"{{"core": {{"hash_buffer_size_in_kb": {hash_buf_kb}}}}}"#
            ))?
            .with_asset_transport_async(
                AsyncRangeAssetTransport::new(move |_| {
                    Ok(InMemoryAsyncRanges {
                        bytes: source.as_ref().clone(),
                        reads: served.reads.clone(),
                        max_len: served.max_len.clone(),
                    })
                })
                // No whole-object rung, so a fallback would fail rather than hide the
                // chunked path.
                .with_config(RangeConfig::default().with_max_whole_object(None)),
            );

        let ranged = Reader::from_context(context)
            .with_asset_async(AssetRef::Uri("https://example.test/v.mp4"), Some("video/mp4"))
            .await?;

        assert!(ranged.active_manifest().is_some());
        assert_eq!(
            ranged.validation_state(),
            whole.validation_state(),
            "chunked async verification disagreed with the whole-object read: {:?}",
            ranged.validation_status()
        );

        let reads = stats.reads.load(std::sync::atomic::Ordering::SeqCst);
        assert!(reads > 1, "the asset was read in one request, not chunked");
        let max_len = stats.max_len.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            max_len <= (hash_buf_kb * 1024) as u64,
            "a single request asked for {max_len} bytes, above the {hash_buf_kb} KiB buffer"
        );
        Ok(())
    }

    /// The chunked BMFF path must reject a corrupted byte the file-level hash covers.
    /// Without this, `async_ranges_verify_bmff_in_chunks` would pass against a hash
    /// that checked nothing.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn async_ranges_reject_tampered_bmff() -> Result<()> {
        use crate::asset_transport::{AsyncRangeAssetTransport, RangeConfig};

        let mut bytes = std::fs::read("tests/fixtures/video1.mp4")?;
        let last = bytes.len() - 64;
        bytes[last] ^= 0xff;

        let (_, stats) = InMemoryAsyncRanges::new(Vec::new());
        let served = stats.clone();
        let source = std::sync::Arc::new(bytes);
        let context = Context::new().with_asset_transport_async(
            AsyncRangeAssetTransport::new(move |_| {
                Ok(InMemoryAsyncRanges {
                    bytes: source.as_ref().clone(),
                    reads: served.reads.clone(),
                    max_len: served.max_len.clone(),
                })
            })
            .with_config(RangeConfig::default().with_max_whole_object(None)),
        );

        let reader = Reader::from_context(context)
            .with_asset_async(AssetRef::Uri("https://example.test/t.mp4"), Some("video/mp4"))
            .await?;

        assert_eq!(
            reader.validation_state(),
            ValidationState::Invalid,
            "tampered BMFF bytes passed chunked verification"
        );
        let codes: Vec<&str> = reader
            .validation_status()
            .unwrap_or_default()
            .iter()
            .map(|s| s.code())
            .collect();
        assert!(
            codes.contains(&"assertion.bmffHash.mismatch"),
            "expected a BMFF hash mismatch, got {codes:?}"
        );
        Ok(())
    }

    /// The decisive test for verified async ranges: a transport that always succeeds
    /// passes every other check. Corrupting a byte the manifest covers must be
    /// rejected, or the binding is not being checked at all.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn async_ranges_reject_tampered_bytes() -> Result<()> {
        use crate::asset_transport::{AsyncRangeAssetTransport, RangeConfig};

        let mut tampered = IMAGE_WITH_MANIFEST.to_vec();
        // Well past the manifest, inside the hashed image data.
        let last = tampered.len() - 64;
        tampered[last] ^= 0xff;

        let reads = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counter = reads.clone();
        let context = Context::new().with_asset_transport_async(
            AsyncRangeAssetTransport::new(move |_| {
                Ok(InMemoryAsyncRanges {
                    bytes: tampered.clone(),
                    reads: counter.clone(),
                    max_len: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
                })
            })
            .with_config(RangeConfig::default()),
        );

        let reader = Reader::from_context(context)
            .with_asset_async(AssetRef::Uri("https://example.test/t.jpg"), Some("image/jpeg"))
            .await?;

        assert_eq!(
            reader.validation_state(),
            ValidationState::Invalid,
            "tampered bytes passed verification over async ranges"
        );
        let codes: Vec<&str> = reader
            .validation_status()
            .unwrap_or_default()
            .iter()
            .map(|s| s.code())
            .collect();
        assert!(
            codes.contains(&"assertion.dataHash.mismatch"),
            "expected a data-hash mismatch, got {codes:?}"
        );
        Ok(())
    }

    #[test]
    fn with_reference_reaches_a_transport_without_file_io() -> Result<()> {
        // A registered transport is reachable in a build with no `file_io`. Runs in
        // every feature configuration. Without `file_io` this is the only path to it.
        use crate::asset_transport::{
            AssetRequest, AssetTransportError, ResolvedAsset, SyncAssetTransport,
        };

        struct InMemory(Vec<u8>);
        impl SyncAssetTransport for InMemory {
            fn open(
                &self,
                _: AssetRequest<'_>,
            ) -> std::result::Result<ResolvedAsset, AssetTransportError> {
                Ok(ResolvedAsset::new(Cursor::new(self.0.clone())))
            }
        }

        let bytes = IMAGE_WITH_MANIFEST.to_vec();
        let context = Context::new().with_asset_transport(InMemory(bytes));
        let reader =
            Reader::from_context(context).with_reference(Some("image/jpeg"), "mem://asset.jpg")?;

        assert!(reader.active_manifest().is_some());
        Ok(())
    }

    #[test]
    fn with_reference_keeps_the_sidecar_reference_verbatim() {
        // Appending `.c2pa` to an opaque reference would address nothing, so the same
        // reference goes out with `kind = Sidecar` and the transport decides.
        use std::sync::{Arc, Mutex};

        use crate::asset_transport::{
            AssetRequest, AssetRequestKind, AssetTransportError, OwnedAssetRef, ResolvedAsset,
            SyncAssetTransport,
        };

        const NO_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/no_manifest.jpg");

        struct Recorder(Arc<Mutex<Vec<(OwnedAssetRef, AssetRequestKind)>>>);
        impl SyncAssetTransport for Recorder {
            fn open(
                &self,
                request: AssetRequest<'_>,
            ) -> std::result::Result<ResolvedAsset, AssetTransportError> {
                self.0
                    .lock()
                    .unwrap()
                    .push((request.reference.into_owned(), request.kind));
                // A real JPEG carrying no manifest, so the reader falls through to the
                // sidecar request rather than failing on format.
                Ok(ResolvedAsset::new(Cursor::new(NO_MANIFEST.to_vec())))
            }
        }

        let seen = Arc::new(Mutex::new(Vec::new()));
        let context = Context::new().with_asset_transport(Recorder(Arc::clone(&seen)));
        let reference = "s3://bucket/key?signature=abc";
        let _ = Reader::from_context(context).with_reference(None, reference);

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "expected an asset then a sidecar request");
        assert_eq!(seen[0].1, AssetRequestKind::Asset);
        assert_eq!(seen[1].1, AssetRequestKind::Sidecar);
        assert_eq!(
            seen[1].0,
            OwnedAssetRef::Uri(reference.to_string()),
            "sidecar reference was rewritten"
        );
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn with_asset_path_sidecar_targets_the_c2pa_sibling() {
        // The path case keeps today's `with_file` behavior.
        use std::sync::{Arc, Mutex};

        use crate::asset_transport::{
            AssetRequest, AssetRequestKind, AssetTransportError, OwnedAssetRef, ResolvedAsset,
            SyncAssetTransport,
        };

        const NO_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/no_manifest.jpg");

        struct Recorder(Arc<Mutex<Vec<(OwnedAssetRef, AssetRequestKind)>>>);
        impl SyncAssetTransport for Recorder {
            fn open(
                &self,
                request: AssetRequest<'_>,
            ) -> std::result::Result<ResolvedAsset, AssetTransportError> {
                self.0
                    .lock()
                    .unwrap()
                    .push((request.reference.into_owned(), request.kind));
                Ok(ResolvedAsset::new(Cursor::new(NO_MANIFEST.to_vec())))
            }
        }

        let seen = Arc::new(Mutex::new(Vec::new()));
        let context = Context::new().with_asset_transport(Recorder(Arc::clone(&seen)));
        let path = std::path::Path::new("/assets/photo.jpg");
        let _ = Reader::from_context(context).with_asset(AssetRef::Path(path), None);

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[1].0,
            OwnedAssetRef::Path(std::path::PathBuf::from("/assets/photo.c2pa"))
        );
    }

    #[test]
    fn with_asset_uses_the_transport_format_hint() -> Result<()> {
        // No path extension and no explicit format: the transport's hint is the only
        // format source left. Regression guard for `with_asset`'s `unwrap_or_default()`.
        use crate::asset_transport::{
            AssetRequest, AssetTransportError, ResolvedAsset, SyncAssetTransport,
        };

        struct HintOnly(Vec<u8>);
        impl SyncAssetTransport for HintOnly {
            fn open(
                &self,
                _: AssetRequest<'_>,
            ) -> std::result::Result<ResolvedAsset, AssetTransportError> {
                Ok(ResolvedAsset::new(Cursor::new(self.0.clone()))
                    .with_format_hint("image/jpeg".to_string()))
            }
        }

        let bytes = IMAGE_WITH_MANIFEST.to_vec();
        let context = Context::new().with_asset_transport(HintOnly(bytes));
        let reader = Reader::from_context(context).with_reference(None, "mem://no-extension")?;

        assert!(reader.active_manifest().is_some());
        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_format_hint_from_transport() -> Result<()> {
        use crate::asset_transport::{
            AssetRequest, AssetTransportError, ResolvedAsset, SyncAssetTransport,
        };

        struct TypedSource(Vec<u8>);
        impl SyncAssetTransport for TypedSource {
            fn open(
                &self,
                _: AssetRequest<'_>,
            ) -> std::result::Result<ResolvedAsset, AssetTransportError> {
                Ok(ResolvedAsset::new(Cursor::new(self.0.clone()))
                    .with_format_hint("image/svg+xml"))
            }
        }

        let svg = include_bytes!("../tests/fixtures/sample1.svg").to_vec();
        let context = Context::new().with_asset_transport(TypedSource(svg));

        let err = Reader::from_context(context)
            .with_file("no/such/asset")
            .err();

        assert!(
            !matches!(err, Some(Error::UnsupportedType)),
            "format hint should have picked the format handler, got {err:?}"
        );
        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_sidecar_uses_same_transport() -> Result<()> {
        use crate::{
            asset_transport::{
                AssetRef, AssetRequest, AssetTransportError, ResolvedAsset, SyncAssetTransport,
            },
            builder::BuilderIntent,
            Builder,
        };

        let signing_context = test_context().into_shared();
        let mut unsigned = Cursor::new(include_bytes!("../tests/fixtures/earth_apollo17.jpg"));

        let mut builder = Builder::from_shared_context(&signing_context);
        builder.set_intent(BuilderIntent::Edit);
        builder.set_no_embed(true);
        let manifest_data = builder.sign(
            signing_context.signer()?,
            "image/jpeg",
            &mut unsigned,
            &mut std::io::empty(),
        )?;

        struct SidecarSource {
            asset: Vec<u8>,
            manifest: Vec<u8>,
        }
        impl SyncAssetTransport for SidecarSource {
            fn open(
                &self,
                request: AssetRequest<'_>,
            ) -> std::result::Result<ResolvedAsset, AssetTransportError> {
                let is_sidecar = match request.reference {
                    AssetRef::Path(p) => p.extension().is_some_and(|e| e == "c2pa"),
                    _ => false,
                };
                let bytes = if is_sidecar {
                    self.manifest.clone()
                } else {
                    self.asset.clone()
                };
                Ok(ResolvedAsset::new(Cursor::new(bytes)))
            }
        }

        let context = Context::new().with_asset_transport(SidecarSource {
            asset: include_bytes!("../tests/fixtures/earth_apollo17.jpg").to_vec(),
            manifest: manifest_data,
        });

        let reader = Reader::from_context(context).with_file("no/such/photo.jpg")?;
        assert!(reader.active_manifest().is_some());
        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_unreadable_sidecar_is_error() -> Result<()> {
        use crate::asset_transport::{
            AssetRef, AssetRequest, AssetTransportError, ResolvedAsset, SyncAssetTransport,
        };

        struct DeniedSidecarSource;
        impl SyncAssetTransport for DeniedSidecarSource {
            fn open(
                &self,
                request: AssetRequest<'_>,
            ) -> std::result::Result<ResolvedAsset, AssetTransportError> {
                match request.reference {
                    AssetRef::Path(p) if p.extension().is_some_and(|e| e == "c2pa") => {
                        Err(AssetTransportError::PermissionDenied {
                            reference: p.to_string_lossy().into_owned(),
                        })
                    }
                    // An asset with no embedded manifest, so the sidecar path is reached.
                    _ => Ok(ResolvedAsset::new(Cursor::new(
                        include_bytes!("../tests/fixtures/earth_apollo17.jpg").to_vec(),
                    ))),
                }
            }
        }

        let context = Context::new().with_asset_transport(DeniedSidecarSource);
        let result = Reader::from_context(context).with_file("no/such/photo.jpg");

        assert!(matches!(
            result,
            Err(Error::AssetTransport(
                AssetTransportError::PermissionDenied { .. }
            ))
        ));
        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn manifestless_via_reference_ignoring_transport() {
        use crate::asset_transport::{
            AssetRequest, AssetTransportError, ResolvedAsset, SyncAssetTransport,
        };

        // Ignores the reference. Always returns the same asset bytes.
        // The sidecar request gets the asset back, not a manifest.
        struct AlwaysSameAsset(Vec<u8>);
        impl SyncAssetTransport for AlwaysSameAsset {
            fn open(
                &self,
                _: AssetRequest<'_>,
            ) -> std::result::Result<ResolvedAsset, AssetTransportError> {
                Ok(ResolvedAsset::new(Cursor::new(self.0.clone())))
            }
        }

        // earth_apollo17.jpg carries no embedded manifest, so the sidecar path is reached.
        let asset = include_bytes!("../tests/fixtures/earth_apollo17.jpg").to_vec();
        let context = Context::new().with_asset_transport(AlwaysSameAsset(asset));

        let err = Reader::from_context(context)
            .with_file("no/such/photo.jpg")
            .err();
        assert!(
            matches!(err, Some(Error::JumbfNotFound)),
            "a manifest-less asset must report JumbfNotFound, not a decode error; got {err:?}"
        );
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn with_file_is_cancellable() {
        // Cancel at the Reading checkpoint only; let every other phase proceed.
        let context =
            Context::new().with_progress_callback(|phase, _, _| phase != ProgressPhase::Reading);

        let result = Reader::from_context(context).with_file("tests/fixtures/CA.jpg");
        assert!(
            matches!(result, Err(Error::OperationCancelled)),
            "cancel() must be honored at with_file's Reading checkpoint; got {result:?}"
        );
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn with_file_reading_steps_rise() {
        use std::sync::{Arc, Mutex};

        use crate::asset_transport::{
            AssetRequest, AssetTransportError, ResolvedAsset, SyncAssetTransport,
        };

        struct AlwaysSameAsset(Vec<u8>);
        impl SyncAssetTransport for AlwaysSameAsset {
            fn open(
                &self,
                _: AssetRequest<'_>,
            ) -> std::result::Result<ResolvedAsset, AssetTransportError> {
                Ok(ResolvedAsset::new(Cursor::new(self.0.clone())))
            }
        }

        let steps = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&steps);
        // Manifest-less asset reaches the sidecar path, so all three checkpoints fire.
        let asset = include_bytes!("../tests/fixtures/earth_apollo17.jpg").to_vec();
        let context = Context::new()
            .with_asset_transport(AlwaysSameAsset(asset))
            .with_progress_callback(move |phase, step, _| {
                if phase == ProgressPhase::Reading {
                    seen.lock().unwrap().push(step);
                }
                true
            });

        let _ = Reader::from_context(context).with_file("no/such/photo.jpg");
        assert_eq!(*steps.lock().unwrap(), vec![1, 2, 3]);
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn unsupported_sidecar_reads_as_no_manifest() {
        use crate::asset_transport::{
            AssetRef, AssetRequest, AssetRequestKind, AssetTransportError, ResolvedAsset,
            SyncAssetTransport,
        };

        // Serves the asset, but rejects any sidecar request as unsupported.
        struct NoSidecar(Vec<u8>);
        impl SyncAssetTransport for NoSidecar {
            fn open(
                &self,
                request: AssetRequest<'_>,
            ) -> std::result::Result<ResolvedAsset, AssetTransportError> {
                match (request.reference, request.kind) {
                    (AssetRef::Path(_), AssetRequestKind::Sidecar) => {
                        Err(AssetTransportError::UnsupportedReference)
                    }
                    _ => Ok(ResolvedAsset::new(Cursor::new(self.0.clone()))),
                }
            }
        }

        let asset = include_bytes!("../tests/fixtures/earth_apollo17.jpg").to_vec();
        let context = Context::new().with_asset_transport(NoSidecar(asset));

        let err = Reader::from_context(context)
            .with_file("no/such/photo.jpg")
            .err();
        assert!(matches!(err, Some(Error::JumbfNotFound)), "got {err:?}");
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn fragmented_files_async_only_errors_at_entry() {
        use crate::asset_transport::{
            AssetRequest, AssetTransportError, AsyncAssetTransport, ResolvedAsset,
        };

        struct AsyncSource;
        #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
        #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
        impl AsyncAssetTransport for AsyncSource {
            async fn open_async(
                &self,
                _: AssetRequest<'_>,
            ) -> std::result::Result<ResolvedAsset, AssetTransportError> {
                Ok(ResolvedAsset::new(Cursor::new(Vec::new())))
            }
        }

        // Sync file API on an async-only Context fails once, at the entry.
        let context = Context::new().with_asset_transport_async(AsyncSource);
        let err = Reader::from_context(context)
            .with_fragmented_files("test.mp4", &[])
            .err();
        assert!(
            matches!(
                err,
                Some(Error::AssetTransport(AssetTransportError::NoSyncTransport))
            ),
            "got {err:?}"
        );
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_reader_from_file_validation_err() -> Result<()> {
        let reader = Reader::default().with_file("tests/fixtures/XCA.jpg")?;
        assert!(reader.validation_status().is_some());
        assert_eq!(
            reader.validation_status().unwrap()[0].code(),
            crate::validation_status::ASSERTION_DATAHASH_MISMATCH
        );
        assert_eq!(reader.validation_state(), ValidationState::Invalid);
        Ok(())
    }

    /// BMFF hash verification now fires at least one `VerifyingAssetHash` progress event per
    /// hash pass (file-level or per-chunk/track), matching the granularity of the data-hash path.
    ///
    /// Uses in-memory streams and an embedded fixture so this runs on targets without a usable
    /// host filesystem (e.g. WASI without preopened paths).
    #[test]
    fn test_bmff_read_reports_verifying_asset_hash_progress() -> Result<()> {
        use std::sync::Mutex;

        use crate::Builder;

        let received = Arc::new(Mutex::new(Vec::<(ProgressPhase, u32, u32)>::new()));
        let received_cb = Arc::clone(&received);
        let ctx = test_context()
            .with_progress_callback(move |phase, step, total| {
                received_cb.lock().unwrap().push((phase, step, total));
                true
            })
            .into_shared();

        let mut builder = Builder::from_shared_context(&ctx);
        let ctx_for_signer = builder.context().clone();
        let signer = ctx_for_signer.signer()?;
        let mut source = Cursor::new(SAMPLE1_HEIC);
        let mut dest = Cursor::new(Vec::new());
        builder.sign(signer, "heic", &mut source, &mut dest)?;

        received.lock().unwrap().clear();

        dest.set_position(0);
        let _reader = Reader::from_shared_context(&ctx).with_stream("image/heic", &mut dest)?;

        let asset_hash_events: Vec<_> = received
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _, _)| *p == ProgressPhase::VerifyingAssetHash)
            .cloned()
            .collect();

        assert!(
            !asset_hash_events.is_empty(),
            "expected at least one VerifyingAssetHash event; got none"
        );
        // Steps should be monotonically increasing, starting from 1.
        for (i, (_, step, _)) in asset_hash_events.iter().enumerate() {
            assert_eq!(
                *step,
                (i + 1) as u32,
                "expected step {} but got {step} at index {i}",
                i + 1
            );
        }

        Ok(())
    }

    #[test]
    fn test_reader_trusted() -> Result<()> {
        let context = Context::new();
        let reader = Reader::from_context(context)
            .with_stream("image/jpeg", std::io::Cursor::new(IMAGE_COMPLEX_MANIFEST))?;
        assert_eq!(reader.validation_state(), ValidationState::Trusted);
        Ok(())
    }

    #[test]
    /// Test that the reader can validate a file with nested assertion errors
    fn test_reader_from_file_nested_errors() -> Result<()> {
        // disable trust check so that the status is Valid vs Trusted
        let settings = crate::Settings::default()
            .with_value("verify.verify_trust", false)
            .unwrap();
        let context = Context::new().with_settings(settings).unwrap();
        let reader = Reader::from_context(context)
            .with_stream("image/jpeg", std::io::Cursor::new(IMAGE_COMPLEX_MANIFEST))?;
        println!("{reader}");
        assert_eq!(reader.validation_status(), None);
        assert_eq!(reader.validation_state(), ValidationState::Valid);
        assert_eq!(reader.manifests.len(), 3);
        Ok(())
    }

    #[test]
    /// Test that the reader can validate a file with nested assertion errors
    fn test_reader_nested_resource() -> Result<()> {
        let reader = Reader::default()
            .with_stream("image/jpeg", std::io::Cursor::new(IMAGE_COMPLEX_MANIFEST))?;
        assert_eq!(reader.validation_status(), None);
        assert_eq!(reader.manifests.len(), 3);
        let manifest = reader.active_manifest().unwrap();
        let ingredient = manifest.ingredients().iter().next().unwrap();
        let uri = ingredient.thumbnail_ref().unwrap().identifier.clone();
        let stream = std::io::Cursor::new(Vec::new());
        let bytes_written = reader.resource_to_stream(&uri, stream)?;
        assert_eq!(bytes_written, 41810);
        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    /// Tests that the reader can write resources to a folder and that ingredients have manifest_data populated
    fn test_reader_to_folder() -> Result<()> {
        // Skip this test in GitHub workflow when target is WASI
        if std::env::var("GITHUB_ACTIONS").is_ok() && cfg!(target_os = "wasi") {
            eprintln!("Skipping test_reader_to_folder on WASI in GitHub Actions");
            return Ok(());
        }

        use crate::utils::{io_utils::tempdirectory, test::temp_dir_path};
        let reader = Reader::default().with_stream(
            "image/jpeg",
            std::io::Cursor::new(IMAGE_WITH_INGREDIENT_MANIFEST),
        )?;
        assert_eq!(reader.validation_status(), None);

        // Verify that ingredients have manifest_data populated
        if let Some(manifest) = reader.active_manifest() {
            for ingredient in manifest.ingredients() {
                assert!(
                    ingredient.manifest_data().is_some(),
                    "Ingredient should have manifest_data populated"
                );
            }
        }

        let temp_dir = tempdirectory().unwrap();
        reader.to_folder(temp_dir.path())?;
        assert!(temp_dir_path(&temp_dir, "manifest_store.json").exists());
        assert!(temp_dir_path(&temp_dir, "manifest_data.c2pa").exists());

        // Collect all thumbnail files written under the manifest subdirectories.
        let thumbnails: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.path().is_dir())
            .flat_map(|manifest_dir| {
                let assertions_dir = manifest_dir.path().join("c2pa.assertions");
                std::fs::read_dir(assertions_dir)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .filter(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .starts_with("c2pa.thumbnail")
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(
            !thumbnails.is_empty(),
            "expected thumbnail files in output folder"
        );
        for thumb in &thumbnails {
            assert!(
                thumb.metadata().unwrap().len() > 0,
                "thumbnail file should not be empty"
            );
        }
        Ok(())
    }

    /// A databox label containing path traversal (as could be read straight
    /// from an attacker-crafted asset's JUMBF `jumd` box - see
    /// `Store::from_jumbf_impl`, which passes that label to `Claim::put_databox`
    /// unmodified) must not let `to_folder` write outside the output folder.
    #[test]
    #[cfg(feature = "file_io")]
    fn test_to_folder_rejects_path_traversal_in_databox_label() {
        use crate::{assertions::DataBox, claim::Claim, utils::io_utils::tempdirectory};

        let malicious_databox = DataBox {
            format: "application/octet-stream".to_string(),
            data: b"attacker controlled bytes".to_vec(),
            data_types: None,
        };
        let db_cbor = c2pa_cbor::to_vec(&malicious_databox).unwrap();

        let mut claim = Claim::new("test", None, 1);
        claim.put_databox("../../../evil", &db_cbor, None).unwrap();

        let mut store = Store::new();
        store.commit_claim(claim).unwrap();

        let reader = Reader {
            store: Arc::new(store),
            ..Default::default()
        };

        let temp_dir = tempdirectory().unwrap();
        let result = reader.to_folder(temp_dir.path());
        assert!(
            result.is_err(),
            "a databox label containing path traversal must be rejected, not written to disk"
        );

        // Confirm nothing escaped into the output folder's parent.
        let escaped = temp_dir.path().parent().unwrap().join("evil");
        assert!(
            !escaped.exists(),
            "traversal must not create files outside the output folder"
        );
    }

    #[test]
    #[cfg(feature = "file_io")]
    /// Test that the reader can validate a file with nested assertion errors
    fn test_reader_detailed_json() -> Result<()> {
        let reader = Reader::default().with_file("tests/fixtures/CACAE-uri-CA.jpg")?;
        let json = reader.json();
        let detailed_json = reader.detailed_json();
        let parsed_json: Value = serde_json::from_str(json.as_str())?;
        let parsed_detailed_json: Value = serde_json::from_str(detailed_json.as_str())?;

        // Undetailed JSON doesn't include "claim" object as child of active manifest object
        // Detailed JSON does include the "claim" object.
        assert!(
            if let Some(active_manifest) = parsed_json["active_manifest"].as_str() {
                let mut is_valid = parsed_json["manifests"]
                    .get(active_manifest)
                    .and_then(|m| m.get("claim"))
                    .is_none();
                is_valid &= parsed_detailed_json["manifests"]
                    .get(active_manifest)
                    .and_then(|m| m.get("claim"))
                    .is_some();
                is_valid
            } else {
                false
            }
        );
        assert!(json.len() < detailed_json.len()); // Detailed JSON should contain more information
        Ok(())
    }

    #[test]
    fn test_reader_post_validate() -> Result<()> {
        use crate::{log_item, status_tracker::StatusTracker};

        let mut reader = Reader::default()
            .with_stream("image/jpeg", std::io::Cursor::new(IMAGE_WITH_MANIFEST))?;

        struct TestValidator;
        impl PostValidator for TestValidator {
            fn validate(
                &self,
                label: &str,
                assertion: &ManifestAssertion,
                uri: &str,
                _preliminary_claim: &PartialClaim,
                tracker: &mut StatusTracker,
            ) -> Result<Option<Value>> {
                let desc = tracker
                    .ingredient_uri()
                    .unwrap_or("active_manifest")
                    .to_string();
                #[allow(clippy::single_match)]
                match label {
                    "c2pa.actions.v2" | "c2pa.actions" => {
                        let actions = assertion.to_assertion::<crate::assertions::Actions>()?;
                        // build a comma separated string list of actions
                        let desc = actions
                            .actions
                            .iter()
                            .map(|action| action.action().to_string())
                            .collect::<Vec<String>>()
                            .join(",");

                        log_item!(uri.to_string(), desc.clone(), "test validator")
                            .validation_status("cai.test.action")
                            .success(tracker);
                        let result = Value::String(desc);
                        return Ok(Some(result));
                    }
                    _ => {}
                }
                log_item!(uri.to_string(), desc, "test validator")
                    .validation_status("cai.test.something")
                    .success(tracker);
                Ok(None)
            }
        }

        reader.post_validate(&TestValidator {})?;

        // Verify the validator replaced c2pa.actions assertion data in the JSON output.
        let json: Value = serde_json::from_str(&reader.json()).unwrap();
        let active_label = json["active_manifest"].as_str().unwrap();
        let assertions = json["manifests"][active_label]["assertions"]
            .as_array()
            .unwrap();
        let actions_assertion = assertions
            .iter()
            .find(|a| {
                matches!(
                    a["label"].as_str(),
                    Some("c2pa.actions.v2") | Some("c2pa.actions")
                )
            })
            .expect("c2pa.actions or c2pa.actions.v2 assertion not found");
        assert!(
            actions_assertion["data"].is_string(),
            "c2pa.actions data should be replaced with a string by the validator, got: {}",
            actions_assertion["data"]
        );

        // Verify validation results contain the success statuses logged by the validator.
        let results = reader
            .validation_results()
            .expect("validation results should exist after post_validate");
        let active = results
            .active_manifest()
            .expect("active manifest statuses should exist");
        let success_codes: Vec<&str> = active.success().iter().map(|s| s.code()).collect();
        assert!(
            success_codes.contains(&"cai.test.action"),
            "expected cai.test.action in success statuses, got: {success_codes:?}"
        );
        assert!(
            success_codes.contains(&"cai.test.something"),
            "expected cai.test.something in success statuses, got: {success_codes:?}"
        );

        Ok(())
    }

    #[test]
    fn test_reader_is_send_sync() {
        // Compile-time assertion that Reader is Send + Sync on non-WASM
        // On WASM, MaybeSend/MaybeSync don't require Send + Sync, so these traits
        // won't be implemented, but that's correct for single-threaded WASM
        #[cfg(not(target_arch = "wasm32"))]
        {
            fn assert_send<T: Send>() {}
            fn assert_sync<T: Sync>() {}

            assert_send::<Reader>();
            assert_sync::<Reader>();
        }
    }

    #[test]
    fn test_two_ingredient_thumbnails_via_resource_to_stream() -> Result<()> {
        let thumbnail1 = b"the first super real thumbnail";
        let thumbnail2 = b"the second super real thumbnail";

        let mut ingredient1 = Ingredient::new_v2("Ingredient One", "image/jpeg");
        ingredient1
            .set_thumbnail("image/jpeg", thumbnail1.to_vec())
            .unwrap();

        let mut ingredient2 = Ingredient::new_v2("Ingredient Two", "image/jpeg");
        ingredient2
            .set_thumbnail("image/jpeg", thumbnail2.to_vec())
            .unwrap();

        let mut builder = Builder::default()
            .with_definition(r#"{"title": "Test Image"}"#)
            .unwrap();
        builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
        builder.add_ingredient(ingredient1);
        builder.add_ingredient(ingredient2);

        let signer = test_signer(SigningAlg::Ps256);
        let mut source = Cursor::new(include_bytes!("../tests/fixtures/C.jpg").as_slice());
        let mut output = Cursor::new(Vec::new());
        builder.sign(&signer, "image/jpeg", &mut source, &mut output)?;

        let reader = Reader::default().with_stream("image/jpeg", &mut output)?;
        let manifest = reader.active_manifest().unwrap();
        let ingredients = manifest.ingredients();
        assert_eq!(ingredients.len(), 2);

        let uri1 = ingredients[0].thumbnail_ref().unwrap().identifier.clone();
        let uri2 = ingredients[1].thumbnail_ref().unwrap().identifier.clone();
        assert_ne!(uri1, uri2);

        let mut out1 = Cursor::new(Vec::new());
        reader.resource_to_stream(&uri1, &mut out1)?;
        assert_eq!(out1.into_inner(), thumbnail1);

        let mut out2 = Cursor::new(Vec::new());
        reader.resource_to_stream(&uri2, &mut out2)?;
        assert_eq!(out2.into_inner(), thumbnail2);

        Ok(())
    }

    /// Verify that `resource_to_stream` can load ingredient `manifest_data`
    /// that is lazily deferred in `source_store`.
    #[test]
    fn test_resource_to_stream_retrieve_deferred_manifest_data() -> Result<()> {
        let reader = Reader::default()
            .with_stream("image/jpeg", Cursor::new(IMAGE_WITH_INGREDIENT_MANIFEST))?;

        let active = reader.active_manifest().unwrap();
        let ingredient = active
            .ingredients()
            .first()
            .expect("no ingredient in CACA.jpg");

        let md_ref = ingredient
            .manifest_data_ref()
            .expect("ingredient has no manifest_data_ref");

        // Confirm the bytes are not already in the in-memory resource store
        assert!(
            !ingredient
                .resources()
                .resources()
                .contains_key(&md_ref.identifier),
            "expected deferred manifest_data — lazy load path not exercised"
        );

        // resource_to_stream must succeed no matter what, loading resources
        let mut out = Cursor::new(Vec::new());
        let n = reader.resource_to_stream(&md_ref.identifier, &mut out)?;
        assert!(n > 0, "expected non-empty manifest_data bytes");
        assert!(!out.into_inner().is_empty());

        Ok(())
    }

    // Regression test for a bug where `resource_to_stream` silently fell back to
    // returning the active manifest's own JUMBF bytes for any uri that didn't match
    // a known assertion/databox pattern, instead of erroring for an unknown resource.
    #[test]
    fn test_resource_to_stream_unknown_uri_errors() -> Result<()> {
        let reader =
            Reader::default().with_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;

        for bad_uri in ["nonexistent_uri", "invalid://nonexistent"] {
            let mut out = Cursor::new(Vec::new());
            let result = reader.resource_to_stream(bad_uri, &mut out);
            assert!(
                matches!(result, Err(Error::ResourceNotFound(_))),
                "expected ResourceNotFound for uri {bad_uri:?}, got {result:?}"
            );
            assert!(
                out.into_inner().is_empty(),
                "no bytes should be written to the stream on error for uri {bad_uri:?}"
            );
        }

        Ok(())
    }

    #[test]
    fn read_zip_signed_on_linux() -> Result<()> {
        let mut stream = Cursor::new(include_bytes!(
            "../tests/fixtures/cross-compatibility-zip/sample1-linux.zip"
        ));
        let reader = Reader::from_context(test_context()).with_stream("zip", &mut stream)?;
        assert_eq!(reader.validation_state(), ValidationState::Trusted);

        Ok(())
    }

    #[test]
    fn read_zip_signed_on_macos() -> Result<()> {
        let mut stream = Cursor::new(include_bytes!(
            "../tests/fixtures/cross-compatibility-zip/sample1-macos.zip"
        ));
        let reader = Reader::from_context(test_context()).with_stream("zip", &mut stream)?;
        assert_eq!(reader.validation_state(), ValidationState::Trusted);

        Ok(())
    }

    #[test]
    fn read_zip_signed_with_backslash_paths_on_windows() -> Result<()> {
        let mut stream = Cursor::new(include_bytes!(
            "../tests/fixtures/cross-compatibility-zip/sample1_backslash-windows.zip"
        ));
        let reader = Reader::from_context(test_context()).with_stream("zip", &mut stream)?;
        assert_eq!(reader.validation_state(), ValidationState::Trusted);

        Ok(())
    }

    #[test]
    fn read_zip_signed_with_normalized_paths_on_windows() -> Result<()> {
        let mut stream = Cursor::new(include_bytes!(
            "../tests/fixtures/cross-compatibility-zip/sample1-windows.zip"
        ));
        let reader = Reader::from_context(test_context()).with_stream("zip", &mut stream)?;
        assert_eq!(reader.validation_state(), ValidationState::Trusted);

        Ok(())
    }
}
