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

//! Traits for implementing a custom C2PA I/O handler for a file format.
//!
//! The SDK ships with built-in handlers for common formats (JPEG, PNG, TIFF, MP4,
//! WAV, GIF, ...). This module is what you implement to add support for a format
//! the SDK doesn't natively handle, and to register it via
//! [`Context::with_io_handler`](crate::Context::with_io_handler).
//!
//! There are three mandatory traits:
//!
//! - [`CAIReader`] — read the C2PA manifest store and XMP from a stream.
//! - [`CAIWriter`] — write, locate, and remove the C2PA manifest store in a stream.
//! - [`AssetIO`] — the master trait; ties a [`CAIReader`]/[`CAIWriter`] pair to a
//!   set of supported file extensions and MIME types.
//!
//! Everything else in this module — [`AssetPatch`], [`AssetBoxHash`],
//! [`ComposedManifestRef`], and [`RemoteManifestUrl`] — is optional. Most custom
//! handlers only need [`RemoteManifestUrl`], and only if they want to support
//! writing a remote manifest URL into the asset's XMP metadata. Implement
//! [`WriteXmp`] rather than `RemoteManifestUrl` directly — a blanket impl derives
//! `RemoteManifestUrl` from it.
//!
//! # Example
//!
//! A minimal custom handler needs a [`CAIReader`] and [`CAIWriter`] impl and an
//! [`AssetIO`] impl that ties them together:
//!
//! ```
//! use std::path::Path;
//!
//! use c2pa::{
//!     asset_io::{AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashObjectPositions},
//!     Result,
//! };
//!
//! struct MyFormatReader;
//!
//! impl CAIReader for MyFormatReader {
//!     fn read_cai(&self, _input_stream: &mut dyn CAIRead) -> Result<Vec<u8>> {
//!         // Locate and return the C2PA manifest store bytes.
//!         todo!()
//!     }
//!
//!     fn read_xmp(&self, _input_stream: &mut dyn CAIRead) -> Option<String> {
//!         None
//!     }
//! }
//!
//! impl CAIWriter for MyFormatReader {
//!     fn write_cai(
//!         &self,
//!         _input_stream: &mut dyn CAIRead,
//!         _output_stream: &mut dyn CAIReadWrite,
//!         _store_bytes: &[u8],
//!     ) -> Result<()> {
//!         todo!()
//!     }
//!
//!     fn get_object_locations_from_stream(
//!         &self,
//!         _input_stream: &mut dyn CAIRead,
//!     ) -> Result<Vec<HashObjectPositions>> {
//!         todo!()
//!     }
//!
//!     fn remove_cai_store_from_stream(
//!         &self,
//!         _input_stream: &mut dyn CAIRead,
//!         _output_stream: &mut dyn CAIReadWrite,
//!     ) -> Result<()> {
//!         todo!()
//!     }
//! }
//!
//! struct MyFormatIO;
//!
//! impl AssetIO for MyFormatIO {
//!     fn new(_asset_type: &str) -> Self {
//!         MyFormatIO
//!     }
//!
//!     fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
//!         Box::new(Self::new(asset_type))
//!     }
//!
//!     fn get_reader(&self) -> &dyn CAIReader {
//!         &MyFormatReader
//!     }
//!
//!     fn get_writer(&self, _asset_type: &str) -> Option<Box<dyn CAIWriter>> {
//!         Some(Box::new(MyFormatReader))
//!     }
//!
//!     fn supported_types(&self) -> &[&str] {
//!         &["myformat", "application/x-myformat"]
//!     }
//! }
//! ```
//!
//! Register it on a [`Context`](crate::Context) with
//! [`Context::with_io_handler`](crate::Context::with_io_handler), and it will be
//! consulted before the SDK's built-in handlers for any format string it claims.

use std::{
    collections::HashMap,
    ffi::OsStr,
    fmt, fs,
    io::{Cursor, Read, Seek, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use tempfile::{Builder, NamedTempFile};

use crate::{
    error::Result,
    maybe_send_sync::MaybeSend,
    utils::{
        mime::normalize_format,
        xmp_inmemory_utils::{add_provenance, extract_provenance, remove_provenance, MIN_XMP},
    },
    Error,
};

/// The kind of region a [`HashObjectPositions`] entry describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashBlockObjectType {
    /// The C2PA manifest store.
    Cai,
    /// An XMP metadata block.
    Xmp,
    /// Any other region that should be hashed.
    Other,
    /// A region that should be excluded from hashing.
    OtherExclusion,
}

impl fmt::Display for HashBlockObjectType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A byte range within an asset, tagged with the kind of region it covers.
///
/// Returned by [`CAIWriter::get_object_locations_from_stream`] so the hashing system
/// knows what to hash and what to exclude.
#[derive(Debug, PartialEq)]
pub struct HashObjectPositions {
    /// Offset from the beginning of the asset to the beginning of the region.
    pub offset: usize,
    /// Length of the region, in bytes.
    pub length: usize,
    /// The kind of region this entry describes.
    pub htype: HashBlockObjectType,
}

/// Marker trait for a seekable, readable stream that can be sent across threads.
///
/// Blanket-implemented for any type that is `Read + Seek + Send` (or `Read + Seek`
/// on targets without threading). Exists so it can be used in `dyn` position
/// (`&mut dyn CAIRead`) — Rust trait objects can only name one non-auto trait, so
/// this trait exists to bundle `Read` + `Seek` into one.
pub trait CAIRead: Read + Seek + MaybeSend {}

impl<T> CAIRead for T where T: Read + Seek + MaybeSend {}

impl From<String> for Box<dyn CAIRead> {
    fn from(val: String) -> Self {
        Box::new(Cursor::new(val))
    }
}

// Helper struct to create a concrete type for CAIRead when
// that is required.  For example a function defined like this
//  pub fn read<T>(&self, reader: &mut T) cannot currently accept
// a CAIRead trait because it is not Sized (bound to a object).
// Needed because some third-party crates (e.g. `riff`, `id3`) expose generic
// `fn read<T: Read + Seek>(reader: T)` APIs with an implicit `Sized` bound, so a
// bare `&mut dyn CAIRead` can't be passed directly.
pub(crate) struct CAIReadWrapper<'a> {
    pub reader: &'a mut dyn CAIRead,
}

impl Read for CAIReadWrapper<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Seek for CAIReadWrapper<'_> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.reader.seek(pos)
    }
}

/// Marker trait for a seekable, readable, writable stream that can be sent across
/// threads.
///
/// Blanket-implemented for any type that is `CAIRead + Write`. Exists for the same
/// reason as [`CAIRead`]: to bundle multiple traits into one for use in `dyn`
/// position (`&mut dyn CAIReadWrite`).
pub trait CAIReadWrite: CAIRead + Write {}

impl<T> CAIReadWrite for T where T: CAIRead + Write {}

// Helper struct to create a concrete type for CAIReadWrite when
// that is required. See [`CAIReadWrapper`] for why this is needed.
pub(crate) struct CAIReadWriteWrapper<'a> {
    pub reader_writer: &'a mut dyn CAIReadWrite,
}

impl Read for CAIReadWriteWrapper<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader_writer.read(buf)
    }
}

impl Write for CAIReadWriteWrapper<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.reader_writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.reader_writer.flush()
    }
}

impl Seek for CAIReadWriteWrapper<'_> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.reader_writer.seek(pos)
    }
}

/// Reads the C2PA manifest store and XMP metadata from an asset stream.
pub trait CAIReader: Sync + Send {
    /// Returns the raw C2PA JUMBF manifest store bytes from `input_stream`.
    ///
    /// Returns [`Error::JumbfNotFound`] if no manifest
    /// store is present, or
    /// [`Error::TooManyManifestStores`] if
    /// more than one is detected.
    fn read_cai(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<u8>>;

    /// Returns the asset's XMP metadata as a string, or `None` if the format
    /// doesn't carry XMP or none is present.
    fn read_xmp(&self, input_stream: &mut dyn CAIRead) -> Option<String>;
}

/// Writes, locates, and removes the C2PA manifest store in an asset stream.
pub trait CAIWriter: Sync + Send {
    /// Reads `input_stream`, embeds `store_bytes` as the C2PA manifest store, and
    /// writes the result to `output_stream`.
    ///
    /// Must replace any existing manifest store. The output must be a valid asset
    /// of the same format.
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()>;

    /// Returns the byte positions and lengths of the key regions in `input_stream`
    /// (the C2PA manifest, XMP, and everything else) so the hashing system knows
    /// what to hash and what to exclude.
    ///
    /// If no manifest store exists yet, this should still return a placeholder
    /// entry at the location where one would be written, so the hashing system
    /// knows where the manifest will go.
    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>>;

    /// Rewrites `input_stream` into `output_stream` with the C2PA manifest store
    /// removed. The output must remain a valid asset of the same format.
    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()>;
}

/// The master trait for a C2PA I/O handler for a single file format.
///
/// Implement this (plus [`CAIReader`] and [`CAIWriter`]) to add support for a
/// format the SDK doesn't natively handle, and register it with
/// [`Context::with_io_handler`](crate::Context::with_io_handler).
pub trait AssetIO: Sync + Send {
    // -- Construction --

    /// Creates an instance of this handler. `asset_type` is one of the strings
    /// returned by [`supported_types`](AssetIO::supported_types), passed in so
    /// format-specific customizations can be applied during manifest embedding.
    fn new(asset_type: &str) -> Self
    where
        Self: Sized;

    /// Returns an [`AssetIO`] handler configured for `asset_type`.
    ///
    /// Typically implemented as `Box::new(Self::new(asset_type))`.
    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO>;

    // -- Reader / writer access --

    /// Returns the streaming reader for this format.
    fn get_reader(&self) -> &dyn CAIReader;

    /// Returns the streaming writer for this format, if writing is supported.
    ///
    /// Defaults to `None` (read-only format).
    fn get_writer(&self, _asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        None
    }

    // -- File-based operations --

    /// Reads the C2PA manifest store from the file at `asset_path`.
    ///
    /// The default implementation opens `asset_path` and delegates to
    /// [`get_reader`](AssetIO::get_reader)'s [`CAIReader::read_cai`].
    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut input_stream = fs::OpenOptions::new()
            .read(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        self.get_reader().read_cai(&mut input_stream)
    }

    /// Writes `store_bytes` as the C2PA manifest store in the file at `asset_path`.
    ///
    /// The default implementation opens `asset_path`, calls
    /// [`get_writer`](AssetIO::get_writer)'s [`CAIWriter::write_cai`] into a
    /// temporary file, and moves the result into place with [`rename_or_move`].
    /// Returns [`Error::UnsupportedType`] if [`get_writer`](AssetIO::get_writer)
    /// returns `None`.
    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let ext = asset_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        let writer = self.get_writer(ext).ok_or(Error::UnsupportedType)?;

        let mut input_stream = fs::OpenOptions::new()
            .read(true)
            .open(asset_path)
            .map_err(Error::IoError)?;
        let mut temp_file = tempfile_builder("c2pa_temp")?;

        writer.write_cai(&mut input_stream, &mut temp_file, store_bytes)?;

        rename_or_move(temp_file, asset_path)
    }

    /// Removes the C2PA manifest store from the file at `asset_path`.
    ///
    /// The default implementation mirrors [`save_cai_store`](AssetIO::save_cai_store),
    /// calling [`CAIWriter::remove_cai_store_from_stream`] instead.
    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        let ext = asset_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        let writer = self.get_writer(ext).ok_or(Error::UnsupportedType)?;

        let mut input_stream = fs::OpenOptions::new()
            .read(true)
            .open(asset_path)
            .map_err(Error::IoError)?;
        let mut temp_file = tempfile_builder("c2pa_temp")?;

        writer.remove_cai_store_from_stream(&mut input_stream, &mut temp_file)?;

        rename_or_move(temp_file, asset_path)
    }

    // -- Metadata --

    /// Returns the list of file extensions and MIME types this handler supports
    /// (e.g. `["jpg", "jpeg", "image/jpeg"]`).
    fn supported_types(&self) -> &[&str];

    /// Returns (extension, MIME type) pairs for this handler's supported formats.
    ///
    /// The default implementation derives pairs from [`supported_types`](Self::supported_types):
    /// every extension-shaped entry (no `/`) is paired with the first MIME-shaped entry (the
    /// first one containing `/`). That's correct when every entry refers to the same
    /// underlying format (e.g. `["jpg", "jpeg", "image/jpeg"]`), which covers most handlers.
    ///
    /// Override this when `supported_types()` covers multiple distinct sub-formats that each
    /// need their own MIME type (e.g. BMFF's `avif`/`heic`/`heif`/`mp4`/`mov`, all handled by
    /// one `AssetIO` impl but each needing a different MIME type) — the default heuristic
    /// can't tell those apart from a single flat list.
    fn mime_type_map(&self) -> Vec<(String, String)> {
        let types = self.supported_types();
        let Some(mime) = types.iter().find(|t| t.contains('/')) else {
            return Vec::new();
        };
        types
            .iter()
            .filter(|t| !t.contains('/'))
            .map(|ext| (ext.to_string(), mime.to_string()))
            .collect()
    }

    // -- Advanced / optional capabilities --
    //
    // These four accessors all default to `None`. Most custom handlers only need
    // `remote_manifest_url_ref` (to support writing a remote manifest URL into XMP);
    // the rest are spec-specific or performance features used only by a subset of
    // the SDK's built-in handlers.

    /// Returns this handler's [`AssetPatch`] implementation, if it supports
    /// in-place patching of an existing manifest store.
    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        None
    }

    /// Returns this handler's [`RemoteManifestUrl`] implementation, if it supports
    /// writing a remote manifest URL (e.g. into XMP).
    fn remote_manifest_url_ref(&self) -> Option<&dyn RemoteManifestUrl> {
        None
    }

    /// Returns this handler's [`AssetBoxHash`] implementation, if it supports
    /// `c2pa.hash.boxes` box-hash assertions.
    fn asset_box_hash_ref(&self) -> Option<&dyn AssetBoxHash> {
        None
    }

    /// Returns this handler's [`ComposedManifestRef`] implementation, if it can
    /// produce a pre-composed, format-ready manifest wrapper.
    fn composed_data_ref(&self) -> Option<&dyn ComposedManifestRef> {
        None
    }

    /// Returns this handler's [`WriteXmp`] implementation, if it supports writing
    /// an exact XMP packet (as opposed to [`RemoteManifestUrl`], which always
    /// merges a URL into the *current* XMP).
    fn write_xmp_ref(&self) -> Option<&dyn WriteXmp> {
        None
    }
}

/// Optimizes manifest updates for handlers that can patch an existing manifest
/// store in place, without rewriting the rest of the asset.
///
/// This is a performance optimization: only works when the new store is the same
/// size as the existing one, and the resultant file must still be a valid asset.
pub trait AssetPatch {
    /// Patches the existing manifest store at `asset_path` with `store_bytes`.
    ///
    /// Only valid when `store_bytes` is the same length as the existing manifest
    /// store — any other change would invalidate the asset's hashes.
    ///
    /// The default implementation opens `asset_path` for reading and writing and
    /// delegates to [`patch_cai_store_stream`](Self::patch_cai_store_stream).
    fn patch_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(asset_path)
            .map_err(Error::IoError)?;
        self.patch_cai_store_stream(&mut file, store_bytes)
    }

    /// Same operation as [`patch_cai_store`](Self::patch_cai_store), but on an
    /// already-open stream: seeks to the existing manifest store's location and
    /// overwrites it with `store_bytes` in place, without touching anything else
    /// in the stream.
    ///
    /// Only valid when `store_bytes` is the same length as the existing manifest
    /// store; implementations must verify this and return an error otherwise.
    ///
    /// The default implementation returns [`Error::NotImplemented`] — override
    /// this (and rely on [`patch_cai_store`](Self::patch_cai_store)'s default
    /// file-based wrapper above) for handlers whose manifest store can be
    /// located and patched purely from a stream, with no file path needed.
    fn patch_cai_store_stream(
        &self,
        _stream: &mut dyn CAIReadWrite,
        _store_bytes: &[u8],
    ) -> Result<()> {
        Err(Error::NotImplemented(
            "patch_cai_store_stream is not implemented by this handler".to_string(),
        ))
    }
}

/// The well-known box/chunk name every format's C2PA manifest store is reported
/// under in a [`BoxMap`], regardless of the format's native naming (e.g. PNG's
/// `caBX` chunk, a BMFF `uuid` box, ...).
pub const C2PA_BOXHASH: &str = "C2PA";

/// Describes one hashable region ("box") in an asset's container format.
///
/// Returned by [`AssetBoxHash::get_box_map`] to describe the byte range and name
/// of each box, in the order they occur. This only describes *where* the boxes
/// are — computing and recording hashes over these regions is the job of the
/// `c2pa.hash.boxes` assertion, not this type.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BoxMap {
    /// The box name(s) covered by this entry. More than one name means several
    /// consecutive boxes were collapsed into a single hashable range.
    pub names: Vec<String>,
    /// Whether this region should be excluded from hashing — for example, a
    /// placeholder for a C2PA box that doesn't exist in the asset yet.
    pub excluded: Option<bool>,
    /// Byte offset of the region within the asset.
    pub range_start: u64,
    /// Length in bytes of the region.
    pub range_len: u64,
}

impl BoxMap {
    /// Creates a new region entry, not excluded from hashing.
    pub fn new(names: Vec<String>, range_start: u64, range_len: u64) -> Self {
        BoxMap {
            names,
            excluded: None,
            range_start,
            range_len,
        }
    }

    /// Marks this region as excluded from hashing.
    pub fn excluded(mut self) -> Self {
        self.excluded = Some(true);
        self
    }
}

/// Provides box-hash information for C2PA `c2pa.hash.boxes` assertions.
///
/// Only implemented by handlers for formats that support box hashing.
pub trait AssetBoxHash {
    /// Returns a `Vec` of every hashable region ("box") in the asset, in the order
    /// they occur.
    ///
    /// Hashes don't need to be calculated here — only the name and positional
    /// information. If the C2PA manifest isn't present yet, include a placeholder
    /// entry at the location it would occupy once written.
    fn get_box_map(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<BoxMap>>;
}

/// Writes a remote manifest URL into an asset, so a reader can find the manifest
/// even though it isn't stored in the asset itself.
///
/// Note the direction: this is for a *remote* manifest (referenced by URL, not
/// present in the asset) — unrelated to *embedding* a manifest store, which is what
/// [`CAIWriter::write_cai`] does.
///
/// Implement [`WriteXmp`] instead of this trait directly — every format writes the
/// remote manifest URL the same way (merge it into XMP, then write XMP back), and
/// there's a blanket impl of `RemoteManifestUrl` for any type that implements
/// [`WriteXmp`] and [`CAIReader`] that does exactly that.
///
/// This is deliberately narrow: it only covers "point a reader at a manifest hosted
/// elsewhere." A future non-XMP technique (e.g. a watermark) would be its own
/// separate trait, not folded into this one.
pub trait RemoteManifestUrl {
    /// Writes `remote_manifest_url` into the asset read from `input_stream`,
    /// producing `output_stream`.
    fn write_remote_manifest_url(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        remote_manifest_url: &str,
    ) -> Result<()>;

    /// Reads the remote manifest URL from the asset in `input_stream`, if any.
    ///
    /// The default implementation returns `None`. The blanket impl for
    /// [`WriteXmp`] overrides this to extract the URL from XMP, since that's
    /// where `write_remote_manifest_url` puts it. Implement this directly if
    /// your format stores the remote manifest URL somewhere other than XMP.
    fn read_manifest_url(&self, _input_stream: &mut dyn CAIRead) -> Option<String> {
        None
    }

    /// Removes the remote manifest URL reference from the asset, if present,
    /// leaving everything else (including any unrelated XMP) untouched.
    ///
    /// Needed when re-saving with a mode that no longer points at a remote
    /// manifest (e.g. embedding a full manifest after a prior sidecar/remote
    /// save) — without this, a stale reference would be left behind.
    ///
    /// The default implementation returns [`Error::NotImplemented`]. The
    /// blanket impl for [`WriteXmp`] overrides this to read the current XMP,
    /// strip the reference, and write the result back.
    fn remove_remote_manifest_url(
        &self,
        _input_stream: &mut dyn CAIRead,
        _output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        Err(Error::NotImplemented(
            "remove_remote_manifest_url is not supported by this handler".to_string(),
        ))
    }
}

/// Writes a complete XMP packet into an asset stream, replacing any existing XMP.
///
/// This is the format-specific half of [`RemoteManifestUrl`]: given the final XMP
/// string to write (already merged with the remote manifest URL), insert it into
/// the asset's container format. Implement this instead of `RemoteManifestUrl`
/// directly — a blanket impl derives `RemoteManifestUrl` from it, handling the
/// "read current XMP, merge in the URL" part common to every format.
pub trait WriteXmp {
    /// Writes `xmp` into `input_stream`, producing `output_stream`.
    fn write_xmp(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        xmp: &str,
    ) -> Result<()>;
}

impl<T: WriteXmp + CAIReader> RemoteManifestUrl for T {
    fn write_remote_manifest_url(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        remote_manifest_url: &str,
    ) -> Result<()> {
        let current_xmp = self
            .read_xmp(input_stream)
            .unwrap_or_else(|| MIN_XMP.to_string());
        let updated_xmp = add_provenance(&current_xmp, remote_manifest_url)?;
        self.write_xmp(input_stream, output_stream, &updated_xmp)
    }

    fn read_manifest_url(&self, input_stream: &mut dyn CAIRead) -> Option<String> {
        self.read_xmp(input_stream)
            .as_deref()
            .and_then(extract_provenance)
    }

    fn remove_remote_manifest_url(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        let current_xmp = self
            .read_xmp(input_stream)
            .unwrap_or_else(|| MIN_XMP.to_string());
        let updated_xmp = remove_provenance(&current_xmp)?;
        self.write_xmp(input_stream, output_stream, &updated_xmp)
    }
}

/// Generates a pre-composed C2PA manifest ready for direct insertion into an
/// asset of a given format.
pub trait ComposedManifestRef {
    /// Wraps `manifest_data` into the container structure expected by `format`
    /// (e.g. a JPEG APP11 segment, or a PNG `caBX` chunk).
    fn compose_manifest(&self, manifest_data: &[u8], format: &str) -> Result<Vec<u8>>;
}

/// A registry of [`AssetIO`] handlers, dispatching by format string (a file extension or
/// MIME type, e.g. `"jpg"` or `"image/jpeg"`).
///
/// Handlers are matched by exact format string, case-insensitively and with surrounding
/// whitespace trimmed. Registering a handler for a format string already claimed by an
/// earlier one overrides it ("last-registered wins").
///
/// An optional `fallback` registry is consulted only when this registry has no match for a
/// format. This lets a small registry (e.g. a caller's custom handlers) cheaply extend a
/// larger one (e.g. the SDK's built-in handlers) without copying it.
pub struct HandlerRegistry {
    handlers: HashMap<String, Arc<dyn AssetIO>>,
    containers: HashMap<String, String>,
    mimes: HashMap<String, String>,
    fallback: Option<Arc<HandlerRegistry>>,
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HandlerRegistry {
    /// Creates an empty registry with no fallback.
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            containers: HashMap::new(),
            mimes: HashMap::new(),
            fallback: None,
        }
    }

    /// Creates an empty registry that consults `fallback` for any format it has no handler
    /// for itself.
    pub fn with_fallback(fallback: Arc<HandlerRegistry>) -> Self {
        Self {
            handlers: HashMap::new(),
            containers: HashMap::new(),
            mimes: HashMap::new(),
            fallback: Some(fallback),
        }
    }

    /// Registers `handler`, returning `self` for chaining.
    pub fn with_handler(mut self, handler: impl AssetIO + 'static) -> Self {
        self.add_handler(handler);
        self
    }

    /// Registers `handler` for every format string in its [`AssetIO::supported_types`].
    pub fn add_handler(&mut self, handler: impl AssetIO + 'static) {
        self.add_boxed_handler(Box::new(handler));
    }

    /// Like [`add_handler`](Self::add_handler), but takes an already-boxed handler. Useful
    /// when the caller only has a `Box<dyn AssetIO>` (e.g. from another
    /// [`AssetIO::get_handler`] call) rather than a concrete, sized type.
    pub fn add_boxed_handler(&mut self, handler: Box<dyn AssetIO>) {
        let handler: Arc<dyn AssetIO> = Arc::from(handler);
        let types = handler.supported_types();
        let Some(canonical) = types.first() else {
            log::warn!(
                "asset handler declares no supported types"
            );
            return;
        };
        let canonical = normalize_format(canonical);
        for t in types {
            let t = normalize_format(t);
            self.containers.insert(t.clone(), canonical.clone());
            self.handlers.insert(t, Arc::clone(&handler));
        }

        for (ext, mime) in handler.mime_type_map() {
            let mime = normalize_format(&mime);
            self.mimes.insert(normalize_format(&ext), mime.clone());
            self.mimes.insert(mime.clone(), mime);
        }
    }

    /// Looks up the full [`AssetIO`] handler for `format`, checking `fallback` if this
    /// registry has no match.
    pub fn handler(&self, format: &str) -> Option<&dyn AssetIO> {
        let key = normalize_format(format);
        match self.handlers.get(&key) {
            Some(h) => Some(h.as_ref()),
            None => self.fallback.as_deref().and_then(|f| f.handler(format)),
        }
    }

    /// Looks up the [`CAIReader`] for `format`, checking `fallback` if this registry has no
    /// match.
    pub fn reader(&self, format: &str) -> Option<&dyn CAIReader> {
        self.handler(format).map(|h| h.get_reader())
    }

    /// Looks up the [`CAIWriter`] for `format`, checking `fallback` if this registry has no
    /// match.
    ///
    /// Returns an owned `Box<dyn CAIWriter>` because [`AssetIO::get_writer`] allocates a new
    /// writer instance on each call.
    pub fn writer(&self, format: &str) -> Option<Box<dyn CAIWriter>> {
        self.handler(format).and_then(|h| h.get_writer(format))
    }

    /// Looks up the full [`AssetIO`] handler for the file extension of `asset_path`, if any.
    #[cfg(feature = "file_io")]
    pub fn handler_from_path(&self, asset_path: &Path) -> Option<&dyn AssetIO> {
        let ext = asset_path.extension()?.to_str()?;
        self.handler(ext)
    }

    /// Returns the (lowercased) file extension of `path` if a handler supports it.
    #[cfg(feature = "file_io")]
    pub fn supported_extension(&self, path: &Path) -> Option<String> {
        let ext = path.extension()?.to_str()?.to_lowercase();
        self.handler(&ext).is_some().then_some(ext)
    }

    /// Returns every format string with a registered reader, including `fallback`'s.
    pub fn reader_mime_types(&self) -> Vec<String> {
        let mut types: Vec<String> = self.handlers.keys().cloned().collect();
        if let Some(f) = &self.fallback {
            for t in f.reader_mime_types() {
                if !types.contains(&t) {
                    types.push(t);
                }
            }
        }
        types
    }

    /// Returns every format string with a registered writer, including `fallback`'s.
    pub fn writer_mime_types(&self) -> Vec<String> {
        let mut types: Vec<String> = self
            .handlers
            .iter()
            .filter(|(format, handler)| handler.get_writer(format).is_some())
            .map(|(format, _)| format.clone())
            .collect();
        if let Some(f) = &self.fallback {
            for t in f.writer_mime_types() {
                if !types.contains(&t) {
                    types.push(t);
                }
            }
        }
        types
    }

    /// Returns the canonical container-family id for `format`, checking `fallback` if this
    /// registry has no match.
    ///
    /// The canonical id is the first entry in the registering handler's own
    /// [`AssetIO::supported_types`] — e.g. `"dng"`, `"tif"`, and `"image/tiff"` all resolve to
    /// `"tif"`. Two format strings are the same container family iff their canonical ids
    /// match: `registry.container_for("dng") == registry.container_for("tif")`.
    pub fn container_for(&self, format: &str) -> Option<&str> {
        let key = normalize_format(format);
        match self.containers.get(&key) {
            Some(c) => Some(c.as_str()),
            None => self
                .fallback
                .as_deref()
                .and_then(|f| f.container_for(format)),
        }
    }

    /// Returns whether `format` belongs to the same container family as `"avif"` (i.e. the
    /// ISO BMFF family: MP4, MOV, HEIC, HEIF, AVIF, ...).
    pub fn is_bmff_format(&self, format: &str) -> bool {
        self.container_for(format) == self.container_for("avif")
    }

    /// Returns the MIME type for `format` (an extension or MIME type), checking `fallback`
    /// if this registry has no match.
    ///
    /// Derived from the registered handlers' [`AssetIO::mime_type_map`], so it's only known
    /// for a format string some registered handler actually supports.
    pub fn mime_for(&self, format: &str) -> Option<&str> {
        let key = normalize_format(format);
        match self.mimes.get(&key) {
            Some(m) => Some(m.as_str()),
            None => self.fallback.as_deref().and_then(|f| f.mime_for(format)),
        }
    }

    /// Returns the MIME type for `format` (an extension or MIME type), derived from a
    /// registered handler (via [`Self::mime_for`]) so a custom handler's format is
    /// recognized. Returns `format` itself (trimmed and lowercased) when no registered
    /// handler recognizes it.
    pub fn format_to_mime(&self, format: &str) -> String {
        match self.mime_for(format) {
            Some(mime) => mime.to_string(),
            None => normalize_format(format),
        }
    }

    /// Returns the MIME type for the file at `path`, based on its extension. See
    /// [`Self::format_to_mime`].
    pub fn format_from_path<P: AsRef<Path>>(&self, path: P) -> Option<String> {
        let ext = path.as_ref().extension()?.to_string_lossy();
        Some(self.format_to_mime(&ext))
    }

    /// Resolves the format string to use for reading by combining a caller-supplied hint
    /// with stream-based container detection.
    ///
    /// * If the hint maps to the same container family as the detected bytes, the hint is
    ///   returned unchanged (it may be more specific, e.g. `"dng"` within the TIFF family).
    /// * If they differ, the stream-detected container's canonical format is returned.
    /// * If stream detection fails, the hint is returned as-is.
    /// * Note that for reading, the exact format is not critical as long as it leads to the
    ///   right container.
    pub fn format_from_stream<R: Read + Seek>(&self, hint: &str, stream: &mut R) -> String {
        let detected = sniff_container_from_stream(stream);
        let hinted = self.container_for(hint);
        match (hinted, detected) {
            (Some(h), Some(d)) if h == d => hint.to_string(),
            (_, Some(d)) => d.to_string(),
            (_, None) => hint.to_string(),
        }
    }

    /// Reads the C2PA manifest store from `stream` via the registered reader for
    /// `asset_type`, checking `fallback` if this registry has no match.
    pub(crate) fn read_jumbf(&self, asset_type: &str, stream: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let cai_block = match self.reader(asset_type) {
            Some(r) => r.read_cai(stream)?,
            None => return Err(Error::UnsupportedType),
        };
        if cai_block.is_empty() {
            return Err(Error::JumbfNotFound);
        }
        Ok(cai_block)
    }

    /// Writes `store_bytes` as the C2PA manifest store, reading an asset of `asset_type`
    /// from `input_stream` and writing the result to `output_stream`, via the registered
    /// writer for `asset_type`, checking `fallback` if this registry has no match.
    pub(crate) fn write_jumbf(
        &self,
        asset_type: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        match self.writer(asset_type) {
            Some(w) => w.write_cai(input_stream, output_stream, store_bytes),
            None => Err(Error::UnsupportedType),
        }
    }

    /// Reads the C2PA manifest store from the file at `in_path`, via the registered handler
    /// for its file extension, checking `fallback` if this registry has no match.
    ///
    /// Unlike [`Self::read_jumbf`], this does not treat an empty result as
    /// [`Error::JumbfNotFound`] — it returns whatever [`CAIReader::read_cai`] returns,
    /// matching the legacy `jumbf_io::load_jumbf_from_file` behavior.
    #[cfg(feature = "file_io")]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn read_jumbf_from_file<P: AsRef<Path>>(&self, in_path: P) -> Result<Vec<u8>> {
        let ext = in_path
            .as_ref()
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .ok_or(Error::UnsupportedType)?;

        match self.handler(&ext) {
            Some(asset_handler) => {
                let mut file = fs::File::open(in_path.as_ref()).map_err(Error::IoError)?;
                asset_handler.get_reader().read_cai(&mut file)
            }
            None => Err(Error::UnsupportedType),
        }
    }

    /// Writes `data` as the C2PA manifest store in the file at `in_path`, via the registered
    /// handler for its file extension, checking `fallback` if this registry has no match.
    ///
    /// If `out_path` is `None`, a new file is created alongside `in_path` with `-c2pa`
    /// appended to the file name (e.g. `test.jpg` -> `test-c2pa.jpg`). If `in_path` and
    /// `out_path` are the same, the input file is overwritten. Patches the existing manifest
    /// store in place when the handler supports it (via [`AssetIO::asset_patch_ref`]) and the
    /// patch succeeds, saving a full rewrite; falls back to [`AssetIO::save_cai_store`]
    /// otherwise — matching the legacy `jumbf_io::save_jumbf_to_file` behavior.
    #[cfg(feature = "file_io")]
    pub(crate) fn write_jumbf_to_file<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        data: &[u8],
        in_path: P1,
        out_path: Option<P2>,
    ) -> Result<()> {
        let ext = in_path
            .as_ref()
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .ok_or(Error::UnsupportedType)?;

        // if no output path make a new file based off of source file name
        let asset_out_path: PathBuf = match out_path.as_ref() {
            Some(p) => p.as_ref().to_owned(),
            None => {
                let filename_osstr = in_path.as_ref().file_stem().ok_or(Error::UnsupportedType)?;
                let filename = filename_osstr.to_str().ok_or(Error::UnsupportedType)?;

                let out_name = format!("{filename}-c2pa.{ext}");
                in_path.as_ref().to_owned().with_file_name(out_name)
            }
        };

        // clone output to be overwritten
        if in_path.as_ref() != asset_out_path {
            fs::copy(in_path, &asset_out_path).map_err(Error::IoError)?;
        }

        match self.handler(&ext) {
            Some(asset_handler) => {
                // patch if possible to save time and resources
                if let Some(patch_handler) = asset_handler.asset_patch_ref() {
                    if patch_handler.patch_cai_store(&asset_out_path, data).is_ok() {
                        return Ok(());
                    }
                }

                // couldn't patch so just save
                asset_handler.save_cai_store(&asset_out_path, data)
            }
            None => Err(Error::UnsupportedType),
        }
    }

    /// Returns the byte positions and lengths of the key regions (the C2PA manifest, XMP,
    /// and everything else) in `stream`, via the registered writer for `format`, checking
    /// `fallback` if this registry has no match.
    pub(crate) fn object_locations(
        &self,
        format: &str,
        stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        match self.writer(format) {
            Some(w) => w.get_object_locations_from_stream(stream),
            None => Err(Error::UnsupportedType),
        }
    }
}

/// Detects the container format of a stream by inspecting its leading bytes.
///
/// Reads a small header from the stream and matches it against magic signatures for each
/// known container, then rewinds before returning. Returns `None` when the container cannot
/// be identified from the bytes alone.
fn sniff_container_from_stream<R: Read + Seek>(stream: &mut R) -> Option<&'static str> {
    use std::io::SeekFrom;

    stream.rewind().ok()?;
    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).ok()?;
    stream.rewind().ok()?;

    if n < 2 {
        return None;
    }

    // JPEG: FF D8 FF
    if n >= 3 && buf[0] == 0xff && buf[1] == 0xd8 && buf[2] == 0xff {
        return Some("jpg");
    }

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if n >= 8 && buf[0..8] == [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] {
        return Some("png");
    }

    // GIF87a or GIF89a
    if n >= 6 && &buf[0..3] == b"GIF" && (&buf[3..6] == b"87a" || &buf[3..6] == b"89a") {
        return Some("gif");
    }

    // TIFF (standard and BigTIFF, both byte orders).
    // DNG, ARW, and NEF all share the TIFF magic bytes; they all use TiffIO.
    if n >= 4
        && (buf[0..4] == [0x49, 0x49, 0x2A, 0x00]   // TIFF little-endian
            || buf[0..4] == [0x4D, 0x4D, 0x00, 0x2A] // TIFF big-endian
            || buf[0..4] == [0x49, 0x49, 0x2B, 0x00] // BigTIFF little-endian
            || buf[0..4] == [0x4D, 0x4D, 0x00, 0x2B])
    // BigTIFF big-endian
    {
        return Some("tif");
    }

    // JPEG XL container: 00 00 00 0C 4A 58 4C 20 0D 0A 87 0A
    if n >= 12
        && buf[0..12]
            == [
                0x00, 0x00, 0x00, 0x0c, 0x4a, 0x58, 0x4c, 0x20, 0x0d, 0x0a, 0x87, 0x0a,
            ]
    {
        return Some("jxl");
    }

    // RIFF family (WEBP, AVI, WAV, …): all use the same I/O handler.
    if n >= 4 && &buf[0..4] == b"RIFF" {
        return Some("avi");
    }

    // BMFF family: ISO 14496-12 "ftyp" box at bytes 4-7.
    // All BMFF subtypes (MP4, MOV, HEIC, HEIF, AVIF, …) share the same handler.
    if n >= 8 && &buf[4..8] == b"ftyp" {
        return Some("avif");
    }

    // FLAC: fLaC marker
    if n >= 4 && &buf[0..4] == b"fLaC" {
        return Some("flac");
    }

    // ID3 tag: may precede MP3 or FLAC audio.
    // Decode the sync-safe tag size and peek past the tag to check for fLaC.
    if n >= 10 && &buf[0..3] == b"ID3" {
        let tag_size = ((buf[6] as u64 & 0x7f) << 21)
            | ((buf[7] as u64 & 0x7f) << 14)
            | ((buf[8] as u64 & 0x7f) << 7)
            | (buf[9] as u64 & 0x7f);
        let flac_offset = 10 + tag_size;
        let mut marker = [0u8; 4];
        let is_flac = stream
            .seek(SeekFrom::Start(flac_offset))
            .and_then(|_| stream.read_exact(&mut marker))
            .map(|_| &marker == b"fLaC")
            .unwrap_or(false);
        let _ = stream.rewind();
        return if is_flac { Some("flac") } else { Some("mp3") };
    }

    // MPEG audio frame sync: 0xFF followed by a byte with the top 3 bits set.
    if n >= 2 && buf[0] == 0xff && (buf[1] & 0xe0) == 0xe0 {
        return Some("mp3");
    }

    // PDF: %PDF (only available with the pdf feature)
    #[cfg(feature = "pdf")]
    if n >= 4 && &buf[0..4] == b"%PDF" {
        return Some("pdf");
    }

    None
}

fn tempfile_builder<T: AsRef<OsStr> + Sized>(prefix: T) -> Result<NamedTempFile> {
    #[cfg(all(target_os = "wasi", target_env = "p1"))]
    return Err(Error::NotImplemented(
        "tempfile_builder requires wasip2 or later".to_string(),
    ));

    #[cfg(all(target_os = "wasi", not(target_env = "p1")))]
    return Builder::new()
        .prefix(&prefix)
        .rand_bytes(5)
        .tempfile_in("/")
        .map_err(Error::IoError);

    #[cfg(not(target_os = "wasi"))]
    return Builder::new()
        .prefix(&prefix)
        .rand_bytes(5)
        .tempfile()
        .map_err(Error::IoError);
}

/// Renames a file or, if the provided paths are on separate mounting points, moves
/// a file from a temporary location to its final location.
///
/// If the rename is not possible due to cross volume references, the file will be copied to the
/// final and then the temp file we be deleted.
pub fn rename_or_move<P>(temp_file: NamedTempFile, asset_path: P) -> Result<()>
where
    P: AsRef<Path>,
{
    // Clear temp flag for Windows.
    let (_, path) = temp_file
        .keep()
        .map_err(|e| crate::Error::OtherError(Box::new(e)))?;

    // Move the temp_file to the asset's final path.
    fs::rename(&path, asset_path.as_ref())
        // Attempt to copy the file instead if the file's final location is on a different volume.
        .or_else(|_| {
            fs::copy(&path, asset_path).map(|_| ()).and_then(|_| {
                // Remove the temporary file.
                fs::remove_file(path)
            })
        })
        .map_err(crate::Error::IoError)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;

    struct TestHandler {
        types: Vec<&'static str>,
        tag: &'static [u8],
        mime_map: Vec<(String, String)>,
    }
    impl AssetIO for TestHandler {
        fn new(_asset_type: &str) -> Self {
            unimplemented!("not needed for these tests")
        }

        fn get_handler(&self, _asset_type: &str) -> Box<dyn AssetIO> {
            Box::new(TestHandler {
                types: self.types.clone(),
                tag: self.tag,
                mime_map: self.mime_map.clone(),
            })
        }

        fn get_reader(&self) -> &dyn CAIReader {
            self
        }

        fn supported_types(&self) -> &[&str] {
            &self.types
        }

        fn mime_type_map(&self) -> Vec<(String, String)> {
            if self.mime_map.is_empty() {
                // Fall back to the default derivation, same as a handler that doesn't
                // override this method at all.
                let types = self.types.clone();
                let Some(mime) = types.iter().find(|t| t.contains('/')) else {
                    return Vec::new();
                };
                types
                    .iter()
                    .filter(|t| !t.contains('/'))
                    .map(|ext| (ext.to_string(), mime.to_string()))
                    .collect()
            } else {
                self.mime_map.clone()
            }
        }
    }
    impl CAIReader for TestHandler {
        fn read_cai(&self, _: &mut dyn CAIRead) -> Result<Vec<u8>> {
            Ok(self.tag.to_vec())
        }

        fn read_xmp(&self, _: &mut dyn CAIRead) -> Option<String> {
            None
        }
    }

    fn handler(types: &[&'static str], tag: &'static [u8]) -> TestHandler {
        TestHandler {
            types: types.to_vec(),
            tag,
            mime_map: Vec::new(),
        }
    }

    fn handler_with_mime_map(
        types: &[&'static str],
        tag: &'static [u8],
        mime_map: &[(&str, &str)],
    ) -> TestHandler {
        TestHandler {
            types: types.to_vec(),
            tag,
            mime_map: mime_map
                .iter()
                .map(|(ext, mime)| (ext.to_string(), mime.to_string()))
                .collect(),
        }
    }

    #[test]
    fn test_last_registered_wins() {
        let reg = HandlerRegistry::new()
            .with_handler(handler(&["x-custom/test"], b"A"))
            .with_handler(handler(&["x-custom/test"], b"B"));

        let mut stream = Cursor::new(vec![]);
        let reader = reg.reader("x-custom/test").unwrap();
        assert_eq!(reader.read_cai(&mut stream).unwrap(), b"B");
    }

    #[test]
    fn test_fallback_is_only_consulted_when_own_handlers_miss() {
        let base =
            Arc::new(HandlerRegistry::new().with_handler(handler(&["image/jpeg"], b"builtin")));
        let overlay =
            HandlerRegistry::with_fallback(base).with_handler(handler(&["image/jpeg"], b"custom"));

        let mut stream = Cursor::new(vec![]);
        assert_eq!(
            overlay
                .reader("image/jpeg")
                .unwrap()
                .read_cai(&mut stream)
                .unwrap(),
            b"custom"
        );
    }

    #[test]
    fn test_fallback_covers_formats_not_registered_locally() {
        let base =
            Arc::new(HandlerRegistry::new().with_handler(handler(&["image/png"], b"builtin-png")));
        let overlay = HandlerRegistry::with_fallback(base)
            .with_handler(handler(&["image/jpeg"], b"custom-jpeg"));

        assert!(overlay.handler("image/png").is_some());
        assert!(overlay.handler("image/jpeg").is_some());
        assert!(overlay.handler("nonexistent/format").is_none());
    }

    #[test]
    fn test_container_for_groups_by_first_supported_type() {
        let reg = HandlerRegistry::new()
            .with_handler(handler(&["tif", "dng", "image/tiff"], b"tiff"))
            .with_handler(handler(&["avif", "mp4", "mov"], b"bmff"));

        assert_eq!(reg.container_for("dng"), reg.container_for("tif"));
        assert_eq!(reg.container_for("image/tiff"), reg.container_for("tif"));
        assert_ne!(reg.container_for("mp4"), reg.container_for("tif"));
        assert_eq!(reg.container_for("nonexistent/format"), None);
    }

    #[test]
    fn test_is_bmff_format() {
        let reg = HandlerRegistry::new()
            .with_handler(handler(&["tif", "dng"], b"tiff"))
            .with_handler(handler(&["avif", "mp4", "mov", "heic"], b"bmff"));

        assert!(reg.is_bmff_format("mp4"));
        assert!(reg.is_bmff_format("heic"));
        assert!(!reg.is_bmff_format("tif"));
        assert!(!reg.is_bmff_format("nonexistent/format"));
    }

    #[test]
    fn test_format_from_stream_detects_jpeg_from_bytes() {
        let reg =
            HandlerRegistry::new().with_handler(handler(&["jpg", "jpeg", "image/jpeg"], b"jpeg"));
        let mut stream = Cursor::new(vec![0xff, 0xd8, 0xff, 0xe0, 0, 0, 0, 0]);

        // Hint disagrees with detected bytes: detected container wins.
        assert_eq!(reg.format_from_stream("png", &mut stream), "jpg");

        // Hint already matches the detected container family: hint is preserved as-is.
        assert_eq!(reg.format_from_stream("jpeg", &mut stream), "jpeg");
    }

    #[test]
    fn test_format_from_stream_falls_back_to_hint_when_undetectable() {
        let reg = HandlerRegistry::new();
        let mut stream = Cursor::new(vec![0u8; 4]);
        assert_eq!(
            reg.format_from_stream("custom/unknown", &mut stream),
            "custom/unknown"
        );
    }

    #[test]
    fn test_trims_and_lowercases_format_strings() {
        let reg = HandlerRegistry::new().with_handler(handler(&["image/jpeg"], b"jpeg"));
        assert!(reg.handler("  IMAGE/JPEG  ").is_some());
    }

    #[test]
    fn test_mime_for_derives_default_from_supported_types() {
        let reg =
            HandlerRegistry::new().with_handler(handler(&["jpg", "jpeg", "image/jpeg"], b"jpeg"));
        assert_eq!(reg.mime_for("jpg"), Some("image/jpeg"));
        assert_eq!(reg.mime_for("jpeg"), Some("image/jpeg"));
        assert_eq!(reg.mime_for("image/jpeg"), Some("image/jpeg"));
        assert_eq!(reg.mime_for("nonexistent/format"), None);
    }

    /// Regression test for the case a single-canonical-mime heuristic gets wrong: a handler
    /// whose `supported_types()` covers multiple distinct sub-formats must be able to
    /// override `mime_type_map()` to give each extension its own correct MIME type.
    #[test]
    fn test_mime_for_uses_explicit_mime_type_map_for_multi_format_handler() {
        let reg = HandlerRegistry::new().with_handler(handler_with_mime_map(
            &[
                "avif",
                "heif",
                "heic",
                "mp4",
                "application/mp4",
                "image/avif",
                "image/heic",
                "image/heif",
                "video/mp4",
            ],
            b"bmff",
            &[
                ("avif", "image/avif"),
                ("heif", "image/heif"),
                ("heic", "image/heic"),
                ("mp4", "video/mp4"),
            ],
        ));

        assert_eq!(reg.mime_for("heic"), Some("image/heic"));
        assert_eq!(reg.mime_for("heif"), Some("image/heif"));
        assert_eq!(reg.mime_for("avif"), Some("image/avif"));
        assert_eq!(reg.mime_for("mp4"), Some("video/mp4"));
    }

    #[test]
    fn test_format_to_mime_echoes_input_when_no_handler_registered() {
        let reg = HandlerRegistry::new();
        // No handler for "psd" — c2pa-rs doesn't process that format — so the normalized
        // input is returned unchanged rather than consulting any fixed table.
        assert_eq!(reg.format_to_mime("  PSD  "), "psd");
    }

    #[test]
    fn test_format_from_path_uses_registered_handler() {
        let reg = HandlerRegistry::new().with_handler(handler_with_mime_map(
            &["heic", "image/heic"],
            b"bmff",
            &[("heic", "image/heic")],
        ));
        assert_eq!(
            reg.format_from_path("photo.HEIC"),
            Some("image/heic".to_string())
        );
    }
}
