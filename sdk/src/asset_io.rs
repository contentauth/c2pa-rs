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
    fmt, fs,
    io::{Cursor, Read, Seek, Write},
    path::Path,
};

use tempfile::NamedTempFile;

use crate::{
    assertions::BoxMap,
    error::Result,
    maybe_send_sync::MaybeSend,
    utils::{
        io_utils::tempfile_builder,
        xmp_inmemory_utils::{add_provenance, MIN_XMP},
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
    ///
    /// # Deprecation
    /// This method has no remaining callers within the SDK itself — it exists only
    /// to back the deprecated `jumbf_io::remove_jumbf_from_file` (only available with
    /// the `file_io` feature) — and is slated for removal in a future release.
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
    fn patch_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()>;
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
}

/// Generates a pre-composed C2PA manifest ready for direct insertion into an
/// asset of a given format.
pub trait ComposedManifestRef {
    /// Wraps `manifest_data` into the container structure expected by `format`
    /// (e.g. a JPEG APP11 segment, or a PNG `caBX` chunk).
    fn compose_manifest(&self, manifest_data: &[u8], format: &str) -> Result<Vec<u8>>;
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
