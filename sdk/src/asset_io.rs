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

use std::{
    fmt,
    io::{Read, Seek, Write},
    path::Path,
};

use tempfile::NamedTempFile;

use crate::{assertions::BoxMap, error::Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashBlockObjectType {
    Cai,
    Xmp,
    Other,
}

impl fmt::Display for HashBlockObjectType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
#[derive(Debug)]
pub struct HashObjectPositions {
    pub offset: usize, // offset from beginning of file to the beginning of object
    pub length: usize, // length of object
    pub htype: HashBlockObjectType, // type of hash block object
}

// Disable `Send` for wasm32 since we are not sending data across threads
#[cfg(target_arch = "wasm32")]
pub trait CAIRead: Read + Seek {}
#[cfg(not(target_arch = "wasm32"))]
pub trait CAIRead: Read + Seek + Send {}

impl CAIRead for std::fs::File {}
impl CAIRead for std::io::Cursor<&[u8]> {}
impl CAIRead for std::io::Cursor<&mut [u8]> {}
impl CAIRead for std::io::Cursor<Vec<u8>> {}
impl CAIRead for NamedTempFile {}

// Helper struct to create a concrete type for CAIRead when
// that is required.  For example a function defined like this
//  pub fn read<T>(&self, reader: &mut T) cannot currently accept
// a CAIRead trait because it is not Sized (bound to a object).
// This will likely change in a future version of Rust.
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

pub trait CAIReadWrite: CAIRead + Write {}

impl CAIReadWrite for std::fs::File {}
impl CAIReadWrite for std::io::Cursor<&mut [u8]> {}
impl CAIReadWrite for std::io::Cursor<Vec<u8>> {}
impl CAIReadWrite for NamedTempFile {}

// Helper struct to create a concrete type for CAIReadWrite when
// that is required. For example a function defined like this
//  pub fn write<T>(&self, writer: &mut T) cannot currently accept
// a CAIReadWrite trait because it is not Sized (bound to a object).
// This will likely change in a future version of Rust.
// go away in future revisions of Rust.
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

/// CAIReader trait to insure CAILoader method support both Read & Seek
// Interface for in memory CAI reading
pub trait CAIReader: Sync + Send {
    // Return entire CAI block as Vec<u8>
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>>;

    // Get XMP block
    fn read_xmp(&self, asset_reader: &mut dyn CAIRead) -> Option<String>;
}

pub trait CAIWriter: Sync + Send {
    // Writes store_bytes into output_steam using input_stream as the source asset
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()>;

    // Finds location where the C2PA manifests will be placed in the asset specified by input_stream
    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>>;

    // Remove entire C2PA manifest store from asset
    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()>;
}

pub trait AssetIO: Sync + Send {
    // Create instance of AssetIO handler.  The extension type is passed in so
    // that format specific customizations can be used during manifest embedding
    fn new(asset_type: &str) -> Self
    where
        Self: Sized;

    // Return AssetIO handler for this asset type
    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO>;

    // Return streaming reader for this asset type
    fn get_reader(&self) -> &dyn CAIReader;

    // Return streaming writer if available
    fn get_writer(&self, _asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        None
    }

    // Return entire CAI block as Vec<u8>
    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>>;

    // Write the CAI block to an asset
    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()>;

    /// List of standard object offsets
    /// If the offsets exist return the start of those locations other it should
    /// return the calculated location of when it should start.  There may still be a
    /// length if the format contains extra header information for example.
    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>>;

    // Remove entire C2PA manifest store from asset
    fn remove_cai_store(&self, asset_path: &Path) -> Result<()>;

    // List of supported extensions and mime types
    fn supported_types(&self) -> &[&str];

    /// OPTIONAL INTERFACES

    // Returns [`AssetPatch`] trait if this I/O handler supports patching.
    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        None
    }

    // Returns [`RemoteRefEmbed`] trait if this I/O handler supports remote reference embedding.
    fn remote_ref_writer_ref(&self) -> Option<&dyn RemoteRefEmbed> {
        None
    }

    // Returns [`AssetBoxHash`] trait if this I/O handler supports box hashing.
    fn asset_box_hash_ref(&self) -> Option<&dyn AssetBoxHash> {
        None
    }

    // Returns [`ComposedManifestRefEmbed`] trait if this I/O handler supports composed data.
    fn composed_data_ref(&self) -> Option<&dyn ComposedManifestRef> {
        None
    }
}

// `AssetPatch` optimizes output generation for asset_io handlers that
// are able to patch blocks of data without changing any other data. The
// resultant file must still be a valid asset. This saves having to rewrite
// assets since only the patched bytes are modified.
pub trait AssetPatch {
    // Patches an existing manifest store with new manifest store.
    // Only existing manifest stores of the same size may be patched
    // since any other changes will invalidate asset hashes.
    fn patch_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()>;
}

// `AssetBoxHash` provides interfaces needed to support C2PA BoxHash functionality.
//  This trait is only implemented for supported types
pub trait AssetBoxHash {
    // Returns Vec containing all BoxMap level objects in the asset in the order
    // they occur in the asset.  The hashes do not need to be calculated, only the
    // name and the positional information.  The list should be flat with each BoxMap
    // representing a single entry.
    fn get_box_map(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<BoxMap>>;
}

// Type of remote reference to embed.  Some of the listed
// emums are for future uses and experiments.
#[allow(unused_variables)]
pub enum RemoteRefEmbedType {
    Xmp(String),
    StegoS(String),
    StegoB(Vec<u8>),
    Watermark(String),
}

// `RemoteRefEmbed` is used to embed remote references to external manifests.  The
// technique used to embed a reference varies bases on the type of embedding.  Not
// all embedding choices need be supported.
pub trait RemoteRefEmbed {
    // Embed RemoteRefEmbedType into the asset
    fn embed_reference(&self, asset_path: &Path, embed_ref: RemoteRefEmbedType) -> Result<()>;
    // Embed RemoteRefEmbedType into the asset stream
    fn embed_reference_to_stream(
        &self,
        source_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        embed_ref: RemoteRefEmbedType,
    ) -> Result<()>;
}

/// `ComposedManifestRefEmbed` is used to generate a C2PA manifest.  The
/// returned `Vec<u8>` contains data preformatted to be directly compatible
/// with the type specified in `format`.  
pub trait ComposedManifestRef {
    // Return entire CAI block as Vec<u8>
    fn compose_manifest(&self, manifest_data: &[u8], format: &str) -> Result<Vec<u8>>;
}
