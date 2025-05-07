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

pub mod bmff_io;
pub mod c2pa_io;
pub mod dash_io;
pub mod gif_io;
pub mod jpeg_io;
pub mod mp3_io;
pub mod png_io;
pub mod riff_io;
pub mod svg_io;
pub mod tiff_io;

#[cfg(feature = "pdf")]
pub(crate) mod pdf;
#[cfg(feature = "pdf")]
pub mod pdf_io;

use std::path::Path;

use crate::error::Result;
use crate::asset_io::HashObjectPositions;

pub trait AssetIO {
    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch>;
    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>>;
    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()>;
    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>>;
    fn remove_cai_store(&self, asset_path: &Path) -> Result<()>;
}

pub trait AssetPatch {
    fn patch_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()>;
}

pub trait CAIReader {
    fn read_cai(&self, reader: &mut dyn CAIRead) -> Result<Vec<u8>>;
    fn read_xmp(&self, reader: &mut dyn CAIRead) -> Option<String>;
}

pub trait CAIWriter {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()>;
    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>>;
    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()>;
}

pub trait CAIRead: std::io::Read + std::io::Seek {
    fn rewind(&mut self) -> Result<()> {
        self.seek(std::io::SeekFrom::Start(0))?;
        Ok(())
    }
}

pub trait CAIReadWrite: CAIRead + std::io::Write {}

impl<T: std::io::Read + std::io::Seek> CAIRead for T {}
impl<T: std::io::Read + std::io::Seek + std::io::Write> CAIReadWrite for T {}

pub trait RemoteRefEmbed {
    fn embed_reference(&self, asset_path: &Path, embed_ref: RemoteRefEmbedType) -> Result<()>;
    fn embed_reference_to_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        embed_ref: RemoteRefEmbedType,
    ) -> Result<()>;
}

#[derive(Debug, Clone)]
pub enum RemoteRefEmbedType {
    Url(String),
    ManifestStore(Vec<u8>),
}
