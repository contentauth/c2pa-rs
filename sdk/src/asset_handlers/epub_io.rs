use crate::{
    asset_io::{AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashObjectPositions},
    // assertions::Metadata,
    error::Result,
};

use std::path::Path;

static SUPPORTED_TYPES: [&str; 6] = [
    "epub",
    "application/epub+zip",
    "application/zip",
    "application/octet-stream",
    "zip",
    ""
];
pub struct EpubIo;

impl AssetIO for EpubIo {
    fn supported_types(&self) -> &[&str] {
        println!("supported_types called for EPUB");
        &SUPPORTED_TYPES
    }

    fn new(_asset_type: &str) -> Self {
        println!("EpubIo::new() called");

        EpubIo
    }

    fn get_handler(&self, _asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(EpubIo::new(""))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, _asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(EpubIo))
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        println!("EPUB read_cai_store called on {:?}", asset_path);
        Ok(vec![]) //temporarily return empty vec
    }

    fn save_cai_store(&self, asset_path: &Path, _store_bytes: &[u8]) -> Result<()> {
        println!("EPUB save_cai_store called on {:?}", asset_path);
        Ok(())
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        println!("EPUB get_object_locations called on {:?}", asset_path);
        Ok(vec![]) // stub implementation
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        println!("EPUB remove_cai_store called on {:?}", asset_path);
        Ok(())
    }
}

impl CAIReader for EpubIo {
    fn read_cai(&self, _reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        println!("EPUB read_cai called!");
        Ok(vec![])
    }

    fn read_xmp(&self, _reader: &mut dyn CAIRead) -> Option<String> {
        println!("EPUB read_xmp called!");
        None
    }
}

impl CAIWriter for EpubIo {
    fn write_cai(
        &self,
        _input: &mut dyn CAIRead,
        _output: &mut dyn CAIReadWrite,
        _store_bytes: &[u8],
    ) -> Result<()> {
        println!("EPUB write_cai called!");
        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        _input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        println!("EPUB get_object_locations_from_stream called!");
        Ok(vec![])
    }

    fn remove_cai_store_from_stream(
        &self,
        _input_stream: &mut dyn CAIRead,
        _output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        println!("EPUB remove_cai_store_from_stream called!");
        Ok(())
    }
}
