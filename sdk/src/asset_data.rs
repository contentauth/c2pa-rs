use std::{
    io::{Cursor, Read, Seek},
    path::Path,
};

use async_generic::async_generic;

use crate::{asset_io::CAIRead, settings::Settings, Reader, Result};

/// An enum representing different types of assets that can be read by the Reader
pub enum AssetData<'a> {
    Stream(Box<dyn CAIRead + 'a>, &'a str),
    StreamFragment(&'a mut dyn CAIRead, &'a mut dyn CAIRead, &'a str),
    StreamWithManifest(Box<dyn CAIRead + 'a>, &'a str, &'a [u8]),
    StreamFragments(&'a mut dyn CAIRead, &'a mut [Box<dyn CAIRead>], &'a str),
    StreamWithManifestsAndFragments(
        &'a mut dyn CAIRead,
        &'a mut [Box<dyn CAIRead>],
        &'a str,
        &'a [u8],
    ),
}

impl<'a> AssetData<'a> {
    /// Create a ReaderAsset from a file path
    #[cfg(feature = "file_io")]
    pub fn from_file(path: &'a Path) -> Result<Self> {
        use std::fs::File;
        let format = crate::format_from_path(path).ok_or(crate::Error::UnsupportedType)?;
        let file = File::open(path)?;
        Ok(Self::Stream(
            Box::new(file),
            Box::leak(format.into_boxed_str()),
        ))
    }

    /// Create a ReaderAsset from in-memory data
    pub fn from_memory(data: &'a [u8], format: &'a str) -> Self {
        let cursor = Cursor::new(data);
        Self::Stream(Box::new(cursor), format)
    }

    /// Create a ReaderAsset from a stream that implements Read + Seek + Send
    pub fn from_stream<T: Read + Seek + Send + 'a>(stream: T, format: &'a str) -> Self {
        Self::Stream(Box::new(stream), format)
    }

    /// Create a ReaderAsset from a stream with fragment
    pub fn from_stream_fragment(
        initial_segment: &'a mut dyn CAIRead,
        fragment: &'a mut dyn CAIRead,
        format: &'a str,
    ) -> Self {
        Self::StreamFragment(initial_segment, fragment, format)
    }

    /// Create a ReaderAsset from bytes in a cursor
    pub fn from_cursor(data: Vec<u8>, format: &'a str) -> Self {
        let cursor = Cursor::new(data);
        Self::from_stream(cursor, format)
    }

    /// Create a ReaderAsset from a stream with separate manifest data
    pub fn from_manifest_data_and_stream<T: Read + Seek + Send + 'a>(
        manifest_data: &'a [u8],
        stream: T,
        format: &'a str,
    ) -> Self {
        Self::StreamWithManifest(Box::new(stream), format, manifest_data)
    }

    /// Create a ReaderAsset from an initial segment and fragment streams for fragmented MP4
    pub fn from_fragment_streams(
        initial_segment: &'a mut dyn CAIRead,
        fragments: &'a mut [Box<dyn CAIRead>],
        format: &'a str,
    ) -> Self {
        Self::StreamFragments(initial_segment, fragments, format)
    }

    /// Create a ReaderAsset from an initial segment and fragment streams with manifest data for fragmented MP4
    pub fn from_manifest_data_and_fragment_streams(
        manifest_data: &'a [u8],
        initial_segment: &'a mut dyn CAIRead,
        fragments: &'a mut [Box<dyn CAIRead>],
        format: &'a str,
    ) -> Self {
        Self::StreamWithManifestsAndFragments(initial_segment, fragments, format, manifest_data)
    }

    /// Convert to a Reader by processing the asset data with the given settings
    #[async_generic]
    pub fn to_reader(self, settings: &Settings) -> Result<Reader> {
        if _sync {
            Reader::from_asset(self, settings)
        } else {
            Reader::from_asset_async(self, settings).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");

    #[test]
    fn test_from_memory() -> Result<()> {
        let settings = Settings::default();
        let asset = AssetData::from_memory(IMAGE_WITH_MANIFEST, "image/jpeg");
        let reader = asset.to_reader(&settings)?;
        assert!(reader.active_manifest().is_some());
        println!("{reader}");
        Ok(())
    }

    #[test]
    fn test_from_cursor() -> Result<()> {
        let settings = Settings::default();
        let asset = AssetData::from_cursor(IMAGE_WITH_MANIFEST.to_vec(), "image/jpeg");
        let reader = asset.to_reader(&settings)?;
        assert!(reader.active_manifest().is_some());
        println!("{reader}");
        Ok(())
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn test_from_file() -> Result<()> {
        use std::path::Path;

        let settings = Settings::default();
        let path = Path::new("tests/fixtures/CA.jpg");
        let asset = AssetData::from_file(path)?;
        let reader = asset.to_reader(&settings)?;
        assert!(reader.active_manifest().is_some());
        Ok(())
    }
}
