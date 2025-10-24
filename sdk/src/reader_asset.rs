use std::{
    fs::File,
    io::{Cursor, Read, Seek},
    path::Path,
};

use async_generic::async_generic;

use crate::{
    asset_io::CAIRead, settings::Settings, status_tracker::StatusTracker, store::Store, Reader,
    Result,
};

// Simple enum to handle different stream types
pub enum StreamType {
    File(File),
    Memory(Cursor<Vec<u8>>),
    Generic(Box<dyn CAIRead>),
}

impl Read for StreamType {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            StreamType::File(f) => f.read(buf),
            StreamType::Memory(c) => c.read(buf),
            StreamType::Generic(s) => s.read(buf),
        }
    }
}

impl Seek for StreamType {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match self {
            StreamType::File(f) => f.seek(pos),
            StreamType::Memory(c) => c.seek(pos),
            StreamType::Generic(s) => s.seek(pos),
        }
    }
}

pub struct ReaderAsset {
    pub settings: Settings,
    pub format: String,
    pub stream: StreamType,
    pub manifest_data: Option<Vec<u8>>,
    pub fragments: Option<Vec<StreamType>>,
}

impl ReaderAsset {
    pub fn from_file(settings: &Settings, path: &Path) -> Result<Self> {
        let format = crate::format_from_path(path).ok_or(crate::Error::UnsupportedType)?;
        let file = File::open(path)?;

        Ok(Self {
            settings: settings.clone(),
            format,
            stream: StreamType::File(file),
            manifest_data: None,
            fragments: None,
        })
    }

    pub fn from_memory(settings: &Settings, format: String, data: Vec<u8>) -> Self {
        Self {
            settings: settings.clone(),
            format,
            stream: StreamType::Memory(Cursor::new(data)),
            manifest_data: None,
            fragments: None,
        }
    }

    pub fn from_stream(settings: &Settings, format: String, stream: Box<dyn CAIRead>) -> Self {
        Self {
            settings: settings.clone(),
            format,
            stream: StreamType::Generic(stream),
            manifest_data: None,
            fragments: None,
        }
    }

    pub fn with_manifest_data(mut self, manifest_data: Vec<u8>) -> Self {
        self.manifest_data = Some(manifest_data);
        self
    }

    pub fn with_fragments(mut self, fragments: Vec<StreamType>) -> Self {
        self.fragments = Some(fragments);
        self
    }

    #[async_generic]
    pub fn to_reader(mut self) -> Result<Reader> {
        let mut validation_log = StatusTracker::default();
        let verify = self.settings.verify.verify_after_reading;

        if let Some(manifest_data) = self.manifest_data {
            if let Some(fragments) = self.fragments {
                // Convert Vec<StreamType> to Vec<Box<dyn CAIRead>>
                let mut fragment_boxes: Vec<Box<dyn CAIRead>> = fragments
                    .into_iter()
                    .map(|f| Box::new(f) as Box<dyn CAIRead>)
                    .collect();

                let store = if _sync {
                    Store::from_manifest_data_and_stream_and_fragments(
                        &manifest_data,
                        &self.format,
                        &mut self.stream,
                        &mut fragment_boxes,
                        verify,
                        &mut validation_log,
                        &self.settings,
                    )?
                } else {
                    Store::from_manifest_data_and_stream_and_fragments_async(
                        &manifest_data,
                        &self.format,
                        &mut self.stream,
                        &mut fragment_boxes,
                        verify,
                        &mut validation_log,
                        &self.settings,
                    )
                    .await?
                };

                if _sync {
                    Reader::from_store(store, &mut validation_log, &self.settings)
                } else {
                    Reader::from_store_async(store, &mut validation_log, &self.settings).await
                }
            } else {
                let store = if _sync {
                    Store::from_manifest_data_and_stream(
                        &manifest_data,
                        &self.format,
                        &mut self.stream,
                        verify,
                        &mut validation_log,
                        &self.settings,
                    )?
                } else {
                    Store::from_manifest_data_and_stream_async(
                        &manifest_data,
                        &self.format,
                        &mut self.stream,
                        verify,
                        &mut validation_log,
                        &self.settings,
                    )
                    .await?
                };

                if _sync {
                    Reader::from_store(store, &mut validation_log, &self.settings)
                } else {
                    Reader::from_store_async(store, &mut validation_log, &self.settings).await
                }
            }
        } else {
            let store = if _sync {
                Store::from_stream(
                    &self.format,
                    &mut self.stream,
                    verify,
                    &mut validation_log,
                    &self.settings,
                )?
            } else {
                Store::from_stream_async(
                    &self.format,
                    &mut self.stream,
                    verify,
                    &mut validation_log,
                    &self.settings,
                )
                .await?
            };

            if _sync {
                Reader::from_store(store, &mut validation_log, &self.settings)
            } else {
                Reader::from_store_async(store, &mut validation_log, &self.settings).await
            }
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
        let asset = ReaderAsset::from_memory(
            &settings,
            "image/jpeg".to_string(),
            IMAGE_WITH_MANIFEST.to_vec(),
        );
        let reader = asset.to_reader()?;
        assert!(reader.active_manifest().is_some());
        println!("{reader}");
        Ok(())
    }

    #[test]
    fn test_from_stream() -> Result<()> {
        let settings = Settings::default();
        let cursor = Cursor::new(IMAGE_WITH_MANIFEST.to_vec());
        let asset = ReaderAsset::from_stream(&settings, "image/jpeg".to_string(), Box::new(cursor));
        let reader = asset.to_reader()?;
        assert!(reader.active_manifest().is_some());
        println!("{reader}");
        Ok(())
    }
}
