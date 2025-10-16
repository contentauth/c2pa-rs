use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
};

use tempfile::Builder;
use zip::{
    result::{ZipError, ZipResult},
    write::SimpleFileOptions,
    CompressionMethod, ZipArchive, ZipWriter,
};

use crate::{
    asset_io::{
        self, AssetIO, CAIRead, CAIReadWrapper, CAIReadWrite, CAIReadWriteWrapper, CAIReader,
        CAIWriter, HashObjectPositions,
    },
    error::Result,
    Error,
};

pub struct ZipIO {}

impl CAIWriter for ZipIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        mut store_bytes: &[u8],
    ) -> Result<()> {
        let mut writer = self
            .writer(input_stream, output_stream)
            .map_err(|_| Error::EmbeddingError)?;

        match writer.add_directory("META-INF", SimpleFileOptions::default()) {
            Err(ZipError::InvalidArchive(err)) if err.starts_with("Duplicate filename") => {}
            Err(err) => {
                println!("{:?}", err);
                return Err(Error::EmbeddingError);
            }
            _ => {}
        }

        match writer.start_file_from_path(
            Path::new("META-INF/content_credential.c2pa"),
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        ) {
            Err(ZipError::InvalidArchive(err)) if err.starts_with("Duplicate filename") => {
                writer.abort_file().map_err(|_| Error::EmbeddingError)?;
                // TODO: remove code duplication
                writer
                    .start_file_from_path(
                        Path::new("META-INF/content_credential.c2pa"),
                        SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
                    )
                    .map_err(|_| Error::EmbeddingError)?;
            }
            Err(_) => return Err(Error::EmbeddingError),
            _ => {}
        }

        io::copy(&mut store_bytes, &mut writer)?;
        writer.finish().map_err(|_| Error::EmbeddingError)?;

        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        _input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        // TODO: error?
        Ok(Vec::new())
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        let mut writer = self
            .writer(input_stream, output_stream)
            .map_err(|_| Error::EmbeddingError)?;

        match writer.start_file_from_path(
            Path::new("META-INF/content_credential.c2pa"),
            SimpleFileOptions::default(),
        ) {
            Err(ZipError::InvalidArchive(err)) if err.starts_with("Duplicate filename") => {}
            Err(_) => return Err(Error::EmbeddingError),
            _ => {}
        }
        writer.abort_file().map_err(|_| Error::EmbeddingError)?;
        writer.finish().map_err(|_| Error::EmbeddingError)?;

        Ok(())
    }
}

impl CAIReader for ZipIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let mut reader = self
            .reader(asset_reader)
            .map_err(|_| Error::JumbfNotFound)?;

        let index = reader
            .index_for_path(Path::new("META-INF/content_credential.c2pa"))
            .ok_or(Error::JumbfNotFound)?;
        let mut file = reader.by_index(index).map_err(|_| Error::JumbfNotFound)?;

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;

        Ok(bytes)
    }

    fn read_xmp(&self, _asset_reader: &mut dyn CAIRead) -> Option<String> {
        None
    }
}

impl AssetIO for ZipIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        ZipIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(ZipIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(ZipIO::new(asset_type)))
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut stream = fs::OpenOptions::new()
            .read(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        let mut temp_file = Builder::new()
            .prefix("c2pa_temp")
            .rand_bytes(5)
            .tempfile()?;

        self.write_cai(&mut stream, &mut temp_file, store_bytes)?;

        asset_io::rename_or_move(temp_file, asset_path)
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        let mut f = std::fs::File::open(asset_path).map_err(|_err| Error::EmbeddingError)?;
        self.get_object_locations_from_stream(&mut f)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        let mut stream = fs::OpenOptions::new()
            .read(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        let mut temp_file = Builder::new()
            .prefix("c2pa_temp")
            .rand_bytes(5)
            .tempfile()?;

        self.remove_cai_store_from_stream(&mut stream, &mut temp_file)?;

        asset_io::rename_or_move(temp_file, asset_path)
    }

    fn supported_types(&self) -> &[&str] {
        &[
            // Zip
            "zip",
            "application/x-zip",
            // EPUB
            "epub",
            "application/epub+zip",
            // Office Open XML
            "docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "pptx",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "docm",
            "application/vnd.ms-word.document.macroenabled.12",
            "xlsm",
            "application/vnd.ms-excel.sheet.macroenabled.12",
            "pptm",
            "application/vnd.ms-powerpoint.presentation.macroenabled.12",
            // Open Document
            "odt",
            "application/vnd.oasis.opendocument.text",
            "ods",
            "application/vnd.oasis.opendocument.spreadsheet",
            "odp",
            "application/vnd.oasis.opendocument.presentation",
            "odg",
            "application/vnd.oasis.opendocument.graphics",
            "ott",
            "application/vnd.oasis.opendocument.text-template",
            "ots",
            "application/vnd.oasis.opendocument.spreadsheet-template",
            "otp",
            "application/vnd.oasis.opendocument.presentation-template",
            "otg",
            "application/vnd.oasis.opendocument.graphics-template",
            // OpenXPS
            "oxps",
            "application/oxps",
        ]
    }
}

impl ZipIO {
    fn reader<'a>(
        &self,
        input_stream: &'a mut dyn CAIRead,
    ) -> ZipResult<ZipArchive<CAIReadWrapper<'a>>> {
        ZipArchive::new(CAIReadWrapper {
            reader: input_stream,
        })
    }

    fn writer<'a>(
        &self,
        input_stream: &'a mut dyn CAIRead,
        output_stream: &'a mut dyn CAIReadWrite,
    ) -> ZipResult<ZipWriter<CAIReadWriteWrapper<'a>>> {
        input_stream.rewind()?;
        io::copy(input_stream, output_stream)?;

        ZipWriter::new_append(CAIReadWriteWrapper {
            reader_writer: output_stream,
        })
    }
}

#[cfg(test)]
mod tests {
    use io::{Cursor, Seek};

    use super::*;

    // TODO: add more sample file types
    const SAMPLES: [&[u8]; 3] = [
        include_bytes!("../../tests/fixtures/sample1.zip"),
        include_bytes!("../../tests/fixtures/sample1.docx"),
        include_bytes!("../../tests/fixtures/sample1.odt"),
    ];

    #[test]
    fn test_write_bytes() -> Result<()> {
        for sample in SAMPLES {
            let mut stream = Cursor::new(sample);

            let zip_io = ZipIO {};

            assert!(matches!(
                zip_io.read_cai(&mut stream),
                Err(Error::JumbfNotFound)
            ));

            let mut output_stream = Cursor::new(Vec::with_capacity(sample.len() + 7));
            let random_bytes = [1, 2, 3, 4, 3, 2, 1];
            zip_io.write_cai(&mut stream, &mut output_stream, &random_bytes)?;

            let data_written = zip_io.read_cai(&mut output_stream)?;
            assert_eq!(data_written, random_bytes);
        }

        Ok(())
    }

    #[test]
    fn test_write_bytes_replace() -> Result<()> {
        for sample in SAMPLES {
            let mut stream = Cursor::new(sample);

            let zip_io = ZipIO {};

            assert!(matches!(
                zip_io.read_cai(&mut stream),
                Err(Error::JumbfNotFound)
            ));

            let mut output_stream1 = Cursor::new(Vec::with_capacity(sample.len() + 7));
            let random_bytes = [1, 2, 3, 4, 3, 2, 1];
            zip_io.write_cai(&mut stream, &mut output_stream1, &random_bytes)?;

            let data_written = zip_io.read_cai(&mut output_stream1)?;
            assert_eq!(data_written, random_bytes);

            let mut output_stream2 = Cursor::new(Vec::with_capacity(sample.len() + 5));
            let random_bytes = [3, 2, 1, 2, 3];
            zip_io.write_cai(&mut output_stream1, &mut output_stream2, &random_bytes)?;

            let data_written = zip_io.read_cai(&mut output_stream2)?;
            assert_eq!(data_written, random_bytes);

            let mut bytes = Vec::new();
            stream.rewind()?;
            stream.read_to_end(&mut bytes)?;
            assert_eq!(sample, bytes);
        }

        Ok(())
    }
}
