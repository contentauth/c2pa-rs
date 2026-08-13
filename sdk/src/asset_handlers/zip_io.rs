use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use tempfile::Builder;
use zip::{result::ZipResult, write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

use crate::{
    asset_io::{
        self, AssetIO, CAIRead, CAIReadWrapper, CAIReadWrite, CAIReadWriteWrapper, CAIReader,
        CAIWriter, HashObjectPositions,
    },
    error::Result,
    Error, HashRange,
};

pub(crate) const MANIFEST_PATH: &str = "META-INF/content_credential.c2pa";

pub(crate) const CENTRAL_DIRECTORY_CRC_OFFSET: u64 = 16;
pub(crate) const CRC_LEN: u64 = 4;

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
            .map_err(ZipError::Write)?;

        match writer.add_directory("META-INF", SimpleFileOptions::default()) {
            Err(zip::result::ZipError::InvalidArchive(err))
                if err.starts_with("Duplicate filename") => {}
            Err(source) => return Err(ZipError::Write(source).into()),
            _ => {}
        }

        match writer.start_file_from_path(
            Path::new(MANIFEST_PATH),
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        ) {
            Err(zip::result::ZipError::InvalidArchive(err))
                if err.starts_with("Duplicate filename") =>
            {
                writer.abort_file().map_err(ZipError::Write)?;
                writer
                    .start_file_from_path(
                        Path::new(MANIFEST_PATH),
                        SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
                    )
                    .map_err(ZipError::Write)?;
            }
            Err(source) => return Err(ZipError::Write(source).into()),
            _ => {}
        }

        io::copy(&mut store_bytes, &mut writer)?;
        writer.finish().map_err(ZipError::Write)?;

        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        _input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        Err(ZipError::ObjectLocationsUnsupported.into())
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        let mut writer = self
            .writer(input_stream, output_stream)
            .map_err(ZipError::Remove)?;

        match writer.start_file_from_path(Path::new(MANIFEST_PATH), SimpleFileOptions::default()) {
            Err(zip::result::ZipError::InvalidArchive(err))
                if err.starts_with("Duplicate filename") => {}
            Err(source) => return Err(ZipError::Remove(source).into()),
            _ => {}
        }
        writer.abort_file().map_err(ZipError::Remove)?;
        writer.finish().map_err(ZipError::Remove)?;

        Ok(())
    }
}

impl CAIReader for ZipIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let mut reader = self.reader(asset_reader).map_err(ZipError::Read)?;

        let index = reader
            .index_for_path(Path::new(MANIFEST_PATH))
            .ok_or(Error::JumbfNotFound)?;
        let mut file = reader.by_index(index).map_err(ZipError::Read)?;

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

    fn get_object_locations(&self, _asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        Err(ZipError::ObjectLocationsUnsupported.into())
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

/// Computes the byte ranges for the ZIP central directory, skipping the manifest's checksum (if present).
pub(crate) fn zip_central_directory_range<R>(reader: &mut R) -> Result<Vec<HashRange>>
where
    R: Read + Seek + ?Sized,
{
    let length = reader.seek(SeekFrom::End(0))?;
    let mut reader = ZipArchive::new(reader).map_err(ZipError::Read)?;

    let start = reader.central_directory_start();

    let range = match reader.index_for_path(Path::new(MANIFEST_PATH)) {
        Some(index) => {
            let file = reader.by_index(index).map_err(ZipError::Read)?;
            let crc_start = file.central_header_start() + CENTRAL_DIRECTORY_CRC_OFFSET;
            vec![
                HashRange::new(start, crc_start - start),
                HashRange::new(crc_start + CRC_LEN, length - (crc_start + CRC_LEN)),
            ]
        }
        None => vec![HashRange::new(start, length - start)],
    };

    Ok(range)
}

/// Computes the byte ranges for each file entry in a ZIP stream, from local header entry to end of data.
pub(crate) fn zip_uri_ranges<R>(stream: &mut R) -> Result<HashMap<PathBuf, HashRange>>
where
    R: Read + Seek + ?Sized,
{
    let mut reader = ZipArchive::new(stream).map_err(ZipError::Read)?;

    let mut ranges = HashMap::new();
    let file_names: Vec<String> = reader.file_names().map(|n| n.to_owned()).collect();
    for file_name in file_names {
        let file = reader.by_name(&file_name).map_err(ZipError::Read)?;

        if !file.is_dir() {
            match file.enclosed_name() {
                Some(path) => {
                    if path != Path::new(MANIFEST_PATH) {
                        let header_start = file.header_start();
                        let data_start = file.data_start().ok_or(Error::JumbfNotFound)?;
                        let len = (data_start + file.compressed_size()) - header_start;
                        ranges.insert(path, HashRange::new(header_start, len));
                    }
                }
                None => {
                    return Err(Error::BadParam(format!(
                        "Invalid stored path `{}` in zip file",
                        file_name
                    )))
                }
            }
        }
    }

    Ok(ranges)
}

/// Errors that can occur while handling C2PA data in a ZIP-based asset.
#[derive(Debug, thiserror::Error)]
pub enum ZipError {
    /// The asset could not be read as a ZIP container.
    #[error("could not read the ZIP")]
    Read(#[source] zip::result::ZipError),

    /// The C2PA manifest could not be embedded into the ZIP.
    #[error("could not embed the C2PA manifest into the ZIP")]
    Write(#[source] zip::result::ZipError),

    /// The C2PA manifest could not be removed from the ZIP.
    #[error("could not remove the C2PA manifest from the ZIP")]
    Remove(#[source] zip::result::ZipError),

    /// Data hashing (object locations) is not supported for ZIP.
    #[error("data hashing is not supported for ZIP, use a collection hash instead")]
    ObjectLocationsUnsupported,
}

#[cfg(test)]
mod tests {
    use io::{Cursor, Seek};

    use super::*;

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
