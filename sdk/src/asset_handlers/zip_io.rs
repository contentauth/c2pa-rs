use std::{
    fs::{self, File},
    io::{self, Read, Seek},
    path::Path,
};

use tempfile::Builder;
use zip::{result::ZipResult, write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

use crate::{
    assertions::{UriHashResolver, UriHashedDataMap},
    asset_io::{
        self, AssetIO, CAIReadWrapper, CAIReadWriteWrapper, CAIReader, CAIWriter,
        HashObjectPositions,
    },
    error::Result,
    CAIRead, CAIReadWrite, Error, HashRange,
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

        // TODO: what happens if the dir exists?
        writer
            .add_directory("META-INF", SimpleFileOptions::default())
            .map_err(|_| Error::EmbeddingError)?;

        writer
            .start_file_from_path(
                Path::new("META-INF/content_credential.c2pa"),
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
            )
            .map_err(|_| Error::EmbeddingError)?;
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

        writer
            .start_file_from_path(
                Path::new("META-INF/content_credential.c2pa"),
                SimpleFileOptions::default(),
            )
            .map_err(|_| Error::EmbeddingError)?;
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
            "application/vnd.ms-word.document.macroEnabled.12",
            "xlsm",
            "application/vnd.ms-excel.sheet.macroEnabled.12",
            "pptm",
            "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
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
    fn writer<'a>(
        &self,
        input_stream: &'a mut dyn CAIRead,
        output_stream: &'a mut dyn CAIReadWrite,
    ) -> ZipResult<ZipWriter<CAIReadWriteWrapper<'a>>> {
        let mut writer = ZipWriter::new_append(CAIReadWriteWrapper {
            reader_writer: output_stream,
        })?;

        writer.merge_archive(ZipArchive::new(CAIReadWrapper {
            reader: input_stream,
        })?)?;

        Ok(writer)
    }

    fn reader<'a>(
        &self,
        input_stream: &'a mut dyn CAIRead,
    ) -> ZipResult<ZipArchive<CAIReadWrapper<'a>>> {
        ZipArchive::new(CAIReadWrapper {
            reader: input_stream,
        })
    }
}

pub fn central_directory_inclusions<R>(reader: &mut R) -> Result<Vec<HashRange>>
where
    R: Read + Seek + ?Sized,
{
    let _reader = ZipArchive::new(reader).map_err(|_| Error::JumbfNotFound)?;

    // TODO: https://github.com/zip-rs/zip2/pull/71
    //       or
    //       https://gitlab.com/xMAC94x/zip-core (https://github.com/zip-rs/zip2/issues/204)

    todo!()
}

pub struct ZipHashResolver {
    ranges: Vec<HashRange>,
    i: usize,
}

impl ZipHashResolver {
    pub fn new<R: Read + Seek + ?Sized>(
        stream: &mut R,
        uri_maps: &[UriHashedDataMap],
    ) -> Result<Self> {
        let mut reader = ZipArchive::new(stream).map_err(|_| Error::JumbfNotFound)?;

        let mut ranges = Vec::new();
        for uri_map in uri_maps {
            let index = reader
                .index_for_path(Path::new(&uri_map.uri))
                .ok_or(Error::JumbfNotFound)?;
            let file = reader.by_index(index).map_err(|_| Error::JumbfNotFound)?;
            // TODO: hash from header or data? does compressed_size include header?
            //       and fix error type
            ranges.push(HashRange::new(
                usize::try_from(file.header_start()).map_err(|_| Error::JumbfNotFound)?,
                usize::try_from(file.compressed_size()).map_err(|_| Error::JumbfNotFound)?,
            ));
        }

        Ok(Self { ranges, i: 0 })
    }
}

impl UriHashResolver for ZipHashResolver {
    fn resolve(&mut self, _uri_map: &UriHashedDataMap) -> Vec<HashRange> {
        let range = self.ranges[self.i].clone();
        self.i += 1;
        vec![range]
    }
}
