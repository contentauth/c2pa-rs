use std::{
    collections::HashMap,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use zip::{
    result::ZipResult, write::SimpleFileOptions, CompressionMethod, HasZipMetadata, ZipArchive,
    ZipWriter,
};

use crate::{
    asset_io::{AssetIO, C2paReader, C2paWriter, ObjectLocations, ReadSeek, ReadWriteSeek},
    error::Result,
    Error, HashRange,
};

const MANIFEST_PATH: &str = "META-INF/content_credential.c2pa";

const CENTRAL_DIRECTORY_CRC_OFFSET: u64 = 16;
const CRC_LEN: u64 = 4;

const DATA_DESCRIPTOR_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x07, 0x08];
const LOCAL_FILE_HEADER_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const CENTRAL_DIRECTORY_HEADER_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];

pub struct ZipIO {}

impl C2paWriter for ZipIO {
    fn write_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        mut store_bytes: &[u8],
    ) -> Result<()> {
        let mut writer = self.writer(input_stream, output_stream).map_err(|e| {
            Error::InvalidAsset(format!(
                "could not embed the C2PA manifest into the ZIP: {e}"
            ))
        })?;

        match writer.add_directory("META-INF", SimpleFileOptions::DEFAULT) {
            Err(zip::result::ZipError::InvalidArchive(err))
                if err.starts_with("Duplicate filename") => {}
            Err(source) => {
                return Err(Error::InvalidAsset(format!(
                    "could not embed the C2PA manifest into the ZIP: {source}"
                )))
            }
            _ => {}
        }

        match writer.start_file_from_path(
            Path::new(MANIFEST_PATH),
            SimpleFileOptions::DEFAULT.compression_method(CompressionMethod::Stored),
        ) {
            Err(zip::result::ZipError::InvalidArchive(err))
                if err.starts_with("Duplicate filename") =>
            {
                writer.abort_file().map_err(|e| {
                    Error::InvalidAsset(format!(
                        "could not embed the C2PA manifest into the ZIP: {e}"
                    ))
                })?;
                writer
                    .start_file_from_path(
                        Path::new(MANIFEST_PATH),
                        SimpleFileOptions::DEFAULT.compression_method(CompressionMethod::Stored),
                    )
                    .map_err(|e| {
                        Error::InvalidAsset(format!(
                            "could not embed the C2PA manifest into the ZIP: {e}"
                        ))
                    })?;
            }
            Err(source) => {
                return Err(Error::InvalidAsset(format!(
                    "could not embed the C2PA manifest into the ZIP: {source}"
                )))
            }
            _ => {}
        }

        io::copy(&mut store_bytes, &mut writer)?;
        writer.finish().map_err(|e| {
            Error::InvalidAsset(format!(
                "could not embed the C2PA manifest into the ZIP: {e}"
            ))
        })?;

        Ok(())
    }

    fn get_object_locations(
        &self,
        _input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        Err(Error::NotImplemented(
            "data hashing is not supported for ZIP, use a collection hash instead".to_string(),
        ))
    }

    fn remove_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        let mut writer = self.writer(input_stream, output_stream).map_err(|e| {
            Error::InvalidAsset(format!(
                "could not remove the C2PA manifest from the ZIP: {e}"
            ))
        })?;

        match writer.start_file_from_path(Path::new(MANIFEST_PATH), SimpleFileOptions::default()) {
            Err(zip::result::ZipError::InvalidArchive(err))
                if err.starts_with("Duplicate filename") => {}
            Err(source) => {
                return Err(Error::InvalidAsset(format!(
                    "could not remove the C2PA manifest from the ZIP: {source}"
                )))
            }
            _ => {}
        }
        writer.abort_file().map_err(|e| {
            Error::InvalidAsset(format!(
                "could not remove the C2PA manifest from the ZIP: {e}"
            ))
        })?;
        writer.finish().map_err(|e| {
            Error::InvalidAsset(format!(
                "could not remove the C2PA manifest from the ZIP: {e}"
            ))
        })?;

        Ok(())
    }
}

impl C2paReader for ZipIO {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let mut reader = self
            .reader(input_stream)
            .map_err(|e| Error::InvalidAsset(format!("could not read the ZIP: {e}")))?;

        let index = reader
            .index_for_path(Path::new(MANIFEST_PATH))
            .ok_or(Error::JumbfNotFound)?;
        let mut file = reader
            .by_index(index)
            .map_err(|e| Error::InvalidAsset(format!("could not read the ZIP: {e}")))?;

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;

        Ok(bytes)
    }

    fn read_xmp(&self, _input_stream: &mut dyn ReadSeek) -> Option<String> {
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

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(ZipIO::new(asset_type)))
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
        input_stream: &'a mut dyn ReadSeek,
    ) -> ZipResult<ZipArchive<&'a mut dyn ReadSeek>> {
        ZipArchive::new(input_stream)
    }

    fn writer<'a>(
        &self,
        input_stream: &'a mut dyn ReadSeek,
        output_stream: &'a mut dyn ReadWriteSeek,
    ) -> ZipResult<ZipWriter<&'a mut dyn ReadWriteSeek>> {
        input_stream.rewind()?;
        io::copy(input_stream, output_stream)?;

        ZipWriter::new_append(output_stream)
    }
}

/// Computes the byte ranges for the ZIP central directory, skipping the manifest's checksum (if present).
pub(crate) fn zip_central_directory_range<R>(reader: &mut R) -> Result<Vec<HashRange>>
where
    R: Read + Seek + ?Sized,
{
    let length = reader.seek(SeekFrom::End(0))?;
    let mut reader = ZipArchive::new(reader)
        .map_err(|e| Error::InvalidAsset(format!("could not read the ZIP: {e}")))?;

    let start = reader.central_directory_start();

    let range = match reader.index_for_path(Path::new(MANIFEST_PATH)) {
        Some(index) => {
            let file = reader
                .by_index(index)
                .map_err(|e| Error::InvalidAsset(format!("could not read the ZIP: {e}")))?;
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

/// Computes the byte ranges for each file entry in a ZIP stream.
pub(crate) fn zip_uri_ranges<R>(stream: &mut R) -> Result<HashMap<PathBuf, HashRange>>
where
    R: Read + Seek + ?Sized,
{
    let mut ranges = HashMap::new();
    for entry in zip_uri_entries(stream)? {
        if entry.path == Path::new(MANIFEST_PATH) {
            continue;
        }

        // https://en.wikipedia.org/wiki/ZIP_(file_format)#Data_descriptor
        let mut end = entry.data_end;
        if entry.using_data_descriptor {
            stream.seek(SeekFrom::Start(entry.data_end))?;
            let mut signature = [0; DATA_DESCRIPTOR_SIGNATURE.len()];
            stream.read_exact(&mut signature)?;

            // the `zip2` crate writes the data descriptor flag on the local file header of
            // directories, yet it doesn't write a data descriptor. if the next entry is not
            // a local file header or the start of the central directory, then there must be
            // a data descriptor present (or an incorrect zip). note the data descriptor
            // signature is optional.
            //
            // we handle it here in case we run into it in the wild, althoughh the bug only occurs
            // when generating zips with the zip crate.
            //
            // https://github.com/zip-rs/zip2/issues/971
            if signature != LOCAL_FILE_HEADER_SIGNATURE
                && signature != CENTRAL_DIRECTORY_HEADER_SIGNATURE
            {
                let signature_len: u64 = if signature == DATA_DESCRIPTOR_SIGNATURE {
                    DATA_DESCRIPTOR_SIGNATURE.len() as u64
                } else {
                    0
                };
                let size_field_len: u64 = if entry.large_file { 8 } else { 4 };

                end += signature_len + CRC_LEN + (2 * size_field_len);
            }
        }
        ranges.insert(
            entry.path,
            HashRange::new(entry.header_start, end - entry.header_start),
        );
    }

    Ok(ranges)
}

/// Location of a single ZIP entry gathered from the central directory.
struct ZipUriEntry {
    path: PathBuf,
    header_start: u64,
    data_end: u64,
    using_data_descriptor: bool,
    large_file: bool,
}

/// Collects the location of each file entry in a ZIP stream from the central directory.
fn zip_uri_entries<R>(stream: &mut R) -> Result<Vec<ZipUriEntry>>
where
    R: Read + Seek + ?Sized,
{
    let mut reader = ZipArchive::new(&mut *stream)
        .map_err(|e| Error::InvalidAsset(format!("could not read the ZIP: {e}")))?;
    let file_names: Vec<String> = reader.file_names().map(|name| name.to_owned()).collect();

    let mut entries = Vec::new();
    for file_name in file_names {
        let file = reader
            .by_name(&file_name)
            .map_err(|e| Error::InvalidAsset(format!("could not read the ZIP: {e}")))?;

        let path = match file.enclosed_name() {
            Some(path) => path,
            None => {
                return Err(Error::InvalidAsset(format!(
                    "invalid stored path `{file_name}` in the ZIP"
                )))
            }
        };

        let header_start = file.header_start();
        let data_start = file.data_start().ok_or_else(|| {
            Error::InvalidAsset(format!(
                "could not locate the data start for `{file_name}` in the ZIP"
            ))
        })?;
        let metadata = file.get_metadata();
        entries.push(ZipUriEntry {
            path,
            header_start,
            data_end: data_start + file.compressed_size(),
            using_data_descriptor: metadata.using_data_descriptor,
            large_file: metadata.large_file,
        });
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::io::Write;

    use io::{Cursor, Seek};

    use super::*;

    const SAMPLES: [&[u8]; 3] = [
        include_bytes!("../../tests/fixtures/sample1.zip"),
        include_bytes!("../../tests/fixtures/sample1.docx"),
        include_bytes!("../../tests/fixtures/sample1.odt"),
    ];

    #[test]
    fn test_write_bytes() {
        for sample in SAMPLES {
            let mut stream = Cursor::new(sample);

            let zip_io = ZipIO {};

            assert!(matches!(
                zip_io.read_c2pa(&mut stream),
                Err(Error::JumbfNotFound)
            ));

            let mut output_stream = Cursor::new(Vec::with_capacity(sample.len() + 7));
            let random_bytes = [1, 2, 3, 4, 3, 2, 1];
            zip_io
                .write_c2pa(&mut stream, &mut output_stream, &random_bytes)
                .unwrap();

            let data_written = zip_io.read_c2pa(&mut output_stream).unwrap();
            assert_eq!(data_written, random_bytes);
        }
    }

    #[test]
    fn test_write_bytes_replace() {
        for sample in SAMPLES {
            let mut stream = Cursor::new(sample);

            let zip_io = ZipIO {};

            assert!(matches!(
                zip_io.read_c2pa(&mut stream),
                Err(Error::JumbfNotFound)
            ));

            let mut output_stream1 = Cursor::new(Vec::with_capacity(sample.len() + 7));
            let random_bytes = [1, 2, 3, 4, 3, 2, 1];
            zip_io
                .write_c2pa(&mut stream, &mut output_stream1, &random_bytes)
                .unwrap();

            let data_written = zip_io.read_c2pa(&mut output_stream1).unwrap();
            assert_eq!(data_written, random_bytes);

            let mut output_stream2 = Cursor::new(Vec::with_capacity(sample.len() + 5));
            let random_bytes = [3, 2, 1, 2, 3];
            zip_io
                .write_c2pa(&mut output_stream1, &mut output_stream2, &random_bytes)
                .unwrap();

            let data_written = zip_io.read_c2pa(&mut output_stream2).unwrap();
            assert_eq!(data_written, random_bytes);

            let mut bytes = Vec::new();
            stream.rewind().unwrap();
            stream.read_to_end(&mut bytes).unwrap();
            assert_eq!(sample, bytes);
        }
    }

    #[test]
    fn test_remove_cai_store() {
        for sample in SAMPLES {
            let zip_io = ZipIO {};

            let mut input = Cursor::new(sample);
            let mut with_manifest = Cursor::new(Vec::new());
            zip_io
                .write_c2pa(&mut input, &mut with_manifest, &[1, 2, 3])
                .unwrap();
            assert_eq!(zip_io.read_c2pa(&mut with_manifest).unwrap(), [1, 2, 3]);

            let mut removed = Cursor::new(Vec::new());
            zip_io
                .remove_c2pa(&mut with_manifest, &mut removed)
                .unwrap();

            assert!(matches!(
                zip_io.read_c2pa(&mut removed),
                Err(Error::JumbfNotFound)
            ));
        }
    }

    #[test]
    fn test_read_cai_invalid_zip() {
        let zip_io = ZipIO {};
        let mut not_a_zip = Cursor::new(b"i am a zip".to_vec());

        assert!(matches!(
            zip_io.read_c2pa(&mut not_a_zip),
            Err(Error::InvalidAsset(_))
        ));
    }

    #[test]
    fn test_object_locations_unsupported() {
        let zip_io = ZipIO {};
        let mut stream = Cursor::new(SAMPLES[0]);

        assert!(matches!(
            zip_io.get_object_locations(&mut stream),
            Err(Error::NotImplemented(_))
        ));
    }

    #[test]
    fn test_zip_central_directory_range_no_manifest() {
        let mut stream = Cursor::new(SAMPLES[0]);
        assert_eq!(
            zip_central_directory_range(&mut stream).unwrap(),
            vec![HashRange::new(369, 727)]
        );
    }

    #[test]
    fn test_zip_uri_ranges1() {
        let mut stream = Cursor::new(SAMPLES[0]);
        let ranges = zip_uri_ranges(&mut stream).unwrap();

        assert_eq!(ranges.len(), 7);
        assert_eq!(
            ranges.get(Path::new("sample1/test1.txt")),
            Some(&HashRange::new(44, 47))
        );
        assert_eq!(
            ranges.get(Path::new("sample1/test2.txt")),
            Some(&HashRange::new(313, 56))
        );
    }

    #[test]
    fn test_zip_uri_ranges_data_descriptor_length() {
        let mut writer = ZipWriter::new_stream(Vec::new());
        writer
            .start_file("only.txt", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"hello").unwrap();
        let bytes = writer.finish().unwrap().into_inner();

        let mut stream = Cursor::new(bytes);

        let (header_start, data_end) = {
            let mut archive = ZipArchive::new(&mut stream).unwrap();
            let file = archive.by_name("only.txt").unwrap();
            (
                file.header_start(),
                file.data_start().unwrap() + file.compressed_size(),
            )
        };

        let data_descriptor_len = 16;

        let ranges = zip_uri_ranges(&mut stream).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges.get(Path::new("only.txt")),
            Some(&HashRange::new(
                header_start,
                (data_end + data_descriptor_len) - header_start
            ))
        );
    }

    #[test]
    fn test_zip_uri_ranges_includes_directory_local_header() {
        let mut writer = ZipWriter::new_stream(Vec::new());
        writer
            .add_directory("mydir", SimpleFileOptions::default())
            .unwrap();
        writer
            .start_file("mydir/file.txt", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"hello").unwrap();
        let bytes = writer.finish().unwrap().into_inner();

        let ranges = zip_uri_ranges(&mut Cursor::new(bytes)).unwrap();

        assert_eq!(ranges.len(), 2);

        let dir_range = ranges.get(Path::new("mydir/")).unwrap();
        let file_range = ranges.get(Path::new("mydir/file.txt")).unwrap();
        assert_eq!(dir_range.start(), 0);
        assert_eq!(dir_range.start() + dir_range.length(), file_range.start());
    }

    #[test]
    fn test_central_directory_range_skips_manifest_crc() {
        let zip_io = ZipIO {};
        let mut input = Cursor::new(SAMPLES[0]);
        let mut with_manifest = Cursor::new(Vec::new());
        zip_io
            .write_c2pa(&mut input, &mut with_manifest, &[1, 2, 3])
            .unwrap();

        let ranges = zip_central_directory_range(&mut with_manifest).unwrap();
        assert_eq!(ranges.len(), 2);

        let uri_ranges = zip_uri_ranges(&mut with_manifest).unwrap();
        assert!(!uri_ranges.contains_key(Path::new(MANIFEST_PATH)));
    }

    #[test]
    fn test_write_preserves_existing_entry_bytes() {
        fn read_range<R: Read + Seek>(stream: &mut R, range: &HashRange) -> Vec<u8> {
            stream.seek(SeekFrom::Start(range.start())).unwrap();

            let mut bytes = vec![0; range.length() as usize];
            stream.read_exact(&mut bytes).unwrap();

            bytes
        }

        let zip_io = ZipIO {};

        let mut src = Cursor::new(SAMPLES[0].to_vec());
        let input_ranges = zip_uri_ranges(&mut src).unwrap();

        let mut src_with_manifest = Cursor::new(Vec::new());
        zip_io
            .write_c2pa(&mut src, &mut src_with_manifest, &[1, 2, 3])
            .unwrap();
        let output_ranges = zip_uri_ranges(&mut src_with_manifest).unwrap();

        assert_eq!(output_ranges.len(), input_ranges.len() + 1);

        for (path, input_range) in input_ranges {
            let output_range = output_ranges.get(&path).unwrap();

            assert_eq!(
                read_range(&mut src, &input_range),
                read_range(&mut src_with_manifest, output_range),
                "entry `{}` bytes changed after embedding the manifest",
                path.display()
            );
        }
    }
}
