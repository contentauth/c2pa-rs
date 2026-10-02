use std::{
    cell::Cell,
    collections::HashMap,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    rc::Rc,
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

/// The content types part of an Open Packaging Conventions (OPC) package, such as an OOXML
/// document or OpenXPS file. Every part in such a package needs a declared content type.
const OPC_CONTENT_TYPES_PATH: &str = "[Content_Types].xml";
const OPC_C2PA_DEFAULT: &str = r#"<Default Extension="c2pa" ContentType="application/c2pa"/>"#;

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

    /// Returns a writer that appends to the archive in `input_stream`, writing to `output_stream`.
    ///
    /// `ZipWriter::new_append` writes new entries after the existing central directory, which
    /// would leave it in the file as unreferenced bytes. Those bytes are outside the collection
    /// hash, and strict readers such as PowerPoint reject the file. So only the entries are copied
    /// to `output_stream`; the central directory is kept in memory for `new_append` to read, and new
    /// entries are written where it began. Existing entries are left byte-for-byte unchanged.
    fn writer<'a>(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &'a mut dyn ReadWriteSeek,
    ) -> ZipResult<ZipWriter<AppendStream<'a>>> {
        let entries_len = ZipArchive::new(&mut *input_stream)?.central_directory_start();

        input_stream.rewind()?;
        output_stream.rewind()?;
        io::copy(&mut (&mut *input_stream).take(entries_len), output_stream)?;
        let mut central_directory = Vec::new();
        input_stream.read_to_end(&mut central_directory)?;

        let detached = Rc::new(Cell::new(false));
        let writer = ZipWriter::new_append(AppendStream {
            inner: output_stream,
            entries_len,
            central_directory,
            detached: Rc::clone(&detached),
            pos: 0,
        })?;
        detached.set(true);

        Ok(writer)
    }
}

/// A stream over an archive's entries in `inner`, followed by its old central directory held in
/// memory, so that `ZipWriter::new_append` can read the existing entries.
///
/// Once `detached` is set, the old central directory is dropped and the stream is positioned at
/// the end of the entries, so that the writer overwrites it rather than writing after it.
struct AppendStream<'a> {
    inner: &'a mut dyn ReadWriteSeek,
    entries_len: u64,
    central_directory: Vec<u8>,
    detached: Rc<Cell<bool>>,
    pos: u64,
}

impl AppendStream<'_> {
    /// Returns whether the old central directory is still part of the stream.
    fn attached(&mut self) -> bool {
        if self.detached.get() && !self.central_directory.is_empty() {
            self.central_directory = Vec::new();
            self.pos = self.entries_len;
        }
        !self.central_directory.is_empty()
    }
}

impl Read for AppendStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = if !self.attached() {
            self.inner.seek(SeekFrom::Start(self.pos))?;
            self.inner.read(buf)?
        } else if self.pos < self.entries_len {
            let len = buf.len().min((self.entries_len - self.pos) as usize);
            self.inner.seek(SeekFrom::Start(self.pos))?;
            self.inner.read(&mut buf[..len])?
        } else {
            let start = ((self.pos - self.entries_len) as usize).min(self.central_directory.len());
            (&self.central_directory[start..]).read(buf)?
        };
        self.pos += n as u64;
        Ok(n)
    }
}

impl Write for AppendStream<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.attached() {
            return Err(io::Error::other(
                "cannot write before the old central directory is detached",
            ));
        }
        self.inner.seek(SeekFrom::Start(self.pos))?;
        let n = self.inner.write(buf)?;
        self.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Seek for AppendStream<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let len = if self.attached() {
            self.entries_len + self.central_directory.len() as u64
        } else {
            self.inner.seek(SeekFrom::End(0))?
        };
        let pos = match from {
            SeekFrom::Start(pos) => Some(pos),
            SeekFrom::End(offset) => len.checked_add_signed(offset),
            SeekFrom::Current(offset) => self.pos.checked_add_signed(offset),
        };
        self.pos = pos.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid seek in the ZIP")
        })?;
        Ok(self.pos)
    }
}

/// Declares a content type for the C2PA manifest in an Open Packaging Conventions (OPC) package,
/// such as an OOXML document or OpenXPS file.
///
/// OPC consumers such as PowerPoint and Word reject or "repair" a package containing a part with
/// no declared content type, and repairing removes the manifest. Declaring it changes
/// `[Content_Types].xml`, so this must happen before the collection hash is computed.
///
/// If the package needs the declaration, writes a copy of it to `output_stream` with the content
/// types part updated and returns `true`. All other entries are copied without being
/// recompressed. Otherwise writes nothing and returns `false`.
pub(crate) fn declare_opc_c2pa_content_type(
    input_stream: &mut dyn ReadSeek,
    output_stream: &mut dyn ReadWriteSeek,
) -> Result<bool> {
    let Some(content_types) = opc_content_types_with_c2pa(input_stream)? else {
        return Ok(false);
    };

    let rewrite =
        |input_stream: &mut dyn ReadSeek, output_stream: &mut dyn ReadWriteSeek| -> ZipResult<()> {
            input_stream.rewind()?;
            output_stream.rewind()?;
            let mut reader = ZipArchive::new(input_stream)?;
            let mut writer = ZipWriter::new(output_stream);

            for index in 0..reader.len() {
                let file = reader.by_index_raw(index)?;
                if file.name() == OPC_CONTENT_TYPES_PATH {
                    let mut options =
                        SimpleFileOptions::DEFAULT.compression_method(CompressionMethod::Deflated);
                    if let Some(time) = file.last_modified() {
                        options = options.last_modified_time(time);
                    }
                    writer.start_file(OPC_CONTENT_TYPES_PATH, options)?;
                    io::Write::write_all(&mut writer, content_types.as_bytes())?;
                } else {
                    writer.raw_copy_file(file)?;
                }
            }
            writer.finish()?;
            Ok(())
        };
    rewrite(input_stream, output_stream).map_err(|e| {
        Error::InvalidAsset(format!(
            "could not declare the C2PA content type in the ZIP: {e}"
        ))
    })?;

    Ok(true)
}

/// Returns the OPC content types part with a content type declared for the C2PA manifest, or
/// `None` if the archive is not an OPC package or the part already declares one.
fn opc_content_types_with_c2pa(input_stream: &mut dyn ReadSeek) -> Result<Option<String>> {
    input_stream.rewind()?;
    let mut reader = ZipArchive::new(&mut *input_stream)
        .map_err(|e| Error::InvalidAsset(format!("could not read the ZIP: {e}")))?;
    let Some(index) = reader.index_for_name(OPC_CONTENT_TYPES_PATH) else {
        return Ok(None);
    };

    let mut bytes = Vec::new();
    reader
        .by_index(index)
        .map_err(|e| Error::InvalidAsset(format!("could not read the ZIP: {e}")))?
        .read_to_end(&mut bytes)?;
    // OPC allows UTF-8 or UTF-16; Office writes UTF-8. Leave anything else untouched.
    let Ok(content_types) = String::from_utf8(bytes) else {
        return Ok(None);
    };

    Ok(add_c2pa_content_type(&content_types))
}

/// Inserts a `Default` element for the `c2pa` extension as the first child of `Types`, unless the
/// manifest's content type is already declared by extension or by part name. OPC compares
/// extensions and part names case-insensitively.
fn add_c2pa_content_type(content_types: &str) -> Option<String> {
    let lower = content_types.to_ascii_lowercase();
    let declared = [
        "extension=\"c2pa\"",
        "extension='c2pa'",
        "partname=\"/meta-inf/content_credential.c2pa\"",
        "partname='/meta-inf/content_credential.c2pa'",
    ]
    .iter()
    .any(|attr| lower.contains(attr));
    if declared {
        return None;
    }

    let types_start = lower.find("<types")?;
    let types_end = types_start + lower[types_start..].find('>')?;
    if lower[..types_end].ends_with('/') {
        return None; // An empty `<Types/>` element is not a usable OPC package.
    }

    let insert_at = types_end + 1;
    Some(format!(
        "{}{OPC_C2PA_DEFAULT}{}",
        &content_types[..insert_at],
        &content_types[insert_at..]
    ))
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
                .by_index_raw(index)
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
    let mut entries = Vec::new();
    for index in 0..reader.len() {
        // Raw access: only offsets are needed, and the hash is over the stored (compressed)
        // bytes, so the entry must not be decompressed. Decompression is not compiled in
        // (`zip` is built without default features), so `by_name` fails on deflated entries.
        let file = reader
            .by_index_raw(index)
            .map_err(|e| Error::InvalidAsset(format!("could not read the ZIP: {e}")))?;
        let file_name = file.name().to_owned();

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

    fn content_types(stream: &mut (impl Read + Seek)) -> Option<String> {
        let mut reader = ZipArchive::new(stream).unwrap();
        let mut file = reader.by_name(OPC_CONTENT_TYPES_PATH).ok()?;
        let mut xml = String::new();
        file.read_to_string(&mut xml).unwrap();
        Some(xml)
    }

    #[test]
    fn test_add_c2pa_content_type() {
        let xml = r#"<?xml version="1.0"?><Types xmlns="x"><Default Extension="xml" ContentType="application/xml"/></Types>"#;
        assert_eq!(
            add_c2pa_content_type(xml).unwrap(),
            format!(
                r#"<?xml version="1.0"?><Types xmlns="x">{OPC_C2PA_DEFAULT}<Default Extension="xml" ContentType="application/xml"/></Types>"#
            )
        );

        // Already declared, by extension or part name, in any case or quoting.
        for declared in [
            r#"<Types><Default Extension="C2PA" ContentType="application/c2pa"/></Types>"#,
            r#"<Types><Default Extension='c2pa' ContentType='application/c2pa'/></Types>"#,
            r#"<Types><Override PartName="/META-INF/content_credential.c2pa" ContentType="application/c2pa"/></Types>"#,
        ] {
            assert_eq!(add_c2pa_content_type(declared), None, "{declared}");
        }

        // Not a usable content types part.
        assert_eq!(add_c2pa_content_type("<Types/>"), None);
        assert_eq!(add_c2pa_content_type("not xml"), None);
    }

    #[test]
    fn test_declare_opc_c2pa_content_type() {
        let mut stream = Cursor::new(include_bytes!("../../tests/fixtures/sample1.docx"));
        assert!(!content_types(&mut stream).unwrap().contains("c2pa"));

        let mut declared = Cursor::new(Vec::new());
        assert!(declare_opc_c2pa_content_type(&mut stream, &mut declared).unwrap());
        let xml = content_types(&mut declared).unwrap();
        assert_eq!(xml.matches(OPC_C2PA_DEFAULT).count(), 1);

        // Every other entry is copied unchanged.
        let mut original = ZipArchive::new(&mut stream).unwrap();
        let mut copy = ZipArchive::new(&mut declared).unwrap();
        assert_eq!(original.len(), copy.len());
        for index in 0..original.len() {
            let a = original.by_index_raw(index).unwrap();
            let b = copy.by_index_raw(index).unwrap();
            assert_eq!(a.name(), b.name());
            if a.name() != OPC_CONTENT_TYPES_PATH {
                assert_eq!(a.crc32(), b.crc32(), "{}", a.name());
                assert_eq!(a.compressed_size(), b.compressed_size(), "{}", a.name());
            }
        }
        drop((original, copy));

        // Already declared: nothing to do.
        let mut again = Cursor::new(Vec::new());
        assert!(!declare_opc_c2pa_content_type(&mut declared, &mut again).unwrap());
        assert!(again.get_ref().is_empty());
    }

    #[test]
    fn test_declare_skips_non_opc_packages() {
        let mut stream = Cursor::new(include_bytes!("../../tests/fixtures/sample1.odt"));
        let mut output = Cursor::new(Vec::new());
        assert!(!declare_opc_c2pa_content_type(&mut stream, &mut output).unwrap());
        assert!(output.get_ref().is_empty());
    }

    #[test]
    fn test_write_leaves_no_stale_central_directory() {
        for sample in SAMPLES {
            let mut stream = Cursor::new(sample);
            let entries = ZipArchive::new(&mut stream).unwrap().len();

            // A manifest smaller than the old central directory must not leave part of it behind.
            let mut output = Cursor::new(Vec::new());
            ZipIO {}
                .write_c2pa(&mut stream, &mut output, &[1, 2, 3])
                .unwrap();
            let written = ZipArchive::new(&mut output).unwrap().len();
            let bytes = output.get_ref();
            let count = |sig: &[u8]| bytes.windows(4).filter(|w| *w == sig).count();

            assert!(written > entries);
            assert_eq!(
                count(b"PK\x01\x02"),
                written,
                "stale central directory headers"
            );
            assert_eq!(
                count(b"PK\x05\x06"),
                1,
                "stale end of central directory record"
            );
        }
    }
}
