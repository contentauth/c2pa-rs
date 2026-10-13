use std::{
    cell::Cell,
    collections::HashMap,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    rc::Rc,
};

use quick_xml::{events::Event, Reader as XmlReader, XmlVersion};
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
/// The largest `[Content_Types].xml` that is decompressed. Real ones are a few kilobytes, even
/// with thousands of parts; the cap stops a small, highly compressed entry from expanding to
/// fill memory.
const MAX_CONTENT_TYPES_LEN: u64 = 16 * 1024 * 1024;

const END_OF_CENTRAL_DIRECTORY_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const CENTRAL_DIRECTORY_HEADER_LEN: usize = 46;
const END_OF_CENTRAL_DIRECTORY_LEN: usize = 22;

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
        // The manifest shall be stored and not encrypted. Reading it raw means it is never
        // decompressed, so its size is bounded by the file's.
        let mut file = reader
            .by_index_raw(index)
            .map_err(|e| Error::InvalidAsset(format!("could not read the ZIP: {e}")))?;
        if file.compression() != CompressionMethod::Stored || file.encrypted() {
            return Err(Error::InvalidAsset(
                "the C2PA manifest in the ZIP is compressed or encrypted".to_string(),
            ));
        }

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
        let mut entries_len = ZipArchive::new(&mut *input_stream)?.central_directory_start();
        input_stream.seek(SeekFrom::Start(entries_len))?;
        let mut central_directory = Vec::new();
        input_stream.read_to_end(&mut central_directory)?;

        // When re-signing, drop the existing manifest so that the new one replaces its bytes
        // rather than leaving them behind. This applies when the manifest is the last entry,
        // as this handler writes it.
        if let Some((manifest_start, without_manifest)) =
            trailing_manifest_removed(&mut *input_stream, entries_len, &central_directory)?
        {
            entries_len = manifest_start;
            central_directory = without_manifest;
        }

        input_stream.rewind()?;
        output_stream.rewind()?;
        io::copy(&mut (&mut *input_stream).take(entries_len), output_stream)?;

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

/// If the archive's last entry (in file order) is the C2PA manifest, returns where that entry
/// starts and the central directory and end-of-central-directory record with it removed.
///
/// Returns `None` when there is no manifest, when it is not the last entry, or for ZIP64
/// archives, in which case the archive is appended to as it is.
fn trailing_manifest_removed(
    input_stream: &mut dyn ReadSeek,
    central_directory_start: u64,
    central_directory: &[u8],
) -> ZipResult<Option<(u64, Vec<u8>)>> {
    let mut archive = ZipArchive::new(&mut *input_stream)?;
    let Some(index) = archive.index_for_name(MANIFEST_PATH) else {
        return Ok(None);
    };
    let manifest_start = archive.by_index_raw(index)?.header_start();
    for i in 0..archive.len() {
        if archive.by_index_raw(i)?.header_start() > manifest_start {
            return Ok(None);
        }
    }
    let Ok(central_directory_start) = u32::try_from(central_directory_start) else {
        return Ok(None); // ZIP64
    };

    // Walk the central directory headers, leaving out the manifest's.
    let u16_at = |data: &[u8], i: usize| u16::from_le_bytes([data[i], data[i + 1]]);
    let mut kept = Vec::with_capacity(central_directory.len());
    let mut pos = 0;
    let mut removed = false;
    while central_directory.get(pos..pos + 4) == Some(&CENTRAL_DIRECTORY_HEADER_SIGNATURE[..]) {
        let Some(header) = central_directory.get(pos..pos + CENTRAL_DIRECTORY_HEADER_LEN) else {
            return Ok(None);
        };
        let name_len = u16_at(header, 28) as usize;
        let len = CENTRAL_DIRECTORY_HEADER_LEN
            + name_len
            + u16_at(header, 30) as usize
            + u16_at(header, 32) as usize;
        let Some(record) = central_directory.get(pos..pos + len) else {
            return Ok(None);
        };
        let name = &record[CENTRAL_DIRECTORY_HEADER_LEN..CENTRAL_DIRECTORY_HEADER_LEN + name_len];
        if name == MANIFEST_PATH.as_bytes() && !removed {
            removed = true;
        } else {
            kept.extend_from_slice(record);
        }
        pos += len;
    }

    // Only a plain end-of-central-directory record may follow (no ZIP64 records).
    let Some(eocd) = central_directory.get(pos..) else {
        return Ok(None);
    };
    if !removed
        || eocd.len() < END_OF_CENTRAL_DIRECTORY_LEN
        || eocd[..4] != END_OF_CENTRAL_DIRECTORY_SIGNATURE
    {
        return Ok(None);
    }
    let mut eocd = eocd.to_vec();
    let entries = u16_at(&eocd, 10).saturating_sub(1);
    eocd[8..10].copy_from_slice(&entries.to_le_bytes());
    eocd[10..12].copy_from_slice(&entries.to_le_bytes());
    eocd[12..16].copy_from_slice(&(kept.len() as u32).to_le_bytes());
    let Ok(manifest_start_u32) = u32::try_from(manifest_start) else {
        return Ok(None);
    };
    debug_assert!(manifest_start_u32 < central_directory_start);
    eocd[16..20].copy_from_slice(&manifest_start_u32.to_le_bytes());
    kept.extend_from_slice(&eocd);

    Ok(Some((manifest_start, kept)))
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

    // Check the declared size, then read through a hard limit in case it is wrong.
    let too_large = || {
        Error::InvalidAsset(format!(
            "`{OPC_CONTENT_TYPES_PATH}` is larger than {MAX_CONTENT_TYPES_LEN} bytes"
        ))
    };
    let declared_len = reader
        .by_index_raw(index)
        .map_err(|e| Error::InvalidAsset(format!("could not read the ZIP: {e}")))?
        .size();
    if declared_len > MAX_CONTENT_TYPES_LEN {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    reader
        .by_index(index)
        .map_err(|e| Error::InvalidAsset(format!("could not read the ZIP: {e}")))?
        .take(MAX_CONTENT_TYPES_LEN + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONTENT_TYPES_LEN {
        return Err(too_large());
    }
    // OPC allows UTF-8 or UTF-16; Office writes UTF-8. Leave anything else untouched.
    let Ok(content_types) = String::from_utf8(bytes) else {
        return Ok(None);
    };

    Ok(add_c2pa_content_type(&content_types))
}

/// Inserts a `Default` element for the `c2pa` extension as the first child of `Types`, unless the
/// manifest's content type is already declared by extension or by part name. OPC compares
/// extensions and part names case-insensitively. Returns `None` if nothing needs to change, or
/// if the part is not well-formed XML with a non-empty `Types` element, so it is left alone.
fn add_c2pa_content_type(content_types: &str) -> Option<String> {
    let mut reader = XmlReader::from_str(content_types);
    let mut insert_at = None;
    loop {
        match reader.read_event().ok()? {
            Event::Start(e) | Event::Empty(e) => {
                let is_empty = content_types
                    .as_bytes()
                    .get(reader.buffer_position() as usize - 2)
                    == Some(&b'/');
                let attribute = |name: &[u8]| {
                    e.attributes()
                        .flatten()
                        .find(|a| a.key.local_name().as_ref().eq_ignore_ascii_case(name))
                        .and_then(|a| {
                            a.normalized_value(XmlVersion::default())
                                .ok()
                                .map(|v| v.into_owned())
                        })
                };
                match e.local_name().as_ref() {
                    b"Types" if insert_at.is_none() => {
                        if is_empty {
                            return None; // An empty `<Types/>` is not a usable OPC package.
                        }
                        insert_at = Some(reader.buffer_position() as usize);
                    }
                    b"Default"
                        if attribute(b"Extension")
                            .is_some_and(|v| v.eq_ignore_ascii_case("c2pa")) =>
                    {
                        return None;
                    }
                    b"Override"
                        if attribute(b"PartName").is_some_and(|v| {
                            v.eq_ignore_ascii_case(&format!("/{MANIFEST_PATH}"))
                        }) =>
                    {
                        return None;
                    }
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    let insert_at = insert_at?;
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

    /// Builds a ZIP with the given `(name, contents, compression)` entries.
    fn build_zip(entries: &[(&str, &[u8], CompressionMethod)]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, contents, method) in entries {
            writer
                .start_file(
                    *name,
                    SimpleFileOptions::DEFAULT.compression_method(*method),
                )
                .unwrap();
            writer.write_all(contents).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    /// Bytes before the central directory that no entry accounts for.
    fn unreferenced_bytes(zip: &[u8]) -> u64 {
        let mut archive = ZipArchive::new(Cursor::new(zip)).unwrap();
        let entries: u64 = zip_uri_ranges(&mut Cursor::new(zip))
            .unwrap()
            .values()
            .map(|r| r.length())
            .sum();
        let manifest = archive
            .by_name(MANIFEST_PATH)
            .map(|f| f.data_start().unwrap() + f.compressed_size() - f.header_start())
            .unwrap_or(0);
        archive.central_directory_start() - entries - manifest
    }

    #[test]
    fn test_read_rejects_compressed_manifest() {
        // A small deflated "manifest" that would expand to 64 MiB.
        let zip = build_zip(&[(
            MANIFEST_PATH,
            &vec![0u8; 64 * 1024 * 1024],
            CompressionMethod::Deflated,
        )]);
        assert!(zip.len() < 1024 * 1024);
        assert!(matches!(
            ZipIO {}.read_c2pa(&mut Cursor::new(&zip)),
            Err(Error::InvalidAsset(_))
        ));
    }

    #[test]
    fn test_content_types_size_is_capped() {
        let mut xml = b"<Types>".to_vec();
        xml.resize(MAX_CONTENT_TYPES_LEN as usize + 1024, b' ');
        xml.extend(b"</Types>");
        let zip = build_zip(&[(OPC_CONTENT_TYPES_PATH, &xml, CompressionMethod::Deflated)]);
        assert!(zip.len() < 1024 * 1024);
        assert!(matches!(
            declare_opc_c2pa_content_type(&mut Cursor::new(&zip), &mut Cursor::new(Vec::new())),
            Err(Error::InvalidAsset(_))
        ));
    }

    #[test]
    fn test_resign_replaces_the_manifest() {
        for sample in SAMPLES {
            let mut first = Cursor::new(Vec::new());
            ZipIO {}
                .write_c2pa(&mut Cursor::new(sample), &mut first, &[1; 300])
                .unwrap();
            let mut second = Cursor::new(Vec::new());
            ZipIO {}
                .write_c2pa(&mut first, &mut second, &[2; 100])
                .unwrap();

            assert_eq!(ZipIO {}.read_c2pa(&mut second).unwrap(), [2; 100]);
            assert_eq!(unreferenced_bytes(first.get_ref()), 0);
            assert_eq!(unreferenced_bytes(second.get_ref()), 0);
            let names = |zip: &Vec<u8>| {
                let archive = ZipArchive::new(Cursor::new(zip)).unwrap();
                archive.file_names().map(str::to_owned).collect::<Vec<_>>()
            };
            assert_eq!(names(first.get_ref()), names(second.get_ref()));
        }
    }

    #[test]
    fn test_add_c2pa_content_type_uses_xml_structure() {
        let types =
            r#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">"#;

        // A declaration inside a comment does not count, and the element is added after the
        // real `Types` start tag, not one mentioned in a comment.
        let commented = format!(
            r#"<?xml version="1.0"?><!-- <Types> Extension="c2pa" -->{types}<Default Extension="xml" ContentType="application/xml"/></Types>"#
        );
        let updated = add_c2pa_content_type(&commented).unwrap();
        assert!(updated.contains(&format!("{types}{OPC_C2PA_DEFAULT}<Default")));

        // A `>` inside an attribute value does not end the start tag.
        let odd_attribute =
            r#"<Types data-note="a>b"><Default Extension="xml" ContentType="x"/></Types>"#;
        let updated = add_c2pa_content_type(odd_attribute).unwrap();
        assert!(updated.starts_with(&format!(r#"<Types data-note="a>b">{OPC_C2PA_DEFAULT}"#)));

        // Declarations with unusual whitespace, case or namespace prefixes are recognized.
        for declared in [
            "<Types>\n  <Default\n    Extension = \"C2PA\"\n    ContentType=\"application/c2pa\" />\n</Types>",
            r#"<ct:Types xmlns:ct="x"><ct:Override PartName="/meta-inf/CONTENT_CREDENTIAL.c2pa" ContentType="application/c2pa"/></ct:Types>"#,
        ] {
            assert_eq!(add_c2pa_content_type(declared), None, "{declared}");
        }

        // Not well-formed: left alone.
        assert_eq!(add_c2pa_content_type("<Types><Default"), None);
    }
}
