use std::{
    collections::HashMap,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use zip::{
    result::{ZipError, ZipResult},
    write::SimpleFileOptions,
    CompressionMethod, HasZipMetadata, ZipArchive, ZipWriter,
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
        let mut archive =
            ZipArchive::new(input_stream).map_err(|err| Error::InvalidAsset(err.to_string()))?;
        match archive.index_for_name(MANIFEST_PATH) {
            Some(_) => zip_replace_entries(
                &mut archive,
                output_stream,
                &mut [(MANIFEST_PATH, &mut store_bytes)],
            ),
            None => zip_append_c2pa(&mut archive, output_stream, store_bytes),
        }
        .map_err(|err| Error::InvalidAsset(err.to_string()))
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
        let mut archive =
            ZipArchive::new(input_stream).map_err(|err| Error::InvalidAsset(err.to_string()))?;
        zip_remove_entries(&mut archive, output_stream, &[MANIFEST_PATH])
            .map_err(|err| Error::InvalidAsset(err.to_string()))
    }
}

impl C2paReader for ZipIO {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let mut reader = ZipArchive::new(input_stream)
            .map_err(|e| Error::InvalidAsset(format!("could not read the ZIP: {e}")))?;

        let index = reader
            .index_for_path(Path::new(MANIFEST_PATH))
            .ok_or(Error::JumbfNotFound)?;
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
            "application/zip",
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

/// Writes a copy of `archive` to `output_stream` with the manifest appended as the last entry.
fn zip_append_c2pa<R, W>(
    archive: &mut ZipArchive<R>,
    output_stream: &mut W,
    store_bytes: &[u8],
) -> ZipResult<()>
where
    R: Read + Seek,
    W: Write + Seek + ?Sized,
{
    output_stream.rewind()?;

    let comment = archive.comment().to_vec();
    let mut writer = ZipWriter::new(output_stream);

    for index in 0..archive.len() {
        writer.raw_copy_file(archive.by_index_raw(index)?)?;
    }

    match writer.add_directory("META-INF", SimpleFileOptions::DEFAULT) {
        Err(ZipError::InvalidArchive(err)) if err.starts_with("Duplicate filename") => {}
        Err(err) => return Err(err),
        _ => {}
    }
    writer.start_file_from_path(
        Path::new(MANIFEST_PATH),
        SimpleFileOptions::DEFAULT.compression_method(CompressionMethod::Stored),
    )?;
    writer.write_all(store_bytes)?;

    writer.set_raw_comment(comment.into_boxed_slice())?;
    writer.finish()?;

    Ok(())
}

/// Writes a copy of `archive` to `output_stream` with the contents of the entries named in
/// `replacements` replaced.
pub(crate) fn zip_replace_entries<R, W>(
    archive: &mut ZipArchive<R>,
    output_stream: &mut W,
    replacements: &mut [(&str, &mut dyn Read)],
) -> ZipResult<()>
where
    R: Read + Seek,
    W: Write + Seek + ?Sized,
{
    output_stream.rewind()?;

    let comment = archive.comment().to_vec();
    let mut writer = ZipWriter::new(output_stream);

    for index in 0..archive.len() {
        let file = archive.by_index_raw(index)?;
        let replacement = str::from_utf8(file.name_raw()).ok().and_then(|name| {
            replacements
                .iter_mut()
                .find(|(replacement_name, _)| *replacement_name == name)
        });
        match replacement {
            Some((name, contents)) => {
                let options = file.options();
                writer.start_file(*name, options)?;
                io::copy(contents, &mut writer)?;
            }
            None => writer.raw_copy_file(file)?,
        }
    }

    writer.set_raw_comment(comment.into_boxed_slice())?;
    writer.finish()?;

    Ok(())
}

/// Writes a copy of `archive` to `output_stream` without the entries named in `exclude`.
pub(crate) fn zip_remove_entries<R, W>(
    archive: &mut ZipArchive<R>,
    output_stream: &mut W,
    exclude: &[&str],
) -> ZipResult<()>
where
    R: Read + Seek,
    W: Write + Seek + ?Sized,
{
    output_stream.rewind()?;

    let comment = archive.comment().to_vec();
    let mut writer = ZipWriter::new(output_stream);

    for index in 0..archive.len() {
        let file = archive.by_index_raw(index)?;
        let excluded = str::from_utf8(file.name_raw()).is_ok_and(|name| exclude.contains(&name));
        if !excluded {
            writer.raw_copy_file(file)?;
        }
    }

    writer.set_raw_comment(comment.into_boxed_slice())?;
    writer.finish()?;

    Ok(())
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
    let file_names = reader
        .file_names()
        .map(|name| name.map(|name| name.into_owned()))
        .collect::<ZipResult<Vec<_>>>()
        .map_err(|e| Error::InvalidAsset(format!("could not read the ZIP: {e}")))?;

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
            using_data_descriptor: metadata.is_using_data_descriptor(),
            large_file: metadata.large_file,
        });
    }

    Ok(entries)
}

/// Support for Open Packaging Conventions (OPC) packages, such as Office Open XML and OpenXPS.
pub(crate) mod opc {
    use std::io::{BufRead, BufReader, Read, Seek, Write};

    use quick_xml::{
        events::{BytesStart, Event},
        Reader, Writer, XmlVersion,
    };
    use zip::ZipArchive;

    use super::zip_replace_entries;
    use crate::{asset_io::ReadWriteSeek, error::Result, utils::io_utils, Error};

    const CONTENT_TYPES_PATH: &str = "[Content_Types].xml";
    const MANIFEST_PART_NAME: &str = "/META-INF/content_credential.c2pa";
    const MANIFEST_EXTENSION: &str = "c2pa";
    const MANIFEST_CONTENT_TYPE: &str = "application/c2pa";

    const MAX_CONTENT_TYPES_LEN: u64 = 16 * 1024 * 1024;

    /// Writes a copy of `archive` to `output_stream` with `application/c2pa` declared for the
    /// manifest part in the OPC `[Content_Types].xml`.
    ///
    /// Returns `false` without writing anything if the archive isn't an OPC package or already
    /// declares the content type.
    pub(crate) fn add_c2pa_content_type<R>(
        archive: &mut ZipArchive<R>,
        output_stream: &mut dyn ReadWriteSeek,
        threshold_mb: usize,
    ) -> Result<bool>
    where
        R: Read + Seek,
    {
        let Some(content_types_index) = archive.index_for_name(CONTENT_TYPES_PATH) else {
            return Ok(false);
        };

        let file = archive
            .by_index(content_types_index)
            .map_err(|err| Error::InvalidAsset(err.to_string()))?;
        let mut new_content_types = io_utils::stream_with_fs_fallback(
            threshold_mb,
            file.size().min(MAX_CONTENT_TYPES_LEN),
        )?;

        let mut content_types = BufReader::new(file.take(MAX_CONTENT_TYPES_LEN + 1));
        let changed = patch_content_types_xml(&mut content_types, &mut new_content_types);

        if content_types.get_ref().limit() == 0 {
            return Err(Error::InvalidAsset(format!(
                "{CONTENT_TYPES_PATH} is larger than {MAX_CONTENT_TYPES_LEN} bytes"
            )));
        }
        if !changed? {
            return Ok(false);
        }

        drop(content_types);
        new_content_types.rewind()?;

        zip_replace_entries(
            archive,
            output_stream,
            &mut [(CONTENT_TYPES_PATH, &mut new_content_types)],
        )
        .map_err(|err| Error::InvalidAsset(err.to_string()))?;

        Ok(true)
    }

    /// Ensures an OPC `[Content_Types].xml` declares `application/c2pa` for the manifest part.
    ///
    /// Writes the patched content types to `output` and returns `true`, or returns `false` if the
    /// content types already declare it (in which case `output` should be discarded).
    fn patch_content_types_xml<R: BufRead, W: Write>(content_types: R, output: W) -> Result<bool> {
        let mut reader = Reader::from_reader(content_types);
        let mut writer = Writer::new(output);
        let mut buffer = Vec::new();

        let mut has_default = false;
        let mut has_override = false;
        let mut changed = false;
        let mut skipping_override = false;

        loop {
            let event = reader
                .read_event_into(&mut buffer)
                .map_err(|err| Error::InvalidAsset(err.to_string()))?;

            // skip all the incorrect stuff in the existing Override
            if skipping_override {
                match &event {
                    Event::End(end) if end.local_name().as_ref() == b"Override" => {
                        skipping_override = false;
                    }
                    Event::Eof => break,
                    _ => {}
                }

                buffer.clear();
                continue;
            }

            match &event {
                // handle `Override`s
                Event::Start(element) | Event::Empty(element) if is_manifest_override(element)? => {
                    has_override = true;

                    // if we encounter an Override for c2pa that has issues, we write the fixed up one
                    // and then skip the rest of the contents
                    if !attribute_value(element, b"ContentType")?.is_some_and(|content_type| {
                        content_type
                            .trim()
                            .eq_ignore_ascii_case(MANIFEST_CONTENT_TYPE)
                    }) {
                        let prefix = element.name().prefix();
                        let new_override =
                            override_element(prefix.as_ref().map(|prefix| prefix.as_ref()))?;

                        writer.write_event(Event::Empty(new_override))?;
                        changed = true;

                        skipping_override = matches!(event, Event::Start(_));

                        buffer.clear();
                        continue;
                    }
                }
                // handle `Default`s
                Event::Start(element) | Event::Empty(element)
                    if element.local_name().as_ref() == b"Default"
                        && attribute_value(element, b"Extension")?.is_some_and(|extension| {
                            extension.eq_ignore_ascii_case(MANIFEST_EXTENSION)
                        }) =>
                {
                    has_default =
                        attribute_value(element, b"ContentType")?.is_some_and(|content_type| {
                            content_type
                                .trim()
                                .eq_ignore_ascii_case(MANIFEST_CONTENT_TYPE)
                        });
                }
                // if we are at the end and there's nothing declared
                Event::End(end)
                    if end.local_name().as_ref() == b"Types" && !has_override && !has_default =>
                {
                    let prefix = end.name().prefix();
                    let element = override_element(prefix.as_ref().map(|prefix| prefix.as_ref()))?;

                    writer.write_event(Event::Empty(element))?;
                    changed = true;
                }
                Event::Eof => break,
                _ => {}
            }

            writer.write_event(event)?;
            buffer.clear();
        }

        Ok(changed)
    }

    fn attribute_value(element: &BytesStart, name: &[u8]) -> Result<Option<String>> {
        for attribute in element.attributes() {
            let attribute = attribute.map_err(|err| Error::InvalidAsset(err.to_string()))?;
            if attribute.key.local_name().as_ref() == name {
                let value = attribute
                    .normalized_value(XmlVersion::Implicit1_0)
                    .map_err(|err| Error::InvalidAsset(err.to_string()))?;
                return Ok(Some(value.into_owned()));
            }
        }

        Ok(None)
    }

    fn is_manifest_override(element: &BytesStart) -> Result<bool> {
        Ok(element.local_name().as_ref() == b"Override"
            && attribute_value(element, b"PartName")?
                .is_some_and(|part_name| part_name.eq_ignore_ascii_case(MANIFEST_PART_NAME)))
    }

    fn override_element(prefix: Option<&[u8]>) -> Result<BytesStart<'static>> {
        let name = match prefix {
            Some(prefix) => format!(
                "{}:Override",
                str::from_utf8(prefix).map_err(|err| Error::InvalidAsset(err.to_string()))?
            ),
            None => "Override".to_string(),
        };

        Ok(BytesStart::new(name).with_attributes([
            ("PartName", MANIFEST_PART_NAME),
            ("ContentType", MANIFEST_CONTENT_TYPE),
        ]))
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::unwrap_used)]

        use std::io::{Cursor, Seek};

        use quick_xml::events::{BytesEnd, BytesText};

        use super::*;

        const ZIP: &[u8] = include_bytes!("../../tests/fixtures/sample1.zip");
        const DOCX: &[u8] = include_bytes!("../../tests/fixtures/sample1.docx");
        const ODT: &[u8] = include_bytes!("../../tests/fixtures/sample1.odt");

        const THRESHOLD_MB: usize = 1;

        const MANIFEST_OVERRIDE: &str = r#"
            <Override
                PartName="/META-INF/content_credential.c2pa"
                ContentType="application/c2pa"/>
        "#;

        /// Runs [`patch_content_types_xml`], returning the patched content types if it changed them.
        fn patch_content_types_xml_string(content_types: &str) -> Option<String> {
            let mut output = Vec::new();
            patch_content_types_xml(content_types.as_bytes(), &mut output)
                .unwrap()
                .then(|| String::from_utf8(output).unwrap())
        }

        /// Joins xml's lines with their indentation trimmed.
        fn compact(xml: &str) -> String {
            xml.lines()
                .map(str::trim)
                .collect::<Vec<_>>()
                .join(" ")
                .replace(" <", "<")
                .replace("> ", ">")
                .trim()
                .to_string()
        }

        fn read_entry(stream: &mut Cursor<Vec<u8>>, name: &str) -> Option<String> {
            stream.rewind().unwrap();

            let mut archive = ZipArchive::new(stream).unwrap();
            let mut file = archive.by_name(name).ok()?;
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap();

            Some(contents)
        }

        #[test]
        fn test_patch_content_types_xml_adds_override() {
            let xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
                    <Default Extension="xml" ContentType="application/xml"/>
                </Types>
            "#;
            let patched = patch_content_types_xml_string(xml).unwrap();
            assert_eq!(
                compact(&patched),
                compact(&format!(
                    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                        <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
                            <Default Extension="xml" ContentType="application/xml"/>
                            {MANIFEST_OVERRIDE}
                        </Types>
                    "#
                ))
            );
            assert!(patch_content_types_xml_string(&patched).is_none());
        }

        #[test]
        fn test_patch_content_types_xml_invalid_xml() {
            let mismatched = r#"
                <Types>
                    <Default Extension="xml" ContentType="application/xml">
                </Types>
            "#;
            assert!(matches!(
                patch_content_types_xml(mismatched.as_bytes(), Vec::new()),
                Err(Error::InvalidAsset(_))
            ));
        }

        #[test]
        fn test_patch_content_types_xml_long_form_override() {
            let xml = r#"
                <Types>
                    <Override
                        PartName="/META-INF/content_credential.c2pa"
                        ContentType="text/plain">
                    </Override>
                </Types>
            "#;
            let patched = patch_content_types_xml_string(xml).unwrap();
            assert_eq!(
                compact(&patched),
                compact(&format!("<Types>{MANIFEST_OVERRIDE}</Types>"))
            );

            let xml = r#"
                <Types>
                    <Override
                        PartName="/META-INF/content_credential.c2pa"
                        ContentType="application/c2pa">
                    </Override>
                </Types>
            "#;
            assert!(patch_content_types_xml_string(xml).is_none());
        }

        #[test]
        fn test_patch_content_types_xml_override_beats_default() {
            let xml = r#"
                <Types>
                    <Default Extension="c2pa" ContentType="application/c2pa"/>
                    <Override
                        PartName="/META-INF/content_credential.c2pa"
                        ContentType="text/plain"/>
                </Types>
            "#;
            let patched = patch_content_types_xml_string(xml).unwrap();
            assert_eq!(
                compact(&patched),
                compact(&format!(
                    r#"
                        <Types>
                            <Default Extension="c2pa" ContentType="application/c2pa"/>
                            {MANIFEST_OVERRIDE}
                        </Types>
                    "#
                ))
            );
        }

        #[test]
        fn test_patch_content_types_xml_already_declared() {
            let by_default = r#"
                <Types>
                    <Default Extension="C2PA" ContentType="application/c2pa"/>
                </Types>
            "#;
            assert!(patch_content_types_xml_string(by_default).is_none());

            let by_override = r#"
                <Types>
                    <Override
                        PartName="/meta-inf/CONTENT_CREDENTIAL.c2pa"
                        ContentType="application/c2pa"/>
                </Types>
            "#;
            assert!(patch_content_types_xml_string(by_override).is_none());

            let escaped = r#"
                <Types>
                    <Override
                        PartName="/META-INF/content&#95;credential.c2pa"
                        ContentType="application&#x2F;c2pa"/>
                </Types>
            "#;
            assert!(patch_content_types_xml_string(escaped).is_none());
        }

        #[test]
        fn test_patch_content_types_xml_unknown_entity() {
            let xml = r#"
                <Types>
                    <Override
                        PartName="/META-INF/content_credential.c2pa"
                        ContentType="&unknown;"/>
                </Types>
            "#;
            assert!(matches!(
                patch_content_types_xml(xml.as_bytes(), Vec::new()),
                Err(Error::InvalidAsset(_))
            ));
        }

        #[test]
        fn test_patch_content_types_xml_fixes_wrong_types() {
            // a Default with the wrong type is overridden for the manifest part
            let xml = r#"
                <Types>
                    <Default Extension="c2pa" ContentType="application/octet-stream"/>
                </Types>
            "#;
            let patched = patch_content_types_xml_string(xml).unwrap();
            assert_eq!(
                compact(&patched),
                compact(&format!(
                    r#"
                        <Types>
                            <Default Extension="c2pa" ContentType="application/octet-stream"/>
                            {MANIFEST_OVERRIDE}
                        </Types>
                    "#
                ))
            );

            // an Override with the wrong type is replaced
            let xml = r#"
                <Types>
                    <Override
                        PartName="/META-INF/content_credential.c2pa"
                        ContentType="text/plain"/>
                </Types>
            "#;
            let patched = patch_content_types_xml_string(xml).unwrap();
            assert_eq!(
                compact(&patched),
                compact(&format!("<Types>{MANIFEST_OVERRIDE}</Types>"))
            );
        }

        #[test]
        fn test_add_c2pa_content_type_opc() {
            let mut input = Cursor::new(DOCX.to_vec());
            let original = read_entry(&mut input, CONTENT_TYPES_PATH).unwrap();
            assert!(!compact(&original).contains(&compact(MANIFEST_OVERRIDE)));

            let mut added = Cursor::new(Vec::new());
            assert!(add_c2pa_content_type(
                &mut ZipArchive::new(&mut input).unwrap(),
                &mut added,
                THRESHOLD_MB
            )
            .unwrap());
            assert!(
                compact(&read_entry(&mut added, CONTENT_TYPES_PATH).unwrap())
                    .contains(&compact(MANIFEST_OVERRIDE))
            );

            // every other entry is unchanged and in the same order
            input.rewind().unwrap();
            added.rewind().unwrap();
            let input_names: Vec<String> = ZipArchive::new(&mut input)
                .unwrap()
                .file_names()
                .map(|name| name.unwrap().into_owned())
                .collect();
            let added_names: Vec<String> = ZipArchive::new(&mut added)
                .unwrap()
                .file_names()
                .map(|name| name.unwrap().into_owned())
                .collect();
            assert_eq!(input_names, added_names);

            // already declared, so nothing else to do
            let mut again = Cursor::new(Vec::new());
            assert!(!add_c2pa_content_type(
                &mut ZipArchive::new(&mut added).unwrap(),
                &mut again,
                THRESHOLD_MB
            )
            .unwrap());
            assert!(again.get_ref().is_empty());
        }

        #[test]
        fn test_add_c2pa_content_type_size_is_limited() {
            let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
            writer
                .start_file(
                    CONTENT_TYPES_PATH,
                    zip::write::SimpleFileOptions::DEFAULT
                        .compression_method(zip::CompressionMethod::Deflated),
                )
                .unwrap();

            let mut xml_writer = Writer::new(&mut writer);
            xml_writer
                .write_event(Event::Start(BytesStart::new("Types")))
                .unwrap();
            xml_writer
                .write_event(Event::Text(BytesText::new(
                    &" ".repeat(MAX_CONTENT_TYPES_LEN as usize),
                )))
                .unwrap();
            xml_writer
                .write_event(Event::End(BytesEnd::new("Types")))
                .unwrap();

            let mut zip = writer.finish().unwrap();
            assert!(zip.get_ref().len() < 1024 * 1024);

            let mut output = Cursor::new(Vec::new());
            let result = add_c2pa_content_type(
                &mut ZipArchive::new(&mut zip).unwrap(),
                &mut output,
                THRESHOLD_MB,
            );
            assert!(
                matches!(&result, Err(Error::InvalidAsset(msg)) if msg.contains("larger than")),
                "expected the size limit error, got {result:?}"
            );
        }

        #[test]
        fn test_add_c2pa_content_type_skips_non_opc() {
            for sample in [ZIP, ODT] {
                let mut input = Cursor::new(sample.to_vec());
                let mut output = Cursor::new(Vec::new());
                assert!(!add_c2pa_content_type(
                    &mut ZipArchive::new(&mut input).unwrap(),
                    &mut output,
                    THRESHOLD_MB
                )
                .unwrap());
                assert!(output.get_ref().is_empty());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::io::{Cursor, Seek, Write};

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
    fn test_read_rejects_compressed_manifest() {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(
                MANIFEST_PATH,
                SimpleFileOptions::DEFAULT.compression_method(CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(&vec![0; 64 * 1024 * 1024]).unwrap();

        let zip = writer.finish().unwrap().into_inner();
        assert!(zip.len() < 1024 * 1024);

        assert!(matches!(
            ZipIO {}.read_c2pa(&mut Cursor::new(zip)),
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

    /// A ZIP whose manifest isn't the last entry.
    fn zip_with_manifest_in_middle() -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("first.txt", SimpleFileOptions::DEFAULT)
            .unwrap();
        writer.write_all(b"first").unwrap();

        writer
            .start_file(
                MANIFEST_PATH,
                SimpleFileOptions::DEFAULT.compression_method(CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(&[9, 9, 9]).unwrap();

        writer
            .start_file("last.txt", SimpleFileOptions::DEFAULT)
            .unwrap();
        writer.write_all(b"last").unwrap();
        writer.set_comment("archive comment").unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn entry_names(stream: &mut Cursor<Vec<u8>>) -> Vec<String> {
        let mut archive = ZipArchive::new(stream).unwrap();
        (0..archive.len())
            .map(|index| {
                archive
                    .by_index_raw(index)
                    .unwrap()
                    .name()
                    .unwrap()
                    .into_owned()
            })
            .collect()
    }

    #[test]
    fn test_write_replaces_manifest_in_place() {
        let zip_io = ZipIO {};
        let mut src = Cursor::new(zip_with_manifest_in_middle());

        let mut output = Cursor::new(Vec::new());
        zip_io
            .write_c2pa(&mut src, &mut output, &[1, 2, 3])
            .unwrap();

        assert_eq!(
            entry_names(&mut output),
            ["first.txt", MANIFEST_PATH, "last.txt"]
        );
        assert_eq!(zip_io.read_c2pa(&mut output).unwrap(), [1, 2, 3]);

        let mut archive = ZipArchive::new(&mut output).unwrap();
        assert_eq!(archive.comment(), b"archive comment");

        let mut last = String::new();
        archive
            .by_name("last.txt")
            .unwrap()
            .read_to_string(&mut last)
            .unwrap();
        assert_eq!(last, "last");
    }

    #[test]
    fn test_remove_keeps_entries_after_manifest() {
        let zip_io = ZipIO {};
        let mut src = Cursor::new(zip_with_manifest_in_middle());

        let mut output = Cursor::new(Vec::new());
        zip_io.remove_c2pa(&mut src, &mut output).unwrap();

        assert_eq!(entry_names(&mut output), ["first.txt", "last.txt"]);
        assert_eq!(
            ZipArchive::new(&mut output).unwrap().comment(),
            b"archive comment"
        );
    }

    #[test]
    fn test_remove_without_manifest_keeps_entries() {
        let zip_io = ZipIO {};
        let mut src = Cursor::new(SAMPLES[0].to_vec());

        let mut output = Cursor::new(Vec::new());
        zip_io.remove_c2pa(&mut src, &mut output).unwrap();

        assert_eq!(entry_names(&mut output), entry_names(&mut src));

        let mut src_archive = ZipArchive::new(&mut src).unwrap();
        let mut output_archive = ZipArchive::new(&mut output).unwrap();
        for index in 0..src_archive.len() {
            let mut expected = Vec::new();
            src_archive
                .by_index(index)
                .unwrap()
                .read_to_end(&mut expected)
                .unwrap();
            let mut actual = Vec::new();
            output_archive
                .by_index(index)
                .unwrap()
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(expected, actual);
        }
    }
}
