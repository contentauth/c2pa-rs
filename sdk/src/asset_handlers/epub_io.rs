use crate::{
    asset_io::{AssetIO, CAIReadWrapper, CAIReadWriteWrapper, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashObjectPositions},
    error::{Error, Result},
};

use std::{
    fs::File, io::{self, Cursor, Read, Write, Seek}, path::Path, str::from_utf8
};
// use zip::ZipArchive;
use zip::{
    result::{ZipError, ZipResult},
    write::{SimpleFileOptions}, 
    ZipArchive, 
    ZipWriter
};

static SUPPORTED_TYPES: [&str; 6] = [
    "epub",
    "application/epub+zip",
    "application/zip",
    "application/octet-stream",
    "zip",
    ""
];

const CAI_STORE_PATHS: [&str; 3] = [
    "META-INF/c2pa.json",
    "META-INF/manifest.c2pa",
    "META-INF/manifest.json",
];

pub struct EpubIo;

impl AssetIO for EpubIo {
    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }

    fn new(_asset_type: &str) -> Self {
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
        println!("Attempting to open file: {:?}", asset_path);

        // Open the EPUB file
        let file = match File::open(asset_path) {
            Ok(f) => f,
            Err(e) => {
                println!("Error opening file: {:?}", e);
                return Err(e.into());
            }
        };
        
        println!("File opened successfully, attempting to create ZIP archive");
        let mut archive = match ZipArchive::new(file) {
            Ok(a) => a,
            Err(e) => {
                println!("Error creating ZIP archive: {:?}", e);
                return Err(e.into());
            }
        };
        
        println!("ZIP archive created, looking for CAI store in {:?}", CAI_STORE_PATHS);
        // Try to find and read the CAI store file from any of the possible paths
        let mut cai_data: Option<Vec<u8>> = None;
        let mut last_error = None;

        for path in CAI_STORE_PATHS.iter() {
            match archive.by_name(path) {
            Ok(mut cai_file) => {
                println!("Found {} in ZIP archive", path);
                let mut data = Vec::new();
                match cai_file.read_to_end(&mut data) {
                Ok(_) => {
                    if !data.is_empty() {
                    println!("Successfully read CAI data ({} bytes)", data.len());
                    cai_data = Some(data);
                    break;
                    } else {
                    println!("CAI data at {} is empty", path);
                    last_error = Some(Error::JumbfNotFound);
                    }
                }
                Err(e) => {
                    println!("Error reading CAI data at {}: {:?}", path, e);
                    last_error = Some(e.into());
                }
                }
            }
            Err(e) => {
                println!("{} not found in ZIP archive: {:?}", path, e);
                last_error = Some(Error::JumbfNotFound);
            }
            }
        }

        let result = match cai_data {
            Some(data) => Ok(data),
            None => Err(last_error.unwrap_or(Error::JumbfNotFound)),
        };
        result
    }

  
    fn save_cai_store(&self, _asset_path: &Path, _store_bytes: &[u8]) -> Result<()> {
        let cai_store_str = from_utf8(_store_bytes)?;
        let mut epub_data = Vec::new();
        {
            let mut epub_file = File::open(&_asset_path)?;
            epub_file.read_to_end(&mut epub_data)?;
        }

        let reader = Cursor::new(&epub_data);
        let mut zip = ZipArchive::new(reader)?;

        let mut new_epub_data = Vec::new();
        {
            let mut zip_writer = ZipWriter::new(Cursor::new(&mut new_epub_data));

            // Copy all files except the old c2pa.json
            for i in 0..zip.len() {
                let mut file = zip.by_index(i)?;
                let name = file.name().to_string();

                if name == "META-INF/c2pa.json" {
                    continue;
                }

                let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
                zip_writer.start_file(&name, options)?;

                std::io::copy(&mut file, &mut zip_writer)?;
            }

            // Add or replace c2pa.json
            zip_writer.start_file(
                "META-INF/c2pa.json", 
                zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored))?;
            zip_writer.write_all(cai_store_str.as_bytes())?;

            zip_writer.finish()?;
        }

        // Overwrite the original EPUB with the new content
        let mut epub_file = File::create(&_asset_path)?;
        epub_file.write_all(&new_epub_data)?;

        Ok(())
    }

    fn get_object_locations(&self, _asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        Ok(vec![])
    }

    fn remove_cai_store(&self, _asset_path: &Path) -> Result<()> {
        let mut epub_data = Vec::new();
        {
            let mut epub_file = File::open(&_asset_path)?;
            epub_file.read_to_end(&mut epub_data)?;
        }

        let reader = Cursor::new(&epub_data);
        let mut zip = ZipArchive::new(reader)?;

        let mut new_epub_data = Vec::new();
        {
            let mut zip_writer = ZipWriter::new(
                Cursor::new(
                    &mut new_epub_data
                )
            );

            // Copy all files except the c2pa.json
            for i in 0..zip.len() {
                let mut file = zip.by_index(i)?;
                let name = file.name().to_string();

                if name == "META-INF/c2pa.json" {
                    continue;
                }

                let options = SimpleFileOptions::default().compression_method(
                    zip::CompressionMethod::Stored
                );
                zip_writer.start_file(&name, options)?;

                std::io::copy(&mut file, &mut zip_writer)?;
            }

            zip_writer.finish()?;
        }

        // Overwrite the original EPUB with the new content
        let mut epub_file = File::create(&_asset_path)?;
        epub_file.write_all(&new_epub_data)?;
        Ok(())
    }

}

impl CAIReader for EpubIo {
    fn read_cai(&self, _reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let mut reader = self
            .reader(_reader)
            .map_err(|_| Error::JumbfNotFound)?;


        let mut index = None;
        for path in CAI_STORE_PATHS.iter() {
            if let Some(i) = reader.index_for_path(Path::new(path)) {
                index = Some(i);
                break;
            }
        }
        let index = index.ok_or(Error::JumbfNotFound)?;
        let mut file = reader.by_index(index).map_err(|_| Error::JumbfNotFound)?;

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;

        Ok(bytes)
    }

    fn read_xmp(&self, _reader: &mut dyn CAIRead) -> Option<String> {
        None
    }
}

impl CAIWriter for EpubIo {
    fn write_cai(
        &self, 
        _reader: &mut dyn CAIRead, 
        _writer: &mut dyn CAIReadWrite, 
        mut _cai_data: &[u8]
    ) -> Result<()> {
        let mut writer = self
            .writer(_reader, _writer)
            .map_err(|_| Error::EmbeddingError)?;

        match writer.add_directory("META-INF", SimpleFileOptions::default()) {
            Err(ZipError::InvalidArchive(msg)) if msg == "Duplicate filename: META-INF/" => {}
            Err(_) => return Err(Error::EmbeddingError),
            _ => {}
        }

        // Helper closure to start the file, retry once if duplicate
        let start_manifest_file = |writer: &mut ZipWriter<CAIReadWriteWrapper>, path: &Path| -> std::result::Result<(), ZipError> {
            match writer.start_file_from_path(
                path,
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
            ) {
                Err(ZipError::InvalidArchive(msg)) if msg.contains("Duplicate filename: META-INF/") =>  {
                    println!("Duplicate filename detected, aborting file and retrying: {:?}", path);
                    writer.abort_file()?;
                    writer.start_file_from_path(
                        path,
                        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
                    )
                }
                res => res,
            }
        };
        start_manifest_file(&mut writer, Path::new("META-INF/manifest.c2pa"))
            .map_err(|_| Error::EmbeddingError)?;
        
        io::copy(&mut _cai_data, &mut writer)?;
        writer.finish().map_err(|_| Error::EmbeddingError)?;
        Ok(())
    }

    fn remove_cai_store_from_stream(
        &self, 
        _reader: &mut dyn CAIRead, 
        _writer: &mut dyn CAIReadWrite
    ) -> Result<()> {
        Ok(())
    }

    fn get_object_locations_from_stream(
        &self, 
        _input_stream: &mut dyn CAIRead
    ) -> Result<Vec<HashObjectPositions>> {
        Ok(vec![])
    }
}


impl EpubIo {
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
    use serde_json::{json, Value};

    use super::*;
    use std::path::PathBuf;

    const SAMPLES: [&[u8]; 1] = [
        include_bytes!("../../tests/fixtures/sample.epub"),
        // include_bytes!("../../tests/fixtures/sample_with_manifest.epub"),
        // include_bytes!("../../tests/fixtures/sample1.docx"),
        // include_bytes!("../../tests/fixtures/sample1.odt"),
    ];

    fn get_sample_epub_path(path_str: &str) -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let mut path = PathBuf::from(manifest_dir);
        path.push(path_str);
        path
    }


    #[test]
    fn test_read_cai_store_without_cai() -> Result<()> {
        println!("\n=== Test: EPUB without CAI store ===");
        println!("1. Getting sample EPUB path");
        let epub_path = get_sample_epub_path("tests/fixtures/sample.epub");
        println!("   Path: {:?}", epub_path);
        
        println!("\n2. Attempting to read CAI store");
        let epub_io = EpubIo::new("epub");
        let result = epub_io.read_cai_store(&epub_path);
        
        println!("\n3. Verifying result");
        match &result {
            Err(Error::JumbfNotFound) => println!("   ✓ Success: Correctly detected missing CAI store"),
            Err(e) => println!("   ✗ Error: Unexpected error: {:?}", e),
            Ok(_) => println!("   ✗ Error: Expected error but got success"),
        }
        assert!(matches!(result, Err(Error::JumbfNotFound)));
        
        println!("\n=== Test completed ===\n");
        Ok(())
    }

    #[test]
    fn test_read_cai_store_with_cai() -> Result<()> {
        println!("\n=== Test: EPUB with CAI store ===");
        
        println!("1. Creating test EPUB with CAI store");
        let test_epub_path = get_sample_epub_path("tests/fixtures/sample_with_manifest.epub");
        // let test_epub_path = get_sample_epub_path("tests/fixtures/sample_with_manifest_diff_ending.epub"); // manifest.c2pa
        println!("   Path: {:?}", test_epub_path);
        
        println!("\n2. Reading CAI store");
        let epub_io = EpubIo::new("epub");
        let result = epub_io.read_cai_store(&test_epub_path)?;
        println!("   ✓ Successfully read {} bytes", result.len());
        
        println!("\n3. Verifying content");
        let content = String::from_utf8(result)?;
        println!("   - CAI store content:\n{}", content);
        let has_signature = content.contains("test-signature");
        let has_title = content.contains("Test CAI EPUB");
        
        println!("   - Test signature found: {}", if has_signature { "✓" } else { "✗" });
        println!("   - Test title found: {}", if has_title { "✓" } else { "✗" });
        
        assert!(has_signature, "Test signature not found in CAI store");
        assert!(has_title, "Test title not found in CAI store");
        
        println!("\n=== Test completed ===\n");
        Ok(())
    }

    #[test]
    fn test_save_cai_store_with_cai() -> Result<()> {
        println!("\n=== Test: EPUB with CAI store ===");
        
        println!("1. Creating test EPUB with CAI store");
        let test_epub_path = get_sample_epub_path("tests/fixtures/sample_with_manifest.epub");
        println!("   Path: {:?}", test_epub_path);
        println!("\n2. Reading CAI store");
        let epub_io = EpubIo::new("epub");

        let result = epub_io.read_cai_store(&test_epub_path)?;
        println!("   ✓ Successfully read {} bytes", result.len());
        println!("\n3. Verifying content");
        let content = String::from_utf8(result)?;
        // let content = "{\"claim_generator\":\"python_test/0.1\",\"title\":\"Test CAI EPUB\",\"format\":\"epub\",\"assertions\":[{\"label\":\"c2pa.training-mining\",\"data\":{\"entries\":{\"c2pa.ai_generative_training\":{\"use\":\"notAllowed\"},\"c2pa.ai_inference\":{\"use\":\"notAllowed\"},\"c2pa.ai_training\":{\"use\":\"notAllowed\"},\"c2pa.data_mining\":{\"use\":\"notAllowed\"}}}}],\"claim\":{\"signature\":\"test-signature\"}}";
        println!("   - CAI store content:\n{}", content);

        let mut test_content_json: Value = serde_json::from_str(&content).expect("Invalid JSON");

        if let Some(entries) = test_content_json["assertions"][0]["data"]["entries"].as_object_mut() {
            let save_key = "c2pa.save_times_test";
            if let Some(save_entry) = entries.get_mut(save_key) {
                // if entity c2pa.save_times_test exists, times++
                if let Some(times) = save_entry.get_mut("times") {
                    if let Some(n) = times.as_u64() {
                        *times = json!(n + 1);
                    }
                }
            } else {
                // if not, insert this entity
                entries.insert(save_key.to_string(), json!({ "times": 1 }));
            }
        }

        println!("  - New c2pa.json: \n{}", serde_json::to_string_pretty(&test_content_json).unwrap());
        
        let test_content_json_bytes: Vec<u8> = serde_json::to_vec(&test_content_json).expect("Failed to serialize JSON");
        let test_content_json_slice: &[u8] = &test_content_json_bytes;
        let _ = epub_io.save_cai_store(&test_epub_path, test_content_json_slice);

        println!("   - New CAI store content:\n{}", String::from_utf8(epub_io.read_cai_store(&test_epub_path)?)?);
        
        println!("\n=== Test completed ===\n");
        Ok(())
    }

    #[test]
    fn test_remove_cai_store() -> Result<()> {
        println!("\n=== Test: Remove CAI store ===");
        
        let test_epub_path = get_sample_epub_path("tests/fixtures/sample_with_manifest.epub");
        println!("   Path: {:?}", test_epub_path);
        let epub_io = EpubIo::new("epub");
        let result = epub_io.read_cai_store(&test_epub_path)?;
        let content = String::from_utf8(result)?;
        // let content = "{\"claim_generator\":\"python_test/0.1\",\"title\":\"Test CAI EPUB\",\"format\":\"epub\",\"assertions\":[{\"label\":\"c2pa.training-mining\",\"data\":{\"entries\":{\"c2pa.ai_generative_training\":{\"use\":\"notAllowed\"},\"c2pa.ai_inference\":{\"use\":\"notAllowed\"},\"c2pa.ai_training\":{\"use\":\"notAllowed\"},\"c2pa.data_mining\":{\"use\":\"notAllowed\"}}}}],\"claim\":{\"signature\":\"test-signature\"}}";
        println!("   - CAI store content:\n{}", content);

        let _ = epub_io.remove_cai_store(&test_epub_path);

        let result_new = epub_io.read_cai_store(&test_epub_path);
        
        match &result_new {
            Err(Error::JumbfNotFound) => println!("   ✓ Success: Correctly detected missing CAI store"),
            Err(e) => println!("   ✗ Error: Unexpected error: {:?}", e),
            Ok(_) => println!("   ✗ Error: Expected error but got success"),
        }
        assert!(matches!(result_new, Err(Error::JumbfNotFound)));

        println!("\n=== Test completed ===\n");
        Ok(())
    }

    #[test]
    fn test_read_bytes() -> Result<()> {
        let epub_io = EpubIo::new("epub");
        let epub_path = get_sample_epub_path("tests/fixtures/sample_with_manifest.epub");
        let mut file = File::open(&epub_path)?;
        let mut epub_data = Vec::new();
        println!("File opened successfully, reading data");
        file.read_to_end(&mut epub_data)?;
        println!("Read {} bytes from EPUB file", epub_data.len());

        let mut reader = Cursor::new(epub_data);
        let mut cai_reader = CAIReadWrapper {
            reader: &mut reader,
        };

        println!("Reading CAI store from real EPUB file");
        let result = epub_io.read_cai(&mut cai_reader)?;
        println!("   ✓ Successfully read {} bytes", result.len());
        assert!(result.len() > 0, "CAI store should not be empty");
        
        println!("\n3. Verifying content");
        let content = String::from_utf8(result)?;
        println!("   - CAI store content:\n{}", content);
        let has_signature = content.contains("test-signature");
        let has_title = content.contains("Test CAI EPUB");
        
        println!("   - Test signature found: {}", if has_signature { "✓" } else { "✗" });
        println!("   - Test title found: {}", if has_title { "✓" } else { "✗" });
        
        assert!(has_signature, "Test signature not found in CAI store");
        assert!(has_title, "Test title not found in CAI store");
        
        println!("\n=== Test completed ===\n");
        Ok(())
    }

    #[test]
    fn test_write_bytes() -> Result<()> {
        for sample in SAMPLES {
            let mut stream = Cursor::new(sample);

            let epub_io = EpubIo {};

            assert!(matches!(
                epub_io.read_cai(&mut stream),
                Err(Error::JumbfNotFound)
            ));

            let mut output_stream = Cursor::new(Vec::with_capacity(sample.len() + 7));
            let random_bytes = [1, 2, 3, 4, 3, 2, 1];
            epub_io.write_cai(&mut stream, &mut output_stream, &random_bytes)?;

            let data_written = epub_io.read_cai(&mut output_stream)?;
            assert_eq!(data_written, random_bytes);
        }

        Ok(())
    }

    #[test]
    fn test_write_bytes_replace() -> Result<()> {
        for sample in SAMPLES {
            let mut stream = Cursor::new(sample);

            let epub_io = EpubIo {};

            assert!(matches!(
                epub_io.read_cai(&mut stream),
                Err(Error::JumbfNotFound)
            ));

            let mut output_stream1 = Cursor::new(Vec::with_capacity(sample.len() + 7));
            let random_bytes = [1, 2, 3, 4, 3, 2, 1];
            epub_io.write_cai(&mut stream, &mut output_stream1, &random_bytes)?;

            let data_written = epub_io.read_cai(&mut output_stream1)?;
            assert_eq!(data_written, random_bytes);

            let mut output_stream2 = Cursor::new(Vec::with_capacity(sample.len() + 5));
            let random_bytes = [3, 2, 1, 2, 3];
            output_stream1.rewind()?;
            epub_io.write_cai(&mut output_stream1, &mut output_stream2, &random_bytes)?;

            output_stream2.rewind()?;
            let data_written = epub_io.read_cai(&mut output_stream2)?;
            println!("Data written: {:?}", data_written);
            assert_eq!(data_written, random_bytes);

            let mut bytes = Vec::new();
            stream.rewind()?;
            stream.read_to_end(&mut bytes)?;
            assert_eq!(sample, bytes);
        }

        Ok(())
    }
}
