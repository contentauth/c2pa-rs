use crate::{
    asset_io::{AssetIO, CAIReadWrapper, CAIReadWriteWrapper, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashObjectPositions},
    error::{Error, Result},
    Builder, Signer
};

use std::{
    fs::File, io::{self, Cursor, Read, Write}, path::Path, str::from_utf8
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

            // Copy all files except any CAI store files
            for i in 0..zip.len() {
                let mut file = zip.by_index(i)?;
                let name = file.name().to_string();

                // Skip any file that matches one of the CAI store paths
                if CAI_STORE_PATHS.iter().any(|&path| name == path) {
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
        let mut writer = match self.writer(_reader, _writer) {
            Ok(w) => w,
            Err(e) => {
                println!("write_cai: failed to create writer: {:?}", e);
                return Err(Error::EmbeddingError);
            }
        };

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

#[allow(dead_code)]
pub fn sign_epub_with_manifest(
    epub_path: &Path,
    manifest_json: &str,
    signer: &dyn Signer,
    output_path: &Path
) -> Result<Vec<u8>> {
    // 1.create builder from json
    let mut builder = Builder::from_json(manifest_json)?;
    
    // 2.set epub format
    builder.set_format("application/epub+zip");
    
    // 3.copy source epub to target epub
    std::fs::copy(epub_path, output_path)?;
    
    // 4.open target epub as dest_file
    let mut dest_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(output_path)?;
    let mut source_file = File::open(epub_path)?;
    
    // 5.sign and embed manifest
    let manifest_bytes = builder.sign(
        signer,
        "application/epub+zip",
        &mut source_file,
        &mut dest_file
    )?;
    
    Ok(manifest_bytes)
}

/// create a test signer (only for test)
#[cfg(test)]
#[cfg(feature = "file_io")]
pub fn create_test_signer() -> Result<Box<dyn Signer>> {
    use crate::{create_signer, SigningAlg};
    
    // use test cert and key
    let cert_path = "tests/fixtures/certs/ps256.pub";
    let key_path = "tests/fixtures/certs/ps256.pem";
    
    let signer = create_signer::from_files(
        cert_path,
        key_path,
        SigningAlg::Ps256,
        None
    )?;
    
    Ok(signer)
}

/// create a test signer (only for test, no file_io feature)
#[cfg(test)]
#[cfg(not(feature = "file_io"))]
pub fn create_test_signer() -> Result<Box<dyn Signer>> {
    use crate::{create_signer, SigningAlg};
    
    // use built-in test signer
    let signer = create_signer::from_keys(
        &include_bytes!("../../tests/fixtures/certs/ps256.pub")[..],
        &include_bytes!("../../tests/fixtures/certs/ps256.pem")[..],
        SigningAlg::Ps256,
        None
    )?;
    
    Ok(signer)
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;
    use std::path::PathBuf;
    use std::fs;

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

    fn create_temp_epub_copy(original_path: &Path) -> Result<PathBuf> {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("test_epub_{}.epub", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()));
        
        // read the entire file into memory first, then write to temp file
        let mut original_file = File::open(original_path)?;
        let mut file_data = Vec::new();
        original_file.read_to_end(&mut file_data)?;
        
        let mut temp_file_handle = File::create(&temp_file)?;
        temp_file_handle.write_all(&file_data)?;
        temp_file_handle.flush()?;
        
        Ok(temp_file)
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
        let test_epub_path = get_sample_epub_path("tests/fixtures/sample_with_manifest_diff_ending.epub");
        println!("   Path: {:?}", test_epub_path);
        
        println!("\n2. Reading CAI store");
        let epub_io = EpubIo::new("epub");
        let result = epub_io.read_cai_store(&test_epub_path)?;
        println!("   ✓ Successfully read {} bytes", result.len());
        
        println!("\n3. Verifying content");
        println!("   - CAI store bytes: {} bytes", result.len());
        println!("   - CAI store head: {:02x?}", &result[..32.min(result.len())]);
        
        // verify content length
        assert!(result.len() > 0, "CAI store should not be empty");
        
        // verify binary content contains expected markers
        let has_c2pa_marker = result.windows(4).any(|window| window == b"c2pa");
        let has_test_content = result.windows(13).any(|window| window == b"test-signature");
        
        println!("   - Has c2pa marker: {}", if has_c2pa_marker { "✓" } else { "✗" });
        println!("   - Has test signature: {}", if has_test_content { "✓" } else { "✗" });
        
        assert!(has_c2pa_marker || has_test_content, "CAI store should contain expected content");
        
        println!("\n=== Test completed ===\n");
        Ok(())
    }

    #[test]
    fn test_save_cai_store_with_cai() -> Result<()> {
        println!("\n=== Test: EPUB with CAI store ===");
        
        println!("1. Creating test EPUB with CAI store");
        let original_epub_path = get_sample_epub_path("tests/fixtures/sample_with_manifest_diff_ending.epub");
        let test_epub_path = create_temp_epub_copy(&original_epub_path)?;
        println!("   Original path: {:?}", original_epub_path);
        println!("   Temp path: {:?}", test_epub_path);
        
        println!("\n2. Reading CAI store");
        let epub_io = EpubIo::new("epub");

        let result = epub_io.read_cai_store(&test_epub_path)?;
        println!("   ✓ Successfully read {} bytes", result.len());
        println!("\n3. Verifying content");
        println!("   - CAI store bytes: {} bytes", result.len());
        println!("   - CAI store head: {:02x?}", &result[..32.min(result.len())]);
        
        assert!(result.len() > 0, "CAI store should not be empty");
        
        // try to parse as json if possible
        let content = String::from_utf8_lossy(&result);
        println!("   - CAI store content (lossy):\n{}", content);
        
        // if content looks like json, try to parse
        if content.trim().starts_with('{') {
            if let Ok(test_content_json) = serde_json::from_str::<Value>(&content) {
                if let Some(entries) = test_content_json["assertions"][0]["data"]["entries"].as_object() {
                    let save_key = "c2pa.save_times_test";
                    if let Some(save_entry) = entries.get(save_key) {
                        // if entity c2pa.save_times_test exists, times++
                        if let Some(times) = save_entry.get("times") {
                            if let Some(n) = times.as_u64() {
                                let mut new_json = test_content_json.clone();
                                if let Some(new_entries) = new_json["assertions"][0]["data"]["entries"].as_object_mut() {
                                    if let Some(new_save_entry) = new_entries.get_mut(save_key) {
                                        if let Some(new_times) = new_save_entry.get_mut("times") {
                                            *new_times = json!(n + 1);
                                        }
                                    }
                                }
                                
                                println!("  - New c2pa.json: \n{}", serde_json::to_string_pretty(&new_json).unwrap());
                                
                                let test_content_json_bytes: Vec<u8> = serde_json::to_vec(&new_json).expect("Failed to serialize JSON");
                                let test_content_json_slice: &[u8] = &test_content_json_bytes;
                                let _ = epub_io.save_cai_store(&test_epub_path, test_content_json_slice);
                            }
                        }
                    } else {
                        // if not, insert this entity
                        let mut new_json = test_content_json.clone();
                        if let Some(new_entries) = new_json["assertions"][0]["data"]["entries"].as_object_mut() {
                            new_entries.insert(save_key.to_string(), json!({ "times": 1 }));
                        }
                        
                        println!("  - New c2pa.json: \n{}", serde_json::to_string_pretty(&new_json).unwrap());
                        
                        let test_content_json_bytes: Vec<u8> = serde_json::to_vec(&new_json).expect("Failed to serialize JSON");
                        let test_content_json_slice: &[u8] = &test_content_json_bytes;
                        let _ = epub_io.save_cai_store(&test_epub_path, test_content_json_slice);
                    }
                }
            }
        }
        
        // read updated content
        let updated_result = epub_io.read_cai_store(&test_epub_path)?;
        println!("   - Updated CAI store bytes: {} bytes", updated_result.len());
        
        // clean up temp file
        let _ = fs::remove_file(&test_epub_path);
        
        println!("\n=== Test completed ===\n");
        Ok(())
    }

    #[test]
    fn test_remove_cai_store() -> Result<()> {
        println!("\n=== Test: Remove CAI store ===");
        
        let original_epub_path = get_sample_epub_path("tests/fixtures/sample_with_manifest_diff_ending.epub");
        let test_epub_path = create_temp_epub_copy(&original_epub_path)?;
        println!("   Original path: {:?}", original_epub_path);
        println!("   Temp path: {:?}", test_epub_path);
        
        let epub_io = EpubIo::new("epub");
        let result = epub_io.read_cai_store(&test_epub_path)?;
        println!("   - CAI store bytes: {} bytes", result.len());
        println!("   - CAI store head: {:02x?}", &result[..32.min(result.len())]);
        
        assert!(result.len() > 0, "CAI store should not be empty");

        let _ = epub_io.remove_cai_store(&test_epub_path);

        let result_new = epub_io.read_cai_store(&test_epub_path);
        
        match &result_new {
            Err(Error::JumbfNotFound) => println!("   ✓ Success: Correctly detected missing CAI store"),
            Err(e) => println!("   ✗ Error: Unexpected error: {:?}", e),
            Ok(_) => println!("   ✗ Error: Expected error but got success"),
        }
        assert!(matches!(result_new, Err(Error::JumbfNotFound)));

        // Clean up temp file
        let _ = fs::remove_file(&test_epub_path);

        println!("\n=== Test completed ===\n");
        Ok(())
    }

    #[test]
    fn test_read_bytes() -> Result<()> {
        let epub_io = EpubIo::new("epub");
        let epub_path = get_sample_epub_path("tests/fixtures/sample_with_manifest_diff_ending.epub");
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
        println!("   - CAI store bytes: {} bytes", result.len());
        println!("   - CAI store head: {:02x?}", &result[..32.min(result.len())]);
        
        // verify binary content contains expected markers
        let has_c2pa_marker = result.windows(4).any(|window| window == b"c2pa");
        let has_test_content = result.windows(13).any(|window| window == b"test-signature");
        
        println!("   - Has c2pa marker: {}", if has_c2pa_marker { "✓" } else { "✗" });
        println!("   - Has test signature: {}", if has_test_content { "✓" } else { "✗" });
        
        assert!(has_c2pa_marker || has_test_content, "CAI store should contain expected content");
        
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

    #[test]
    fn test_sign_epub_with_manifest() -> Result<()> {
        println!("\n=== Test: Sign EPUB with Manifest ===");
        
        // 1. prepare test file
        let original_epub_path = get_sample_epub_path("tests/fixtures/sample.epub");
        let temp_epub_path = create_temp_epub_copy(&original_epub_path)?;
        let output_epub_path = create_temp_epub_copy(&original_epub_path)?;
        
        println!("   Original path: {:?}", original_epub_path);
        println!("   Temp source path: {:?}", temp_epub_path);
        println!("   Output path: {:?}", output_epub_path);
        
        // 2. create manifest json
        let manifest_json = r#"{
            "claim_generator_info": [
                {
                    "name": "epub_c2pa_extension",
                    "version": "1.0.0"
                }
            ],
            "title": "Test Signed EPUB",
            "format": "application/epub+zip",
            "assertions": [
                {
                    "label": "c2pa.training-mining",
                    "data": {
                        "entries": {
                            "c2pa.ai_generative_training": {"use": "notAllowed"},
                            "c2pa.ai_inference": {"use": "notAllowed"},
                            "c2pa.ai_training": {"use": "notAllowed"},
                            "c2pa.data_mining": {"use": "notAllowed"}
                        }
                    }
                }
            ]
        }"#;
        
        println!("\n2. Manifest JSON:");
        println!("{}", manifest_json);
        
        // 3. create signer
        let signer = create_test_signer()?;
        println!("\n3. Created test signer");
        
        // 4. sign epub
        println!("\n4. Signing EPUB...");
        let manifest_bytes = sign_epub_with_manifest(
            &temp_epub_path,
            manifest_json,
            signer.as_ref(),
            &output_epub_path
        )?;
        
        println!("   ✓ Successfully signed EPUB");
        println!("   ✓ Manifest bytes: {} bytes", manifest_bytes.len());
        
        // 5. verify signed result
        println!("\n5. Verifying signed EPUB...");
        let epub_io = EpubIo::new("epub");
        let result = epub_io.read_cai_store(&output_epub_path)?;
        
        println!("   - CAI store bytes: {} bytes", result.len());
        println!("   - CAI store head: {:02x?}", &result[..32.min(result.len())]);
        
        assert!(result.len() > 0, "CAI store should not be empty");
        assert!(result.len() > 1000, "CAI store should be substantial size"); // signed manifest is usually large
        
        // verify binary content contains expected markers
        // C2PA manifest usually starts with a specific byte sequence
        let has_jumbf_header = result.len() >= 4 && result[0..4] == [0x00, 0x00, 0x60, 0x1D]; // JUMBF box header
        let has_c2pa_marker = result.windows(4).any(|window| window == b"c2pa");
        
        println!("   - Has JUMBF header: {}", if has_jumbf_header { "✓" } else { "✗" });
        println!("   - Has c2pa marker: {}", if has_c2pa_marker { "✓" } else { "✗" });
        
        assert!(has_jumbf_header || has_c2pa_marker, "CAI store should contain valid C2PA manifest markers");
        
        // clean up temp files
        let _ = fs::remove_file(&temp_epub_path);
        let _ = fs::remove_file(&output_epub_path);
        
        println!("\n=== Test completed ===\n");
        Ok(())
    }
}
