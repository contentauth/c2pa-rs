use crate::{
    asset_io::{AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashObjectPositions},
    error::{Error, Result},
};

use std::{
    io::Read,
    path::Path,
    fs::File,
};
use zip::ZipArchive;

static SUPPORTED_TYPES: [&str; 6] = [
    "epub",
    "application/epub+zip",
    "application/zip",
    "application/octet-stream",
    "zip",
    ""
];

const CAI_STORE_PATH: &str = "META-INF/c2pa.json";

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
        
        println!("ZIP archive created, looking for {}", CAI_STORE_PATH);
        // Try to find and read the CAI store file
        let result = {
            match archive.by_name(CAI_STORE_PATH) {
                Ok(mut cai_file) => {
                    println!("Found {} in ZIP archive", CAI_STORE_PATH);
                    let mut cai_data = Vec::new();
                    match cai_file.read_to_end(&mut cai_data) {
                        Ok(_) => {
                            if cai_data.is_empty() {
                                println!("CAI data is empty");
                                Err(Error::JumbfNotFound)
                            } else {
                                println!("Successfully read CAI data ({} bytes)", cai_data.len());
                                Ok(cai_data)
                            }
                        }
                        Err(e) => {
                            println!("Error reading CAI data: {:?}", e);
                            Err(e.into())
                        }
                    }
                }
                Err(e) => {
                    println!("Error finding {} in ZIP archive: {:?}", CAI_STORE_PATH, e);
                    Err(Error::JumbfNotFound)
                }
            }
        };
        result
    }

    // Stub implementations
    fn save_cai_store(&self, _asset_path: &Path, _store_bytes: &[u8]) -> Result<()> {
        Ok(())
    }

    fn get_object_locations(&self, _asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        Ok(vec![])
    }

    fn remove_cai_store(&self, _asset_path: &Path) -> Result<()> {
        Ok(())
    }
}

impl CAIReader for EpubIo {
    fn read_cai(&self, _reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        Ok(vec![])
    }

    fn read_xmp(&self, _reader: &mut dyn CAIRead) -> Option<String> {
        None
    }
}

impl CAIWriter for EpubIo {
    fn write_cai(&self, _reader: &mut dyn CAIRead, _writer: &mut dyn CAIReadWrite, _cai_data: &[u8]) -> Result<()> {
        Ok(())
    }

    fn remove_cai_store_from_stream(&self, _reader: &mut dyn CAIRead, _writer: &mut dyn CAIReadWrite) -> Result<()> {
        Ok(())
    }

    fn get_object_locations_from_stream(&self, _input_stream: &mut dyn CAIRead) -> Result<Vec<HashObjectPositions>> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;
    use zip::{ZipArchive, ZipWriter, write::FileOptions};
    use std::io::Write;

    fn get_sample_epub_path() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let mut path = PathBuf::from(manifest_dir);
        path.push("tests/fixtures/sample.epub");
        path
    }

    fn create_test_epub_with_cai() -> Result<PathBuf> {
        // Create a temporary directory
        let temp_dir = tempdir()?;
        let test_epub_path = temp_dir.path().join("test_with_cai.epub");
        
        // Read the original sample.epub
        let sample_path = get_sample_epub_path();
        let sample_file = File::open(&sample_path)?;
        let mut archive = ZipArchive::new(sample_file)?;
        
        // Create a new EPUB with the fake c2pa.json
        let test_file = File::create(&test_epub_path)?;
        let mut writer = ZipWriter::new(test_file);
        
        // Copy all files from the original EPUB
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let outpath = file.name().to_string();
            
            if outpath == CAI_STORE_PATH {
                continue; // Skip the original c2pa.json if it exists
            }
            
            let options: FileOptions<()> = file.options().into();
            writer.start_file(outpath, options)?;
            std::io::copy(&mut file, &mut writer)?;
        }
        
        // Add our fake c2pa.json
        let fake_cai = r#"{
            "version": "1.0",
            "claim_generator": "test",
            "title": "Test CAI Store",
            "format": "epub",
            "instance_id": "test-instance",
            "claim": {
                "signature": "test-signature"
            }
        }"#;
        
        let options: FileOptions<()> = FileOptions::default();
        writer.start_file(CAI_STORE_PATH, options)?;
        writer.write_all(fake_cai.as_bytes())?;
        
        // Finish writing the ZIP file
        writer.finish()?;
        
        // Keep the temp_dir alive by storing it in a static
        static mut TEMP_DIR: Option<tempfile::TempDir> = None;
        unsafe {
            TEMP_DIR = Some(temp_dir);
        }
        
        Ok(test_epub_path)
    }

    #[test]
    fn test_read_cai_store_without_cai() -> Result<()> {
        println!("\n=== Test: EPUB without CAI store ===");
        println!("1. Getting sample EPUB path");
        let epub_path = get_sample_epub_path();
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
        let test_epub_path = create_test_epub_with_cai()?;
        println!("   Path: {:?}", test_epub_path);
        
        println!("\n2. Reading CAI store");
        let epub_io = EpubIo::new("epub");
        let result = epub_io.read_cai_store(&test_epub_path)?;
        println!("   ✓ Successfully read {} bytes", result.len());
        
        println!("\n3. Verifying content");
        let content = String::from_utf8(result)?;
        let has_signature = content.contains("test-signature");
        let has_title = content.contains("Test CAI Store");
        
        println!("   - Test signature found: {}", if has_signature { "✓" } else { "✗" });
        println!("   - Test title found: {}", if has_title { "✓" } else { "✗" });
        
        assert!(has_signature, "Test signature not found in CAI store");
        assert!(has_title, "Test title not found in CAI store");
        
        println!("\n=== Test completed ===\n");
        Ok(())
    }
}
