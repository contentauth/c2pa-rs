use std::fs;
use tempfile::tempdir;
use c2pa::{Reader, Ingredient};

#[test]
fn test_read_file_with_wrong_extension() {
    let dir = tempdir().unwrap();
    let image_path = dir.path().join("image.png"); // Actually a JPEG
    let jpeg_data = fs::read("tests/fixtures/IMG_0003.jpg").expect("Failed to read fixture");
    fs::write(&image_path, jpeg_data).expect("Failed to write image");

    // Even though it has a .png extension, it should be detected as a JPEG and read correctly
    // Note: If our current implementation prioritizes extension, this might still work 
    // because JpegIO might be tried if PngIO fails, OR it might just work because we check content.
    
    let reader = Reader::from_file(&image_path);
    // If it was treated as PNG, it would likely fail to find JUMBF because PNG and JPEG have different embedding.
    // If it is treated as JPEG, it should find the JUMBF (if fixture has one) or at least not fail with UnsupportedType.
    
    match reader {
        Ok(_) => (), // Success
        Err(c2pa::Error::JumbfNotFound) => (), // Success - found it's a JPEG but no JUMBF
        Err(e) => panic!("Should have detected as JPEG, but got error: {:?}", e),
    }
}

#[test]
fn test_ingredient_from_file_no_extension() {
    let dir = tempdir().unwrap();
    let image_path = dir.path().join("image_no_ext"); 
    let jpeg_data = fs::read("tests/fixtures/IMG_0003.jpg").expect("Failed to read fixture");
    fs::write(&image_path, jpeg_data).expect("Failed to write image");

    let ingredient = Ingredient::from_file(&image_path).expect("Failed to create ingredient");
    assert_eq!(ingredient.format(), Some("image/jpeg"));
}

#[test]
fn test_sidecar_with_unsupported_asset() {
    let dir = tempdir().unwrap();
    let asset_path = dir.path().join("unsupported.xyz"); 
    let asset_data = b"unsupported file content";
    fs::write(&asset_path, asset_data).expect("Failed to write asset");

    let sidecar_path = asset_path.with_extension("c2pa");
    let manifest_data = fs::read("tests/fixtures/cloud_manifest.c2pa").expect("Failed to read fixture");
    fs::write(&sidecar_path, manifest_data).expect("Failed to write sidecar");

    // Should detect the sidecar even though .xyz is unsupported
    let reader = Reader::from_file(&asset_path);
    
    match reader {
        Ok(r) => {
            assert!(r.active_manifest().is_some());
        },
        Err(e) => panic!("Should have detected sidecar for unsupported asset, but got error: {:?}", e),
    }
}

#[test]
fn test_sign_unsupported_with_sidecar() {
    use c2pa::{Builder, Context};
    use std::io::Cursor;

    let dir = tempdir().unwrap();
    let asset_path = dir.path().join("unsupported.txt");
    let asset_data = b"This is a text file that c2pa-rs doesn't normally support.";
    fs::write(&asset_path, asset_data).expect("Failed to write asset");

    // Create context with a test signer from standard test settings
    let settings_str = include_str!("../tests/fixtures/test_settings.toml");
    let context = Context::new().with_settings(settings_str).unwrap();

    let mut builder = Builder::from_context(context)
        .with_definition(serde_json::json!({"title": "Unsupported Format Test"})).unwrap();
    // Request a sidecar manifest
    builder.set_no_embed(true);

    let mut source = fs::File::open(&asset_path).unwrap();
    let mut dest = Cursor::new(Vec::new());

    // Should work now!
    // We use "application/octet-stream" as the format for the stream
    let result = builder.save_to_stream("application/octet-stream", &mut source, &mut dest);
    
    match result {
        Ok(manifest_bytes) => {
            assert!(!manifest_bytes.is_empty());
            // The destination should contain the original asset (since it's a sidecar)
            assert_eq!(dest.get_ref().as_slice(), asset_data);
            
            // Now verify we can read it back
            let sidecar_path = asset_path.with_extension("c2pa");
            fs::write(&sidecar_path, manifest_bytes).unwrap();
            
            let reader = Reader::from_file(&asset_path).expect("Failed to read back");
            assert_eq!(reader.active_manifest().unwrap().title().unwrap(), "Unsupported Format Test");
        },
        Err(e) => panic!("Should have allowed signing unsupported format with sidecar, but got error: {:?}", e),
    }
}