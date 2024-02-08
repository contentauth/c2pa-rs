use std::io::{Cursor, Seek};

use anyhow::Result;
#[cfg(not(target_arch = "wasm32"))]
use c2pa::{create_signer, SigningAlg};
use c2pa::{ManifestStore, ManifestStoreBuilder, RemoteSigner};
use serde_json::json;
#[cfg(not(target_arch = "wasm32"))]
use tokio::runtime::Runtime;

const PARENT_JSON: &str = r#"
{
    "title": "Parent Test",
    "format": "image/jpeg",
    "relationship": "parentOf"
}
"#;

const TEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/es256.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/es256.pem");

fn get_manifest_def(title: &str, format: &str) -> String {
    json!({
        "title": title,
        "format": format,
        "claim_generator_info": [
            {
                "name": "c2pa test",
                "version": env!("CARGO_PKG_VERSION")
            }
        ],
        "thumbnail": {
            "format": "image/jpeg",
            "identifier": "manifest_thumbnail.jpg"
        },
        "ingredients": [
            {
                "title": "Test",
                "format": "image/jpeg",
                "instance_id": "12345",
                "relationship": "inputTo"
            }
        ],
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.edited",
                            "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
                            "softwareAgent": "Adobe Firefly 0.1.0"
                        }
                    ]
                }
            }
        ]
    }).to_string()
}

//#[cfg(not(target_arch = "wasm32"))]
fn main() -> Result<()> {
    let title = "CA.jpg";
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    let json = get_manifest_def(title, format);

    let mut builder = ManifestStoreBuilder::new();
    builder
        //.with_options({{ "validation": true}})
        .with_json(&json)?
        .add_ingredient(PARENT_JSON, format, &mut source)?;

    // add a manifest thumbnail ( just reuse the image for now )
    source.rewind()?;
    builder.add_resource("manifest_thumbnail.jpg", &mut source)?;

    // write the manifest builder to a zipped stream
    let mut zipped = Cursor::new(Vec::new());
    builder.zip(&mut zipped)?;

    // write the zipped stream to a file for debugging
    let debug_path = format!("{}/../target/test.zip", env!("CARGO_MANIFEST_DIR"));
    std::fs::write(debug_path, zipped.get_ref())?;

    // unzip the manifest builder from the zipped stream
    zipped.rewind()?;
    let mut builder = ManifestStoreBuilder::unzip(&mut zipped)?;

    // sign the ManifestStoreBuilder and write it to the output stream
    #[cfg(not(target_arch = "wasm32"))]
    let mut dest = Cursor::new(Vec::new());
    #[cfg(not(target_arch = "wasm32"))]
    {
        let signer = create_signer::from_keys(CERTS, PRIVATE_KEY, SigningAlg::Es256, None)?;

        builder.sign(format, &mut source, &mut dest, signer.as_ref())?;

        // read and validate the signed manifest store
        dest.rewind()?;
    }
    #[cfg(target_arch = "wasm32")]
    let mut dest = source; // todo: figure out how to sign in wasm

    let manifest_store = ManifestStore::from_stream(format, &mut dest, true)?;

    // extract a thumbnail image from the ManifestStore
    let mut thumbnail = Cursor::new(Vec::new());
    if let Some(manifest) = manifest_store.get_active() {
        if let Some(thumbnail_ref) = manifest.thumbnail_ref() {
            manifest_store.get_resource(&thumbnail_ref.identifier, &mut thumbnail)?;
            println!(
                "wrote thumbnail {} of size {}",
                thumbnail_ref.format,
                thumbnail.get_ref().len()
            );
        }
    }

    println!("{}", manifest_store);
    assert!(manifest_store.validation_status().is_none());
    assert_eq!(manifest_store.get_active().unwrap().title().unwrap(), title);

    // an example of using asynchronous remote signing
    #[cfg(not(target_arch = "wasm32"))]
    {
        println!("remote signing {}", format);
        let mut dest = Cursor::new(Vec::new());
        let remote_signer = Box::new(TestRemoteSigner {});
        let _manifest_bytes = Runtime::new()?.block_on(async {
            builder
                .sign_remote(format, &mut source, &mut dest, &*remote_signer)
                .await
        })?;
        dest.rewind()?;
        let manifest_store = ManifestStore::from_stream(format, &mut dest, true)?;
        println!("remote signed: {}", manifest_store);
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
struct TestRemoteSigner {}

//#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg(not(target_arch = "wasm32"))]
impl RemoteSigner for TestRemoteSigner {
    async fn sign_remote(&self, claim_bytes: &[u8]) -> c2pa::Result<Vec<u8>> {
        // you could call a remote server here to sign the claim
        // it would need to make calls like this
        // we must return a cose structured signature here.
        let signer = create_signer::from_keys(CERTS, PRIVATE_KEY, SigningAlg::Es256, None)?;
        c2pa::cose_sign::sign_claim(claim_bytes, &*signer, self.reserve_size())
    }

    fn reserve_size(&self) -> usize {
        10000
    }
}
