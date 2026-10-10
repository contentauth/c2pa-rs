#![cfg(all(feature = "file_io", not(target_arch = "wasm32")))]

#[path = "common/embed_manifest.rs"]
mod embed_manifest;

use std::{env, fs, path::PathBuf, sync::Arc};

use c2pa::{create_signer, Context, Result, SigningAlg};

fn compatibility_dir() -> PathBuf {
    PathBuf::from(env::var_os("COMPAT_DIR").expect("COMPAT_DIR must be set"))
}

fn compatibility_context() -> Result<Arc<Context>> {
    // Test certificates are not public trust anchors. Signature and asset-hash
    // validation stay enabled, without contacting external services.
    Ok(Context::new()
        .with_settings(
            r#"{
                "verify": {
                    "verify_after_reading": true,
                    "verify_after_sign": true,
                    "verify_trust": false,
                    "ocsp_fetch": false,
                    "remote_manifest_fetch": false
                },
                "builder": {
                    "intent": "edit",
                    "thumbnail": {"enabled": false}
                }
            }"#,
        )?
        .into_shared())
}

#[test]
#[ignore = "Run by compatibility-check.yml with shared fixtures"]
fn compatibility_sign() -> Result<()> {
    let dir = compatibility_dir();
    let fixtures = dir.join("fixtures");
    let certs = fs::read(fixtures.join("certs/ed25519.pub"))?;
    let private_key = fs::read(fixtures.join("certs/ed25519.pem"))?;
    let signer = create_signer::from_keys(&certs, &private_key, SigningAlg::Ed25519, None)?;

    embed_manifest::sign_embed_manifest(
        &compatibility_context()?,
        signer.as_ref(),
        &fixtures,
        &dir.join("test_file.jpg"),
    )
}

#[test]
#[ignore = "Run by compatibility-check.yml after the other SDK signs"]
fn compatibility_verify() -> Result<()> {
    let dir = compatibility_dir();
    let reader = embed_manifest::verify_embed_manifest(
        &compatibility_context()?,
        &dir.join("test_file.jpg"),
    )?;
    fs::write(dir.join("report.json"), reader.to_string())?;
    Ok(())
}
