//! Deserialization profiling tests comparing c2pa_cbor with original serde_cbor.
//! These tests are disabled by default since serde_cbor is aliased to c2pa_cbor.
//! To enable: add serde_cbor = "0.11" to dev-dependencies and run:
//! cargo test --features compare_serde_cbor

#![cfg(feature = "compare_serde_cbor")]

use std::time::Instant;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
struct SimpleStruct {
    name: String,
    age: u32,
    active: bool,
}

#[test]
fn profile_simple_deserialization() {
    let data = SimpleStruct {
        name: "John Doe".to_string(),
        age: 30,
        active: true,
    };

    let c2pa_bytes = c2pa_cbor::to_vec(&data).unwrap();
    let serde_bytes = serde_cbor::to_vec(&data).unwrap();

    println!("\n=== Encoded Bytes Comparison ===");
    println!("c2pa_cbor: {:?}", c2pa_bytes);
    println!("serde_cbor: {:?}", serde_bytes);
    println!("Same bytes: {}", c2pa_bytes == serde_bytes);

    // Profile individual operations
    let iterations = 100_000;

    println!("\n=== Microbenchmark ({}x iterations) ===", iterations);

    // Test raw slice reading
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = &c2pa_bytes[..];
    }
    let slice_time = start.elapsed();
    println!(
        "Slice access overhead: {:?} ({:.2} ns/iter)",
        slice_time,
        slice_time.as_nanos() as f64 / iterations as f64
    );

    // Test c2pa_cbor deserialization
    let start = Instant::now();
    for _ in 0..iterations {
        let _: SimpleStruct = c2pa_cbor::from_slice(&c2pa_bytes).unwrap();
    }
    let c2pa_time = start.elapsed();
    println!(
        "c2pa_cbor::from_slice: {:?} ({:.2} ns/iter)",
        c2pa_time,
        c2pa_time.as_nanos() as f64 / iterations as f64
    );

    // Test serde_cbor deserialization
    let start = Instant::now();
    for _ in 0..iterations {
        let _: SimpleStruct = serde_cbor::from_slice(&serde_bytes).unwrap();
    }
    let serde_time = start.elapsed();
    println!(
        "serde_cbor::from_slice: {:?} ({:.2} ns/iter)",
        serde_time,
        serde_time.as_nanos() as f64 / iterations as f64
    );

    println!(
        "\nRatio: {:.2}x slower",
        c2pa_time.as_nanos() as f64 / serde_time.as_nanos() as f64
    );
}

#[test]
fn profile_primitive_types() {
    let iterations = 100_000;

    println!("\n=== u32 Deserialization ===");
    let value: u32 = 42;
    let c2pa_bytes = c2pa_cbor::to_vec(&value).unwrap();
    let serde_bytes = serde_cbor::to_vec(&value).unwrap();

    let start = Instant::now();
    for _ in 0..iterations {
        let _: u32 = c2pa_cbor::from_slice(&c2pa_bytes).unwrap();
    }
    let c2pa_time = start.elapsed();

    let start = Instant::now();
    for _ in 0..iterations {
        let _: u32 = serde_cbor::from_slice(&serde_bytes).unwrap();
    }
    let serde_time = start.elapsed();

    println!(
        "c2pa_cbor: {:.2} ns/iter",
        c2pa_time.as_nanos() as f64 / iterations as f64
    );
    println!(
        "serde_cbor: {:.2} ns/iter",
        serde_time.as_nanos() as f64 / iterations as f64
    );
    println!(
        "Ratio: {:.2}x",
        c2pa_time.as_nanos() as f64 / serde_time.as_nanos() as f64
    );

    println!("\n=== String Deserialization ===");
    let value = "Hello World";
    let c2pa_bytes = c2pa_cbor::to_vec(&value).unwrap();
    let serde_bytes = serde_cbor::to_vec(&value).unwrap();

    let start = Instant::now();
    for _ in 0..iterations {
        let _: String = c2pa_cbor::from_slice(&c2pa_bytes).unwrap();
    }
    let c2pa_time = start.elapsed();

    let start = Instant::now();
    for _ in 0..iterations {
        let _: String = serde_cbor::from_slice(&serde_bytes).unwrap();
    }
    let serde_time = start.elapsed();

    println!(
        "c2pa_cbor: {:.2} ns/iter",
        c2pa_time.as_nanos() as f64 / iterations as f64
    );
    println!(
        "serde_cbor: {:.2} ns/iter",
        serde_time.as_nanos() as f64 / iterations as f64
    );
    println!(
        "Ratio: {:.2}x",
        c2pa_time.as_nanos() as f64 / serde_time.as_nanos() as f64
    );

    println!("\n=== Vec<u32> Deserialization ===");
    let value: Vec<u32> = vec![1, 2, 3, 4, 5];
    let c2pa_bytes = c2pa_cbor::to_vec(&value).unwrap();
    let serde_bytes = serde_cbor::to_vec(&value).unwrap();

    let start = Instant::now();
    for _ in 0..iterations {
        let _: Vec<u32> = c2pa_cbor::from_slice(&c2pa_bytes).unwrap();
    }
    let c2pa_time = start.elapsed();

    let start = Instant::now();
    for _ in 0..iterations {
        let _: Vec<u32> = serde_cbor::from_slice(&serde_bytes).unwrap();
    }
    let serde_time = start.elapsed();

    println!(
        "c2pa_cbor: {:.2} ns/iter",
        c2pa_time.as_nanos() as f64 / iterations as f64
    );
    println!(
        "serde_cbor: {:.2} ns/iter",
        serde_time.as_nanos() as f64 / iterations as f64
    );
    println!(
        "Ratio: {:.2}x",
        c2pa_time.as_nanos() as f64 / serde_time.as_nanos() as f64
    );
}

#[test]
fn profile_map_vs_struct() {
    let iterations = 100_000;

    println!("\n=== Map with 3 entries ===");
    use std::collections::HashMap;
    let mut map = HashMap::new();
    map.insert("name".to_string(), "John".to_string());
    map.insert("age".to_string(), "30".to_string());
    map.insert("active".to_string(), "true".to_string());

    let c2pa_bytes = c2pa_cbor::to_vec(&map).unwrap();
    let serde_bytes = serde_cbor::to_vec(&map).unwrap();

    let start = Instant::now();
    for _ in 0..iterations {
        let _: HashMap<String, String> = c2pa_cbor::from_slice(&c2pa_bytes).unwrap();
    }
    let c2pa_time = start.elapsed();

    let start = Instant::now();
    for _ in 0..iterations {
        let _: HashMap<String, String> = serde_cbor::from_slice(&serde_bytes).unwrap();
    }
    let serde_time = start.elapsed();

    println!(
        "c2pa_cbor: {:.2} ns/iter",
        c2pa_time.as_nanos() as f64 / iterations as f64
    );
    println!(
        "serde_cbor: {:.2} ns/iter",
        serde_time.as_nanos() as f64 / iterations as f64
    );
    println!(
        "Ratio: {:.2}x",
        c2pa_time.as_nanos() as f64 / serde_time.as_nanos() as f64
    );
}

#[test]
fn profile_with_error_checking() {
    let data = SimpleStruct {
        name: "John Doe".to_string(),
        age: 30,
        active: true,
    };

    let c2pa_bytes = c2pa_cbor::to_vec(&data).unwrap();
    let iterations = 10_000;

    println!("\n=== Detailed Deserialization Steps ===");

    // Test just creating the decoder
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = c2pa_cbor::Decoder::new(&c2pa_bytes[..]);
    }
    let decoder_create = start.elapsed();
    println!(
        "Decoder creation: {:.2} ns/iter",
        decoder_create.as_nanos() as f64 / iterations as f64
    );

    // Test full deserialization
    let start = Instant::now();
    for _ in 0..iterations {
        let _: Result<SimpleStruct, _> = c2pa_cbor::from_slice(&c2pa_bytes);
    }
    let full_deser = start.elapsed();
    println!(
        "Full deserialize (with Result): {:.2} ns/iter",
        full_deser.as_nanos() as f64 / iterations as f64
    );

    // Compare with serde_cbor
    let serde_bytes = serde_cbor::to_vec(&data).unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        let _: Result<SimpleStruct, _> = serde_cbor::from_slice(&serde_bytes);
    }
    let serde_full = start.elapsed();
    println!(
        "serde_cbor full: {:.2} ns/iter",
        serde_full.as_nanos() as f64 / iterations as f64
    );
}
