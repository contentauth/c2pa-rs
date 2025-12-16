//! Performance comparison tests between c2pa_cbor and original serde_cbor.
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
struct ComplexStruct {
    id: u64,
    metadata: Metadata,
    tags: Vec<String>,
    scores: Vec<f64>,
    nested: Vec<NestedData>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
struct Metadata {
    title: String,
    description: Option<String>,
    version: u32,
    authors: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
struct NestedData {
    key: String,
    value: i32,
    enabled: bool,
}

fn create_simple_data() -> SimpleStruct {
    SimpleStruct {
        name: "John Doe".to_string(),
        age: 30,
        active: true,
    }
}

fn create_complex_data() -> ComplexStruct {
    ComplexStruct {
        id: 12345678901234,
        metadata: Metadata {
            title: "Test Document".to_string(),
            description: Some("A comprehensive test of CBOR encoding performance".to_string()),
            version: 42,
            authors: vec![
                "Alice".to_string(),
                "Bob".to_string(),
                "Charlie".to_string(),
            ],
        },
        tags: vec![
            "rust".to_string(),
            "cbor".to_string(),
            "serialization".to_string(),
            "benchmark".to_string(),
            "performance".to_string(),
        ],
        scores: vec![1.5, 2.7, 3.9, 4.2, 5.8, 6.1, 7.3, 8.4, 9.6, 10.0],
        nested: vec![
            NestedData {
                key: "item1".to_string(),
                value: 100,
                enabled: true,
            },
            NestedData {
                key: "item2".to_string(),
                value: 200,
                enabled: false,
            },
            NestedData {
                key: "item3".to_string(),
                value: 300,
                enabled: true,
            },
        ],
    }
}

#[test]
fn compare_simple_struct_size() {
    let data = create_simple_data();

    let c2pa_bytes = c2pa_cbor::to_vec(&data).unwrap();
    let serde_bytes = serde_cbor::to_vec(&data).unwrap();

    println!("\n=== Simple Struct Size Comparison ===");
    println!("c2pa_cbor size: {} bytes", c2pa_bytes.len());
    println!("serde_cbor size: {} bytes", serde_bytes.len());
    println!(
        "Difference: {} bytes",
        c2pa_bytes.len() as i32 - serde_bytes.len() as i32
    );

    // Verify both produce valid output
    let _: SimpleStruct = c2pa_cbor::from_slice(&c2pa_bytes).unwrap();
    let _: SimpleStruct = serde_cbor::from_slice(&serde_bytes).unwrap();
}

#[test]
fn compare_complex_struct_size() {
    let data = create_complex_data();

    let c2pa_bytes = c2pa_cbor::to_vec(&data).unwrap();
    let serde_bytes = serde_cbor::to_vec(&data).unwrap();

    println!("\n=== Complex Struct Size Comparison ===");
    println!("c2pa_cbor size: {} bytes", c2pa_bytes.len());
    println!("serde_cbor size: {} bytes", serde_bytes.len());
    println!(
        "Difference: {} bytes",
        c2pa_bytes.len() as i32 - serde_bytes.len() as i32
    );

    // Verify both produce valid output
    let _: ComplexStruct = c2pa_cbor::from_slice(&c2pa_bytes).unwrap();
    let _: ComplexStruct = serde_cbor::from_slice(&serde_bytes).unwrap();
}

#[test]
fn compare_simple_struct_speed() {
    let data = create_simple_data();
    let iterations = 10_000;

    // Warm up
    for _ in 0..100 {
        let _ = c2pa_cbor::to_vec(&data).unwrap();
        let _ = serde_cbor::to_vec(&data).unwrap();
    }

    // Benchmark c2pa_cbor serialization
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = c2pa_cbor::to_vec(&data).unwrap();
    }
    let c2pa_serialize_time = start.elapsed();

    // Benchmark serde_cbor serialization
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = serde_cbor::to_vec(&data).unwrap();
    }
    let serde_serialize_time = start.elapsed();

    println!(
        "\n=== Simple Struct Serialization Speed ({}x) ===",
        iterations
    );
    println!(
        "c2pa_cbor: {:?} ({:.2} ns/iter)",
        c2pa_serialize_time,
        c2pa_serialize_time.as_nanos() as f64 / iterations as f64
    );
    println!(
        "serde_cbor: {:?} ({:.2} ns/iter)",
        serde_serialize_time,
        serde_serialize_time.as_nanos() as f64 / iterations as f64
    );
    println!(
        "Ratio: {:.2}x",
        c2pa_serialize_time.as_nanos() as f64 / serde_serialize_time.as_nanos() as f64
    );

    // Benchmark deserialization
    let c2pa_bytes = c2pa_cbor::to_vec(&data).unwrap();
    let serde_bytes = serde_cbor::to_vec(&data).unwrap();

    let start = Instant::now();
    for _ in 0..iterations {
        let _: SimpleStruct = c2pa_cbor::from_slice(&c2pa_bytes).unwrap();
    }
    let c2pa_deserialize_time = start.elapsed();

    let start = Instant::now();
    for _ in 0..iterations {
        let _: SimpleStruct = serde_cbor::from_slice(&serde_bytes).unwrap();
    }
    let serde_deserialize_time = start.elapsed();

    println!(
        "\n=== Simple Struct Deserialization Speed ({}x) ===",
        iterations
    );
    println!(
        "c2pa_cbor: {:?} ({:.2} ns/iter)",
        c2pa_deserialize_time,
        c2pa_deserialize_time.as_nanos() as f64 / iterations as f64
    );
    println!(
        "serde_cbor: {:?} ({:.2} ns/iter)",
        serde_deserialize_time,
        serde_deserialize_time.as_nanos() as f64 / iterations as f64
    );
    println!(
        "Ratio: {:.2}x",
        c2pa_deserialize_time.as_nanos() as f64 / serde_deserialize_time.as_nanos() as f64
    );
}

#[test]
fn compare_complex_struct_speed() {
    let data = create_complex_data();
    let iterations = 1_000;

    // Warm up
    for _ in 0..100 {
        let _ = c2pa_cbor::to_vec(&data).unwrap();
        let _ = serde_cbor::to_vec(&data).unwrap();
    }

    // Benchmark c2pa_cbor serialization
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = c2pa_cbor::to_vec(&data).unwrap();
    }
    let c2pa_serialize_time = start.elapsed();

    // Benchmark serde_cbor serialization
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = serde_cbor::to_vec(&data).unwrap();
    }
    let serde_serialize_time = start.elapsed();

    println!(
        "\n=== Complex Struct Serialization Speed ({}x) ===",
        iterations
    );
    println!(
        "c2pa_cbor: {:?} ({:.2} µs/iter)",
        c2pa_serialize_time,
        c2pa_serialize_time.as_micros() as f64 / iterations as f64
    );
    println!(
        "serde_cbor: {:?} ({:.2} µs/iter)",
        serde_serialize_time,
        serde_serialize_time.as_micros() as f64 / iterations as f64
    );
    println!(
        "Ratio: {:.2}x",
        c2pa_serialize_time.as_nanos() as f64 / serde_serialize_time.as_nanos() as f64
    );

    // Benchmark deserialization
    let c2pa_bytes = c2pa_cbor::to_vec(&data).unwrap();
    let serde_bytes = serde_cbor::to_vec(&data).unwrap();

    let start = Instant::now();
    for _ in 0..iterations {
        let _: ComplexStruct = c2pa_cbor::from_slice(&c2pa_bytes).unwrap();
    }
    let c2pa_deserialize_time = start.elapsed();

    let start = Instant::now();
    for _ in 0..iterations {
        let _: ComplexStruct = serde_cbor::from_slice(&serde_bytes).unwrap();
    }
    let serde_deserialize_time = start.elapsed();

    println!(
        "\n=== Complex Struct Deserialization Speed ({}x) ===",
        iterations
    );
    println!(
        "c2pa_cbor: {:?} ({:.2} µs/iter)",
        c2pa_deserialize_time,
        c2pa_deserialize_time.as_micros() as f64 / iterations as f64
    );
    println!(
        "serde_cbor: {:?} ({:.2} µs/iter)",
        serde_deserialize_time,
        serde_deserialize_time.as_micros() as f64 / iterations as f64
    );
    println!(
        "Ratio: {:.2}x",
        c2pa_deserialize_time.as_nanos() as f64 / serde_deserialize_time.as_nanos() as f64
    );
}

#[test]
fn compare_vec_of_integers_size() {
    let data: Vec<u32> = (0..100).collect();

    let c2pa_bytes = c2pa_cbor::to_vec(&data).unwrap();
    let serde_bytes = serde_cbor::to_vec(&data).unwrap();

    println!("\n=== Vec<u32> (100 elements) Size Comparison ===");
    println!("c2pa_cbor size: {} bytes", c2pa_bytes.len());
    println!("serde_cbor size: {} bytes", serde_bytes.len());
    println!(
        "Difference: {} bytes",
        c2pa_bytes.len() as i32 - serde_bytes.len() as i32
    );
}

#[test]
fn compare_string_size() {
    let data =
        "The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs.";

    let c2pa_bytes = c2pa_cbor::to_vec(&data).unwrap();
    let serde_bytes = serde_cbor::to_vec(&data).unwrap();

    println!("\n=== String ({} chars) Size Comparison ===", data.len());
    println!("c2pa_cbor size: {} bytes", c2pa_bytes.len());
    println!("serde_cbor size: {} bytes", serde_bytes.len());
    println!(
        "Difference: {} bytes",
        c2pa_bytes.len() as i32 - serde_bytes.len() as i32
    );
}
