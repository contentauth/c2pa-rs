// Copyright 2025 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

use std::collections::HashMap;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

// Test struct for complex serialization
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TestStruct {
    name: String,
    age: u32,
    active: bool,
    tags: Vec<String>,
    metadata: HashMap<String, String>,
}

impl TestStruct {
    fn sample() -> Self {
        let mut metadata = HashMap::new();
        metadata.insert("key1".to_string(), "value1".to_string());
        metadata.insert("key2".to_string(), "value2".to_string());
        metadata.insert("key3".to_string(), "value3".to_string());

        TestStruct {
            name: "Alice Johnson".to_string(),
            age: 30,
            active: true,
            tags: vec!["rust".to_string(), "cbor".to_string(), "c2pa".to_string()],
            metadata,
        }
    }
}

// Benchmark encoding and decoding of byte arrays at various sizes
fn bench_byte_arrays(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_arrays");

    for size in [5, 256, 1024, 10_240, 102_400, 1_048_576].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        let data = vec![0xabu8; *size];
        let byte_buf = ByteBuf::from(data.clone());

        // Encoding benchmark
        group.bench_with_input(BenchmarkId::new("encode", size), size, |b, _| {
            b.iter(|| {
                let encoded = c2pa_cbor::to_vec(black_box(&byte_buf)).unwrap();
                black_box(encoded);
            });
        });

        // Decoding benchmark
        let encoded = c2pa_cbor::to_vec(&byte_buf).unwrap();
        group.bench_with_input(BenchmarkId::new("decode", size), size, |b, _| {
            b.iter(|| {
                let decoded: ByteBuf = c2pa_cbor::from_slice(black_box(&encoded)).unwrap();
                black_box(decoded);
            });
        });

        // Size overhead
        group.bench_with_input(BenchmarkId::new("size_overhead", size), size, |b, _| {
            b.iter(|| {
                let encoded = c2pa_cbor::to_vec(black_box(&byte_buf)).unwrap();
                black_box(encoded.len() - data.len());
            });
        });
    }

    group.finish();
}

// Benchmark structured data serialization
fn bench_structured_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("structured_data");

    let test_struct = TestStruct::sample();

    // Encoding
    group.bench_function("encode_struct", |b| {
        b.iter(|| {
            let encoded = c2pa_cbor::to_vec(black_box(&test_struct)).unwrap();
            black_box(encoded);
        });
    });

    // Decoding
    let encoded = c2pa_cbor::to_vec(&test_struct).unwrap();
    group.bench_function("decode_struct", |b| {
        b.iter(|| {
            let decoded: TestStruct = c2pa_cbor::from_slice(black_box(&encoded)).unwrap();
            black_box(decoded);
        });
    });

    // Round-trip
    group.bench_function("roundtrip_struct", |b| {
        b.iter(|| {
            let encoded = c2pa_cbor::to_vec(black_box(&test_struct)).unwrap();
            let decoded: TestStruct = c2pa_cbor::from_slice(&encoded).unwrap();
            black_box(decoded);
        });
    });

    group.finish();
}

// Benchmark collections (Vec, HashMap)
fn bench_collections(c: &mut Criterion) {
    let mut group = c.benchmark_group("collections");

    // Vec of integers
    let vec_int: Vec<i32> = (0..1000).collect();
    group.bench_function("encode_vec_1000_ints", |b| {
        b.iter(|| {
            let encoded = c2pa_cbor::to_vec(black_box(&vec_int)).unwrap();
            black_box(encoded);
        });
    });

    let encoded_vec = c2pa_cbor::to_vec(&vec_int).unwrap();
    group.bench_function("decode_vec_1000_ints", |b| {
        b.iter(|| {
            let decoded: Vec<i32> = c2pa_cbor::from_slice(black_box(&encoded_vec)).unwrap();
            black_box(decoded);
        });
    });

    // HashMap
    let mut map: HashMap<String, String> = HashMap::new();
    for i in 0..100 {
        map.insert(format!("key{}", i), format!("value{}", i));
    }

    group.bench_function("encode_hashmap_100_entries", |b| {
        b.iter(|| {
            let encoded = c2pa_cbor::to_vec(black_box(&map)).unwrap();
            black_box(encoded);
        });
    });

    let encoded_map = c2pa_cbor::to_vec(&map).unwrap();
    group.bench_function("decode_hashmap_100_entries", |b| {
        b.iter(|| {
            let decoded: HashMap<String, String> =
                c2pa_cbor::from_slice(black_box(&encoded_map)).unwrap();
            black_box(decoded);
        });
    });

    group.finish();
}

// Benchmark Option handling (with skip_serializing_if)
fn bench_option_handling(c: &mut Criterion) {
    #[derive(Serialize, Deserialize)]
    struct WithOptions {
        required: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        optional1: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        optional2: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        optional3: Option<HashMap<String, String>>,
    }

    let mut group = c.benchmark_group("option_handling");

    let with_some = WithOptions {
        required: "test".to_string(),
        optional1: Some("value".to_string()),
        optional2: Some(vec!["a".to_string(), "b".to_string()]),
        optional3: Some({
            let mut m = HashMap::new();
            m.insert("key".to_string(), "val".to_string());
            m
        }),
    };

    let with_none = WithOptions {
        required: "test".to_string(),
        optional1: None,
        optional2: None,
        optional3: None,
    };

    group.bench_function("encode_options_all_some", |b| {
        b.iter(|| {
            let encoded = c2pa_cbor::to_vec(black_box(&with_some)).unwrap();
            black_box(encoded);
        });
    });

    group.bench_function("encode_options_all_none", |b| {
        b.iter(|| {
            let encoded = c2pa_cbor::to_vec(black_box(&with_none)).unwrap();
            black_box(encoded);
        });
    });

    group.finish();
}

// Benchmark flatten attribute (tests buffering path)
fn bench_flatten(c: &mut Criterion) {
    #[derive(Serialize, Deserialize)]
    struct WithFlatten {
        name: String,
        #[serde(flatten)]
        extra: HashMap<String, String>,
    }

    let mut extra = HashMap::new();
    for i in 0..10 {
        extra.insert(format!("param{}", i), format!("value{}", i));
    }

    let data = WithFlatten {
        name: "test".to_string(),
        extra,
    };

    c.bench_function("encode_with_flatten", |b| {
        b.iter(|| {
            let encoded = c2pa_cbor::to_vec(black_box(&data)).unwrap();
            black_box(encoded);
        });
    });
}

// Benchmark nested structures
fn bench_nested_structures(c: &mut Criterion) {
    #[derive(Serialize, Deserialize)]
    struct Nested {
        level1: Vec<Level2>,
    }

    #[derive(Serialize, Deserialize)]
    struct Level2 {
        name: String,
        level3: Vec<Level3>,
    }

    #[derive(Serialize, Deserialize)]
    struct Level3 {
        id: u32,
        data: Vec<u8>,
    }

    let mut group = c.benchmark_group("nested_structures");

    let nested = Nested {
        level1: (0..10)
            .map(|i| Level2 {
                name: format!("item{}", i),
                level3: (0..5)
                    .map(|j| Level3 {
                        id: j,
                        data: vec![0xab; 100],
                    })
                    .collect(),
            })
            .collect(),
    };

    group.bench_function("encode_nested_3_levels", |b| {
        b.iter(|| {
            let encoded = c2pa_cbor::to_vec(black_box(&nested)).unwrap();
            black_box(encoded);
        });
    });

    let encoded = c2pa_cbor::to_vec(&nested).unwrap();
    group.bench_function("decode_nested_3_levels", |b| {
        b.iter(|| {
            let decoded: Nested = c2pa_cbor::from_slice(black_box(&encoded)).unwrap();
            black_box(decoded);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_byte_arrays,
    bench_structured_data,
    bench_collections,
    bench_option_handling,
    bench_flatten,
    bench_nested_structures
);
criterion_main!(benches);
