# c2pa_cbor Benchmarks

This document describes the benchmark suite for the c2pa_cbor library.

## Running Benchmarks

To run all benchmarks:

```bash
cargo bench -p c2pa_cbor
```

To run a specific benchmark group:

```bash
# Byte array performance
cargo bench -p c2pa_cbor --bench cbor_perf -- byte_arrays

# Structured data
cargo bench -p c2pa_cbor --bench cbor_perf -- structured_data

# Collections (Vec, HashMap)
cargo bench -p c2pa_cbor --bench cbor_perf -- collections

# Option handling
cargo bench -p c2pa_cbor --bench cbor_perf -- option_handling

# Flatten attribute
cargo bench -p c2pa_cbor --bench cbor_perf -- flatten

# Nested structures
cargo bench -p c2pa_cbor --bench cbor_perf -- nested
```

## Benchmark Categories

### 1. Byte Arrays (`byte_arrays`)
Tests encoding/decoding performance and size overhead for binary data at various sizes:
- 5 bytes (tiny)
- 256 bytes (small)
- 1 KB (small)
- 10 KB (medium)
- 100 KB (large)
- 1 MB (very large)

Measures:
- Encoding speed and throughput
- Decoding speed and throughput
- CBOR overhead (header size)

### 2. Structured Data (`structured_data`)
Tests performance with complex Rust structs containing:
- Strings
- Numbers
- Booleans
- Vectors
- HashMaps

Measures:
- Encoding
- Decoding
- Round-trip (encode + decode)

### 3. Collections (`collections`)
Tests specific collection types:
- Vec of 1000 integers
- HashMap with 100 string entries

### 4. Option Handling (`option_handling`)
Tests the cost of `#[serde(skip_serializing_if = "Option::is_none")]`:
- All fields Some (maximum size)
- All fields None (minimum size)

### 5. Flatten Attribute (`flatten`)
Tests the buffering path with `#[serde(flatten)]` which requires unknown-length serialization.

### 6. Nested Structures (`nested_structures`)
Tests 3-level nested structures with vectors at each level to measure recursion overhead.

## Results Location

Benchmark results are saved to:
- `target/criterion/` - Detailed HTML reports
- View reports by opening `target/criterion/report/index.html` in a browser

## Performance Expectations

Based on current benchmarks (Apple Silicon):

### Binary Data (with serde_bytes)
- **Small (1KB)**: ~70ns encode, ~50ns decode
- **Large (1MB)**: ~18µs encode, ~26µs decode
- **Throughput**: 50+ GB/s encoding, 35+ GB/s decoding

### Structured Data
- **Simple struct**: ~340ns encode, ~990ns decode
- **1000 ints**: ~3µs encode, ~5µs decode
- **100 map entries**: ~1.8µs encode, ~17µs decode

### Advanced Features
- **Options (Some)**: ~287ns
- **Options (None)**: ~59ns (nearly free!)
- **Flatten**: ~1.7µs (buffering overhead minimal)

#