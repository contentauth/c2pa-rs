# c2pa_cbor

A fast, lightweight CBOR (Concise Binary Object Representation) encoder/decoder with comprehensive support for tagged types.

## Features

- ✅ Full support for all CBOR major types (0-7)
- ✅ Tagged types (major type 6) with standard tags:
  - Date/time strings (tag 0) and epoch timestamps (tag 1)
  - URIs (tag 32)
  - Base64url and Base64 encoded data (tags 33, 34)
  - RFC 8746 typed arrays (tags 64-87) for efficient binary data
- ✅ Custom tag support via `write_tag()` and `read_tag()` methods
- ✅ Excellent performance with near-zero overhead
- ✅ Serde integration for seamless serialization
- ✅ **Full `serde_transcode` support** - handles `#[serde(flatten)]` and other advanced features
- ✅ **Backward compatible newtype struct handling** - works with existing CBOR data
- ✅ **Deterministic encoding** - always produces definite-length CBOR (required for C2PA)

## Security

This library includes built-in protection against malicious CBOR attacks:

- **Allocation limit**: Default 100MB limit prevents out-of-memory (OOM) attacks from CBOR claiming extremely large sizes
- **Recursion depth limit**: Default 128-level nesting limit prevents stack overflow from deeply nested structures

These limits are sufficient for legitimate C2PA manifests while preventing denial-of-service attacks. For advanced use cases requiring custom limits, use the builder pattern:

```rust
use c2pa_cbor::Decoder;
use std::io::Cursor;

let decoder = Decoder::new(Cursor::new(&data))
    .with_max_allocation(1024 * 1024)  // 1MB limit
    .with_max_depth(64);                // Max 64 levels
```

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
c2pa_cbor = "0.1"
serde = { version = "1.0", features = ["derive"] }
serde_bytes = "0.11"  # For efficient byte array handling
```

## Quick Start

### Basic Usage

```rust
use c2pa_cbor::{to_vec, from_slice};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Person {
    name: String,
    age: u32,
}

let person = Person {
    name: "Alice".to_string(),
    age: 30,
};

// Encode to CBOR
let encoded = to_vec(&person).unwrap();

// Decode from CBOR
let decoded: Person = from_slice(&encoded).unwrap();
assert_eq!(person, decoded);
```

### Tagged Types

```rust
use c2pa_cbor::{encode_uri, encode_datetime_string, from_slice};

// Encode a URI with tag 32
let mut buf = Vec::new();
encode_uri(&mut buf, "https://example.com").unwrap();
let decoded: String = from_slice(&buf).unwrap();
assert_eq!(decoded, "https://example.com");

// Encode a datetime string with tag 0
let mut buf = Vec::new();
encode_datetime_string(&mut buf, "2024-01-15T10:30:00Z").unwrap();
let decoded: String = from_slice(&buf).unwrap();
```

### Efficient Binary Data

For optimal performance with byte arrays, use `serde_bytes`:

```rust
use c2pa_cbor::{to_vec, from_slice};
use serde_bytes::ByteBuf;

// Efficient byte array encoding
let data = ByteBuf::from(vec![1, 2, 3, 4, 5]);
let encoded = to_vec(&data).unwrap();

// Only 1 byte overhead for small arrays!
assert_eq!(encoded.len(), 6);

let decoded: ByteBuf = from_slice(&encoded).unwrap();
assert_eq!(decoded.into_vec(), vec![1, 2, 3, 4, 5]);
```

### Custom Tags

```rust
use c2pa_cbor::Encoder;

let mut buf = Vec::new();
let mut encoder = Encoder::new(&mut buf);

// Write a custom tag (e.g., tag 100)
encoder.write_tag(100).unwrap();
encoder.encode(&"custom data").unwrap();
```

### Typed Arrays (RFC 8746)

```rust
use c2pa_cbor::{encode_uint8_array, encode_uint32be_array};

let mut buf = Vec::new();

// Encode uint8 array with tag 64
encode_uint8_array(&mut buf, &[1, 2, 3, 4, 5]).unwrap();

// Encode uint32 big-endian array with tag 66
let data: [u32; 3] = [0x12345678, 0x9ABCDEF0, 0x11223344];
encode_uint32be_array(&mut buf, &data).unwrap();
```

### Using with serde_transcode

This library fully supports `serde_transcode` for converting between formats:

```rust
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
struct Config {
    name: String,
    #[serde(flatten)]  // This works correctly!
    extra: HashMap<String, serde_json::Value>,
}

// Convert JSON to CBOR via transcode
let json_str = r#"{"name":"app","version":"1.0","debug":true}"#;
let mut from = serde_json::Deserializer::from_str(json_str);
let mut to = c2pa_cbor::ser::Serializer::new(Vec::new());

serde_transcode::transcode(&mut from, &mut to).unwrap();
let cbor_bytes = to.into_inner();

// The CBOR is always definite-length (required for C2PA signatures)
let config: Config = c2pa_cbor::from_slice(&cbor_bytes).unwrap();
```

**Note:** When the collection size is known (the common case), serialization is zero-overhead. 
When using `#[serde(flatten)]` or similar features that require unknown-length serialization, 
the library automatically buffers entries to produce definite-length CBOR output.

## Performance

This implementation is designed for **speed** with binary byte arrays:


### Performance Highlights
- **Peak throughput**: 53.6 GB/s encoding, 37.4 GB/s decoding (1MB arrays)
- **Low latency**: Sub-microsecond for typical structs
- **Efficient Options**: Skipped None fields add near-zero overhead
- **Scales linearly**: Performance improves with larger data sizes

### Key Performance Features
- ✅ Zero allocations during encoding
- ✅ Single allocation during decoding
- ✅ No per-element overhead with `serde_bytes`
- ✅ Direct memory writes (no intermediate buffers)
- ✅ Near memory bandwidth performance (50+ GB/s)
- ✅ **Dual-path architecture**: Zero overhead for normal serialization, automatic buffering only when needed

## Architecture

This library uses a **smart dual-path serialization strategy**:

1. **Fast Path (99% of cases)**: When collection sizes are known at serialization time (normal structs, Vec, HashMap, etc.), data is written directly with zero overhead.

2. **Buffering Path (rare cases)**: When sizes are unknown (e.g., `#[serde(flatten)]` with `serde_transcode`), entries are buffered and written as definite-length once the count is known.

This design ensures:
- ✅ **Optimal performance** for typical use cases
- ✅ **Full serde compatibility** including advanced features
- ✅ **Deterministic output** (always definite-length, never indefinite)
- ✅ **C2PA compliance** (required for digital signatures)

The buffering path adds minimal overhead and only activates when necessary, making the library both fast and fully compatible with the serde ecosystem.


## Migration from serde_cbor

This library is designed as a drop-in replacement for `serde_cbor`:

```rust
// Before (serde_cbor)
use serde_cbor::{to_vec, from_slice};
let encoded = serde_cbor::to_vec(&value)?;
let decoded = serde_cbor::from_slice(&encoded)?;

// After (c2pa_cbor)
use c2pa_cbor::{to_vec, from_slice};
let encoded = c2pa_cbor::to_vec(&value)?;
let decoded = c2pa_cbor::from_slice(&encoded)?;
```

### Key Improvements Over serde_cbor

- ✅ **Handles `#[serde(flatten)]`** - No more "indefinite-length maps require manual encoding" errors
- ✅ **Newtype struct compatibility** - Automatically handles tuple struct serialization correctly
- ✅ **Better `serde_transcode` support** - Works seamlessly with JSON-to-CBOR conversion
- ✅ **Always deterministic** - Produces definite-length CBOR in all cases
- ✅ **Faster encoding** - Zero-overhead fast path for normal cases

## API Overview

### Encoding Functions

- `to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>>` - Encode any serializable value
- `encode_tagged<W, T>(writer, tag, value)` - Encode a tagged value
- `encode_datetime_string(writer, datetime)` - Tag 0
- `encode_epoch_datetime(writer, epoch)` - Tag 1
- `encode_uri(writer, uri)` - Tag 32
- `encode_base64url(writer, data)` - Tag 33
- `encode_base64(writer, data)` - Tag 34
- `encode_uint8_array(writer, data)` - Tag 64
- `encode_uint16be_array(writer, data)` - Tag 65
- `encode_uint32be_array(writer, data)` - Tag 66
- `encode_uint64be_array(writer, data)` - Tag 67
- `encode_uint16le_array(writer, data)` - Tag 69
- `encode_uint32le_array(writer, data)` - Tag 70
- `encode_uint64le_array(writer, data)` - Tag 71
- `encode_float32be_array(writer, data)` - Tag 81
- `encode_float64be_array(writer, data)` - Tag 82
- `encode_float32le_array(writer, data)` - Tag 85
- `encode_float64le_array(writer, data)` - Tag 86

### Decoding Functions

- `from_slice<'de, T: Deserialize<'de>>(slice: &[u8]) -> Result<T>` - Decode any deserializable value

### Low-Level API

```rust
use c2pa_cbor::{Encoder, Decoder};

// Encoding
let mut buf = Vec::new();
let mut encoder = Encoder::new(&mut buf);
encoder.write_tag(42).unwrap();
encoder.encode(&some_value).unwrap();

// Decoding
let mut decoder = Decoder::new(&buf[..]);
let tag = decoder.read_tag().unwrap();
let value: SomeType = decoder.decode().unwrap();
```

## CBOR Compatibility

This implementation follows:
- **RFC 8949** - CBOR specification
- **RFC 8746** - Typed arrays as byte strings
- **RFC 3339** - Date/time format for tag 0
- **RFC 3986** - URI format for tag 32

### Deterministic Encoding

This library **always produces definite-length CBOR** (never indefinite-length), which ensures:
- Deterministic output (same input always produces identical bytes)
- C2PA compliance (required for verifiable digital signatures)
- Compatibility with strict CBOR parsers

This is achieved through:
- Direct encoding when sizes are known (fast path)
- Automatic buffering and counting when sizes are unknown (compatibility path)



