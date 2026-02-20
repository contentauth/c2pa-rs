# Asset Hash Implementation for JPEG Trust Reader

## Summary

This document describes the implementation of asset hash functionality for the `JpegTrustReader`, addressing the short-term recommendation in `jpeg_trust_reader_missing_functionality.md`.

## Objective

Enable the `JpegTrustReader` to compute and include the `asset_info` section in the JPEG Trust format output, containing the SHA-256 hash of the asset file.

## Implementation Details

### 1. Data Structure Changes

Added an `AssetHash` struct and optional field to `JpegTrustReader`:

```rust
pub struct JpegTrustReader {
    inner: Reader,
    asset_hash: Option<AssetHash>,
}

struct AssetHash {
    algorithm: String,
    hash: String,
}
```

### 2. Public API Methods

Implemented four public methods for asset hash management:

#### `compute_asset_hash(&mut self, stream: &mut (impl Read + Seek)) -> Result<String>`
- Computes SHA-256 hash from a stream
- Rewinds the stream to the beginning before hashing
- Stores the hash in the reader for later use
- Returns the base64-encoded hash string

#### `compute_asset_hash_from_file(&mut self, path: P) -> Result<String>` (requires `file_io` feature)
- Convenience method for computing hash from a file path
- Opens the file and delegates to `compute_asset_hash()`
- Returns the base64-encoded hash string

#### `set_asset_hash(&mut self, algorithm: &str, hash: &str)`
- Allows setting a pre-computed hash directly
- Useful when hash is computed externally or with a different algorithm
- Supports any algorithm identifier (e.g., "sha256", "sha512")

#### `asset_hash(&self) -> Option<(&str, &str)>`
- Accessor method to retrieve the currently stored hash
- Returns a tuple of (algorithm, hash) if set, or None

### 3. JSON Output Integration

The `to_json_value()` method was updated to include `asset_info` when a hash is present:

```rust
if let Some(asset_info) = self.get_asset_hash_json() {
    result["asset_info"] = asset_info;
}
```

This produces the JPEG Trust format:

```json
{
  "@context": { ... },
  "asset_info": {
    "alg": "sha256",
    "hash": "5xv/WPxXZAgD5uZfdTTi+wwvmQGMhSdswUsw8EQnzHY="
  },
  "manifests": [ ... ]
}
```

### 4. Constructor Updates

All `JpegTrustReader` constructors were updated to initialize `asset_hash` to `None`:
- `from_context()`
- `from_shared_context()`
- `from_stream()` / `from_stream_async()`
- `from_file()` / `from_file_async()`
- `from_manifest_data_and_stream()` / `from_manifest_data_and_stream_async()`

## Testing

Comprehensive test coverage was implemented across two test suites:

### Unit Tests in `jpeg_trust_reader.rs`

1. **test_compute_asset_hash_from_stream** - Verifies hash computation from stream
2. **test_compute_asset_hash_from_file** - Verifies hash computation from file
3. **test_set_asset_hash_directly** - Tests direct hash setting
4. **test_asset_hash_consistency** - Ensures consistent hashing of same data
5. **test_json_without_asset_hash** - Confirms `asset_info` absent when no hash
6. **test_json_with_asset_hash** - Confirms `asset_info` present when hash computed
7. **test_asset_hash_update** - Tests hash replacement
8. **test_asset_hash_with_different_files** - Verifies different files produce different hashes

**Results**: 11 tests pass (8 basic + 3 with `file_io` feature)

### Integration Tests in `test_jpeg_trust_asset_hash.rs`

1. **test_asset_hash_in_json_output** - Full JSON output verification
2. **test_multiple_hash_computations** - Consistency across multiple computations
3. **test_set_hash_directly** - Custom hash and algorithm setting
4. **test_accessor_methods** - API accessor functionality
5. **test_compute_from_file** - File-based computation
6. **test_different_files_different_hashes** - Hash uniqueness
7. **test_hash_persistence_across_json_calls** - State persistence
8. **test_hash_format_is_base64** - Output format validation
9. **test_complete_jpeg_trust_format_with_asset_info** - Complete structure verification

**Results**: 9 tests pass (7 basic + 2 with `file_io` feature)

### Test Results Summary

All 20 tests pass successfully:
- ✅ 11 unit tests in `jpeg_trust_reader::tests`
- ✅ 9 integration tests in `test_jpeg_trust_asset_hash`
- ✅ All doc tests compile and pass
- ✅ No regressions in existing 573 c2pa tests

## Usage Example

```rust
use c2pa::{JpegTrustReader, Result};

fn main() -> Result<()> {
    // Create reader
    let mut reader = JpegTrustReader::from_file("image.jpg")?;
    
    // Compute asset hash
    let hash = reader.compute_asset_hash_from_file("image.jpg")?;
    println!("Asset hash: {}", hash);
    
    // Get JPEG Trust format JSON with asset_info included
    let json = reader.json();
    println!("{}", json);
    
    Ok(())
}
```

Alternative usage with streams:

```rust
use std::fs::File;

let mut reader = JpegTrustReader::from_file("image.jpg")?;
let mut file = File::open("image.jpg")?;
let hash = reader.compute_asset_hash(&mut file)?;
```

Or with pre-computed hash:

```rust
let mut reader = JpegTrustReader::from_file("image.jpg")?;
reader.set_asset_hash("sha256", "JPkcXXC5DfT9IUUBPK5UaKxGsJ8YIE67BayL+ei3ats=");
```

## Documentation Updates

The following documentation was updated to reflect the new functionality:

### `jpeg_trust_reader_missing_functionality.md`
- Changed status of Asset Hash from ❌ **Not Available** to ✅ **Implemented**
- Updated structural changes checklist to include `asset_info`
- Marked short-term recommendation #1 as ✅ **COMPLETED**
- Updated usage example to demonstrate asset hash computation
- Updated conclusion to highlight the completed implementation

### Example Code
- Updated `examples/jpeg_trust_format.rs` to demonstrate hash computation

## Design Decisions

### 1. Optional Hash Storage
The hash is stored as `Option<AssetHash>` to allow readers to be created without immediately computing the hash. This provides flexibility for users who may not need the `asset_info` section.

### 2. Mutable Methods
The computation methods require `&mut self` because they modify the internal state by storing the computed hash. This is consistent with builder patterns in Rust.

### 3. SHA-256 Default
While the API supports any algorithm identifier, the `compute_asset_hash()` method uses SHA-256 by default, as this is the most common hash algorithm in the JPEG Trust specification.

### 4. Stream Rewinding
The `compute_asset_hash()` method automatically rewinds the stream to ensure consistent hashing regardless of the stream's current position.

### 5. Base64 Encoding
Hashes are stored and returned as base64-encoded strings, matching the JPEG Trust format requirement.

## Integration with Existing Code

The implementation integrates seamlessly with the existing `JpegTrustReader` API:
- No breaking changes to existing methods
- Backward compatible (hash computation is optional)
- Consistent with existing Reader-like API design
- Follows Rust naming conventions and patterns

## Performance Considerations

- Hash computation requires reading the entire asset once: O(n) where n is file size
- Hash is computed on-demand, not during reader construction
- Hash is cached after computation, avoiding redundant calculations
- Stream rewinding is explicit and documented

## Future Enhancements

Possible future improvements (not implemented):
1. Support for other hash algorithms (SHA-512, SHA3, etc.)
2. Async versions of hash computation methods
3. Automatic hash computation during reader construction (via builder pattern)
4. Hash verification against expected values

## Conclusion

The asset hash functionality has been successfully implemented, tested, and documented. The implementation:

✅ Addresses the short-term recommendation in the missing functionality document
✅ Provides a clean, flexible API for hash computation and management
✅ Includes comprehensive test coverage (20 tests)
✅ Maintains backward compatibility
✅ Follows Rust best practices and naming conventions
✅ Integrates seamlessly with existing JPEG Trust format output

The `asset_info` section is now fully supported in the JPEG Trust format output when users compute or provide an asset hash.

