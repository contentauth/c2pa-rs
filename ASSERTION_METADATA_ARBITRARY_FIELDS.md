# AssertionMetadata Arbitrary Key/Value Pairs Implementation

## Summary

This implementation adds support for arbitrary key/value pairs to the `AssertionMetadata` structure, as permitted by the C2PA specification. This allows users to add custom metadata fields beyond the standard schema fields.

## Changes Made

### 1. Data Structure Changes (`sdk/src/assertions/assertion_metadata.rs`)

Added a new field to the `AssertionMetadata` struct:

```rust
#[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
additional_fields: HashMap<String, Value>,
```

This field uses `serde`'s `flatten` attribute to serialize/deserialize custom fields at the same level as known fields, maintaining backward compatibility with the C2PA specification.

### 2. API Changes

Added the following public methods to `AssertionMetadata`:

- **`set_field<S: Into<String>>(self, key: S, value: Value) -> Self`**
  - Sets a single arbitrary key/value pair
  - Uses builder pattern for method chaining
  - Accepts any type that can convert to String for the key
  - Accepts `serde_json::Value` for the value (supports any JSON-compatible type)

- **`get_field(&self, key: &str) -> Option<&Value>`**
  - Retrieves a custom field by key
  - Returns `None` if the key doesn't exist

- **`additional_fields(&self) -> &HashMap<String, Value>`**
  - Returns a reference to all additional fields
  - Useful for inspecting or iterating over all custom fields

- **`set_additional_fields(self, fields: HashMap<String, Value>) -> Self`**
  - Sets multiple arbitrary key/value pairs at once
  - Replaces any existing additional fields
  - Uses builder pattern for method chaining

### 3. Example Usage

```rust
use c2pa::assertions::AssertionMetadata;
use serde_json::json;

// Create metadata with custom fields
let metadata = AssertionMetadata::new()
    .set_field("customString", json!("my custom value"))
    .set_field("customNumber", json!(42))
    .set_field("customBool", json!(true))
    .set_field("customObject", json!({
        "nested": "value",
        "count": 123
    }))
    .set_field("customArray", json!(["item1", "item2", "item3"]));

// Retrieve custom fields
if let Some(value) = metadata.get_field("customString") {
    println!("Custom string: {}", value);
}

// Iterate over all custom fields
for (key, value) in metadata.additional_fields() {
    println!("{}: {}", key, value);
}
```

### 4. Usage in Ingredients

Custom metadata fields can be added to ingredients via the manifest definition:

```rust
let manifest_json = json!({
    "title": "My Asset",
    "format": "image/jpeg",
    "claim_generator_info": [{
        "name": "my-app",
        "version": "1.0"
    }],
    "ingredients": [{
        "title": "My Ingredient",
        "format": "image/jpeg",
        "relationship": "componentOf",
        "metadata": {
            "dateTime": "2024-01-23T10:00:00Z",
            "customField1": "custom value",
            "customField2": 42,
            "customObject": {
                "nested": true
            }
        }
    }]
});

let builder = Builder::new()
    .with_definition(manifest_json.to_string())?;
```

## Tests

### Unit Tests (`sdk/src/assertions/assertion_metadata.rs`)

Added 6 comprehensive unit tests:

1. **`test_arbitrary_key_value_pairs`** - Tests basic functionality of setting and getting custom fields with various data types (string, number, boolean, object, array)

2. **`test_set_additional_fields`** - Tests setting multiple fields at once using the batch API

3. **`test_arbitrary_fields_with_standard_fields`** - Ensures custom fields work alongside standard fields without conflicts

4. **`test_empty_additional_fields`** - Verifies correct handling of empty additional fields

5. **`test_cbor_serialization_with_arbitrary_fields`** - Tests CBOR serialization/deserialization round-trip with various field types

6. **`assertion_metadata`** (existing test) - Still passes, confirming backward compatibility

### Integration Test (`sdk/tests/test_builder.rs`)

Added integration test **`test_ingredient_arbitrary_metadata_fields`** that:
- Creates a manifest with an ingredient containing custom metadata fields
- Signs and embeds the manifest into an image
- Reads back the manifest JSON
- Verifies all custom fields are correctly preserved in the ingredient assertion

This test validates the complete round-trip: from API → internal representation → CBOR serialization → manifest embedding → reading → JSON output.

## Test Results

All tests pass successfully:

```
running 6 tests
test assertions::assertion_metadata::tests::test_empty_additional_fields ... ok
test assertions::assertion_metadata::tests::test_cbor_serialization_with_arbitrary_fields ... ok
test assertions::assertion_metadata::tests::test_arbitrary_key_value_pairs ... ok
test assertions::assertion_metadata::tests::test_arbitrary_fields_with_standard_fields ... ok
test assertions::assertion_metadata::tests::test_set_additional_fields ... ok
test assertions::assertion_metadata::tests::assertion_metadata ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured
```

Integration test:
```
running 1 test
test test_ingredient_arbitrary_metadata_fields ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured
```

Full library test suite: **527 passed; 0 failed; 6 ignored**

## Backward Compatibility

This implementation maintains full backward compatibility:

1. **Serialization**: The `additional_fields` HashMap uses `#[serde(flatten)]`, so custom fields appear at the same level as standard fields in the serialized output, matching the C2PA specification format.

2. **Deserialization**: When reading existing manifests without custom fields, the `additional_fields` HashMap will be empty. The `#[serde(skip_serializing_if = "HashMap::is_empty")]` attribute ensures empty HashMaps are not serialized, keeping output clean.

3. **Existing code**: All existing uses of `AssertionMetadata` continue to work without modification. The new field is initialized to an empty HashMap in the `new()` method.

4. **Standard fields**: All standard fields (reviews, dateTime, reference, dataSource, localizations, regionOfInterest) remain unchanged and work exactly as before.

## C2PA Specification Compliance

This implementation complies with the C2PA specification:

- **Assertion Metadata Spec**: The C2PA specification permits additional fields in assertion metadata beyond the defined schema
- **CBOR Encoding**: All fields are properly encoded in CBOR format as required
- **JSON-LD Compatibility**: Custom fields use serde_json::Value, supporting all JSON types
- **Field Flattening**: Custom fields are serialized at the same level as standard fields, not nested

## Technical Details

### Serialization Format

The implementation uses Rust's `serde` with CBOR encoding. The `flatten` attribute ensures custom fields are serialized alongside standard fields:

**Before (only standard fields):**
```json
{
  "dateTime": "2024-01-23T10:00:00Z",
  "reviewRatings": [...]
}
```

**After (with custom fields):**
```json
{
  "dateTime": "2024-01-23T10:00:00Z",
  "reviewRatings": [...],
  "customField1": "value",
  "customField2": 42
}
```

### Type Safety

The implementation uses `serde_json::Value` for custom field values, which provides:
- Type safety through Rust's type system
- Support for all JSON-compatible types (string, number, boolean, null, array, object)
- Automatic serialization/deserialization via serde
- Easy conversion from/to Rust types

### Memory Efficiency

- Empty `additional_fields` HashMap allocates minimal memory
- Only manifests with custom fields pay the storage cost
- The `skip_serializing_if` attribute prevents empty HashMaps from bloating serialized output

## Future Considerations

Potential enhancements for future versions:

1. **Schema Validation**: Add optional JSON schema validation for custom fields
2. **Namespacing**: Consider adding namespace prefixes for custom fields to avoid collisions
3. **Type Hints**: Add methods for typed access (e.g., `get_string()`, `get_number()`)
4. **Documentation**: Generate documentation for common custom field patterns

## Conclusion

This implementation successfully adds support for arbitrary key/value pairs to `AssertionMetadata` while maintaining:
- Full backward compatibility
- C2PA specification compliance
- Type safety and memory efficiency
- Comprehensive test coverage
- Clear and documented API

The feature is production-ready and thoroughly tested across unit and integration test suites.

