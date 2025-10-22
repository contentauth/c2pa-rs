# C2PA Language Bindings Comparison

This document provides a comprehensive comparison of Reader and Builder methods across the different language bindings for the C2PA Rust SDK.

## Reader Methods Comparison

| Method | c2pa-node-v2 | c2pa-js/c2pa-web | c2pa-c | c2pa-python |
|--------|--------------|------------------|--------|-------------|
| `from_stream` | ❌ | ❌ | ✅ | ✅ |
| `from_file` | ❌ | N/A | ✅ | ✅ |
| `from_json` | ❌ | ❌ | ❌ | ❌ |
| `from_manifest_data_and_stream` | ✅ | ❌ | ❌ | ✅ |
| `from_fragment` | ❌ | ✅ | ❌ | ❌ |
| `from_fragmented_files` | ❌ | N/A | ❌ | ❌ |
| `supported_mime_types` | ❌ | ❌ | ✅ | ✅ |
| `json` | ✅ | ✅ | ✅ | ✅ |
| `detailed_json` | ❌ | ❌ | ❌ | ❌ |
| `remote_url` | ✅ | ❌ | ✅ | ✅ |
| `is_embedded` | ✅ | ❌ | ✅ | ✅ |
| `validation_status` | ❌ | ❌ | ❌ | ❌ |
| `validation_results` | ❌ | ❌ | ❌ | ✅ |
| `validation_state` | ❌ | ❌ | ❌ | ✅ |
| `active_manifest` | ✅ | ✅ | ❌ | ✅ |
| `active_label` | ✅ | ✅ | ❌ | ❌ |
| `iter_manifests` | ❌ | ❌ | ❌ | ❌ |
| `manifests` | ❌ | ❌ | ❌ | ❌ |
| `get_manifest` | ❌ | ❌ | ❌ | ✅ |
| `resource_to_stream` | ✅ | ✅ | ✅ | ✅ |
| `to_folder` | ❌ | N/A | ❌ | ❌ |
| `post_validate` | ✅ | ❌ | ❌ | ❌ |

### Reader Method Notes

- **c2pa-node-v2**: Uses `fromAsset` and `fromManifestDataAndAsset` instead of `from_stream` and `from_manifest_data_and_stream`
- **c2pa-js/c2pa-web**: Uses `fromBlob` and `fromBlobFragment` instead of `from_stream` and `from_fragment`. File-based methods are N/A due to browser security restrictions
- **c2pa-c**: Uses `read_file` function instead of Reader class methods for file reading
- **c2pa-python**: Has comprehensive Reader class with most methods available

## Builder Methods Comparison

| Method | c2pa-node-v2 | c2pa-js/c2pa-web | c2pa-c | c2pa-python |
|--------|--------------|------------------|--------|-------------|
| `new` | ✅ | ❌ | ❌ | ❌ |
| `set_intent` | ✅ | ❌ | ❌ | ❌ |
| `from_json` | ✅ | ✅ | ✅ | ✅ |
| `supported_mime_types` | ❌ | ❌ | ✅ | ✅ |
| `claim_version` | ❌ | ❌ | ❌ | ❌ |
| `set_claim_generator_info` | ❌ | ❌ | ❌ | ❌ |
| `set_format` | ❌ | ❌ | ❌ | ❌ |
| `set_base_path` | ❌ | N/A | ✅ | ❌ |
| `set_remote_url` | ✅ | ✅ | ✅ | ✅ |
| `set_no_embed` | ✅ | ✅ | ✅ | ✅ |
| `set_thumbnail` | ❌ | ✅ | ❌ | ❌ |
| `add_assertion` | ✅ | ❌ | ❌ | ❌ |
| `add_assertion_json` | ❌ | ❌ | ❌ | ❌ |
| `add_action` | ❌ | ❌ | ✅ | ✅ |
| `add_ingredient_from_stream` | ✅ | ✅ | ✅ | ✅ |
| `add_ingredient` | ✅ | ✅ | ❌ | ✅ |
| `add_resource` | ✅ | ✅ | ✅ | ✅ |
| `to_archive` | ✅ | ❌ | ✅ | ✅ |
| `from_archive` | ✅ | ❌ | ✅ | ✅ |
| `data_hashed_placeholder` | ❌ | ❌ | ✅ | ❌ |
| `sign_data_hashed_embeddable` | ❌ | ❌ | ✅ | ❌ |
| `sign_box_hashed_embeddable` | ❌ | ❌ | ❌ | ❌ |
| `sign` | ✅ | ✅ | ✅ | ✅ |
| `sign_fragmented_files` | ❌ | N/A | ❌ | ❌ |
| `sign_file` | ✅ | N/A | ✅ | ✅ |
| `composed_manifest` | ❌ | ❌ | ❌ | ❌ |

### Builder Method Notes

- **c2pa-node-v2**: Uses `withJson` instead of `from_json`, has comprehensive Builder class
- **c2pa-js/c2pa-web**: Uses `fromDefinition` instead of `from_json`, has `setThumbnailFromBlob` instead of `set_thumbnail`. File-based methods are N/A due to browser security restrictions, but archive methods can work with buffers
- **c2pa-c**: Uses `Builder(const std::string &manifest_json)` constructor instead of `from_json`
- **c2pa-python**: Has comprehensive Builder class with most methods available

## Summary

### Reader Coverage
- **c2pa-python**: 15/22 methods (68%) ✅
- **c2pa-c**: 8/22 methods (36%) ⚠️
- **c2pa-node-v2**: 7/22 methods (32%) ⚠️
- **c2pa-js/c2pa-web**: 4/22 methods (18%) - Note: 3 methods N/A due to browser limitations

### Builder Coverage
- **c2pa-python**: 12/25 methods (48%) ✅
- **c2pa-c**: 10/25 methods (40%) ⚠️
- **c2pa-node-v2**: 9/25 methods (36%) ⚠️
- **c2pa-js/c2pa-web**: 6/25 methods (24%) - Note: 2 methods N/A due to browser limitations

### Key Observations

1. **c2pa-python** has the most comprehensive implementation with the highest method coverage
2. **c2pa-c** provides good coverage for core functionality but lacks some advanced features
3. **c2pa-node-v2** has good coverage for Builder operations but limited Reader functionality
4. **c2pa-js/c2pa-web** has the most limited coverage, focusing on web-specific use cases

### Missing Critical Methods

- **Validation methods**: Most bindings lack `validation_status`, `validation_results`, and `validation_state`
- **Advanced Reader methods**: `detailed_json`, `iter_manifests`, `manifests`, `to_folder`
- **Advanced Builder methods**: `data_hashed_placeholder`, `sign_data_hashed_embeddable`, `composed_manifest`

### Legend
- ✅ = Method available
- ❌ = Method not available
- N/A = Not applicable (e.g., file system access in browser environments)
- ⚠️ = Partial coverage