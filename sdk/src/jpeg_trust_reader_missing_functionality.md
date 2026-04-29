# JPEG Trust Format Export - Missing Functionality Analysis

This document describes functionality present in the JPEG Trust format that cannot be fully exposed from the current c2pa-rs library implementation.

## Overview

The JPEG Trust format requires several pieces of information that are either not currently tracked by the c2pa-rs Reader API or would require significant changes to expose. This analysis identifies these gaps and provides recommendations.

## Missing Functionality

### 1. Asset Hash (`asset_info.hash`)

**JPEG Trust Requirement:**
```json
{
  "asset_info": {
    "alg": "sha256",
    "hash": "JPkcXXC5DfT9IUUBPK5UaKxGsJ8YIE67BayL+ei3ats="
  }
}
```

**Current Status:** ✅ **Implemented**

**Details:** The `JpegTrustReader` now provides methods to compute and store the asset hash:

- `compute_asset_hash(&mut stream)` - Compute hash from a stream
- `compute_asset_hash_from_file(path)` - Compute hash from a file (with `file_io` feature)
- `set_asset_hash(algorithm, hash)` - Set a pre-computed hash
- `asset_hash()` - Get the currently stored hash

The hash is computed using SHA-256 and stored in the reader for inclusion in the JPEG Trust format output.

**Usage:**
```rust
let mut reader = JpegTrustReader::from_file("image.jpg")?;

// Compute hash from the same file
let hash = reader.compute_asset_hash_from_file("image.jpg")?;

// Now the JSON output will include asset_info
let json = reader.json();
```

---

### 2. File Metadata (`metadata` object)

**JPEG Trust Requirement:**
```json
{
  "metadata": {
    "@context": {
      "xmp": "http://ns.adobe.com/xap/1.0/",
      "exif": "http://ns.adobe.com/exif/1.0/",
      ...
    },
    "jfif:JFIFVersion": 257,
    "jfif:ResolutionUnit": 0,
    "exif:...": "..."
  }
}
```

**Current Status:** ❌ **Not Available**

**Reason:** The c2pa-rs library focuses on C2PA manifest data and does not extract or expose general file metadata (EXIF, XMP, JFIF, etc.) from the asset. This metadata is typically embedded in the asset file itself, not in the C2PA manifest.

**Workaround:** Would require:
1. Integration with image/video metadata parsing libraries (e.g., `kamadak-exif`, `rexiv2`)
2. Storing metadata during asset parsing
3. Exposing it through the Reader API

**Recommendation:** This is out of scope for the C2PA library, which focuses on provenance data. Applications should use dedicated metadata libraries to extract this information separately if needed for the JPEG Trust format.

---

### 3. Detailed Certificate Distinguished Name Components

**JPEG Trust Requirement:**
```json
{
  "claim_signature": {
    "issuer": {
      "C": "US",
      "ST": "CA",
      "L": "Somewhere",
      "O": "C2PA Test Intermediate Root CA",
      "OU": "FOR TESTING_ONLY",
      "CN": "Intermediate CA"
    },
    "subject": {
      "C": "US",
      "ST": "CA",
      "L": "Somewhere",
      "O": "C2PA Test Signing Cert",
      "OU": "FOR TESTING_ONLY",
      "CN": "C2PA Signer"
    }
  }
}
```

**Current Status:** ✅ **Implemented**

**Details:** The `JpegTrustReader` implementation parses X.509 certificates to extract full DN components using the `x509_parser` crate. This functionality is fully implemented in the `parse_certificate()` and `extract_dn_components()` methods.

---

### 4. Certificate Validity Period

**JPEG Trust Requirement:**
```json
{
  "claim_signature": {
    "validity": {
      "not_before": "2022-06-10T18:46:41.000Z",
      "not_after": "2030-08-26T18:46:41.000Z"
    }
  }
}
```

**Current Status:** ✅ **Implemented**

**Details:** Certificate validity dates are extracted from the X.509 certificate and formatted as ISO 8601/RFC3339 timestamps using the chrono crate.

---

### 5. Actual Assertion Hashes

**JPEG Trust Requirement:**
```json
{
  "claim.v2": {
    "created_assertions": [
      {
        "url": "self#jumbf=c2pa.assertions/c2pa.actions.v2",
        "hash": "we0dLhHUO3nZQ/T37tBjG3AYViMC0pAbWtQwurOgJvs="
      }
    ]
  }
}
```

**Current Status:** ✅ **Partially Implemented**

**Details:** The `JpegTrustReader` uses `manifest.assertion_references()` which provides the hashed URIs from the claim. These are the actual assertion hashes as stored in the C2PA claim structure. However, these may not exactly match the format expected by JPEG Trust in all cases, as they represent the C2PA internal format.

---

### 6. Content Object

**JPEG Trust Requirement:**
```json
{
  "content": {}
}
```

**Current Status:** ✅ **Implemented**

**Details:** The content object is typically empty in JPEG Trust format and is included as a placeholder. The `JpegTrustReader` includes an empty content object.

---

## API Differences from C2PA Tool Output

The JPEG Trust format differs significantly from the standard c2patool JSON output:

### Structural Changes Implemented:

1. **`@context` addition** - ✅ Implemented
2. **`asset_info` with hash** - ✅ Implemented
3. **`manifests` format change** (object → array) - ✅ Implemented  
4. **`assertions` format change** (array → object keyed by label) - ✅ Implemented
5. **`claim.v2` consolidation** - ✅ Implemented
6. **`claim_signature` expansion** - ✅ Implemented
7. **`status` per-manifest validation** - ✅ Implemented
8. **`extras:validation_status` overall validation** - ✅ Implemented

### Key Transformations Performed:

- **Manifests**: Converted from `HashMap<String, Manifest>` to `Vec<Value>` with label as property
- **Assertions**: Converted from array format to object format keyed by assertion label
- **Claim Data**: Consolidated scattered properties (title, instance_id, claim_generator) into `claim.v2` object
- **Validation**: Mapped three separate validation structures in c2patool to two coordinated structures in JPEG Trust
- **Certificate Info**: Expanded from basic fields to detailed DN components with validity period

---

## Recommendations for Future Enhancement

### Short Term
1. Document that metadata must be extracted separately using specialized libraries
2. Add examples showing how to combine JPEG Trust output with metadata from other libraries

### Long Term
1. Consider adding optional metadata extraction if there's demand
2. Create a builder pattern for JPEG Trust format that allows providing external data sources
3. Add validation that the generated JPEG Trust format conforms to the specification

---

## Usage Example

```rust
use c2pa::JpegTrustReader;

// Basic usage with asset hash computation
let mut reader = JpegTrustReader::from_file("image.jpg")?;

// Compute the asset hash
let hash = reader.compute_asset_hash_from_file("image.jpg")?;
println!("Asset hash: {}", hash);

// Get the JSON output
let jpeg_trust_json = reader.json();

// The output will have:
// ✅ Full certificate DN components
// ✅ Certificate validity periods  
// ✅ Proper JPEG Trust structure
// ✅ Asset hash in asset_info section
// ❌ No file metadata (would need to extract separately)

// Alternative: set a pre-computed hash
reader.set_asset_hash("sha256", "JPkcXXC5DfT9IUUBPK5UaKxGsJ8YIE67BayL+ei3ats=");

// Or compute from a stream
use std::fs::File;
let mut file = File::open("image.jpg")?;
let hash = reader.compute_asset_hash(&mut file)?;
```

---

## Conclusion

The `JpegTrustReader` successfully implements the core transformations needed to convert C2PA manifest data to JPEG Trust format, including:

✅ **Full JPEG Trust structure transformation** - All structural changes from the specification are implemented
✅ **Asset hash computation** - Multiple methods for computing and setting asset hashes
✅ **Certificate details** - Complete DN components and validity periods
✅ **Validation status** - Comprehensive validation information in JPEG Trust format

The main remaining limitation is file metadata (EXIF, XMP, JFIF), which is architectural and out of scope for the c2pa-rs library. Applications that need metadata should use specialized libraries to extract this information separately.

These limitations are documented and reasonable given the current scope of the c2pa-rs library.

