# C2PA Settings JSON Configuration

The C2PA SDK can be configured using a JSON file that controls many aspects of the library's behavior. This document describes the complete JSON schema and available options.

This definition works the same in all programming languages and platforms.

## Overview

The configuration JSON has the following top-level structure:

```json
{
  "version": 1,
  "trust": { ... },
  "cawg_trust": { ... },
  "core": { ... },
  "verify": { ... },
  "builder": { ... },
  "signer": { ... },
  "cawg_x509_signer": { ... }
}
```

## Complete Default Configuration

Here's the JSON with all default values:

```json
{
  "version": 1,
  "trust": {
    "verify_trust_list": true,
    "user_anchors": null,
    "trust_anchors": null,
    "trust_config": null,
    "allowed_list": null
  },
  "cawg_trust": {
    "verify_trust_list": true,
    "user_anchors": null,
    "trust_anchors": null,
    "trust_config": null,
    "allowed_list": null
  },
  "core": {
    "merkle_tree_chunk_size_in_kb": null,
    "merkle_tree_max_proofs": 5,
    "backing_store_memory_threshold_in_mb": 512,
    "decode_identity_assertions": true
  },
  "verify": {
    "verify_after_reading": true,
    "verify_after_sign": true,
    "verify_trust": true,
    "verify_timestamp_trust": true,
    "ocsp_fetch": false,
    "remote_manifest_fetch": true,
    "check_ingredient_trust": true,
    "skip_ingredient_conflict_resolution": false,
    "strict_v1_validation": false
  },
  "builder": {
    "claim_generator_info": null,
    "thumbnail": {
      "enabled": true,
      "ignore_errors": true,
      "long_edge": 1024,
      "format": null,
      "prefer_smallest_format": true,
      "quality": "medium"
    },
    "actions": {
      "all_actions_included": null,
      "templates": null,
      "actions": null,
      "auto_created_action": {
        "enabled": true,
        "source_type": "empty"
      },
      "auto_opened_action": {
        "enabled": true,
        "source_type": null
      },
      "auto_placed_action": {
        "enabled": true,
        "source_type": null
      }
    },
    "certificate_status_fetch": null,
    "certificate_status_should_override": null,
    "intent": null,
    "created_assertion_labels": null,
    "generate_c2pa_archive": null
  },
  "signer": null,
  "cawg_x509_signer": null
}
```

## Field Descriptions

### version
- **Type**: `number`
- **Default**: `1`
- **Description**: Configuration format version. Must be `1`.

### trust
Configuration for C2PA certificate trust validation.

- **verify_trust_list** (`boolean`, default: `true`): Whether to verify certificates against trust lists
- **user_anchors** (`string | null`): Additional user-provided root certificates (PEM format)
- **trust_anchors** (`string | null`): Default trust anchor root certificates (PEM format)
- **trust_config** (`string | null`): Allowed extended key usage (EKU) object identifiers
- **allowed_list** (`string | null`): Explicitly allowed certificates (PEM format)

### cawg_trust
Identical structure to `trust` but for CAWG (Coalition for Content Provenance and Authenticity Working Group) certificate validation.

### core
Core library features and performance settings.

- **merkle_tree_chunk_size_in_kb** (`number | null`): Chunk size for BMFF hash merkle trees in KB
- **merkle_tree_max_proofs** (`number`, default: `5`): Maximum merkle tree proofs when validating
- **backing_store_memory_threshold_in_mb** (`number`, default: `512`): Memory threshold before using disk storage
- **decode_identity_assertions** (`boolean`, default: `true`): Whether to decode CAWG identity assertions

### verify
Verification behavior settings.

- **verify_after_reading** (`boolean`, default: `true`): Verify manifests after reading
- **verify_after_sign** (`boolean`, default: `true`): Verify manifests after signing
- **verify_trust** (`boolean`, default: `true`): Verify certificates against trust lists
- **verify_timestamp_trust** (`boolean`, default: `true`): Verify timestamp certificates
- **ocsp_fetch** (`boolean`, default: `false`): Fetch OCSP status during validation
- **remote_manifest_fetch** (`boolean`, default: `true`): Fetch remote manifests
- **check_ingredient_trust** (`boolean`, default: `true`): Verify ingredient certificates
- **skip_ingredient_conflict_resolution** (`boolean`, default: `false`): Skip ingredient conflict resolution
- **strict_v1_validation** (`boolean`, default: `false`): Use strict C2PA v1 validation

### builder
Settings for the Builder API.

#### builder.thumbnail
Automatic thumbnail generation settings.

- **enabled** (`boolean`, default: `true`): Enable automatic thumbnails
- **ignore_errors** (`boolean`, default: `true`): Continue on thumbnail generation errors
- **long_edge** (`number`, default: `1024`): Size of thumbnail's longest edge in pixels
- **format** (`string | null`): Output format (`"jpeg"`, `"png"`, `"webp"`)
- **prefer_smallest_format** (`boolean`, default: `true`): Use smallest format when possible
- **quality** (`string`, default: `"medium"`): Quality setting (`"low"`, `"medium"`, `"high"`)

#### builder.actions
Action assertion configuration.

- **all_actions_included** (`boolean | null`): Whether all actions are specified
- **templates** (`array | null`): Action templates
- **actions** (`array | null`): Predefined actions to add
- **auto_created_action**: Settings for automatic `c2pa.created` actions
  - **enabled** (`boolean`, default: `true`)
  - **source_type** (`string`, default: `"empty"`): Digital source type
- **auto_opened_action**: Settings for automatic `c2pa.opened` actions
  - **enabled** (`boolean`, default: `true`)
  - **source_type** (`string | null`)
- **auto_placed_action**: Settings for automatic `c2pa.placed` actions
  - **enabled** (`boolean`, default: `true`)
  - **source_type** (`string | null`)

#### Other builder fields
- **claim_generator_info** (`object | null`): Default claim generator information
- **certificate_status_fetch** (`string | null`): Certificate status fetching scope
- **certificate_status_should_override** (`boolean | null`): Override OCSP with certificate status assertions
- **intent** (`object | null`): Default builder intent (e.g., `{"Create": "digitalCapture"}`)
- **created_assertion_labels** (`array | null`): Labels for created assertions
- **generate_c2pa_archive** (`boolean | null`): Generate C2PA archive format

### signer
Configuration for the primary C2PA signer. Can be `null` or one of:

#### Local Signer
```json
{
  "local": {
    "alg": "ps256",
    "sign_cert": "-----BEGIN CERTIFICATE-----\n...",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...",
    "tsa_url": "http://timestamp.digicert.com"
  }
}
```

- **alg** (`string`): Signing algorithm (`"ps256"`, `"ps384"`, `"ps512"`, `"es256"`, `"es384"`, `"es512"`, `"ed25519"`)
- **sign_cert** (`string`): Certificate chain for signing (PEM format)
- **private_key** (`string`): Private key for signing (PEM format)
- **tsa_url** (`string | null`): Time stamp authority URL for timestamping

#### Remote Signer
```json
{
  "remote": {
    "url": "https://my-signing-service.com/sign",
    "alg": "ps256",
    "sign_cert": "-----BEGIN CERTIFICATE-----\n...",
    "tsa_url": "http://timestamp.digicert.com"
  }
}
```

- **url** (`string`): URL to the remote signing service (receives POST requests with byte stream)
- **alg** (`string`): Signing algorithm used by the remote service
- **sign_cert** (`string`): Certificate chain for the remote signer (PEM format)
- **tsa_url** (`string | null`): Time stamp authority URL

**Note**: Remote signers are not supported in WASM builds.

### cawg_x509_signer
Configuration for CAWG X.509 signer that generates identity assertions. Has the same structure as `signer` (local or remote). When both `signer` and `cawg_x509_signer` are configured, the system creates a dual signer that:

1. Uses `signer` for the main C2PA claim signature
2. Uses `cawg_x509_signer` to generate CAWG identity assertions with X.509 credentials

**Note**: Remote CAWG X.509 signing is not yet implemented.

## Example Configurations

### Minimal Configuration
```json
{
  "version": 1,
  "builder": {
    "claim_generator": {
        "name": "my app",
        "version": "0.1"
    },
    "intent": {"Create": "digitalCapture"}
  }
}
```

### Local Signer Configuration
```json
{
  "version": 1,
  "signer": {
    "local": {
      "alg": "ps256",
      "sign_cert": "-----BEGIN CERTIFICATE-----\nMIIExample...\n-----END CERTIFICATE-----",
      "private_key": "-----BEGIN PRIVATE KEY-----\nMIIExample...\n-----END PRIVATE KEY-----",
      "tsa_url": "http://timestamp.digicert.com"
    }
  },
  "builder": {
    "intent": {"Create": "digitalCapture"}
  }
}
```

### Remote Signer Configuration
```json
{
  "version": 1,
  "signer": {
    "remote": {
      "url": "https://my-signing-service.com/sign",
      "alg": "ps256",
      "sign_cert": "-----BEGIN CERTIFICATE-----\nMIIExample...\n-----END CERTIFICATE-----",
      "tsa_url": "http://timestamp.digicert.com"
    }
  }
}
```

### CAWG Dual Signer Configuration
```json
{
  "version": 1,
  "signer": {
    "local": {
      "alg": "ps256",
      "sign_cert": "-----BEGIN CERTIFICATE-----\nC2PA Cert...\n-----END CERTIFICATE-----",
      "private_key": "-----BEGIN PRIVATE KEY-----\nC2PA Key...\n-----END PRIVATE KEY-----"
    }
  },
  "cawg_x509_signer": {
    "local": {
      "alg": "es256",
      "sign_cert": "-----BEGIN CERTIFICATE-----\nCAWG Cert...\n-----END CERTIFICATE-----",
      "private_key": "-----BEGIN PRIVATE KEY-----\nCAWG Key...\n-----END PRIVATE KEY-----"
    }
  }
}
```

### Development Configuration
```json
{
  "version": 1,
  "verify": {
    "verify_trust": false,
    "verify_timestamp_trust": false
  },
  "builder": {
    "thumbnail": {
      "enabled": false
    }
  }
}
```

### Production Configuration
```json
{
  "version": 1,
  "trust": {
    "trust_anchors": "-----BEGIN CERTIFICATE-----\n...",
    "trust_config": "1.3.6.1.5.5.7.3.4\n1.3.6.1.5.5.7.3.36"
  },
  "core": {
    "backing_store_memory_threshold_in_mb": 1024
  },
  "builder": {
    "intent": {"Create": "digitalCapture"},
    "thumbnail": {
      "long_edge": 512,
      "quality": "high"
    }
  }
}
```

## Notes

- All fields are optional except `version`
- Settings can be partially specified - unspecified fields use defaults
- Boolean fields should not be quoted
- A setting can be removed by setting it to null
- Certificate fields expect PEM format strings with `\n` for line breaks
- The `intent` field uses object notation: `{"Create": "digitalCapture"}`, `"Edit"`, or `"Update"`
- Signing algorithms supported: `ps256`, `ps384`, `ps512`, `es256`, `es384`, `es512`, `ed25519`
- Remote signers receive POST requests with the data to be signed as the request body, they return the signature data.
- When using both `signer` and `cawg_x509_signer`, the main signature uses `signer` and CAWG identity assertions use `cawg_x509_signer`