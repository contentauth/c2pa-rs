# Configuring settings

You can configure SDK settings using a JSON file that controls many aspects of the library's behavior. This definition works the same in all programming languages and platforms.

This document describes the complete JSON schema and available options.

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

## Complete default configuration

Here's the JSON with all default values:

```json
{
  "version": 1,
  "trust": {
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

## Property reference

The top-level `version` property is a number specifying the settings format version. The only supported value currently is `1`.

- All properties are optional except `version`.
- If you do not specify a value, the configuration will use the default.
- Do not quote Boolean properties.
- To remove a configuration value, set it to null.

### trust

The `trust` object specifies the configuration for C2PA certificate trust validation.

For certificate properties, use PEM format strings with `\n` for line breaks.

| Property | Type | Default value | Description |
| --- | --- | --- | --- |
| `trust.user_anchors` | string | null | Additional user-provided root certificates (PEM format) |
| `trust.trust_anchors` | string | null | Default trust anchor root certificates (PEM format) |
| `trust.trust_config` | string | null | Allowed extended key usage (EKU) object identifiers |
| `trust.allowed_list` | string | null | Explicitly allowed certificates (PEM format) |

### cawg_trust

The `cawg_trust` object specifies configuration for CAWG (Creator Assertions Working Group) validation when an X.509 certificate is used. Its structure identical to `trust`.

For certificate properties, use PEM format strings with `\n` for line breaks.

| Property | Type | Default value | Description |
| --- | --- | --- | --- |
| `cawg_trust.verify_trust_list` | Boolean | true | Enforce verification against the CAWG trust list |
| `cawg_trust.user_anchors` | String | null | Additional user-provided root certificates (PEM format) |
| `cawg_trust.trust_anchors` | String | null | Default trust anchor root certificates (PEM format) |
| `cawg_trust.trust_config` | String | null | Allowed extended key usage (EKU) object identifiers |
| `cawg_trust.allowed_list` | String | null | Explicitly allowed certificates (PEM format) |

### core

The `core` object specifies core library features and performance settings. 

| Property | Type | Default value | Description |
| --- | --- | --- | --- |
| `core.merkle_tree_chunk_size_in_kb` | number or null | null | Chunk size for BMFF hash merkle trees in KB |
| `core.merkle_tree_max_proofs` | number | 5 | Maximum merkle tree proofs when validating |
| `core.backing_store_memory_threshold_in_mb` | number | 512 | Memory threshold before using disk storage (MB) |
| `core.decode_identity_assertions` | Boolean | true | Whether to decode CAWG identity assertions |

## verify

The `verify` object specifies verification behavior. 

| Property | Type | Default value | Description |
| --- | --- | --- | --- |
| `verify.verify_after_reading` | Boolean | true | Verify manifests after reading |
| `verify.verify_after_sign` | Boolean | true | Verify manifests after signing |
| `verify.verify_trust` | Boolean | true | Verify certificates against trust lists |
| `verify.verify_timestamp_trust` | Boolean | true | Verify timestamp certificates |
| `verify.ocsp_fetch` | Boolean | false | Fetch OCSP status during validation |
| `verify.remote_manifest_fetch` | Boolean | true | Fetch remote manifests |
| `verify.check_ingredient_trust` | Boolean | true | Verify ingredient certificates |
| `verify.skip_ingredient_conflict_resolution` | Boolean | false | Skip ingredient conflict resolution |
| `verify.strict_v1_validation` | Boolean | false | Use strict C2PA v1 validation |

### builder

The `builder` object specifies settings for the Builder API.

| Property | Type | Default value | Description |
| --- | --- | --- | --- |
| `builder.claim_generator_info` | object or null | null | Default claim generator information |
| `builder.certificate_status_fetch` | String | null | Certificate status fetching scope |
| `builder.certificate_status_should_override` | Boolean | null | Override OCSP with certificate status assertions |
| `builder.intent` | object | null | Default builder intent. The value uses object notation and must be one of: `{"Create": "digitalCapture"}`, `{"Create": "Edit"}`, or `{"Create": "Update"}`. |
| `builder.created_assertion_labels` | Array | null | Labels for created assertions |
| `builder.generate_c2pa_archive` | Boolean | null | Generate C2PA archive format |
| `builder.actions` | Object | | Action assertion configuration. |
| `builder.actions.all_actions_included` | Boolean | null | Whether all actions are specified |
| `builder.actions.templates` | array or null | null | Action templates |
| `builder.actions.actions` | array or null | null | Predefined actions to add |
| `builder.actions.auto_created_action.enabled` | Boolean | true | Enable automatic `c2pa.created` actions |
| `builder.actions.auto_created_action.source_type` | string | "empty" | Digital source type for created action |
| `builder.actions.auto_opened_action.enabled` | Boolean | true | Enable automatic `c2pa.opened` actions |
| `builder.actions.auto_opened_action.source_type` | String | null | Digital source type for opened action |
| `builder.actions.auto_placed_action.enabled` | Boolean | true | Enable automatic `c2pa.placed` actions |
| `builder.actions.auto_placed_action.source_type` | String | null | Digital source type for placed action |
| `builder.thumbnail` | Object | | Automatic thumbnail generation settings. |
| `builder.thumbnail.enabled` | Boolean | true | Enable automatic thumbnails |
| `builder.thumbnail.ignore_errors` | Boolean | true | Continue on thumbnail generation errors |
| `builder.thumbnail.long_edge` | number | 1024 | Size of thumbnail's longest edge in pixels |
| `builder.thumbnail.format` | "jpeg" <br/> "png" <br/> "webp" <br/> null | null | Output format |
| `builder.thumbnail.prefer_smallest_format` | Boolean | true | Use smallest format when possible |
| `builder.thumbnail.quality` | "low" <br/> "medium" <br/> "high" | "medium" | Quality setting |

### signer

The `signer` object specifies configuration for the primary C2PA signer. Can be `null`, a `local` object, or a `remote` object with values as described below. 

When both `signer` and `cawg_x509_signer` are configured, the system creates a dual signer that:

- Uses `signer` configuration for the main C2PA claim signature.
- Uses `cawg_x509_signer` configuration to generate CAWG identity assertions with X.509 credentials.

**Local signer**

| Property | Type | Default value | Description |
| --- | --- | --- | --- |
| `signer.local` | Object | | Local signer |
| `signer.local.alg` | `ps256`<br/> `ps384`<br/>`ps512`<br/>`es256`<br/>`es384`<br/>`es512`, `ed25519`   | — | Signing algorithm |
| `signer.local.sign_cert` | string | — | Certificate chain for signing (PEM format) |
| `signer.local.private_key` | string | — | Private key for signing (PEM format) |
| `signer.local.tsa_url` | String | null | Time stamp authority URL for timestamping |

**Remote signer**

Remote signers receive POST requests with the data to be signed as the request body, and return the signature data.

| Property | Type | Default value | Description |
| --- | --- | --- | --- |
| `signer.remote` | Object | | Remote signer. NOTE: Remote signers are not supported in WASM builds. |
| `signer.remote.url` | string | — | URL to the remote signing service (receives POST with byte stream) |
| `signer.remote.alg` | "ps256" <br/> "ps384" <br/> "ps512" <br/> "es256" <br/> "es384" <br/> "es512" <br/> "ed25519" | — | Signing algorithm used by the remote service |
| `signer.remote.sign_cert` | string | — | Certificate chain for the remote signer (PEM format) |
| `signer.remote.tsa_url` | String | null | Time stamp authority URL |

### cawg_x509_signer

The `cawg_x509_signer` object specifies configuration for the CAWG X.509 signer that generates identity assertions. It has the same structure as `signer` (local or remote).

When both `signer` and `cawg_x509_signer` are configured, the system creates a dual signer that:

- Uses `signer` configuration for the main C2PA claim signature.
- Uses `cawg_x509_signer` configuration to generate CAWG identity assertions with X.509 credentials.

**Local CAWG signer**

| Property | Type | Default value | Description |
| --- | --- | --- | --- |
| `cawg_x509_signer.local` | Object | | Local CAWG X.509 signer |
| `cawg_x509_signer.local.alg` | `ps256`<br/> `ps384`<br/>`ps512`<br/>`es256`<br/>`es384`<br/>`es512`, `ed25519` | — | Signing algorithm |
| `cawg_x509_signer.local.sign_cert` | string | — | Certificate chain for signing (PEM format) |
| `cawg_x509_signer.local.private_key` | string | — | Private key for signing (PEM format) |
| `cawg_x509_signer.local.tsa_url` | String | null | Time stamp authority URL for timestamping |

**Remote CAWG signer**

Remote signers receive POST requests with the data to be signed as the request body, and return the signature data.

| Property | Type | Default value | Description |
| --- | --- | --- | --- |
| `cawg_x509_signer.remote` | Object | | Remote CAWG X.509 signer. NOTE: Remote CAWG X.509 signing is not yet implemented.
| `cawg_x509_signer.remote.url` | string | — | URL to the remote signing service (receives POST with byte stream) |
| `cawg_x509_signer.remote.alg` | `ps256`<br/> `ps384`<br/>`ps512`<br/>`es256`<br/>`es384`<br/>`es512`, `ed25519` | — | Signing algorithm used by the remote service |
| `cawg_x509_signer.remote.sign_cert` | string | — | Certificate chain for the remote signer (PEM format) |
| `cawg_x509_signer.remote.tsa_url` | String | null | Time stamp authority URL |

## Examples

### Minimal configuration

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

### Local Signer configuration
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

### Remote Signer configuration
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

### CAWG Dual Signer configuration
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

### Development configuration
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

### Production configuration
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

