# Configuring settings

You can configure SDK settings using a JSON file that controls many aspects of the library's behavior. This definition works the same in all programming languages and platforms.

This document describes the complete JSON schema and available options.

NOTE: If you don't specify a value for a property, then the SDK will use the default value.  If you specify a value of `null`, then the property will be set to `null`, not the default.

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

### Specifying settings file

To specify the settings file use [`Settings::from_string`](https://docs.rs/c2pa/latest/c2pa/settings/struct.Settings.html#method.from_string) and specify the format as `"json"`. For example:

```rs
Settings::from_string(include_str!("fixtures/test_settings.json"), "json")?;
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
All other properties are optional.

NOTE: Do not quote Boolean properties.

- If you do not specify a value, the SDK will use the default value, if any.
- If you specify a value of `null`, then the property will be set to `null`, not the default.

### builder

The `builder` object specifies settings for the Builder API.

| Property | Type | Description | Default value |
| --- | --- | --- | --- |
| `builder.claim_generator_info` | Object | Default claim generator information. Used if the `Builder` hasn't specified one. | N/A |
| `builder.certificate_status_fetch` | String | Certificate status fetching scope | null |
| `builder.certificate_status_should_override` | Boolean | Override OCSP with certificate status assertions | null |
| `builder.intent` | object | Default builder intent. The value uses object notation and must be one of: `{"Create": "digitalCapture"}` <br/> `{"Create": "Edit"}` <br/> `{"Create": "Update"}`. | null |
| `builder.created_assertion_labels` | Array | Array of base assertion labels you want to treated as `created`. When the builder encounters one of these, it will become a created assertion.  | null |
| `builder.generate_c2pa_archive` | Boolean | Generate C2PA archive format | null |
| `builder.actions` | Object | Action assertion configuration. |  |
| `builder.actions.all_actions_included` | Boolean | Whether all actions are specified | null |
| `builder.actions.templates` | Array | Action templates | null |
| `builder.actions.actions` | Array or null | Predefined actions to add | null |
| `builder.actions.auto_created_action.enabled` | Boolean | Enable automatic `c2pa.created` actions | true |
| `builder.actions.auto_created_action.source_type` | String | Digital source type for created action | "empty" |
| `builder.actions.auto_opened_action.enabled` | Boolean | Enable automatic `c2pa.opened` actions | true |
| `builder.actions.auto_opened_action.source_type` | String | Digital source type for opened action | null |
| `builder.actions.auto_placed_action.enabled` | Boolean | Enable automatic `c2pa.placed` actions | true |
| `builder.actions.auto_placed_action.source_type` | String | Digital source type for placed action | null |
| `builder.thumbnail` | Object | Automatic thumbnail generation settings. |  |
| `builder.thumbnail.enabled` | Boolean | Enable automatic thumbnails | true |
| `builder.thumbnail.ignore_errors` | Boolean | Continue on thumbnail generation errors | true |
| `builder.thumbnail.long_edge` | Number | Size of thumbnail's longest edge in pixels | 1024 |
| `builder.thumbnail.format` | String | Output format. One of: <br/>`"jpeg"` <br/> `"png"` <br/> `"webp"` <br/> `null` | null |
| `builder.thumbnail.prefer_smallest_format` | Boolean | Use smallest format when possible | true |
| `builder.thumbnail.quality` | String | Quality setting. One of: <br/>`"low"` <br/> `"medium"` <br/> `"high"` | `"medium"` |

***claim_generator_info**

The `builder.claim_generator_info` specifies the default claim generator information.  It's a JSON object as described in the table below. It can have additional custom properties as needed by an implementation.

| Property | Type | Description | Default value |
| --- | --- | --- | --- |
| `name` | String	| A human readable string naming the claim_generator | N/A - Required |
| `version`	| String	 | A human readable string of the product's version | Null |
| `icon` | `UriOrResource` | Hashed URI to the icon (either embedded or remote) | Null |
| `operating_system`	| String	 | Human readable string of the OS the claim generator is running on | Null |

Only the `name` property is required. For example:

```json
"claim_generator_info": [
  {
    "name": "Adobe Content Authenticity",
    "com.adobe.aca-version": "81c4a25",
    "org.cai.c2pa_rs": "0.49.3"
  }
]
```

### cawg_trust

The `cawg_trust` object specifies configuration for CAWG (Creator Assertions Working Group) validation when an X.509 certificate is used. Its structure identical to `trust`.

For certificate properties, use PEM format strings with `\n` for line breaks.

| Property | Type | Description | Default value |
| --- | --- | --- | --- |
| `cawg_trust.verify_trust_list` | Boolean | Enforce verification against the CAWG trust list | true |
| `cawg_trust.user_anchors` | String | Additional user-provided root certificates (PEM format) | N/A |
| `cawg_trust.trust_anchors` | String | Default trust anchor root certificates (PEM format) | N/A |
| `cawg_trust.trust_config` | String | Allowed extended key usage (EKU) object identifiers | N/A |
| `cawg_trust.allowed_list` | String | Explicitly allowed certificates (PEM format) | N/A |


### cawg_x509_signer

The `cawg_x509_signer` object specifies configuration for the CAWG X.509 signer that generates identity assertions. It has the same structure as `signer` (local or remote).

When both `signer` and `cawg_x509_signer` are configured, the system creates a dual signer that:

- Uses `signer` configuration for the main C2PA claim signature.
- Uses `cawg_x509_signer` configuration to generate CAWG identity assertions with X.509 credentials.

**Local CAWG signer**

| Property | Type | Description | Default value |
| --- | --- | --- | --- |
| `cawg_x509_signer.local` | Object | Local CAWG X.509 signer |  |
| `cawg_x509_signer.local.alg` | String | Signing algorithm for CAWG identity. One of:<br/>`"ps256"`<br/> `"ps384"`<br/>`"ps512"`<br/>`"es256"`<br/>`"es384"`<br/>`"es512"`<br/> `"ed25519"` | — |
| `cawg_x509_signer.local.sign_cert` | String | Certificate chain for signing (PEM format) | — |
| `cawg_x509_signer.local.private_key` | String | Private key for signing (PEM format) | — |
| `cawg_x509_signer.local.tsa_url` | String | Time stamp authority URL for timestamping | null |

**Remote CAWG signer**

Remote signers receive POST requests with the data to be signed as the request body, and return the signature data.

| Property | Type | Description | Default value |
| --- | --- | --- | --- |
| `cawg_x509_signer.remote` | Object | Remote CAWG X.509 signer. NOTE: Remote CAWG X.509 signing is not yet implemented. |  |
| `cawg_x509_signer.remote.url` | String | URL to the remote signing service (receives POST with byte stream) | — |
| `cawg_x509_signer.remote.alg` | String | Signing algorithm used by the remote CAWG identity service. One of:<br/>`"ps256"`<br/> `"ps384"`<br/>`"ps512"`<br/>`"es256"`<br/>`"es384"`<br/>`"es512"`<br/> `"ed25519"` | — |
| `cawg_x509_signer.remote.sign_cert` | String | Certificate chain for the remote signer (PEM format) | — |
| `cawg_x509_signer.remote.tsa_url` | String | Time stamp authority URL | null |

### core

The `core` object specifies core features and performance settings. 

| Property | Type | Description | Default value |
| --- | --- | --- | --- |
| `core.merkle_tree_chunk_size_in_kb` | Number | Chunk size for BMFF hash Merkle trees in KB |  |
| `core.merkle_tree_max_proofs` | Number | Maximum Merkle tree proofs when validating | 5 |
| `core.backing_store_memory_threshold_in_mb` | Number | Memory threshold before using disk storage (MB) | 512 |
| `core.decode_identity_assertions` | Boolean | Whether to decode CAWG identity assertions | true |


### signer

The `signer` object specifies configuration for the primary C2PA signer. Can be `null`, a `local` object, or a `remote` object with values as described below. 

When both `signer` and `cawg_x509_signer` are configured, the system creates a dual signer that:

- Uses `signer` configuration for the main C2PA claim signature.
- Uses `cawg_x509_signer` configuration to generate CAWG identity assertions with X.509 credentials.

**Local signer**

| Property | Type | Description | Default value |
| --- | --- | --- | --- |
| `signer.local` | Object | Local signer |  |
| `signer.local.alg` | String | Signing algorithm. One of:<br/>`"ps256"`<br/> `"ps384"`<br/>`"ps512"`<br/>`"es256"`<br/>`"es384"`<br/>`"es512"`<br/> `"ed25519"` | — |
| `signer.local.sign_cert` | String | Certificate chain for signing (PEM format) | — |
| `signer.local.private_key` | String | Private key for signing (PEM format) | — |
| `signer.local.tsa_url` | String | Time stamp authority URL for timestamping | null |

**Remote signer**

Remote signers receive POST requests with the data to be signed as the request body, and return the signature data.

| Property | Type | Description | Default value |
| --- | --- | --- | --- |
| `signer.remote` | Object | Remote signer. NOTE: Remote signers are not supported in WASM builds. |  |
| `signer.remote.url` | String | URL to the remote signing service (receives POST with byte stream) | — |
| `signer.remote.alg` | String | Signing algorithm used by the remote service. One of:<br/>`"ps256"`<br/> `"ps384"`<br/>`"ps512"`<br/>`"es256"`<br/>`"es384"`<br/>`"es512"`<br/> `"ed25519"` | — |
| `signer.remote.sign_cert` | String | Certificate chain for the remote signer (PEM format) | — |
| `signer.remote.tsa_url` | String | Time stamp authority URL | null |

### trust

The `trust` object specifies the configuration for C2PA certificate trust validation.

For certificate properties, use PEM format strings with `\n` for line breaks.

| Property | Type | Description | Default value |
| --- | --- | --- | --- |
| `trust.user_anchors` | String | Additional user-provided root certificates (PEM format) | N/A |
| `trust.trust_anchors` | String | Default trust anchor root certificates (PEM format) | N/A |
| `trust.trust_config` | String | Allowed extended key usage (EKU) object identifiers | N/A |
| `trust.allowed_list` | String | Explicitly allowed certificates (PEM format) | N/A |

### verify

The `verify` object specifies verification behavior. 

| Property | Type | Description | Default value |
| --- | --- | --- | --- |
| `verify.verify_after_reading` | Boolean | Verify manifests after reading | true |
| `verify.verify_after_sign` | Boolean | Verify manifests after signing | true |
| `verify.verify_trust` | Boolean | Verify certificates against trust lists | true |
| `verify.verify_timestamp_trust` | Boolean | Verify time-stamp certificates | true |
| `verify.ocsp_fetch` | Boolean | Fetch OCSP status during validation | false |
| `verify.remote_manifest_fetch` | Boolean | Fetch remote manifests | true |
| `verify.check_ingredient_trust` | Boolean | Verify ingredient certificates | true |
| `verify.skip_ingredient_conflict_resolution` | Boolean | Skip ingredient conflict resolution | false |
| `verify.strict_v1_validation` | Boolean | Use strict C2PA v1 validation | false |

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

### Local signer configuration

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

### Remote signer configuration

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

### CAWG dual signer configuration

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

