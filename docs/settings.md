# Configuring SDK settings

You can configure how the SDK works in any programming language using declarative settings in JSON or TOML format.  This documentation describes the JSON format, since it's a more common format, but TOML works equally well.

## Loading settings

Load settings either inline or from a file using the [`Context::new().with_settings()`](https://docs.rs/c2pa/latest/c2pa/struct.Context.html#method.with_settings) method. This method automatically detects the format (JSON or TOML). Using `Context` is thread-safe and can be shared with `Arc<Context>` and allows multiple configurations in one application.


```rust
use c2pa::{Context, Builder, Result};

fn main() -> Result<()> {

  // From a file
  let context = Context::new()
      .with_settings(include_str!("settings.json"))?;

  // Inline JSON format
  let context = Context::new()
      .with_settings(r#"
        {"verify": 
        {"verify_after_sign": true}}"#)?;

  // Inline TOML format
  let context = Context::new()
      .with_settings(r#"
        [verify]
        verify_after_sign = true
      "#)?;

  // Create builder using context settings
  let builder = Builder::from_context(context);
  Ok(())
}
```

For backwards compatibility, you can still use the old thread-local `Settings::from_toml()`, but this approach is **not recommended**. See [Configuring the SDK using Context](context.md) for details.

## Settings definition

The Settings definition has the following top-level structure:

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

NOTES:

- All properties are optional.  If you do not specify a value, the SDK will use the default value, if any.
- If you specify a value of `null`, then the property will be set to `null`, not the default.
- Do not quote Boolean property values (for example, use `true` not `"true"`).

For a complete reference to all the Settings properties, see the [SDK object reference - Settings](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema).  

| Property | Description |
|----------|-------------|
| `version` | Settings format version (integer). The default and only supported value is 1. |
| [`builder`](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#buildersettings) | Configuration for [Builder](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html). |
| [`cawg_trust`](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#trust) | Configuration CAWG trust lists. |
| [`cawg_x509_signer`](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#signersettings) | Configuration for the [CAWG x.509 signer](https://docs.rs/c2pa/latest/c2pa/struct.Settings.html#structfield.signer). |
| [`core`](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#core) | Configuration for core features. |
| [`signer`](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#signersettings) | Configuration for the base [C2PA signer](https://docs.rs/c2pa/latest/c2pa/struct.Settings.html#structfield.signer) |
| [`trust`](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#trust) | Configuration for C2PA trust lists. |
| [`verify`](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#verify) | Configuration for verification (validation). |

### Default configuration

Here's the Settings JSON with all default values:

```json
{
  "version": 1,
  "builder": {
    "claim_generator_info": null,
    "created_assertion_labels": null,    
    "certificate_status_fetch": null,
    "certificate_status_should_override": null,
    "generate_c2pa_archive": true,
    "intent": null,
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
    "thumbnail": {
      "enabled": true,
      "ignore_errors": true,
      "long_edge": 1024,
      "format": null,
      "prefer_smallest_format": true,
      "quality": "medium"
    },    
  },
  "cawg_trust": {
    "verify_trust_list": true,
    "user_anchors": null,
    "trust_anchors": null,
    "trust_config": null,
    "allowed_list": null
  },
  "cawg_x509_signer": null,
  "core": {
    "merkle_tree_chunk_size_in_kb": null,
    "merkle_tree_max_proofs": 5,
    "backing_store_memory_threshold_in_mb": 512,
    "decode_identity_assertions": true,
    "allowed_network_hosts": null
  },
  "signer": null,
  "trust": {
    "user_anchors": null,
    "trust_anchors": null,
    "trust_config": null,
    "allowed_list": null
  },
  "verify": {
    "verify_after_reading": true,
    "verify_after_sign": true,
    "verify_trust": true,
    "verify_timestamp_trust": true,
    "ocsp_fetch": false,
    "remote_manifest_fetch": true,
    "skip_ingredient_conflict_resolution": false,
    "strict_v1_validation": false
  }
}
```

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

### Local signer

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

### Remote signer

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

### CAWG dual signer

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


