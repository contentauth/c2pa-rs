# Configuring SDK settings

This guide shows you how to configure the C2PA Rust library using the `Context` API with declarative settings in JSON format.

## Overview

The `Context` structure encapsulates configuration for:

- **Settings**: Configuration options for verification, signing, network policies, builder behavior, etc.
- **HTTP Resolvers**: Customizable sync and async HTTP clients for fetching remote manifests
- **Signers**: Cryptographic signers used to sign manifests (created automatically from settings)

`Context` is thread-safe and can be shared with `Arc<Context>`, allowing multiple configurations in one application. It replaces the older thread-local `Settings` pattern with explicit dependencies and better testability.

## Quick start

### Creating a Context

The simplest way to create a `Context` is with default settings:

```rust
use c2pa::Context;

let context = Context::new();
```

### Loading settings from a file

Load settings from a file using the `with_settings()` method, which automatically detects the format (JSON or TOML):

```rust
use c2pa::{Context, Builder, Result};

fn main() -> Result<()> {
    // From a file
    let context = Context::new()
        .with_settings(include_str!("settings.json"))?;

    // Create builder using context settings
    let builder = Builder::from_context(context);
    Ok(())
}
```

### Loading settings inline

You can also provide settings inline in either JSON or TOML format. For example, using JSON:

```rust
use c2pa::{Context, Result};

fn main() -> Result<()> {
    // Inline JSON format
    let context = Context::new()
        .with_settings(r#"
          {"verify":
          {"verify_after_sign": true}}
        "#)?;

    Ok(())
}
```

### Loading settings from a struct

```rust
use c2pa::{Context, Settings, Result};

fn main() -> Result<()> {
    let mut settings = Settings::default();
    settings.verify.verify_after_sign = true;

    let context = Context::new().with_settings(settings)?;
    Ok(())
}
```

## Using Context

### With Reader

`Reader` uses `Context` to control manifest validation and remote resource fetching:

```rust
use c2pa::{Context, Reader, Result};
use std::fs::File;

fn main() -> Result<()> {
    // Configure context
    let context = Context::new()
        .with_settings(r#"{"verify": {"remote_manifest_fetch": false}}"#)?;

    // Create reader with context
    let stream = File::open("path/to/image.jpg")?;
    let reader = Reader::from_context(context)
        .with_stream("image/jpeg", stream)?;

    println!("{}", reader.json());
    Ok(())
}
```

### With Builder

`Builder` uses `Context` to configure signing operations. The `Context` automatically creates a signer from settings when needed:

```rust
use c2pa::{Context, Builder, Result};
use std::io::Cursor;
use serde_json::json;

fn main() -> Result<()> {
    // Configure context with signer and builder settings
    let context = Context::new()
        .with_settings(json!({
            "signer": {
                "local": {
                    "alg": "ps256",
                    "sign_cert": "path/to/cert.pem",
                    "private_key": "path/to/key.pem",
                    "tsa_url": "http://timestamp.digicert.com"
                }
            },
            "builder": {
                "claim_generator_info": {"name": "My App"},
                "intent": {"Create": "digitalCapture"}
            }
        }))?;

    // Create builder with context and inline JSON definition
    let mut builder = Builder::from_context(context)
        .with_definition(json!({"title": "My Image"}))?;

    // Save with automatic signer from context
    let mut source = std::fs::File::open("source.jpg")?;
    let mut dest = Cursor::new(Vec::new());
    builder.save_to_stream("image/jpeg", &mut source, &mut dest)?;

    Ok(())
}
```

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

> [!NOTE]
> - All properties are optional. If you do not specify a value, the SDK will use the default value, if any.
> - If you specify a value of `null`, then the property will be set to `null`, not the default.
> - Do not quote Boolean property values (for example, use `true` not `"true"`).

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

## Configuration examples

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

## Configuring signers

**In most cases, you don't need to explicitly set a signer on the `Context`**. Instead, configure signer settings in your configuration, and `Context` will create the signer automatically when you call `save_to_stream()` or `save_to_file()`.

### From settings (recommended)

Configure signer settings in the settings file, for example in JSON:

```json
{
  "signer": {
    "local": {
      "alg": "ps256",
      "sign_cert": "path/to/cert.pem",
      "private_key": "path/to/key.pem",
      "tsa_url": "http://timestamp.example.com"
    }
  }
}
```

Then use it with Builder:

```rust
use c2pa::{Context, Builder, Result};
use serde_json::json;

fn main() -> Result<()> {
    // Configure context with signer settings
    let context = Context::new()
        .with_settings(include_str!("config.json"))?;

    let mut builder = Builder::from_context(context)
        .with_definition(json!({"title": "My Image"}))?;

    // Signer is created automatically from context's settings
    let mut source = std::fs::File::open("source.jpg")?;
    let mut dest = std::fs::File::create("signed.jpg")?;
    builder.save_to_stream("image/jpeg", &mut source, &mut dest)?;

    Ok(())
}
```

### Custom signer (advanced)

For advanced use cases like HSMs or custom signing logic, you can create and set a custom signer:

```rust
use c2pa::{Context, create_signer, SigningAlg, Result};

fn main() -> Result<()> {
    // Explicitly create a signer
    let signer = create_signer::from_files(
        "path/to/cert.pem",
        "path/to/key.pem",
        SigningAlg::Ps256,
        None
    )?;

    // Set it on the context
    let context = Context::new().with_signer(signer);

    // Later retrieve it
    let signer_ref = context.signer()?;

    Ok(())
}
```

### Signer configuration options

The `signer` field in `Settings` supports two types: `local` and `remote`.

**Local Signer** - for local certificate and private key.

> [!NOTE]
> Using a local signer is suitable primarily for development and testing, not production because values for `sign_cert` and `private_key` must be inline PEM strings.

```json
...
  "signer": {
    "local": {
      "alg": "ps256", // Signing algorithm 
      "sign_cert": "cert.pem", // PEM string
      "private_key": "key.pem", // PEM string
      "tsa_url": "http://timestamp.digicert.com" // Optional timestamp authority URL
    }
  },
...
```

**Remote Signer** - for remote signing services.

```json
  "signer": {
    "remote": {
      "alg": "ps256", // Signing algorithm       
      "url": "https://my-signing-service.com/sign", // Signing service URL
      "sign_cert": "cert.pem", // Path to cert file for verification
      "tsa_url": "http://timestamp.digicert.com" // Optional timestamp authority URL
    }
  }
```

## Advanced topics

### Custom HTTP resolvers

For advanced use cases, you can provide custom HTTP resolvers to control how remote manifests are fetched. Custom resolvers are useful for adding authentication, caching, logging, or mocking network calls in tests.

### Thread safety

`Context` is designed to be used safely across threads. While `Context` itself doesn't implement `Clone`, you can:

1. Create separate contexts for different threads
2. Use `Arc<Context>` to share a context across threads (for read-only access)
3. Pass contexts by reference where appropriate

### When to use Context sharing

Understanding when to use a shared `Context` helps optimize your application:

**Use single-use Context (no Arc needed):**

- Single signing operation
- Single reading operation
- Each operation has different configuration needs

```rust
use c2pa::{Context, Builder, Reader};

// For simple, single-use cases create a fresh Context per operation
let builder = Builder::from_context(Context::new().with_settings(config)?);
// or, for reading:
let reader = Reader::from_context(Context::new().with_settings(config)?);
```

**Use shared Context (with Arc):**
- Multi-threaded operations
- Multiple builders or readers using the same configuration
- Signing and reading with the same settings
- Web servers handling multiple requests with shared configuration

```rust
use std::sync::Arc;

// Shared configuration
let ctx = Arc::new(Context::new().with_settings(config)?);
let builder1 = Builder::from_shared_context(&ctx);
let builder2 = Builder::from_shared_context(&ctx);
```

## Migration from thread-local Settings

The Context API replaces the older thread-local `Settings` pattern. If you're migrating existing code, this section explains how the two approaches differ.

### Backwards compatibility

**Settings still works:** The `Settings` type and its configuration format remain unchanged. All your existing settings files (JSON or TOML) work with Context without modification.

**Key differences:**

| Aspect | Old Thread-Local Settings | New Context API |
|--------|---------------------|-----------------|
| Scope | Global, affects all operations | Per-operation, explicitly passed |
| Thread Safety | Not thread-safe | Thread-safe, shareable with Arc |
| Configuration | Set once per thread | Can have multiple configurations |
| Testability | Difficult (thread-local state) | Easy (isolated contexts) |

### Migration examples

**Old approach (deprecated):**
```rust
use c2pa::Settings;

// Global settings affect all operations
Settings::from_toml(include_str!("settings.toml"))?;
let reader = Reader::from_stream("image/jpeg", stream)?;
```

**New approach with Context:**
```rust
use c2pa::{Context, Reader};

// Explicit context per operation
let context = Context::new()
    .with_settings(include_str!("settings.toml"))?;
let reader = Reader::from_context(context)
    .with_stream("image/jpeg", stream)?;
```

**Multiple configurations (impossible with thread-local settings):**
```rust
use c2pa::{Context, Builder};

// Development signer for testing
let dev_ctx = Context::new()
    .with_settings(include_str!("dev_settings.toml"))?;
let dev_builder = Builder::from_context(dev_ctx);

// Production signer for real signing
let prod_ctx = Context::new()
    .with_settings(include_str!("prod_settings.toml"))?;
let prod_builder = Builder::from_context(prod_ctx);
```

### How Context uses Settings internally

Context wraps a `Settings` instance and uses it to:

1. **Create signers automatically** - When you call `context.signer()` or `builder.save_to_stream()`, the Context creates a signer from the `signer` field in `Settings` (if present).

2. **Configure HTTP resolvers** - The Context creates default HTTP resolvers (for fetching remote manifests) and applies the `core.allowed_network_hosts` setting from `Settings`.

3. **Control verification** - The `verify` settings control how manifests are validated.

4. **Configure builder behavior** - The `builder` settings control thumbnail generation, actions, and other manifest creation options.

The `Settings` format hasn't changed; only how you provide those settings has changed.
