# Configuring the SDK using Context

Use the `Context` structure to configure the C2PA Rust library.
`Context` replaces the older thread-local `Settings` pattern with a more flexible, thread-safe approach.

## What is Context?

`Context` encapsulates all configuration needed for C2PA operations:

- **Settings**: Configuration options (verification, signing, network policies, etc.)
- **HTTP Resolvers**: Customizable sync and async HTTP clients for fetching remote manifests
- **Signers**: Cryptographic signers used to sign manifests (optional - usually created from settings)

Context is better than thread-local `Settings` because it has:

- Explicit dependencies (no hidden thread-local state).
- Multiple configurations in the same application.
- Thread-safe sharing with Arc.
- Easier testability (can pass mock contexts).
- Ability to pass across language barriers, so it's FFI-friendly.

<!--
The Context API:
- Is thread-safe and can be shared with `Arc<Context>`
- Allows multiple configurations in one application
- Makes dependencies explicit (no hidden thread-local state)
- Automatically creates signers from settings when needed
-->

While the old `Settings` pattern is supported for [backwards compatibility](#backwards-compatibility), it is not recommended. For information on moving from the old pattern, see [Migration from thread-local settings](#migration-from-thread-local-settings).

## Creating a Context

The simplest way to create a `Context` is with default settings:

```rust
use c2pa::Context;

let context = Context::new();
```

## Configuring Settings

You can configure settings using multiple formats:

- [From a JSON string](#from-a-json-string)
- [From a TOML string](#from-a-toml-string)
- [From a Settings struct](#from-a-settings-struct)

### From a JSON string

```rust
use c2pa::{Context, Result};

fn main() -> Result<()> {
    let context = Context::new()
        .with_settings(r#"{"verify": {"verify_after_sign": true}}"#)?;
    Ok(())
}
```

### From a TOML string

```rust
use c2pa::{Context, Result};

fn main() -> Result<()> {
    let toml = r#"
        [verify]
        verify_after_sign = true
        
        [core]
        allowed_network_hosts = ["example.com"]
    "#;
    let context = Context::new().with_settings(toml)?;
    Ok(())
}
```

### From a Settings struct

```rust
use c2pa::{Context, Settings, Result};

fn main() -> Result<()> {
    let mut settings = Settings::default();
    settings.verify.verify_after_sign = true;
    
    let context = Context::new().with_settings(settings)?;
    Ok(())
}
```

## Using Context with Reader

`Reader` uses `Context` to control how to validate manifests and how to fetch remote resources:

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

## Using Context with Builder

`Builder` uses Context to configure signing operations. The `Context` automatically creates a signer from settings when needed:

```rust
use c2pa::{Context, Builder, Result};
use std::io::Cursor;
use serde_json::json;

fn main() -> Result<()> {
    // Configure context with signer settings
    let context = Context::new()
        .with_settings(json!({
            "builder": {
                "claim_generator_info": {"name": "My App"},
                "intent": "edit"
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

## Configuring a signer

**In most cases, you don't need to explicitly set a signer on the `Context`.** Instead, configure signer settings in your configuration, and the `Context` will create the signer automatically when you call `save_to_stream()` or `save_to_file()`.

### Configuring a signer from Settings (recommended)

Configure signer settings in JSON:

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

Then use it with the Builder:

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

### Configuring a custom signer (advanced)

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

The `signer` field in `Settings` supports two types:

**Local Signer** - for local certificate and private key:

```toml
[signer.local]
alg = "ps256"              # Signing algorithm (ps256, ps384, ps512, es256, es384, es512, ed25519)
sign_cert = "cert.pem"     # Path to certificate file or PEM string
private_key = "key.pem"    # Path to private key file or PEM string
tsa_url = "http://..."     # Optional: timestamp authority URL
```

**Remote Signer** - for remote signing services:

```toml
[signer.remote]
url = "https://signing.example.com/sign"  # Signing service URL
alg = "ps256"
sign_cert = "cert.pem"     # Certificate for verification
tsa_url = "http://..."     # Optional: timestamp authority URL
```

## Custom HTTP resolvers

For advanced use cases, you can provide custom HTTP resolvers to control how remote manifests are fetched. Custom resolvers are useful for adding authentication, caching, logging, or mocking network calls in tests.

## Thread safety

`Context` is designed to be used safely across threads. While `Context` itself doesn't implement `Clone`, you can:

1. Create separate contexts for different threads.
2. Use `Arc<Context>` to share a context across threads (for read-only access).
3. Pass contexts by reference where appropriate.

## When to use Context sharing

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

The Context API replaces the older thread-local `Settings` pattern. If you're migrating existing code, here's how `Settings` and `Context` work together.

### Backwards compatibility

**Settings still works:** The `Settings` type and its configuration format remain unchanged. All your existing settings files (JSON or TOML) work with Context without modification.

**Key differences:**

| Aspect | Old Global Settings | New Context API |
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

The `Settings` format hasn't changed—only how you provide those settings.


