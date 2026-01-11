# Using the Rust library

## Supported platforms

The C2PA Rust library has been tested on:

* Windows (Intel only)
* MacOS (Intel and Apple silicon)
* Ubuntu Linux (64-bit Intel and ARM v8)
* WebAssembly (Wasm); see [Building for WebAssembly](project-contributions.md#building-for-webassembly) for details.

## Requirements

The C2PA Rust library requires **Rust version 1.88.0** or newer.

To use the library, add this to your `Cargo.toml`:

```toml
[dependencies]
c2pa = "0.72.0"
```

NOTE: The version above is just a placeholder.  Find the latest version at https://crates.io/crates/c2pa.

To read or write a manifest file, add the `file_io` dependency to your `Cargo.toml`.

<!-- Check whether thumbnail generation has been removed -->

Add the `add_thumbnails` dependency to generate thumbnails for JPEG and PNG files. For example:

```
c2pa = { version = "0.72.0", features = ["file_io", "add_thumbnails"] }
```

## Features

You can enable any of the following features:

- **default_http** *(enabled by default)*: Enables default HTTP features for sync and async HTTP resolvers (`http_req`, `http_reqwest`, `http_wasi`, and `http_std`).
- **openssl** *(enabled by default)*: Use the vendored `openssl` implementation for cryptography.
- **rust_native_crypto**: Use Rust native cryptography.
- **add_thumbnails**: Adds the [`image`](https://github.com/image-rs/image) crate to enable auto-generated thumbnails, if possible and enabled in settings.
- **fetch_remote_manifests**: Fetches remote manifests over the network when no embedded manifest is present and that option is enabled in settings.
- **file_io**: Enables APIs that use file system I/O.
- **json_schema**: Adds the [`schemars`](https://github.com/GREsau/schemars) crate to derive JSON schemas for JSON-compatible structs.
- **pdf**: Enables basic PDF read support.
- **http_ureq**: Enables `ureq` for sync HTTP requests.
- **http_reqwest**: Enables `reqwest` for async HTTP requests.
- **http_reqwest_blocking**: Enables the `blocking` feature of `reqwest` for sync HTTP requests.
- **http_wasi**: Enables `wasi` for sync HTTP requests on WASI.
- **http_wstd**: Enables `wstd` for async HTTP requests on WASI.

> [!NOTE]
> If both `rust_native_crypto` and `openssl` are enabled, then only `rust_native_crypto` will be enabled.
> To avoid including `openssl` as a dependency, disable default features when using `rust_native_crypto`.

### Features no longer supported

The following features are no longer supported:

* **v1_api**. The old API that this enabled has been removed.
* **serialize_thumbnails**. Thumbnails can be serialized by accessing resources directly.

### Resource references

A resource reference is a superset of a `HashedUri`, which the C2PA specification refers to as both `hashed-uri-map` and  `hashed-ext-uri-map`. In some cases either can be used.

A resource reference also adds local references to things like the file system or any abstracted storage. You can use the identifier field to distinguish from the URL field, but they are really the same. However, the specification will only allow for JUMBF and HTTP(S) references, so if the external identifier is not HTTP(S), it must be converted to a JUMBF reference before embedding into a manifest.

When defining a resource for the [ManifestStoreBuilder](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html), existing resources in other manifests may be identified via JUMBF URLs. This allows a new manifest to inherit an existing thumbnail and is also used to reference parent ingredients. The API will generally do this resolution as needed, so you do not need to know about JUMBF URL references when creating a manifest.

The specification often requires adding a `HashedUri` to an assertion. Since the JUMBF URIs for a new manifest are not known when defining the manifest, this creates a "chicken and egg" scenario, resolved with local resource references. When constructing the JUMBF for a manifest, the library converts all local URI references into JUMBF references and corrects the the associated cross references.

URI schemes in a resource reference can have the following forms:

- `self#jumbf` - An internal JUMBF reference
- `file:///` - A local file reference
- `app://contentauth/` - A working store reference
- `http://` - Remote URI
- `https://` - Remote secure URI

Note that the `file:` and `app:` schemes are only used in the context of `ManifestStoreBuilder` and will never be in JUMBF data. This is proposal, currently there is no implementation for file or app schemes and we do not yet handle HTTP/HTTPS schemes this way.

<!-- Is the above still true? "This is proposal, currently there is no implementation" -->

When `file_io` is enabled, the lack of a scheme will be interpreted as a `file:///` reference, otherwise as an `app:` reference.

### Source asset versus parent asset

The source asset isn't always the parent asset: The source asset is the asset that is hashed and signed. It can be the output from an editing application that has not preserved the manifest store from the parent. In that case, the application should have extracted a parent ingredient from the parent asset and added that to the manifest definition.

- Parent asset: with a manifest store.
- Parent ingredient: generated from that parent asset (hashed and validated)
- Source asset: may be a generated rendition after edits from the parent asset (manifest?)
- Signed output which will include the source asset, and the new manifest store with parent ingredient.

If there is no parent ingredient defined, and the source has a manifest store, the sdk will generate a parent ingredient from the parent.

### Remote URLs and embedding

The default operation of C2PA signing is to embed a C2PA manifest store into an asset. The library also returns the C2PA manifest store so that it can be written to a sidecar or uploaded to a remote service.

- The API supports embedding a remote URL reference into the asset.
- The remote URL is stored in different ways depending on the asset, but is often stored in XMP data.
- The remote URL must be added to the asset before signing so that it can be hashed along with the asset.
- Not all file formats support embedding remote URLs or embedding manifests stores.
- If you embed a manifest or a remote URL, a new asset will be created with the new data embedded.
- If you don't embed, then the original asset is unmodified and there is no need to write one out.
- The remote URL can be set with `builder.remote_url`.
- If embedding is not needed, set the `builder.no_embed` flag to `true`.

## Using Context for configuration

The C2PA library uses a `Context` structure to configure operations. Context replaces the older thread-local Settings pattern with a more flexible, thread-safe approach.

### What is Context?

`Context` encapsulates all configuration needed for C2PA operations:

- **Settings**: Configuration options (verification, signing, network policies, etc.)
- **HTTP Resolvers**: Customizable sync and async HTTP clients for fetching remote manifests
- **Signers**: Cryptographic signers used to sign manifests (optional - usually created from settings)

### Creating a Context

The simplest way to create a Context is with default settings:

```rust
use c2pa::Context;

let context = Context::new();
```

### Configuring Settings

Settings can be provided in multiple formats:

#### From JSON string

```rust
use c2pa::{Context, Result};

fn main() -> Result<()> {
    let context = Context::new()
        .with_settings(r#"{"verify": {"verify_after_sign": true}}"#)?;
    Ok(())
}
```

#### From TOML string

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

#### From Settings struct

```rust
use c2pa::{Context, Settings, Result};

fn main() -> Result<()> {
    let mut settings = Settings::default();
    settings.verify.verify_after_sign = true;
    
    let context = Context::new().with_settings(settings)?;
    Ok(())
}
```

### Using Context with Reader

`Reader` uses Context to control how manifests are validated and how remote resources are fetched:

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

### Using Context with Builder

`Builder` uses Context to configure signing operations. The Context automatically creates a signer from settings when needed:

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

### Configuring a signer

**In most cases, you don't need to explicitly set a signer on the Context.** Instead, configure signer settings in your configuration, and the Context will create the signer automatically when you call `save_to_stream()` or `save_to_file()`.

#### Method 1: From Settings (recommended)

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

#### Method 2: Custom signer (advanced)

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

#### Signer configuration options

The `signer` field in settings supports two types:

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

### Custom HTTP resolvers

For advanced use cases, you can provide custom HTTP resolvers to control how remote manifests are fetched. Custom resolvers are useful for adding authentication, caching, logging, or mocking network calls in tests.

### Thread safety

Context is designed to be used safely across threads. While Context itself doesn't implement `Clone`, you can:

1. Create separate contexts for different threads
2. Use `Arc<Context>` to share a context across threads (for read-only access)
3. Pass contexts by reference where appropriate

### When to use Context sharing

Understanding when to use shared contexts helps optimize your application:

**Use single-use Context (no Arc needed):**
- Single signing operation
- Single reading operation
- Each operation has different configuration needs

```rust
// Simple case - no Arc needed
let builder = Builder::new();
let reader = Reader::new();
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

### Migration from thread-local Settings

The Context API replaces the older thread-local settings pattern. If you're migrating existing code, here's how Settings and Context work together.

#### Backwards compatibility

**Settings still works:** The Settings type and its configuration format remain unchanged. All your existing settings files (JSON or TOML) work with Context without modification.

**Key differences:**

| Aspect | Old Global Settings | New Context API |
|--------|---------------------|-----------------|
| Scope | Global, affects all operations | Per-operation, explicitly passed |
| Thread Safety | Not thread-safe | Thread-safe, shareable with Arc |
| Configuration | Set once per thread | Can have multiple configurations |
| Testability | Difficult (thread-local state) | Easy (isolated contexts) |

#### Migration examples

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

#### How Context uses Settings internally

Context wraps a `Settings` instance and uses it to:

1. **Create signers automatically** - When you call `context.signer()` or `builder.save_to_stream()`, the Context creates a signer from the `signer` field in Settings (if present).

2. **Configure HTTP resolvers** - The Context creates default HTTP resolvers (for fetching remote manifests) and applies the `core.allowed_network_hosts` setting from Settings.

3. **Control verification** - The `verify` settings control how manifests are validated.

4. **Configure builder behavior** - The `builder` settings control thumbnail generation, actions, and other manifest creation options.

The Settings format hasn't changed - only how you provide those settings:

```rust
// Settings can be created and passed to Context
let settings = Settings::default();
settings.verify.verify_after_sign = true;
let context = Context::new().with_settings(settings)?;

// Or passed directly as JSON/TOML strings
let context = Context::new()
    .with_settings(r#"{"verify": {"verify_after_sign": true}}"#)?;
```

#### Thread-local Settings still available (legacy)

For backwards compatibility, the thread-local Settings pattern still works, but is not recommended for new code:

```rust
use c2pa::Settings;

// Thread-local settings (legacy approach - not recommended)
Settings::from_toml(include_str!("settings.toml"))?;

// Builder/Reader without explicit Context will use thread-local Settings
let builder = Builder::new();  // Uses thread-local Settings internally
```

**Why Context is better:**
- Explicit dependencies (no hidden thread-local state)
- Multiple configurations in the same application
- Thread-safe sharing with Arc
- Easier to test (pass mock contexts)
- FFI-friendly (contexts can be passed across language boundaries)

## Example code

The [sdk/examples](https://github.com/contentauth/c2pa-rs/tree/main/sdk/examples) directory contains some minimal example code.  The [client/client.rs](https://github.com/contentauth/c2pa-rs/blob/main/sdk/examples/client/client.rs) is the most instructive and provides and example of reading the contents of a manifest store, recursively displaying nested manifests.
