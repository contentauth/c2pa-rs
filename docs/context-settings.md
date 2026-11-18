# Configuring SDK settings

This guide shows you how to configure the C2PA Rust library using the `Context` API with declarative settings in JSON format.

## Overview

The `Context` structure encapsulates configuration for:

- **Settings**: Configuration options for verification, signing, network policies, builder behavior, etc.
- **HTTP resolvers**: Customizable sync and async HTTP clients for fetching remote manifests
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

### Limiting remote manifest responses

`verify.max_manifest_response_size` sets the maximum remote manifest response size
in **bytes**, independently for each `Context`. The default is **10 MiB**
(10,485,760 bytes). It applies when the `fetch_remote_manifests` feature is enabled.

For example, to allow responses up to 20 MiB:

```rust
use c2pa::{Context, Result};

fn main() -> Result<()> {
    let context = Context::new()
        .with_settings_value("verify.max_manifest_response_size", 20 * 1024 * 1024u64)?;
    Ok(())
}
```

Equivalent JSON configuration:

```json
{
  "verify": {
    "max_manifest_response_size": 20971520
  }
}
```

The value must be positive and no greater than the platform's `isize::MAX`.
Zero does not disable the limit. Responses whose advertised `Content-Length` or
actual body exceeds the configured limit return `Error::RemoteManifestFetch`;
responses exactly at the limit are accepted.

This limit is enforced after the HTTP resolver returns. It does **not** bound
resolver-internal buffering, including buffering in the built-in reqwest adapters.
It also does not bound downloads or allocations performed by language bindings
before their resolver callbacks return. For example, the C HTTP callback supplies
an already-buffered body, which is copied into Rust memory before Store checks it.
End-to-end protection requires the binding or HTTP adapter to enforce a limit
while receiving the response, before buffering or copying it.
Increasing it allows correspondingly larger Store allocations.

### Configuring HTTP request timeouts

`core.http_request_timeout_in_ms` sets the total time limit, in **milliseconds**, for
SDK HTTP requests: remote manifest fetches, OCSP fetches, CAWG `did:web` resolution and
settings-based remote signing. Time-stamp requests use their own settings (see below).
The default is **10,000 ms** (10 seconds). The value must be positive; zero does not
disable the timeout.

For example, to limit each request to two seconds:

```rust
use c2pa::{Context, Result};

fn main() -> Result<()> {
    let context = Context::new()
        .with_settings_value("core.http_request_timeout_in_ms", 2_000u64)?;
    Ok(())
}
```

Native built-in reqwest and ureq resolvers enforce the limit while receiving headers
and the response body. SDK-managed redirects share the same budget. A remote manifest
timeout returns `Error::RemoteManifestFetch`.

The limit is added by `Context::resolver()` and `Context::resolver_async()`, so custom
resolvers must honor the `c2pa::http::RequestTimeout` request extension. C and C++ HTTP
resolver callbacks receive the remaining limit as `C2paHttpRequest.timeout_ms` (0 means no
limit) and must apply it to their HTTP client; the SDK cannot interrupt a callback. The
browser-based reqwest resolver on WASM cannot enforce this timeout. Public
`SignerSettings::c2pa_signer()` and `SignerSettings::cawg_signer()` calls without a
`Context` use the default.

This is a per-request limit, not an overall deadline or cancellation mechanism for
reading an asset.

### Configuring time-stamp requests

A blocking time-stamp request is retried after a transient failure (no answer, a timeout,
or an HTTP 408, 429, 500, 502, 503 or 504 response), and each attempt has a time limit.
Three `core` settings control this, independently for each `Context`:

| Setting | Default | Meaning |
|---------|---------|---------|
| `time_stamp_request_attempts` | `3` | Attempts before the last error is returned; `1` disables retries. Must be at least 1. |
| `time_stamp_request_timeout_in_ms` | `10000` | Time limit of each attempt, applied by the built-in HTTP resolvers. Must be positive. |
| `time_stamp_retry_delay_in_ms` | `500` | Pause before the second attempt, doubled before each later one. |

For example, to try a slow time-stamp service once, for up to 30 seconds:

```rust
use c2pa::{Context, Result};

fn main() -> Result<()> {
    let context = Context::new()
        .with_settings_value("core.time_stamp_request_attempts", 1u32)?
        .with_settings_value("core.time_stamp_request_timeout_in_ms", 30_000u64)?;
    Ok(())
}
```

Equivalent JSON configuration:

```json
{
  "core": {
    "time_stamp_request_attempts": 1,
    "time_stamp_request_timeout_in_ms": 30000
  }
}
```

Async time-stamp requests are sent once, with the same per-attempt time limit.
Blocking requests on browser WASM are also sent once because that target cannot
sleep between attempts. Native and WASI blocking requests honor the retry settings.

Signing passes the caller's `Context` through to the timestamp provider, including custom
HTTP resolvers and network policy. Redirects share one attempt's timeout budget rather
than restarting it at each hop. Native reqwest and ureq enforce the timeout while receiving
headers and the response body. Browser-based reqwest on WASM does not support this timeout;
other/custom resolvers must enforce the `RequestTimeout` request extension themselves.

### Breaking timestamp API migration

`Signer::send_timestamp_request`, `AsyncSigner::send_timestamp_request`,
`TimeStampProvider::send_time_stamp_request`, and `AsyncTimeStampProvider::send_time_stamp_request`
now take `context: &Context` after `message: &[u8]`. Update custom implementations and
forward this same context when delegating; their dispatch and header/body hooks are unchanged.
Detached `sign_claim`/`sign_claim_async` now take `&Context` instead of `&Settings`.
Construct the context with your settings and resolver once and pass it through rather
than creating a default context inside a timestamp override.

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

When the manifest JSON omits `claim_generator_info` (or uses `[]`), `Builder` resolves it at claim time: first from `builder.claim_generator_info` in the settings you passed to `Context` (as in the `json!` above, if you set that field), otherwise the library default.

## Settings definition

The `Settings` definition has the following top-level structure:

```json
{
  "version": 1,
  "trust": { ... },
  "core": { ... },
  "verify": { ... },
  "builder": { ... },
  "signer": { ... },
  "cawg_x509_signer": { ... },
  "soft_binding": { ... }
}
```

> [!NOTE]
> All properties are optional. If you do not specify a value, the SDK will use the default value, if any.
> If you specify a value of `null`, then the property will be set to `null`, not the default.
> Do not quote Boolean property values (for example, use `true` not `"true"`).

For a complete reference to all the `Settings` properties, see the [SDK object reference: Settings](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema).

| Property | Description |
|----------|-------------|
| `version` | Settings format version (integer). The default and only supported value is 1. |
| [`builder`](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#buildersettings) | Configuration for [Builder](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html). |
| [`cawg_x509_signer`](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#signersettings) | Configuration for the [CAWG x.509 signer](https://docs.rs/c2pa/latest/c2pa/struct.Settings.html#structfield.signer). |
| [`core`](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#core) | Configuration for core features. |
| [`signer`](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#signersettings) | Configuration for the base [C2PA signer](https://docs.rs/c2pa/latest/c2pa/struct.Settings.html#structfield.signer). |
| [`trust`](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#trust) | Configuration for C2PA claim generator trust lists, CAWG trust lists & TSA time-stamp trust lists |
| [`verify`](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#verify) | Configuration for verification (validation). |
| [`soft_binding`](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#soft_binding)  | Configure allowed set of soft bindings |

### Default configuration

Here's the `Settings` JSON with all default values:

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
  "cawg_x509_signer": null,
  "core": {
    "merkle_tree_chunk_size_in_kb": null,
    "merkle_tree_max_proofs": 5,
    "backing_store_memory_threshold_in_mb": 512,
    "decode_identity_assertions": true,
    "allowed_network_hosts": null,
    "max_decompressed_manifest_size_in_mb": 32,
    "time_stamp_request_attempts": 3,
    "time_stamp_request_timeout_in_ms": 10000,
    "time_stamp_retry_delay_in_ms": 500,
    "http_request_timeout_in_ms": 10000
  },
  "signer": null,
  "trust":{ 
    "anchors": [
        {
          "trust_uri": null,
          "trust_kind": "manifest"
          "trust_anchors": null,
          "trust_config": null,
          "allowed_list": null,
          "trusted_ica_issuers": null
        }
    ]
    "trust_config": null,
    "use_default_ekus": true
  },
  "verify": {
    "verify_after_reading": true,
    "verify_after_sign": true,
    "verify_trust": true,
    "verify_timestamp_trust": true,
    "ocsp_fetch": false,
    "ocsp_fetch_should_override": false,
    "remote_manifest_fetch": true,
    "max_manifest_response_size": 10485760,
    "skip_ingredient_conflict_resolution": false,
    "strict_v1_validation": false
  },
  "soft_binding": {
      "soft_binding_algorithms": [
        "com.digimarc.validate.1",
        "org.atsc.a336",
        "io.iscc.v0",
        "com.adobe.trustmark.Q",
        "com.adobe.trustmark.C",
        "com.adobe.icn.dense",
        "ai.steg.api",
        "..."
      ]
  }
}
```

### OCSP fetch response budget

Sync and async OCSP fetching accept at most **1,000,000 response-body bytes**
per responder, preserving the existing fetch-byte budget. The SDK ignores
`Content-Length` when allocating and reading OCSP bodies, including missing,
malformed, conflicting, or inaccurate lengths. A small body is not rejected
merely because its advertised length exceeds the budget.

The SDK reads at most **1,000,001 bytes** from each successful HTTP response body
to detect overflow. It never returns a truncated prefix as a successful response.
An oversized body is discarded and logged, and fetching can try the next AIA
responder in order, honoring the progress/cancellation callback before each
request. If no response can be fetched, existing OCSP-inaccessible reporting and
fallback to other usable OCSP sources remain in effect; an oversized response
does not establish certificate status.

Response-vector capacity requests grow only with bytes actually read and never
exceed **1,000,000 bytes**; the reader also uses an **8192-byte stack buffer**.
These are per-response SDK bounds, not a bound on allocator overhead or transient
memory during reallocation. They do not bound buffering performed inside a
built-in or custom HTTP resolver before returning its body, network framing
bytes, request count, elapsed time, or OCSP verification work. Resolvers remain
responsible for their own buffering and may enforce stricter limits.

This is a fixed fetch-side budget, not a new setting or a verification-side
limit on stapled or certificate-status assertion responses. Verification-side
resource budgeting is tracked separately in [#3026](https://github.com/contentauth/c2pa-rs/issues/3026).

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

By default, `trust.use_default_ekus` is `true`: the built-in EKUs, including
`c2pa-kp-claimSigning`, remain enabled and `trust.trust_config` adds to them.
To restrict claim signers to a configured set, set `trust.use_default_ekus` to
`false` and supply the accepted OIDs in `trust.trust_config`. An empty or absent
configuration with defaults disabled retains legacy emailProtection acceptance;
it does not enable claimSigning or documentSigning. This includes empty or
comment-only lists after parsing; an empty list is not a deny-all policy.

Claim signing, timestamping, and OCSP response signing are separate purposes
([C2PA certificate trust chain requirements](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_certificate_trust_chain)).
The SDK applies the following role rules in addition to the shared certificate
profile, certificate validity, cryptographic signature, and chain checks:

| Role | Allowed/required EKUs |
|---|---|
| Claim signer | At least one effective configured claim EKU. Built-in claim purposes are emailProtection, documentSigning, Microsoft C2PA signing (`1.3.6.1.4.1.311.76.59.1.9`), and c2pa-kp-claimSigning (`1.3.6.1.4.1.62558.2.1`). Alternate configured purposes remain supported; claimSigning is not universally required. timeStamping and OCSPSigning are always rejected, even when explicitly configured. |
| TSA | Must contain timeStamping (`1.3.6.1.5.5.7.3.8`) and no other purpose. A claim EKU cannot substitute for it. |
| Delegated OCSP responder | Must contain OCSPSigning (`1.3.6.1.5.5.7.3.9`) and no other purpose, and satisfy responder authorization. A claim EKU cannot substitute for it. |
| Issuer-signed OCSP response | Uses the existing issuing-CA authorization path, not the delegated end-entity EKU rule. The issuer must be the authorized issuer of the certificate whose status is being reported. |

`anyExtendedKeyUsage` and mixed-purpose certificates containing timeStamping or
OCSPSigning remain invalid under the shared profile. These rules apply regardless
of claim-signing EKU configuration; disabling default EKUs does not disable TSA or
delegated OCSP mandatory-purpose enforcement.

For manifest anchors, `trust.anchors[].trust_config` adds EKUs to the top-level
effective set **only for that anchor set**. Both OpenSSL and Rust-native validation
select eligible anchor sets before building a trusted path: an addition on an
unrelated anchor cannot authorize the same purpose through another anchor. An
absent or empty per-anchor list adds nothing. With defaults disabled and no valid
top-level or per-anchor EKUs, the legacy emailProtection fallback still applies.
An anchor-specific addition cannot opt specialty certificates into claim signing.

**Compatibility and migration:** earlier SDK versions allowed timeStamping-only
or OCSPSigning-only certificates to pass the claim-signer EKU check. They now fail
claim signing and claim validation with `signingCredential.invalid`, including
when explicitly configured or present in private credential storage. Reissue
claim-signing credentials with an accepted claim purpose; do not reuse TSA or
OCSP responder keys. Existing claimSigning, emailProtection, documentSigning,
Microsoft C2PA signing, and configured alternate-purpose credentials retain their
EKU acceptance. Per-anchor-only additions now work with Rust-native validation,
and OpenSSL no longer trusts a chain through an anchor whose effective EKU policy
excludes the leaf.

Accepting an EKU does not install a trust anchor, make a certificate trusted,
change private-credential association, or bypass validity or revocation checking.
CAWG identities use their separate identity policy: documentSigning and interim
S/MIME policy/cutoff and associated-timestamp rules are unchanged. Claim-role
exclusions are not imposed globally on CAWG identity certificates or on the
shared certificate-profile API.

These call sites use an explicit certificate role independently of trust-anchor
association. The long-term CAWG identity-purpose and post-interim migration policy
is tracked separately in [#3077](https://github.com/contentauth/c2pa-rs/issues/3077);
this change does not tighten CAWG acceptance of configured or specialty purposes.

At claim validation, a reported claim-signer EKU rejection produces
`signingCredential.invalid` without a synthetic `claimSignature.mismatch`;
genuine cryptographic signature failures still report the mismatch status.

When `verify.verify_timestamp_trust` is enabled, a TSA certificate that fails its
profile checks (including a missing or incorrect timeStamping EKU) causes the
timestamp to be rejected with informational `timeStamp.untrusted` diagnostics.
It does not produce claim-signer `signingCredential.invalid` failures. The claim
signer is evaluated independently at the current time if no other valid timestamp
is available; a rejected timestamp cannot rescue an expired signer or establish
a trusted signing time for CAWG identity assertions. Claim-signature, certificate,
revocation, and trust failures are still reported independently.

```json
{
  "version": 1,
  "trust": {
      "anchors": [
          {
            "trust_anchors": "-----BEGIN CERTIFICATE-----\n...",
            "trust_config": "1.3.6.1.5.5.7.3.4\n1.3.6.1.5.5.7.3.36",
            "trust_kind": "manifest",
            "trust_uri": "https://c2pa-rs/test_cert_trust_list",
            "trusted_ica_issuers": ["did:jwk:eyJhbGciOiJFZERTQSIs..."]
          }
      ],
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
  },
  "soft_binding": {
      "soft_binding_algorithms": [
        "com.digimarc.validate.1",
        "org.atsc.a336",
        "io.iscc.v0",
        "com.adobe.trustmark.Q",
        "com.adobe.trustmark.C",
        "com.adobe.icn.dense",
        "ai.steg.api",
        "..."
      ]
  }
}
```

## Configuring signers

**In most cases, you don't need to explicitly set a signer on the `Context`**. Instead, configure signer settings in your configuration, and `Context` will create the signer automatically when you call `save_to_stream()` or `save_to_file()`.

### From settings

This is the recommended approach. Configure signer settings in the settings file, for example in JSON:

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

Then use it with `Builder`:

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

### Custom signer

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

**Local signer**: for local certificate and private key.

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

**Remote signer**: for remote signing services.

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

The `Context` API replaces the older thread-local `Settings` pattern. If you're migrating existing code, this section explains how the two approaches differ.

### Backwards compatibility

**Settings still works:** The `Settings` type and its configuration format remain unchanged. All your existing settings files (JSON or TOML) work with `Context` without modification.

**Key differences:**

| Aspect | Old Thread-Local Settings | New Context API |
|--------|---------------------|-----------------|
| Scope | Global, affects all operations | Per-operation, explicitly passed |
| Thread Safety | Not thread-safe | Thread-safe, shareable with `Arc` |
| Configuration | Set once per thread | Can have multiple configurations |
| Testability | Difficult (thread-local state) | Easy (isolated contexts) |

### Migration examples

**Old approach (removed):**
```rust
use c2pa::{Reader, Settings};

// This updates thread-local settings that affect subsequent operations.
Settings::from_toml(include_str!("settings.toml"))?;
let reader = Reader::from_stream("image/jpeg", stream)?;
```

**New approach with `Context`:**
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

`Context` wraps a `Settings` instance and uses it to:

1. **Create signers automatically**: When you call `context.signer()` or `builder.save_to_stream()`, the `Context` creates a signer from the `signer` field in `Settings` (if present).

2. **Configure HTTP resolvers**: The `Context` creates default HTTP resolvers (for fetching remote manifests) and applies the `core.allowed_network_hosts` setting from `Settings`.

3. **Control verification**: The `verify` settings control how manifests are validated.

4. **Configure builder behavior**: The `builder` settings control thumbnail generation, actions, and other manifest creation options.

The `Settings` format hasn't changed; only how you provide those settings has changed.
