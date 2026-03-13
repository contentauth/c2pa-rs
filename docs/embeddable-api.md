# Embeddable signing API

> [!WARNING]
> The embeddable signing API is for advanced use cases that require very low-level control.  Most users won't need it and can instead use the standard `Builder` methods.

The embeddable signing API provides direct control over how a C2PA manifest is embedded into an asset. Instead of letting the SDK manage everything by providing both the source and destination streams to `Builder::sign()`, you perform each step explicitly:

1. Create a placeholder.
2. Embed the placeholder yourself.
3. Hash the asset.
4. Sign the claim.
5. Patch the manifest in place.

This new, more generic API replaces the following `Builder` methods that will soon be deprecated:

- [`data_hashed_placeholder()`](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html#method.data_hashed_placeholder)
- [`sign_data_hashed_embeddable()`](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html#method.sign_data_hashed_embeddable) and [`sign_data_hashed_embeddable_async()`](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html#method.sign_data_hashed_embeddable_async)

<!--
- [`sign_box_hashed_embeddable()`](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html#method.sign_box_hashed_embeddable) and [`sign_box_hashed_embeddable_async()`](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html#method.sign_box_hashed_embeddable_async)
-->

## Why use the embeddable API

The original `Builder::sign()` handles the full pipeline internally:

```rust
// Old approach: SDK controls all I/O
let manifest_bytes = builder.sign(signer, format, &mut source, &mut dest)?;
```

That works well for simple cases but becomes a problem when:

- **You control the I/O pipeline.** Video transcoders, streaming ingest services, and other tools have their own asset-writing code. Transferring stream ownership to the SDK conflicts with that architecture.
- **The asset is too large to buffer.** The SDK's `sign()` may re-read large files. With the embeddable API, you can hash chunks as you write them and pass the results directly to the builder.
- **You need in-place patching.** Some formats store the manifest in a known location. After signing, only that location changes, allowing you to write only those bytes.

## Concepts

### Hard-binding modes

The embeddable API supports three hard-binding strategies, selected automatically based on format and settings:

| Mode | Assertion | Formats | Requires placeholder |
|------|-----------|---------|----------------------|
| [DataHash](#using-datahash-placeholder) | `DataHash` | JPEG, PNG, GIF, WebP, and others | Yes |
| [BmffHash](#using-bmffhash-placeholder) | `BmffHash` | MP4, video (BMFF containers), AVIF, HEIF/HEIC | Yes |

<!--
| [BoxHash](#using-boxhash-directly) | `BoxHash` | JPEG, PNG, GIF, WebP, and others | No |


To use `BoxHash` mode, enable `prefer_box_hash` in [Builder settings (`BuilderSettings`)](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#buildersettings). 
-->

These formats support chunk-based hashing. This mode inserts the manifest as an independent chunk so byte offsets of existing data are never disturbed, which removes the need for a pre-sized placeholder.

<!--
Enable `BoxHash` mode via settings:

```rust
let settings = Settings::new().with_toml(r#"
    [builder]
    prefer_box_hash = true
"#)?;
```
-->

### Placeholder sizing

When a placeholder is required, the SDK pre-sizes the JUMBF manifest based on its current state and records the target length internally. After signing, [`sign_embeddable()`](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html#method.sign_embeddable) pads the compressed manifest to exactly that length so you can overwrite the placeholder bytes without shifting any other data in the file.

## API summary

| Method | Description |
|--------|-------------|
| [`needs_placeholder`](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html#method.needs_placeholder) | Returns `true` when the format requires a pre-embedded placeholder before hashing. Always `true` for BMFF formats. Returns `false` <!-- when `prefer_box_hash` is enabled and the format supports `BoxHash`, or when --> a `BoxHash` assertion has already been added. |
| [`placeholder`](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html#method.placeholder) | Composes a placeholder manifest and returns it as format-specific bytes ready to embed (e.g., JPEG APP11 segments). Automatically adds the appropriate hash assertion (`BmffHash` for BMFF formats, `DataHash` for others). Stores the JUMBF length internally so `sign_embeddable()` can pad to the same size. |
| [`set_data_hash_exclusions`](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html#method.set_data_hash_exclusions) | Replaces the dummy exclusion ranges in the `DataHash` assertion with the actual byte offset and length of the embedded placeholder. Call after embedding placeholder bytes and before `update_hash_from_stream()`. |
| [`update_hash_from_stream`](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html#method.update_hash_from_stream) | Reads the asset and computes the hard-binding hash. Automatically selects the appropriate path based on format: `BmffHash` for BMFF (skips manifest box), `BoxHash` for chunk-based formats (creates assertion if needed), or `DataHash` (skips exclusion ranges). |
| [`set_bmff_mdat_hashes`](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html#method.set_bmff_mdat_hashes) | Provides pre-computed Merkle leaf hashes for `mdat` segments in BMFF assets. Use when your code already hashes `mdat` chunks during writing/transcoding to avoid re-reading large files. Call before `sign_embeddable()`. |
| [`sign_embeddable`](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html#method.sign_embeddable) | Signs the manifest and returns bytes ready to embed. For placeholder workflows, pads to match placeholder size for in-place patching. For BoxHash/direct workflows, returns bytes at natural size for appending as a new chunk. |

## Using the DataHash placeholder

Use this workflow for JPEG, PNG, and other common image formats (not BMFF formats).

For this workflow, make sure `prefer_box_hash` in [Builder settings](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#buildersettings) is `false` (the default).

```rust
use std::io::{Cursor, Seek, Write};
use c2pa::{Builder, HashRange};

// 1. Compose the placeholder — returns JPEG APP11 segments.
let placeholder_bytes = builder.placeholder("image/jpeg")?;

// 2. Construct the output, inserting the placeholder after the JPEG SOI marker.
let source_bytes = std::fs::read("input.jpg")?;
let insert_offset: u64 = 2;
let mut output: Vec<u8> = Vec::new();
output.extend_from_slice(&source_bytes[..insert_offset as usize]);
output.extend_from_slice(&placeholder_bytes);
output.extend_from_slice(&source_bytes[insert_offset as usize..]);
let mut stream = Cursor::new(output);

// 3. Tell the builder where the placeholder lives.
builder.set_data_hash_exclusions(vec![
    HashRange::new(insert_offset, placeholder_bytes.len() as u64),
])?;

// 4. Hash the asset (placeholder bytes are excluded from the hash).
builder.update_hash_from_stream("image/jpeg", &mut stream)?;

// 5. Sign — returned bytes are the same size as placeholder_bytes.
let final_manifest = builder.sign_embeddable("image/jpeg")?;

// 6. Overwrite the placeholder with the signed manifest.
stream.seek(std::io::SeekFrom::Start(insert_offset))?;
stream.write_all(&final_manifest)?;
```

## Using the BmffHash placeholder

Use this workflow with MP4 and other BMFF formats, which always require a placeholder. 

The SDK pre-allocates Merkle slots in the [`BmffHash` assertion](https://docs.rs/c2pa/latest/c2pa/assertions/struct.BmffHash.html).

```rust
// 1. Compose the placeholder — returns a BMFF `uuid` box suitable for insertion.
let placeholder_bytes = builder.placeholder("video/mp4")?;

// 2. Insert the placeholder box into the MP4 container at an appropriate location
//    (for example, before `mdat`). Your muxer/container writer controls this step.
let insert_offset = your_muxer.insert_manifest_box(&placeholder_bytes);

// 3. Hash the asset. BmffHash handles exclusion of the manifest box automatically.
builder.update_hash_from_stream("video/mp4", &mut your_stream)?;

// 4. Sign and patch in place.
let final_manifest = builder.sign_embeddable("video/mp4")?;
your_stream.seek(std::io::SeekFrom::Start(insert_offset))?;
your_stream.write_all(&final_manifest)?;
```

If you hash `mdat` segments at write time, pass the leaf hashes before signing:

```rust
// leaf_hashes is Vec<Vec<Vec<u8>>>: outer = tracks, middle = chunks, inner = hash bytes
builder.set_bmff_mdat_hashes(leaf_hashes)?;
let final_manifest = builder.sign_embeddable("video/mp4")?;
```

<!-- 

h2. Using BoxHash directly

Use this workflow when you don't need a placeholder. In this case, no placeholder is written; the manifest is appended as a new independent chunk after signing.

For this workflow, enable `prefer_box_hash` in [Builder settings](https://opensource.contentauthenticity.org/docs/manifest/json-ref/settings-schema#buildersettings). 

```rust
use c2pa::{Builder, Context, Settings};

let settings = Settings::new().with_toml(r#"
    [builder]
    prefer_box_hash = true
"#)?;
let context = Context::new().with_settings(settings)?.into_shared();
let mut builder = Builder::from_shared_context(&context);

// needs_placeholder returns false for BoxHash-capable formats.
assert!(!builder.needs_placeholder("image/jpeg"));

// No placeholder step. Hash the original asset directly.
let mut source = std::fs::File::open("input.jpg")?;
builder.update_hash_from_stream("image/jpeg", &mut source)?;

// Sign — returns composed bytes at their natural size.
let manifest_bytes = builder.sign_embeddable("image/jpeg")?;

// Append manifest_bytes as a new independent chunk in the asset.
// The exact mechanism depends on the format handler used by your embedding code.
```

-->