# Embeddable signing API

The embeddable signing API gives callers explicit control over how a C2PA manifest is embedded into an asset. Instead of handing both the source and destination streams to `Builder::sign()` and letting the SDK manage everything, you drive each step: create a placeholder, embed it yourself, hash the asset, sign, then patch the manifest in place.

This is a new, more generic api that replaces the older `Builder` methods. These will soon be deprecated:

`data_hashed_placeholder()`
`sign_data_hashed_embeddable()`
`sign_box_hashed_embeddable()`


## Why use the embeddable API

The original `Builder::sign()` handles the full pipeline internally:

```rust
// Old approach: SDK controls all I/O
let manifest_bytes = builder.sign(signer, format, &mut source, &mut dest)?;
```

That works well for simple cases but becomes a problem when:

- **You control the I/O pipeline.** Video transcoders, streaming ingest services, and other tools have their own asset-writing code. Handing ownership of the streams to the SDK conflicts with that architecture.
- **The asset is too large to buffer.** The SDK's `sign()` may re-read large files. With the embeddable API you can hash chunks as you write them and hand the results directly to the builder.
- **You need in-place patching.** Some formats store the manifest in a known location. After signing, only that location changes; you want to write exactly those bytes.

## Concepts

### Hard-binding modes

The embeddable API supports three hard-binding strategies, selected automatically based on format and settings:

| Mode | Assertion | Formats | Requires placeholder |
|------|-----------|---------|----------------------|
| DataHash | `DataHash` | JPEG, PNG, GIF, WebP, and others | Yes |
| BmffHash | `BmffHash` | MP4, video (BMFF containers) | Yes |
| BoxHash | `BoxHash` | JPEG, PNG, GIF, WebP, and others | No (Mode 2) |

`BoxHash` mode is selected when `prefer_box_hash` is enabled in `BuilderSettings` and the format supports chunk-based hashing. It inserts the manifest as an independent chunk so byte offsets of existing data are never disturbed, which removes the need for a pre-sized placeholder.

Enable `BoxHash` mode via settings:

```rust
let settings = Settings::new().with_toml(r#"
    [builder]
    prefer_box_hash = true
"#)?;
```

### Placeholder sizing

When a placeholder is required the SDK pre-sizes the JUMBF manifest based on its current state and records the target length internally. After signing, `sign_embeddable()` pads the compressed manifest to exactly that length so you can overwrite the placeholder bytes without shifting any other data in the file.

## API reference

### `needs_placeholder(format: &str) -> bool`

Returns `true` when the format requires a pre-embedded placeholder before hashing. Always `true` for BMFF formats. Returns `false` when `prefer_box_hash` is enabled and the format supports `BoxHash`, or when a `BoxHash` assertion has already been added.

Call this to decide whether to run the placeholder step or go straight to `update_hash_from_stream()`.

### `placeholder(format: &str) -> Result<Vec<u8>>`

Composes a placeholder manifest and returns it as format-specific bytes ready to embed (for example, JPEG APP11 segments for `image/jpeg`). Automatically adds the appropriate hash assertion:

- BMFF formats: `BmffHash` with Merkle slots pre-allocated.
- Other formats with `prefer_box_hash = false`: `DataHash` with dummy exclusion ranges.
- Other formats with `prefer_box_hash = true`: returns empty bytes; no assertion is added.
- You can use `application/c2pa` if you want the raw c2pa data not preformatted for anything else.

Stores the JUMBF length internally so `sign_embeddable()` can pad to the same size.

### `set_data_hash_exclusions(exclusions: Vec<HashRange>) -> Result<&mut Self>`

Replaces the dummy exclusion ranges in the `DataHash` assertion with the actual byte offset and length of the embedded placeholder. Call this after embedding the bytes returned by `placeholder()` and before calling `update_hash_from_stream()`.

```rust
builder.set_data_hash_exclusions(vec![HashRange::new(offset, length)])?;
```

### `update_hash_from_stream<R>(format: &str, stream: &mut R) -> Result<&mut Self>`

Reads the asset (placeholder may be already embedded) and computes the hard-binding hash. Selects the path automatically:

- `BmffHash` is present → hashes BMFF boxes, skipping the manifest box.
- `BoxHash` is present, or `prefer_box_hash = true` and format supports it → enumerates chunks and hashes each one; auto-creates a `BoxHash` assertion if one does not exist.
- Otherwise → reads the stream while skipping the exclusion ranges recorded in `DataHash`.

### `set_bmff_mdat_hashes(leaf_hashes: Vec<Vec<Vec<u8>>>) -> Result<()>`

Provides pre-computed Merkle leaf hashes for `mdat` segments in BMFF assets. Use this when your code already hashes `mdat` chunks as part of writing or transcoding, avoiding a second read of a potentially large file. Call before `sign_embeddable()`.

### `sign_embeddable(format: &str) -> Result<Vec<u8>>`

Signs the manifest and returns composed bytes ready to embed:

- **Mode 1 (placeholder workflow):** pads the signed JUMBF to exactly the length recorded by `placeholder()`. The returned bytes are the same size as the original placeholder and can overwrite it in place.
- **Mode 2 (BoxHash / direct):** returns composed bytes at their natural size. Embed them as a new independent chunk; no in-place patching is required.

## Workflow walkthroughs

### DataHash placeholder workflow (JPEG, PNG, and others)

Use this workflow when `prefer_box_hash` is `false` (the default) and the format is not BMFF.

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

### BmffHash placeholder workflow (MP4 and other BMFF formats)

BMFF formats always require a placeholder. The SDK pre-allocates Merkle slots in the `BmffHash` assertion.

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

### BoxHash direct workflow (no placeholder)

Enable `prefer_box_hash` in settings. No placeholder is written; the manifest is appended as a new independent chunk after signing.

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


