# Proposed Public Claim / Store API

## Motivation

The current SDK has three high-level types that each maintain their own copy of the
underlying data:

- **`Builder`** holds a `ManifestDefinition`, converts it to `Claim` + `Store` at sign time
- **`Reader`** loads a `Store`, converts it to a `HashMap<String, Manifest>` for access
- **`Ingredient`** (public type) wraps an assertion with its own getters

Every layer involves a conversion step where the same data is reshaped into a parallel
representation. The goal of this redesign is allow bypassing those conversion layers and let
`Claim` and `Store` serve directly as a public API.

Asset_io in this model is not directly used by Claim or Store. 

Assertions that need assets work directly with them, including hard bindings, Ingredients,and Thumbnails.
---

## The Two Boundaries

**Asset-independent** — creating and signing a manifest requires no file I/O:

```
Claim::new(&context)  →  add assertions  →  Store::sign(claim)  →  Vec<u8> (JUMBF)
```

**Asset I/O** — reading, hashing, and embedding involve streams:

```
Ingredient::from_stream(...)  →  (Ingredient, Option<Store>)
BoxHash::from_stream(...)     →  BoxHash  (for hard binding)
jumbf_io::save_jumbf_to_stream(...)  →  write JUMBF into asset
```

---

## Public API Surface

### `Claim`

```rust
// Construction
Claim::new(context: &Context) -> Self

// Building
fn set_title(&mut self, title: Option<String>)
fn add_assertion(&mut self, assertion: &impl AssertionBase) -> Result<HashedUri>
fn add_action(&mut self, action: Action) -> Result<&mut Self>
fn add_claim_generator_info(&mut self, info: ClaimGeneratorInfo) -> &mut Self

// Reading
fn label(&self) -> &str
fn title(&self) -> Option<&String>
fn format(&self) -> Option<&str>
fn instance_id(&self) -> &str
fn version(&self) -> usize
fn alg(&self) -> &str
fn assertions(&self) -> &Vec<HashedUri>
```

### `Store`

```rust
// Signing (combines commit + sign, gets signer from claim's context)
fn sign(&mut self, claim: Claim) -> Result<Vec<u8>>

// Navigation
fn active_claim(&self) -> Option<&Claim>
fn active_label(&self) -> Option<&str>
fn claims(&self) -> Vec<&Claim>
fn get_claim(&self, label: &str) -> Option<&Claim>
fn is_embedded(&self) -> bool
fn remote_url(&self) -> Option<&str>
```

### `Ingredient` (asset I/O entry points)

```rust
// Load from an asset stream — validates and returns the store if one exists
fn from_stream(
    relationship: Relationship,
    format: &str,
    stream: impl Read + Seek + Send,
    context: &Context,
) -> Result<(Ingredient, Option<Store>)>

// Load from a detached manifest + asset stream
fn from_manifest_and_stream(
    relationship: Relationship,
    manifest_bytes: &[u8],
    format: &str,
    stream: impl Read + Seek + Send,
    context: &Context,
) -> Result<(Ingredient, Option<Store>)>
```

Validation results are on the `Ingredient` — `StatusTracker` does not appear in the
public API.

### Asset write policy

Every write operation on an asset needs to declare what to do with two independent
pieces of existing content: the JUMBF manifest and the remote manifest URL in XMP.
All other XMP content is always preserved.

```rust
/// What to do with the JUMBF manifest region when writing an asset.
pub enum ManifestWritePolicy {
    Remove,           // strip any existing JUMBF
    Embed(Vec<u8>),   // insert or replace with these bytes (also used for placeholder)
    Preserve,         // leave existing JUMBF untouched
}

/// What to do with the remote manifest URL in XMP when writing an asset.
pub enum RemoteUrlPolicy {
    Remove,           // strip the remote URL field from XMP
    Set(String),      // write or replace the remote URL field
    Preserve,         // leave existing remote URL field untouched
}

pub struct AssetWriteOptions {
    pub manifest: ManifestWritePolicy,
    pub remote_url: RemoteUrlPolicy,
    // all other XMP content is always preserved
}
```

The four signing scenarios map directly:

| Scenario | `manifest` | `remote_url` |
|---|---|---|
| Sidecar (no asset modification) | `Remove` | `Remove` |
| Cloud-only (remote URL, no embedded manifest) | `Remove` | `Set(url)` |
| Embedded manifest (local signing) | `Embed(jumbf)` | `Remove` |
| Both (cloud backup + embedded) | `Embed(jumbf)` | `Set(url)` |

The placeholder workflow uses `Embed(placeholder_bytes)` for the first write pass, then
`fill_placeholder` as an in-place overwrite that does not touch XMP.

### Asset I/O helpers

Two hard-binding strategies require different asset I/O sequences. Both are exposed as
distinct, composable calls rather than being hidden inside a single sign method.

**BoxHash** — hashes the structural boxes of the asset (JPEG, PNG, etc.). The manifest
box itself is not part of what gets hashed, so the input stream can be hashed directly
before embedding. Simpler but only supported by formats whose handler implements
`AssetBoxHash`.

```rust
// jumbf_io (already public)
fn save_jumbf_to_stream(format, source, dest, jumbf: &[u8]) -> Result<Vec<u8>>
```

The `save_jumbf_to_stream` call would accept `AssetWriteOptions` so callers control
XMP and remote URL handling alongside the JUMBF embedding.

**DataHash / BmffHash** — hashes the asset data around a reserved manifest slot.
The input cannot be hashed directly because the output must first be written with a
placeholder. Requires a two-pass sequence: write → hash → sign → fill.

```rust
// asset_io (proposed additions)
fn write_asset(format, source, dest, options: AssetWriteOptions) -> Result<()>
fn fill_placeholder(format, dest, jumbf: &[u8]) -> Result<()>

// DataHash / BmffHash (proposed)
fn from_stream(format, stream, alg) -> Result<Self>   // compute hash of prepared output
```

`write_asset` with `manifest: Embed(placeholder_bytes)` handles the first pass of the
placeholder workflow; `fill_placeholder` overwrites just the JUMBF region in-place
without touching XMP.

### Fragmented video (BMFF/CMAF)

Fragmented assets are a special case where the manifest lives in the init segment but
the hashed data is spread across an unbounded sequence of fragment streams. The model
is an incremental builder that accumulates fragment hashes one at a time, so that live
streaming is supported — `finish()` is called whenever signing is appropriate (end of
stream, periodic checkpoint, or triggered externally).

**Reading fragments:**

```rust
struct FragmentReader { ... }

impl FragmentReader {
    // Load the init segment (which carries the manifest)
    fn new(
        relationship: Relationship,
        format: &str,
        init_stream: impl Read + Seek + Send,
        context: &Context,
    ) -> Result<Self>

    // Add each fragment as it arrives — can be called any number of times
    fn add_fragment(&mut self, stream: impl Read + Seek + Send) -> Result<()>

    // Validate and produce the ingredient + store once all fragments are available
    fn finish(self) -> Result<(Ingredient, Option<Store>)>
}
```

**Writing/signing fragments:**

```rust
struct FragmentSigner { ... }

impl FragmentSigner {
    // Takes the claim being built; writes init segment with placeholder
    fn new(
        claim: Claim,
        format: &str,
        init_source: impl Read + Seek + Send,
        init_dest: impl Write + Read + Seek + Send,
    ) -> Result<Self>

    // Write each fragment to its output stream and accumulate its hash ranges.
    // Called once per fragment as they are produced — works for live streams.
    fn add_fragment(
        &mut self,
        source: impl Read + Seek + Send,
        dest: impl Write + Read + Seek + Send,
    ) -> Result<()>

    // Finalize the BmffHash, add it to the claim, sign, and fill the init segment
    // placeholder. For live streaming, called at a natural segment boundary or
    // checkpoint. Returns the signed JUMBF bytes for the caller to store or transmit.
    fn finish(self) -> Result<Vec<u8>>
}
```

Internally `FragmentSigner` follows the same placeholder → hash → sign → fill sequence
as the single-stream DataHash workflow, but the hash accumulates across `add_fragment`
calls rather than being computed from one stream. Signing still goes through
`Store::sign(claim)` — fragments don't change that contract.

**Live streaming notes:**

For truly continuous streams, `finish()` would be called at periodic boundaries to
produce a rolling manifest covering the segments signed so far. Segments produced after
a `finish()` would start a new `FragmentSigner` with a new claim referencing the
previous one as an ingredient. This gives a chain of time-bounded manifests rather than
a single manifest covering the entire stream — which is consistent with how C2PA
handles long-running content.

---

## Usage Examples

### 1. Sign a manifest without embedding (no asset)

Suitable for sidecar manifests or detached credentials.

```rust
let context = Context::new().with_settings(settings_json)?;

let mut claim = Claim::new(&context);
claim.add_action(
    Action::new(c2pa_action::CREATED)
        .set_source_type(DigitalSourceType::TrainedAlgorithmicMedia)
)?;

let mut store = Store::new();
let jumbf_bytes = store.sign(claim)?;

// jumbf_bytes can be stored alongside the asset or transmitted separately
```

### 2a. Sign and embed — BoxHash binding

Supported by formats whose handler implements `AssetBoxHash` (JPEG, PNG, GIF, JPEG XL).
The manifest box is structurally separate from the hashed boxes, so the input can be
hashed directly and the signed JUMBF inserted afterwards without invalidating the hash.

```rust
let context = Context::new().with_settings(settings_json)?;

let mut claim = Claim::new(&context);
claim.add_action(Action::new(c2pa_action::CREATED))?;

// Step 1 (asset I/O): hash the asset's structural boxes
let box_hash = BoxHash::from_stream(&mut source, format, claim.alg(), true)?;
claim.add_assertion(&box_hash)?;

// Step 2 (pure): sign
let mut store = Store::new();
let jumbf_bytes = store.sign(claim)?;

// Step 3 (asset I/O): embed JUMBF into the output stream
jumbf_io::save_jumbf_to_stream(format, &mut source, &mut dest, &jumbf_bytes)?;
```

### 2b. Sign and embed — DataHash binding (placeholder workflow)

Required for formats where the manifest is embedded in the data region (most raster
formats). The hash must cover the output stream with the manifest slot already present,
so the sequence is: write placeholder → hash output → sign → fill placeholder.

```rust
let context = Context::new().with_settings(settings_json)?;

let mut claim = Claim::new(&context);
claim.add_action(Action::new(c2pa_action::CREATED))?;

// Step 1 (asset I/O): copy input to output with a reserved manifest placeholder
// The placeholder size is determined by the signer's reserve_size
let signer = context.signer()?;
asset_io::write_placeholder(format, &mut source, &mut dest, signer.reserve_size())?;

// Step 2 (asset I/O): compute DataHash over the output stream
// This hashes the asset data, treating the placeholder region as excluded
let data_hash = DataHash::from_stream(format, &mut dest, claim.alg())?;
claim.add_assertion(&data_hash)?;

// Step 3 (pure): sign — now that the hash assertion is present
let mut store = Store::new();
let jumbf_bytes = store.sign(claim)?;

// Step 4 (asset I/O): overwrite the placeholder with the signed JUMBF
asset_io::fill_placeholder(format, &mut dest, &jumbf_bytes)?;
```

The asset I/O steps are distinct calls so callers retain control over the streams at
each stage. The signing step (3) is always pure regardless of binding strategy.

### 3. Read and validate an asset

The `Ingredient` carries validation results. The `Store` lets you navigate the
full provenance chain.

```rust
let context = Context::new();

let (ingredient, store) = Ingredient::from_stream(
    Relationship::ParentOf,
    format,
    &mut stream,
    &context,
)?;

// Validation is on the ingredient — no StatusTracker needed
if let Some(results) = &ingredient.validation_results {
    println!("validation state: {:?}", results.validation_state());
}

// Navigate the claim graph if needed
if let Some(store) = store {
    let claim = store.active_claim().unwrap();
    println!("active manifest: {}", claim.label());
    println!("title: {:?}", claim.title());

    for uri in claim.assertions() {
        println!("assertion: {}", uri.url());
    }

    // Walk the full provenance chain
    for claim in store.claims() {
        println!("claim: {} (v{})", claim.label(), claim.version());
    }
}
```

### 4. Edit an existing asset (open → add action → re-sign)

```rust
let context = Context::new().with_settings(settings_json)?;

// Read the existing manifest
let (parent_ingredient, parent_store) = Ingredient::from_stream(
    Relationship::ParentOf,
    format,
    &mut source,
    &context,
)?;

// Build a new claim referencing the parent
let mut claim = Claim::new(&context);
let ingredient_uri = claim.add_assertion(&parent_ingredient)?;
claim.add_action(
    Action::new(c2pa_action::EDITED)
        .add_ingredient_id(&ingredient_uri.url())?
)?;

// Hash and sign
let box_hash = BoxHash::from_stream(&mut source, format, claim.alg(), true)?;
claim.add_assertion(&box_hash)?;

let mut store = parent_store.unwrap_or_default();
let jumbf_bytes = store.sign(claim)?;

jumbf_io::save_jumbf_to_stream(format, &mut source, &mut dest, &jumbf_bytes)?;
```

### 5. Validate a detached manifest against an asset

```rust
let context = Context::new();

let (ingredient, store) = Ingredient::from_manifest_and_stream(
    Relationship::ParentOf,
    &jumbf_bytes,
    format,
    &mut stream,
    &context,
)?;

println!("valid: {:?}", ingredient.validation_results);
```

### 6. Add a component ingredient (e.g. a placed image)

```rust
let context = Context::new().with_settings(settings_json)?;

let mut claim = Claim::new(&context);
claim.add_action(Action::new(c2pa_action::CREATED))?;

// Load the component asset as an ingredient
let (component, _store) = Ingredient::from_stream(
    Relationship::ComponentOf,
    component_format,
    &mut component_stream,
    &context,
)?;

let ingredient_uri = claim.add_assertion(&component)?;
claim.add_action(
    Action::new(c2pa_action::PLACED)
        .add_ingredient_id(&ingredient_uri.url())?
)?;

let box_hash = BoxHash::from_stream(&mut source, format, claim.alg(), true)?;
claim.add_assertion(&box_hash)?;

let mut store = Store::new();
let jumbf_bytes = store.sign(claim)?;
jumbf_io::save_jumbf_to_stream(format, &mut source, &mut dest, &jumbf_bytes)?;
```

---

## What Changes

| Current | Proposed |
|---|---|
| `Builder` builds `ManifestDefinition` → converts to `Claim`+`Store` | Work directly with `Claim` and `Store` |
| `Reader` loads `Store` → converts to `HashMap<String, Manifest>` | Load via `Ingredient::from_stream`, navigate `Store` directly |
| `Ingredient` (public type) wraps an assertion with getters | `Ingredient::from_stream` is the I/O entry point; result is an assertion |
| `StatusTracker` surfaces in load signatures | Validation is in `ingredient.validation_results` |
| `Store::from_stream`, `Store::from_manifest_data_and_stream` are public | These become `pub(crate)`; `Ingredient::from_stream` is the public path |

`Builder` and `Reader` remain for backward compatibility but are no longer the only
path, and their implementations can be simplified to delegate to `Claim`/`Store` directly.

---

## Open Questions

1. **`Store::sign(claim)` signature** — the claim carries the context (and thus the
   signer). Should sign fail clearly if the claim has no context, or should there be
   a `sign(claim, &context)` overload?

2. **`Store` for editing** — in example 4, `parent_store.unwrap_or_default()` reuses
   the loaded store so the provenance chain is preserved. Is this the right mental model,
   or should new claims always start with a fresh `Store::new()`?

3. **`Claim::assertions()`** — currently returns `&Vec<HashedUri>` (URIs only). Should
   there be a way to resolve an assertion from its URI directly on `Claim`, or does that
   require going through `Store`?
