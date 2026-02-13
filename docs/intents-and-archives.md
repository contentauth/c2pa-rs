# Intents and archives

## Builder intents

Intents tell the C2PA `Builder` what kind of manifest you are creating. They enable validation, add required default actions, and help prevent invalid operations.

<div style={{display: 'none'}}>

**References**:

- [C2PA specification](https://spec.c2pa.org/specifications/specifications/2.1/index.html)
- [Rust library docs](https://opensource.contentauthenticity.org/docs/rust-sdk/)
- [GitHub repository](https://github.com/contentauth/c2pa-rs)
- [Content Credentials](https://contentcredentials.org/)

</div>

### Intent types

There are three types of intents:

- [**Create**](#create-intent): `BuilderIntent::Create(DigitalSourceType)`
- [**Edit**](#edit-intent): `BuilderIntent::Edit`
- [**Update**](#update-intent): `BuilderIntent::Update`

#### Create intent

Use `BuilderIntent::Create(DigitalSourceType)` for new digital creations without a parent ingredient.  This intent:

- Requires a `DigitalSourceType` (see below).
- Must not have a parent ingredient.
- Automatically adds a `c2pa.created` action if not provided.

Example:

```rust
let mut builder = Builder::from_shared_context(&context)
    .with_definition(manifest_def("New Image", "image/jpeg"))?;
builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
```

**Digital source types**

The value of `digitalSourceType` is one of the enum values [listed in the API documentation](https://docs.rs/c2pa/latest/c2pa/enum.DigitalSourceType.html) including the codes specified by the International Press Telecommunications Council (IPTC) [NewsCodes Digital Source Type scheme](https://cv.iptc.org/newscodes/digitalsourcetype/). For example:

- `Empty` - Blank canvas or zero-length content
- `DigitalCapture` - Captured from real-life using digital device
- `TrainedAlgorithmicMedia` - AI-generated media
- `TrainedAlgorithmicData` - AI-generated data (non-media formats)
- `CompositeCapture` - HDR and multi-frame processing

#### Edit intent

Us `BuilderIntent::Edit` for editing an existing asset (most common case). This intent:

- Requires a parent ingredient.
- Automatically derives the parent ingredient from the source stream if not provided.
- Automatically adds a `c2pa.opened` action linked to the parent.

Example:

```rust
builder.set_intent(BuilderIntent::Edit);
```

#### Update intent

Use `BuilderIntent::Update` for non-editorial (metadata-only) changes. It is a restricted version of the edit intent.  This intent:

- Allows exactly one ingredient (the parent).
- Does not allow changes to the parent’s hashed content.
- Is more compact than an edit intent.
- Is suitable for metadata-only updates.

Example:

```rust
builder.set_intent(BuilderIntent::Update);
```

## Archives for ingredients and builders

Many workflows need to pause and resume manifest authoring or reuse previously validated ingredients. An archive provides a standard way to save and restore this state and:

- Uses the standard JUMBF store (`application/c2pa`)
- Works for signed manifests, working stores, and saved ingredients
- Can be embedded in files, stored as sidecars (for example, `.c2pa`), or kept in cloud/database
- Unsigned working stores use placeholder signatures (`BoxHash`)
- Validate once, then can be reuses without re-validation

### Save and restore a Builder

Use `to_archive()` to save a `Builder`:

```rust
pub fn to_archive(&mut self, mut stream: impl Write + Seek) -> Result<()>
```

For example:

```rust
// Save
let mut archive = Cursor::new(Vec::new());
builder.to_archive(&mut archive)?;
std::fs::write("work.c2pa", archive.get_ref())?;
```

Use `from_archive` to restore an archive using the default `Context`.  Use `with_archive` to restore an archive using a custom shared `Context`:

```rust
pub fn from_archive(stream: impl Read + Seek + Send) -> Result<Self>
pub fn with_archive(self, stream: impl Read + Seek + Send) -> Result<Self>
```

```rust
// Restore (default context)
let builder = Builder::from_archive(Cursor::new(std::fs::read("work.c2pa")?))?;

// Or restore with a custom, shared context (see: docs/context.md)
let builder = Builder::from_shared_context(&context)
    .with_archive(Cursor::new(std::fs::read("work.c2pa")?))?;
```

Note: Archives contain placeholder signatures, so validation is skipped when loading them.

### Capture an ingredient as an archive and reuse it

```rust
// Capture and sign a C2PA-only archive (no embedded asset)
let signer = context.signer()?;
let ingredient_c2pa = builder.sign(
    signer,
    "application/c2pa",
    &mut io::empty(),
    &mut io::empty(),
)?;
```

This returns the raw C2PA manifest store as `Vec<u8>`.

Later, you can add that archived ingredient to a new manifest as follows:

```rust
let mut builder = Builder::from_shared_context(&context)
    .with_definition(manifest_def("New Work", FORMAT))?;
builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));

builder.add_ingredient_from_stream(
    json!({
        "title": "Archived Ingredient",
        "relationship": "componentOf",
        "label": "ingredient_1"
    })
    .to_string(),
    "application/c2pa",
    &mut Cursor::new(ingredient_c2pa),
)?;
builder.add_action(json!({
    "action": "c2pa.placed",
    "parameters": { "ingredientIds": ["ingredient_1"] }
}))?;
```

When you call `add_ingredient_from_stream()` with format `"application/c2pa"`, the API:

1. Reads the archive.
2. Extracts the first ingredient from the active manifest.
3. Merges with provided JSON properties, but your overrides take precedence.

## Best practices

1. [**Use intents**](intents-and-archives.md): Always set an intent to get automatic validation and action generation.
2. **Archive validated ingredients**: Save expensive validation results.
3. [**Use shared context**](context.md): Create once, share across operations.
4. **Label ingredients**: Use labels to link ingredients to actions.
5. **Store archives flexibly**: Files, databases, and cloud storage all work.

## Examples

- [`sdk/examples/builder_sample.rs`](https://github.com/contentauth/c2pa-rs/blob/main/sdk/examples/builder_sample.rs)
- [`sdk/examples/api.rs`](https://github.com/contentauth/c2pa-rs/blob/main/sdk/examples/api.rs)

Run the builder example:

```bash
cd sdk
cargo run --example builder_sample
```

<!-- This largely duplicated the section above; moved there, but the code is slightly different. Is it OK to combine the two?

Important technical details - Adding ingredients from archives

When you call `add_ingredient_from_stream()` with format `"application/c2pa"`, the API:

1. Reads the archive.
2. Extracts the first ingredient from the active manifest.
3. Merges with provided JSON properties. (Your overrides take precedence.)

```rust
builder.add_ingredient_from_stream(
    json!({
        "title": "New Title",           // Overrides archived title
        "relationship": "componentOf"   // Overrides archived relationship
    })
    .to_string(),
    "application/c2pa",
    &mut archived_stream,
)?;
```

For creating and sharing a `Context` (including using `Arc`), see: [Configuring the SDK using Context](context.md).

-->

## Common patterns

### Create new content

```rust
let mut builder = Builder::from_shared_context(&context)
    .with_definition(manifest_def("title", "image/jpeg"))?;
builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
```

### Edit existing content

```rust
builder.set_intent(BuilderIntent::Edit);
builder.add_ingredient_from_stream(
    json!({"title": "Original", "relationship": "parentOf", "label": "parent"}),
    "image/jpeg",
    &mut source_stream,
)?;
```

### Add archived ingredient

```rs
builder.add_ingredient_from_stream(
    json!({
        "title": "Ingredient",
        "relationship": "componentOf",
        "label": "ing_1"
    })
    .to_string(),
    "application/c2pa",
    &mut archived_ingredient_stream,
)?;
```

### Link ingredients to actions

```rs
builder.add_action(json!({
    "action": "c2pa.placed",
    "parameters": {
        "ingredientIds": ["ing_1"],  // References the label
    }
}))?;
```

## FAQs

**Can I use both old and new archive formats?**  

Yes. Archive loading auto-detects supported formats.

**Are archives signed?**

Working archives use placeholder signatures (BoxHash). Sign the final asset when ready.

**Can I modify an archived ingredient's properties?**

Yes. JSON properties passed to `add_ingredient_from_stream()` override archived values.

**Where should I store archives?**

Anywhere. Local files, S3, databases, and in-memory all work.

**Do I need different intents for different asset types?**

No. Intents are about the operation (create/edit/update), not the asset type.

**Can I have multiple parent ingredients?**

No. Only one parent is allowed. Other ingredients use different relationships (for example, `componentOf`, `inputTo`).
