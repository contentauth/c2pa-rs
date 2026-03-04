# Archives

Many workflows need to pause and resume manifest authoring or reuse previously validated ingredients. An archive provides a standard way to save and restore this state and:

- Uses the standard JUMBF store (`application/c2pa`)
- Works for signed manifests, working stores, and saved ingredients
- Can be embedded in files, stored as sidecars (for example, `.c2pa`), or kept in cloud/database
- Unsigned working stores use placeholder signatures (`BoxHash`)
- Validate once, then can be reuses without re-validation

## Best practices

1. [**Use intents**](intents.md): Set an intent to get automatic validation and action generation.
2. **Archive validated ingredients**: Save expensive validation results.
3. [**Use shared context**](settings.md#when-to-use-context-sharing): Create once, share across operations.
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

<div style={{display: 'none'}}>

**References**:

- [C2PA specification](https://spec.c2pa.org/specifications/specifications/2.1/index.html)
- [Rust library docs](https://opensource.contentauthenticity.org/docs/rust-sdk/)
- [GitHub repository](https://github.com/contentauth/c2pa-rs)
- [Content Credentials](https://contentcredentials.org/)

</div>

## Common tasks

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

// Or restore with a custom, shared context (see: docs/settings.md)
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

This ensures:
- No long chains of signed manifests.
- Better user experience.
- Support for iterative workflows.

### Adding ingredients from archives

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

For creating and sharing a `Context` (including using `Arc`), see: [Configuring SDK settings](settings.md).

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

**Can I have multiple parent ingredients?**

No. Only one parent is allowed. Other ingredients use different relationships (for example, `componentOf`, `inputTo`).
