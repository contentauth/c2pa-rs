# C2PA intents API and archives overview

## Builder intents API

### What are intents?

Intents tell the C2PA Builder what kind of manifest you are creating. They help the API validate your operations and automatically add required elements.

### Intent types

#### `BuilderIntent::Create(DigitalSourceType)`

For new digital creations without a parent ingredient.

##### Characteristics

- Requires a `DigitalSourceType` (`Empty`, `DigitalCapture`, `TrainedAlgorithmicMedia`, etc.)
- Must **not** have a parent ingredient
- Automatically adds `c2pa.created` action if not provided

##### Example

```rust
let mut builder = Builder::from_shared_context(&context)
    .with_definition(manifest_def("New Image", "image/jpeg"))?;
builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
```

#### `BuilderIntent::Edit`

For editing pre-existing parent assets (most common case).

##### Characteristics

- Requires a parent ingredient
- Auto-generates parent ingredient from source stream if not provided
- Automatically adds `c2pa.opened` action linked to parent

##### Example

```rust
builder.set_intent(BuilderIntent::Edit);
```

#### `BuilderIntent::Update`

A restricted version of `Edit` for non-editorial changes.

##### Characteristics

- Only one ingredient allowed (as parent)
- No changes can be made to hashed content of parent
- More compact than `Edit`
- Suitable for metadata-only updates

##### Example

```rust
builder.set_intent(BuilderIntent::Update);
```

### How intents work

From `sdk/src/builder.rs`:

```rust
/// An intent lets the API know what kind of manifest to create.
///
/// Intents are `Create`, `Edit`, or `Update`.
///
/// This allows the API to check that you are doing the right thing.
/// It can also do things for you, like add parent ingredients from
/// the source asset and automatically add required `c2pa.created` or
/// `c2pa.opened` actions.
pub fn set_intent(&mut self, intent: BuilderIntent) -> &mut Self {
    self.intent = Some(intent);
    self
}
```

### Digital source types

Available with `Create` intent:

- `Empty` - Blank canvas or zero-length content
- `DigitalCapture` - Captured from real-life using digital device
- `TrainedAlgorithmicMedia` - AI-generated media
- `TrainedAlgorithmicData` - AI-generated data (non-media formats)
- `CompositeCapture` - HDR and multi-frame processing
- And more...

---

## C2PA archives for ingredients and builders

### What problem do archives solve?

- Need to save and continue editing C2PA manifests
- C2PA spec only allows appending new signed manifests
- Many scenarios need work-in-progress functionality:
  - Validating an ingredient once and saving for later use
  - Applications tracking changes over time
  - Frequent small edits without creating long manifest chains

### The archive solution

- Uses standard JUMBF (`application/c2pa`) format
- Same format for signed manifests, working stores, and saved ingredients
- Can be embedded in files, stored in cloud, or saved as `.c2pa` sidecars
- Contains unsigned working stores (signed with `BoxHash` placeholder)
- Enables validation once, use many times

### Archive goals

1. **Save validated ingredients.** Add them to Builders later without re-validation
2. **Archive `Builder` state.** Save and restore work-in-progress manifests

---

## Working with archives

### Saving a `Builder` to archive

```rust
pub fn to_archive(&mut self, mut stream: impl Write + Seek) -> Result<()>
```

#### Example

```rust
// Create and populate builder.
let mut builder = Builder::from_shared_context(&context)
    .with_definition(manifest_def("My Work", "image/jpeg"))?;

// ... add ingredients, assertions, etc ...

// Save to archive.
let mut archive = Cursor::new(Vec::new());
builder.to_archive(&mut archive)?;

// Can save to file, database, cloud storage, etc.
std::fs::write("my_work.c2pa", archive.get_ref())?;
```

### Restoring a `Builder` from archive

```rust
pub fn from_archive(stream: impl Read + Seek + Send) -> Result<Self>
pub fn with_archive(self, stream: impl Read + Seek + Send) -> Result<Self>
```

#### Example

```rust
// Restore with default context.
let builder = Builder::from_archive(archive_stream)?;

// Or restore with custom context.
let context = Context::new().with_settings(settings)?;
let builder = Builder::from_shared_context(&context)
    .with_archive(archive_stream)?;
```

**Note:** Archives contain placeholder signatures, so validation is automatically skipped during loading.

## Complete workflow example

### Capturing an ingredient as archive

```rust
fn capture_ingredient<R>(
    format: &str, 
    stream: &mut R, 
    context: &Arc<Context>
) -> Result<Vec<u8>>
where
    R: Read + Seek + Send,
{
    let mut builder = Builder::from_shared_context(context);

    // Add the ingredient stream.
    builder.add_ingredient_from_stream(
        json!({
            "title": "Archived Ingredient",
            "relationship": "parentOf",
            "label": "test_ingredient"
        })
        .to_string(),
        format,
        stream,
    )?;
    
    // Add required action.
    builder.add_action(json!({
        "action": "c2pa.opened",
        "parameters": {
            "ingredientIds": ["test_ingredient"],
        }
    }))?;

    // Sign as C2PA-only (no embedded asset).
    let signer = context.signer()?;
    let output = builder.sign(
        signer,
        "application/c2pa",
        &mut io::empty(),
        &mut io::empty(),
    )?;

    Ok(output) // Returns Vec<u8> that can be saved anywhere.
}
```

### Using archived ingredients

```rust
// Capture and save ingredient.
let ingredient_c2pa = capture_ingredient(FORMAT, &mut ingredient_source, &context)?;
// Can save to file, blob storage, database, etc.

// Later: Create new builder and add archived ingredient.
let mut builder = Builder::from_shared_context(&context)
    .with_definition(manifest_def("New Work", FORMAT))?;
builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));

// Add the archived ingredient (format: "application/c2pa").
builder.add_ingredient_from_stream(
    json!({
        "title": "Restored Ingredient",
        "relationship": "componentOf",
        "label": "ingredient_1"
    })
    .to_string(),
    "application/c2pa",
    &mut Cursor::new(ingredient_c2pa),
)?;

// Link to action.
builder.add_action(json!({
    "action": "c2pa.placed",
    "parameters": {
        "ingredientIds": ["ingredient_1"],
    }
}))?;
```

### Archive and restore `Builder`

```rust
// Archive the builder.
let mut archive = Cursor::new(Vec::new());
builder.to_archive(&mut archive)?;

// Can save to disk for debugging.
// std::fs::write("archive_test.c2pa", archive.get_ref())?;

// Restore from archive.
archive.rewind()?;
let mut builder = Builder::from_shared_context(&context)
    .with_archive(&mut archive)?;

// Continue working - sign to final asset.
let mut source = Cursor::new(SOURCE_IMAGE);
let mut dest = Cursor::new(Vec::new());
builder.save_to_stream(FORMAT, &mut source, &mut dest)?;
```

---

## Key use cases

### Validate once, use many times

**Scenario:** You have an ingredient that's expensive to validate.

**Solution:**

1. Validate ingredient once with C2PA.
2. Save as `.c2pa` archive.
3. Store in file, cloud, or database.
4. Reuse in multiple manifests without re-validation.

**Benefits:**

- Improved performance
- Consistent validation results
- Portable across systems

### Work-in-progress manifests

**Scenario:** Application needs incremental manifest building.

**Solution:**

1. Build manifest with initial assertions and ingredients.
2. Archive current state with `to_archive()`.
3. User closes application.
4. Later: Restore and continue editing with `from_archive()`.
5. Add more ingredients/assertions.
6. Sign when ready.

**Benefits:**

- No long chains of signed manifests
- Better user experience
- Supports iterative workflows

### Use case 3: Ingredient libraries

**Scenario:** Content library with pre-validated assets.

**Solution:**

1. Create ingredient archive for each library asset.
2. Store archives with metadata in database.
3. Applications query library and retrieve archives.
4. Add archived ingredients to new manifests instantly.

**Benefits:**

- Centralized ingredient management
- Fast composition workflows
- Consistent provenance tracking

---

## Important technical details

### Adding ingredients from C2PA archives

When you call `add_ingredient_from_stream()` with format `"application/c2pa"`:

```rust
let reader = Reader::from_stream(format, stream)?;
builder.add_ingredient_from_stream(
    json!({"title": "Original", "relationship": "parentOf"}),
    "application/c2pa",
    &mut ingredient_archive_stream,
)?;
```

**The API automatically:**

1. Reads the archive.
2. Extracts the first ingredient from the active manifest.
3. Merges with provided JSON properties. (Your overrides take precedence.)

**Property Override Example:**

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

### Context management with `Arc`

Both `Builders` and `Readers` can use shared `Context`s for efficient sharing:

```rust
// Create shared context once.
let context = Context::new()
    .with_settings(settings)?
    .with_signer(signer)
    .into_shared();  // Wraps in Arc

// Share across multiple builders (cheap clone).
let builder1 = Builder::from_shared_context(&context);
let builder2 = Builder::from_shared_context(&context);
let reader = Reader::from_shared_context(&context);
```

**Benefits:**

- Thread-safe configuration
- Multiple configurations possible (unlike global settings)
- Efficient resource sharing
- Single signer/settings setup for multiple operations

### Signing C2PA-only manifests

To create an archive without embedding in an asset:

```rust
builder.sign(
    signer,
    "application/c2pa",    // Special format
    &mut io::empty(),      // No source asset
    &mut io::empty(),      // No destination asset
)?;
```

This returns the raw C2PA manifest store as `Vec<u8>`.

---

## Common Patterns Reference

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

### Archive `Builder`

```rust
let mut archive = Cursor::new(Vec::new());
builder.to_archive(&mut archive)?;
std::fs::write("work.c2pa", archive.get_ref())?;
```

### Restore `Builder`

```rust
let archive_data = std::fs::read("work.c2pa")?;
let builder = Builder::from_archive(Cursor::new(archive_data))?;
```

### Add archived ingredient

```rust
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

```rust
// Add ingredient with label.
builder.add_ingredient_from_stream(
    json!({"title": "Photo", "label": "photo_1"}),
    "image/jpeg",
    &mut stream,
)?;

// Reference in action.
builder.add_action(json!({
    "action": "c2pa.placed",
    "parameters": {
        "ingredientIds": ["photo_1"],  // References the label
    }
}))?;
```

---

## 8. Best practices

### Do's ✅

1. **Use intents.** Always set an intent to get automatic validation and action generation.
2. **Archive validated ingredients.** Save expensive validation results.
3. **Use shared context.** Create once, share across operations.
4. **Label ingredients.** Use labels to link ingredients to actions.
5. **Store archives flexibly.** Files, databases, and cloud storage all work.

### Don'ts ❌

1. **Don't mix intents.** Each `Builder` should have one clear intent.
2. **Don't skip actions.** Always link ingredients to appropriate actions.
3. **Don't re-validate archives.** Archives are pre-validated; trust them.
4. **Don't modify archive format.** Use standard `application/c2pa` format.
5. **Don't ignore errors.** Handle `Result` types properly.

---

## Demo code location

All examples shown are from the actual codebase:

- **Main example:** `sdk/examples/builder_sample.rs`
- **API example:** `sdk/examples/api.rs`
- **Builder source:** `sdk/src/builder.rs`
- **Intent definitions:** Lines 323-346
- **Archive methods:** Lines 1078-1182

### Run the example

```bash
cd sdk
cargo run --example builder_sample
```

---

## Summary

### Intents API

- **Three types:** Create, Edit, Update
- **Automatic validation** and action generation
- **Type-safe** manifest creation
- **Clear intent** communication in code

### Archives

- **Standard JUMBF format** (`application/c2pa`)
- **Save and restore** Builders
- **Capture validated ingredients** for reuse
- **Flexible storage** options
- **No proprietary formats**

### Together

- Build robust C2PA workflows
- Optimize performance with reusable ingredients
- Support iterative editing processes
- Maintain provenance across operations

---

## FAQ

**Q: Can I use both old and new archive formats?**
A: Yes, `from_archive()` tries old format first, then new format automatically.

**Q: Are archives signed?**
A: Archives use placeholder signatures (BoxHash). Sign the final asset when ready.

**Q: Can I modify an archived ingredient's properties?**
A: Yes, JSON properties passed to `add_ingredient_from_stream()` override archived values.

**Q: Where should I store archives?**
A: Anywhere. Local files, S3, databases, and in-memory all work.

**Q: Do I need different intents for different asset types?**
A: No, intents are about the operation (create/edit/update), not the asset type.

**Q: Can I have multiple parent ingredients?**
A: No, only one parent is allowed. Other ingredients use different relationships (componentOf, inputTo, etc.).

---

## Additional resources

- **C2PA specification:** https://c2pa.org/specifications/
- **Rust SDK docs:** https://opensource.contentauthenticity.org/docs/rust-sdk/
- **GitHub repository:** https://github.com/contentauth/c2pa-rs
- **Content Credentials:** https://contentcredentials.org/
