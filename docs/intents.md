# Intents

_Intents_ tell the C2PA `Builder` what kind of manifest you are creating. They enable validation, add required default actions, and help prevent invalid operations.

You can use an intent for any asset type.  Intents are about the operation (create/edit/update), not the asset type.

<div style={{display: 'none'}}>

**References**:

- [C2PA specification](https://spec.c2pa.org/specifications/specifications/2.1/index.html)
- [Rust library docs](https://opensource.contentauthenticity.org/docs/rust-sdk/)
- [GitHub repository](https://github.com/contentauth/c2pa-rs)
- [Content Credentials](https://contentcredentials.org/)

</div>

## Intent types

There are three types of intents:

- [**Create**](#create-intent): `BuilderIntent::Create(DigitalSourceType)`
- [**Edit**](#edit-intent): `BuilderIntent::Edit`
- [**Update**](#update-intent): `BuilderIntent::Update`

### Create intent

Use `BuilderIntent::Create(DigitalSourceType)` for new digital creations without a parent ingredient.  This intent:

- Requires a `DigitalSourceType` (see below).
- Must not have a parent ingredient.
- Automatically adds a `c2pa.created` action if not provided.

For example:

```rust
let mut builder = Builder::from_shared_context(&context)
    .with_definition(r#"{"title": "New Image"}"#)?;
builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
```

**Digital source types**

The value of `digitalSourceType` is one of the enum values [listed in the API documentation](https://docs.rs/c2pa/latest/c2pa/enum.DigitalSourceType.html) including the codes specified by the International Press Telecommunications Council (IPTC) [NewsCodes Digital Source Type scheme](https://cv.iptc.org/newscodes/digitalsourcetype/). For example:

- `Empty` - Blank canvas or zero-length content
- `DigitalCapture` - Captured from real-life using digital device
- `TrainedAlgorithmicMedia` - AI-generated media
- `TrainedAlgorithmicData` - AI-generated data (non-media formats)
- `CompositeCapture` - HDR and multi-frame processing

### Edit intent

Use `BuilderIntent::Edit` for editing an existing asset (most common case). This intent:

- Requires a parent ingredient.
- Automatically derives the parent ingredient from the source stream if not provided.
- Automatically adds a `c2pa.opened` action linked to the parent.

For example:

```rust
builder.set_intent(BuilderIntent::Edit);
builder.add_ingredient_from_stream(
    json!({"title": "Original", "relationship": "parentOf", "label": "parent"}),
    "image/jpeg",
    &mut source_stream,
)?;
```

### Update intent

Use `BuilderIntent::Update` for non-editorial (metadata-only) changes. It is a restricted version of the edit intent.  This intent:

- Allows exactly one ingredient (the parent).
- Does not allow changes to the parent’s hashed content.
- Is more compact than an edit intent.
- Is suitable for metadata-only updates.

Example:

```rust
builder.set_intent(BuilderIntent::Update);
```

## Examples

- [`sdk/examples/builder_sample.rs`](https://github.com/contentauth/c2pa-rs/blob/main/sdk/examples/builder_sample.rs)
- [`sdk/examples/api.rs`](https://github.com/contentauth/c2pa-rs/blob/main/sdk/examples/api.rs)

Run the builder example:

```bash
cd sdk
cargo run --example builder_sample
```



