
### Understanding `.c2pa` Format Usage

The `.c2pa` format is a C2PA manifest store that can be used in different ways:

- **Working Store/Builder Archive**: Contains a temporary active manifest that stores work-in-progress data, including unsigned claims and ingredient references
- **Saved Ingredient**: Contains a validated ingredient that can be incorporated into other manifests
- **Cloud Asset/Sidecar**: Standard C2PA format for storing manifest data separately from assets (as defined in the C2PA spec)

The difference between these use cases is not in the format itself, but in how the data is used and interpreted by the SDK. A cloud asset or sidecar is always signed with a hard binding to a given asset. A working store or saved ingredient is not yet bound to an asset. The active manifest in this case is a work in progress. 

## Working Stores

### What is a Working Store?

A working store (also called a builder archive) allows applications to gather actions and ingredients and save the data to be signed later. This is essential for workflows where:

- Content creation and signing happen at different times
- Multiple contributors add ingredients before final signing
- You want to checkpoint your work-in-progress

### Old Approach: ZIP Archives

Previously, builder archives were stored as ZIP files containing:
- JSON manifest definitions
- Binary assets (thumbnails, ingredient data)
- Folder structures that were difficult to maintain across API versions

```rust
// Old approach - ZIP-based archive (internal format)
let mut archive_file = std::fs::File::create("work-in-progress.zip")?;
builder.to_archive(&mut archive_file)?;

// Later, restore from ZIP
let archive_file = std::fs::File::open("work-in-progress.zip")?;
let builder = Builder::from_archive(archive_file)?;
```

### New Approach: `.c2pa` Working Store

The new format uses a C2PA manifest store with a temporary active manifest:

```rust
// New approach - .c2pa working store
let mut archive_file = std::fs::File::create("work-in-progress.c2pa")?;
builder.to_archive(&mut archive_file)?;

// Later, restore from .c2pa
let archive_file = std::fs::File::open("work-in-progress.c2pa")?;
let builder = Builder::from_archive(archive_file)?;
```

The `.c2pa` working store contains:
- All ingredient data and references
- Unsigned claim information
- Thumbnails and embedded resources
- The same information as the old ZIP format, but in a standardized structure

### Backward Compatibility

The SDK maintains backward compatibility:

```rust
// Old ZIP archives are still supported when reading
let old_zip = std::fs::File::open("legacy-archive.zip")?;
let builder = Builder::from_archive(old_zip)?; // Automatically detects format

// Configuration option to continue writing ZIP format if needed
let mut context = Context::new();
context.settings_mut().builder.generate_c2pa_archive = Some(false);
let mut builder = Builder::from_context(context);
builder.with_json(manifest_json)?;
let mut archive_file = std::fs::File::create("archive.zip")?;
builder.to_archive(&mut archive_file)?; // Creates ZIP if setting is disabled
```

## Saved Ingredients

### What is a Saved Ingredient?

A saved ingredient is a previously validated C2PA asset that you want to reuse in other manifests. Unlike working stores that contain unsigned data, saved ingredients typically contain:

- A complete, validated manifest store
- The parent ingredient from the original asset
- All necessary provenance information

### Creating a Saved Ingredient

To create a saved ingredient, add a single parent asset to a builder and archive it:

```rust
// Create a builder with a single parent ingredient
let mut builder = Builder::from_json(r#"
{
    "claim_generator_info": [
        {
            "name": "my-app",
            "version": "1.0"
        }
    ]
}
"#)?;

// Add the source asset as a parent ingredient
let mut source_file = std::fs::File::open("source.jpg")?;
builder.add_ingredient_from_stream(
    r#"{"relationship": "parentOf"}"#,
    "image/jpeg",
    &mut source_file
)?;

// Archive to create a saved ingredient
let mut ingredient_file = std::fs::File::create("saved-ingredient.c2pa")?;
builder.to_archive(&mut ingredient_file)?;
```

### Using a Saved Ingredient

To use a saved ingredient in a different builder, add it as an `application/c2pa` stream:

```rust
// Create a new builder for your final asset
let mut final_builder = Builder::from_json(r#"
{
    "claim_generator_info": [
        {
            "name": "my-app",
            "version": "1.0"
        }
    ]
}
"#)?;

// Add the saved ingredient
// The SDK automatically extracts the parent ingredient from the .c2pa data
let mut ingredient_file = std::fs::File::open("saved-ingredient.c2pa")?;
let ingredient = final_builder.add_ingredient_from_stream(
    r#"{"relationship": "componentOf"}"#,
    "application/c2pa",
    &mut ingredient_file
)?;
```

The SDK automatically:
- Locates the parent ingredient in the `.c2pa` manifest store
- Extracts all relevant provenance data
- Incorporates it into the new manifest with the specified relationship

## Migration Examples

### Before: Creating and Storing an Ingredient

```rust
// Old approach - multiple steps with folder-based storage
let mut ingredient = Ingredient::from_file("source.jpg")?;
ingredient.with_base_path("ingredients_folder")?;
// Ingredients stored as incomplete folder structures
// Hard to version and maintain
```

### After: Creating a Saved Ingredient

```rust
// New approach - create a builder and archive it
let mut builder = Builder::from_json(r#"
{
    "claim_generator_info": [
        {
            "name": "my-app",
            "version": "1.0"
        }
    ]
}
"#)?;

// Add the source asset
let mut source_file = std::fs::File::open("source.jpg")?;
builder.add_ingredient_from_stream(
    r#"{"relationship": "parentOf"}"#,
    "image/jpeg",
    &mut source_file
)?;

// Archive the builder - creates a complete .c2pa file
let mut archive_file = std::fs::File::create("source.c2pa")?;
builder.to_archive(&mut archive_file)?;
```

### Before: Reusing an Ingredient

```rust
// Old approach - load from folder structure
let ingredient = Ingredient::from_file_with_folder(
    "source.jpg", 
    "ingredients_folder"
)?;

builder.add_ingredient(ingredient, None)?;
```

### After: Reusing in the Same Builder

```rust
// New approach - restore the entire builder state
let archive_file = std::fs::File::open("source.c2pa")?;
let builder = Builder::from_archive(archive_file)?;

// All ingredients are automatically restored
// Continue working with the builder as it was
```

### After: Using in a Different Builder

```rust
// Add to any builder using the application/c2pa format
let mut new_builder = Builder::from_json(r#"
{
     "claim_generator_info": [
        {
            "name": "my-app",
            "version": "1.0"
        }
    ]
}
"#)?;

// The SDK automatically extracts the parent ingredient
let mut c2pa_file = std::fs::File::open("source.c2pa")?;
new_builder.add_ingredient_from_stream(
    "{}",
    "application/c2pa",
    &mut c2pa_file
)?;
```


## Complete Workflow Examples

### Example 1: Work-in-Progress Workflow

```rust
// Day 1: Start working on a project
let mut builder = Builder::from_json(manifest_json)?;
let mut photo1 = std::fs::File::open("photo1.jpg")?;
builder.add_ingredient_from_stream("{}", "image/jpeg", &mut photo1)?;
let mut photo2 = std::fs::File::open("photo2.jpg")?;
builder.add_ingredient_from_stream("{}", "image/jpeg", &mut photo2)?;

// Save work in progress
let mut wip_file = std::fs::File::create("project-wip.c2pa")?;
builder.to_archive(&mut wip_file)?;

// Day 2: Resume work
let wip_file = std::fs::File::open("project-wip.c2pa")?;
let mut builder = Builder::from_archive(wip_file)?;

// Add more ingredients
let mut photo3 = std::fs::File::open("photo3.jpg")?;
builder.add_ingredient_from_stream("{}", "image/jpeg", &mut photo3)?;

// Sign and finalize
builder.sign_file(signer, "output.jpg", "final.jpg")?;
```

### Example 2: Reusable Ingredient Library

```rust
// Create a library of validated ingredients
fn create_ingredient_library() -> Result<()> {
    let sources = vec!["logo.png", "watermark.png", "background.jpg"];
    
    for source in sources {
        let mut builder = Builder::from_json(r#"
        {
            "claim_generator_info": [
                {
                    "name": "ingredient-library",
                    "version": "1.0"
                }
            ]
        }
        "#)?;
        
        let mut source_file = std::fs::File::open(source)?;
        let format = if source.ends_with(".png") { "image/png" } else { "image/jpeg" };
        builder.add_ingredient_from_stream("{}", format, &mut source_file)?;
        
        let ingredient_name = format!("{}.c2pa", 
            Path::new(source).file_stem().unwrap().to_str().unwrap());
        let mut archive_file = std::fs::File::create(
            format!("ingredient-library/{}", ingredient_name)
        )?;
        builder.to_archive(&mut archive_file)?;
    }
    Ok(())
}

// Use ingredients from the library
fn use_library_ingredients() -> Result<()> {
    let mut builder = Builder::from_json(manifest_json)?;
    
    // Add main content
    let mut main_image = std::fs::File::open("main-image.jpg")?;
    builder.add_ingredient_from_stream("{}", "image/jpeg", &mut main_image)?;
    
    // Add library ingredients
    let mut logo_file = std::fs::File::open("ingredient-library/logo.c2pa")?;
    builder.add_ingredient_from_stream(
        "{}",
        "application/c2pa",
        &mut logo_file
    )?;
    
    let mut watermark_file = std::fs::File::open("ingredient-library/watermark.c2pa")?;
    builder.add_ingredient_from_stream(
        "{}",
        "application/c2pa",
        &mut watermark_file
    )?;
    
    builder.sign_file(signer, "output.jpg", "final.jpg")?;
    Ok(())
}
```

## Additional Resources

- [Builder API Documentation](../sdk/src/builder.rs)
- [C2PA Specification - Cloud Assets](https://c2pa.org/specifications/specifications/1.3/specs/C2PA_Specification.html#_cloud_data)
- [Ingredient Struct Documentation](../sdk/src/ingredient.rs)
- [Settings Configuration](settings.md)

## FAQ

**Q: Can I still read old ingredient folders?**  
A: Yes, you can read old ingredient folders by:
1. Add the ingredient JSON from the folder to your manifest definition's ingredients list
2. Either set the builder's `base_path` to the folder using `set_base_path()`, or
3. Add each asset file in the folder to the builder's resources using `add_resource()` with the filename as the identifier

Old ZIP archives will also continue to work with `Builder::from_archive()`.

**Q: What happens to my existing ZIP archives?**  
A: They will continue to work when reading with `Builder::from_archive()`. You can optionally configure the builder to keep writing ZIP format by setting `context.settings_mut().builder.generate_c2pa_archive = Some(false)`.

**Q: How do I convert existing ingredients to the new format?**  
A: If you have old ZIP archives, you can read them with `Builder::from_archive()`, then write them back out as `.c2pa` format (the default when `generate_c2pa_archive` is not set to `false`).

**Q: Can I mix old and new ingredients in the same builder?**  
A: Yes, builders accept ingredients from any source. The archive format is determined when you call `to_archive()`.

**Q: Is the `.c2pa` format the same as what's embedded in images?**  
A: Yes, it's the same C2PA manifest store format, but used differently. In images, it's embedded; for working stores and saved ingredients, it's standalone.

**Q: Do I need to change how I sign manifests?**  
A: No, signing remains the same. Only the way you create, store, and reuse ingredients changes.
