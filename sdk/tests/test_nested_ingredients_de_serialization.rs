// Copyright 2025 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use std::io::{Cursor, Seek};

use c2pa::{
    assertions::DigitalSourceType, settings::Settings, Builder, BuilderIntent, Ingredient, Reader,
    Result,
};

/// Test that nested ingredients are properly reconstructed from a manifest store
/// when undergoing multiple serialize-deserialize cycles.
///
/// This test creates a 3-level ingredient hierarchy:
/// - Base image (level 0)
/// - First edit with base as ingredient (level 1)
/// - Second edit with first edit as ingredient (level 2, so with nested ingredient)
#[test]
fn test_nested_ingredients_reconstruction_from_store() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    let format = "image/jpeg";
    let mut base_image = Cursor::new(include_bytes!("fixtures/no_manifest.jpg"));

    // Top level of nesting
    let mut level1_output = Cursor::new(Vec::new());
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    builder.sign(
        &Settings::signer()?,
        format,
        &mut base_image,
        &mut level1_output,
    )?;

    // Make level 1 an ingredient, so creates level 2
    // When using Edit intent, the source automatically becomes the parent ingredient
    level1_output.rewind()?;
    let mut level2_output = Cursor::new(Vec::new());
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);
    builder.sign(
        &Settings::signer()?,
        format,
        &mut level1_output,
        &mut level2_output,
    )?;

    // Make level 2 an ingredient, so creates level 3
    // When using Edit intent, the source automatically becomes the parent ingredient
    level2_output.rewind()?;
    let mut level3_output = Cursor::new(Vec::new());
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);
    builder.sign(
        &Settings::signer()?,
        format,
        &mut level2_output,
        &mut level3_output,
    )?;

    // Now read the level 3 output and verify nested ingredients are properly reconstructed
    level3_output.rewind()?;
    let reader = Reader::from_stream(format, &mut level3_output)?;

    // Verify we have an active manifest
    let active_manifest = reader
        .active_manifest()
        .expect("Should have active manifest");

    // Verify we have ingredients at level 3
    assert!(
        !active_manifest.ingredients().is_empty(),
        "Level 3 should have ingredients"
    );
    assert_eq!(
        active_manifest.ingredients().len(),
        1,
        "Level 3 should have exactly 1 ingredient"
    );

    // Get the level 2 ingredient (it will be the parent ingredient)
    let level2_ingredient = &active_manifest.ingredients()[0];

    // Verify that the level 2 ingredient has its own nested ingredient (level 1)
    let level2_active_manifest = level2_ingredient
        .active_manifest()
        .expect("Level 2 ingredient should have active manifest");
    let level2_manifest = reader
        .get_manifest(level2_active_manifest)
        .expect("Should be able to get level 2 ingredient's manifest");

    assert!(
        !level2_manifest.ingredients().is_empty(),
        "Level 2 ingredient's manifest should have its own ingredient (nested ingredient from level 1)"
    );
    assert_eq!(
        level2_manifest.ingredients().len(),
        1,
        "Level 2 ingredient should have exactly 1 nested ingredient"
    );

    // Verify the nested ingredient (level 1) is present as the parent of level 2
    assert!(
        !level2_manifest.ingredients().is_empty(),
        "Level 2's manifest should have at least one ingredient (level 1)"
    );

    Ok(())
}

/// Test that converting a Reader to Builder preserves nested ingredients.
#[test]
fn test_reader_to_builder_preserves_nested_ingredients() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    let format = "image/jpeg";
    let mut base_image = Cursor::new(include_bytes!("fixtures/no_manifest.jpg"));

    // Create a 3-level ingredient hierarchy
    let mut level1_output = Cursor::new(Vec::new());
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    builder.sign(
        &Settings::signer()?,
        format,
        &mut base_image,
        &mut level1_output,
    )?;

    base_image.rewind()?;
    level1_output.rewind()?;
    let mut level2_output = Cursor::new(Vec::new());
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);
    builder.add_ingredient_from_stream(
        serde_json::json!({"title": "L1"}).to_string(),
        format,
        &mut level1_output,
    )?;
    builder.sign(
        &Settings::signer()?,
        format,
        &mut base_image,
        &mut level2_output,
    )?;

    base_image.rewind()?;
    level2_output.rewind()?;
    let mut level3_output = Cursor::new(Vec::new());
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);
    builder.add_ingredient_from_stream(
        serde_json::json!({"title": "L2"}).to_string(),
        format,
        &mut level2_output,
    )?;
    builder.sign(
        &Settings::signer()?,
        format,
        &mut base_image,
        &mut level3_output,
    )?;

    // Read the level 3 output
    level3_output.rewind()?;
    let reader = Reader::from_stream(format, &mut level3_output)?;

    // Convert Reader to Builder
    let mut builder_from_reader = reader.into_builder()?;

    // Sign again to create a new manifest
    base_image.rewind()?;
    let mut level4_output = Cursor::new(Vec::new());
    builder_from_reader.sign(
        &Settings::signer()?,
        format,
        &mut base_image,
        &mut level4_output,
    )?;

    // Read the level 4 output and verify nested ingredients are preserved
    level4_output.rewind()?;
    let reader = Reader::from_stream(format, &mut level4_output)?;

    let active_manifest = reader
        .active_manifest()
        .expect("Should have active manifest");

    // Verify top-level ingredient exists
    assert!(!active_manifest.ingredients().is_empty());
    let level2_ingredient = &active_manifest.ingredients()[0];

    // Verify nested ingredient is preserved through Reader to Builder conversion
    let level2_active_manifest = level2_ingredient
        .active_manifest()
        .expect("Level 2 ingredient should have active manifest");
    let level2_manifest = reader
        .get_manifest(level2_active_manifest)
        .expect("Should be able to get level 2 ingredient's manifest");
    assert!(
        !level2_manifest.ingredients().is_empty(),
        "Nested ingredients should be preserved through Reader to Builder conversion"
    );

    Ok(())
}

/// Test that ingredient manifest_data properly includes nested ingredients.
#[test]
fn test_ingredient_manifest_data_includes_nested_ingredients() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    let format = "image/jpeg";
    let mut base_image = Cursor::new(include_bytes!("fixtures/no_manifest.jpg"));

    // Create a 2-level hierarchy
    let mut level1_output = Cursor::new(Vec::new());
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    builder.sign(
        &Settings::signer()?,
        format,
        &mut base_image,
        &mut level1_output,
    )?;

    base_image.rewind()?;
    level1_output.rewind()?;
    let mut level2_output = Cursor::new(Vec::new());
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);
    builder.add_ingredient_from_stream(
        serde_json::json!({"title": "Test ingredient"}).to_string(),
        format,
        &mut level1_output,
    )?;
    builder.sign(
        &Settings::signer()?,
        format,
        &mut base_image,
        &mut level2_output,
    )?;

    // Read and convert to Builder
    level2_output.rewind()?;
    let reader = Reader::from_stream(format, &mut level2_output)?;
    let builder = reader.into_builder()?;

    // Verify the ingredient has manifest_data in its own resources too
    let manifest_def = &builder.definition;
    assert!(!manifest_def.ingredients.is_empty());

    let ingredient = &manifest_def.ingredients[0];

    // The ingredient should have a manifest_data resource reference
    assert!(
        ingredient.manifest_data().is_some(),
        "Ingredient should have manifest_data"
    );

    // Verify the manifest_data is set and contains bytes
    let manifest_data_bytes = ingredient.manifest_data();
    assert!(
        manifest_data_bytes.is_some() && !manifest_data_bytes.unwrap().is_empty(),
        "Ingredient's manifest_data should contain valid bytes"
    );

    Ok(())
}

/// Test that deeply nested ingredients are properly handled.
#[test]
fn test_deeply_nested_ingredients() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    let format = "image/jpeg";
    let mut base_image = Cursor::new(include_bytes!("fixtures/no_manifest.jpg"));

    // Create a deeper ingredient hierarchy (5 levels)
    let mut current_output = Cursor::new(Vec::new());
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    builder.sign(
        &Settings::signer()?,
        format,
        &mut base_image,
        &mut current_output,
    )?;

    // Add more levels for the deep nesting
    for level in 1..=4 {
        base_image.rewind()?;
        current_output.rewind()?;
        let mut next_output = Cursor::new(Vec::new());
        let mut builder = Builder::new();
        builder.set_intent(BuilderIntent::Edit);
        builder.add_ingredient_from_stream(
            serde_json::json!({"title": format!("Level {}", level)}).to_string(),
            format,
            &mut current_output,
        )?;
        builder.sign(
            &Settings::signer()?,
            format,
            &mut base_image,
            &mut next_output,
        )?;
        current_output = next_output;
    }

    // Read the final output
    current_output.rewind()?;
    let reader = Reader::from_stream(format, &mut current_output)?;

    // Walk down the ingredient hierarchy and verify all levels are present
    let mut current_manifest = reader
        .active_manifest()
        .expect("Should have active manifest");

    for level in (1..=4).rev() {
        assert!(
            !current_manifest.ingredients().is_empty(),
            "Should have ingredient at depth {level}"
        );

        let ingredient = &current_manifest.ingredients()[0];
        let expected_title = format!("Level {level}");
        assert_eq!(
            ingredient.title(),
            Some(expected_title.as_str()),
            "Ingredient at level {level} should have correct title"
        );

        if level > 1 {
            let active_manifest_label = ingredient.active_manifest().unwrap_or_else(|| {
                panic!("Ingredient at level {level} should have active manifest")
            });
            current_manifest = reader
                .get_manifest(active_manifest_label)
                .unwrap_or_else(|| panic!("Should be able to get manifest at level {level}"));
        }
    }

    Ok(())
}

/// Test that empty/missing nested ingredients don't cause crashes or issues.
#[test]
fn test_ingredient_without_nested_ingredients() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    let format = "image/jpeg";
    let mut base_image = Cursor::new(include_bytes!("fixtures/no_manifest.jpg"));

    // Create a 2-level hierarchy (level 1 has no ingredients)
    let mut level1_output = Cursor::new(Vec::new());
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    builder.sign(
        &Settings::signer()?,
        format,
        &mut base_image,
        &mut level1_output,
    )?;

    base_image.rewind()?;
    level1_output.rewind()?;
    let mut level2_output = Cursor::new(Vec::new());
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);
    builder.add_ingredient_from_stream(
        serde_json::json!({"title": "Simple ingredient"}).to_string(),
        format,
        &mut level1_output,
    )?;
    builder.sign(
        &Settings::signer()?,
        format,
        &mut base_image,
        &mut level2_output,
    )?;

    // Read and verify...
    level2_output.rewind()?;
    let reader = Reader::from_stream(format, &mut level2_output)?;

    let active_manifest = reader
        .active_manifest()
        .expect("Should have active manifest");

    assert!(!active_manifest.ingredients().is_empty());
    let ingredient = &active_manifest.ingredients()[0];

    // This ingredient has no nested ingredients
    if let Some(active_label) = ingredient.active_manifest() {
        if let Some(ing_manifest) = reader.get_manifest(active_label) {
            assert!(
                ing_manifest.ingredients().is_empty(),
                "Simple ingredient should have no nested ingredients"
            );
        }
    }

    Ok(())
}

/// Helper to create a signed manifest and return the output bytes as a Cursor.
fn sign_manifest(
    builder: &mut Builder,
    format: &str,
    source: &mut Cursor<&[u8]>,
) -> Result<Cursor<Vec<u8>>> {
    let mut output = Cursor::new(Vec::new());
    source.rewind()?;
    builder.sign(&Settings::signer()?, format, source, &mut output)?;
    output.rewind()?;
    Ok(output)
}

/// Test diamond topology: two manifests share a common ancestor ingredient.
///
/// Topology:
///   A (base)
///   ├── B (has A as ingredient)
///   └── C (has A as ingredient)
///   D (has B and C as ingredients)
///
/// Both B and C reference A. D references both B and C.
/// Before the fix, reading D would cause exponential cloning of A's claim
/// because A appeared in both B's and C's ingredient trees.
#[test]
fn test_diamond_topology_read() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    let format = "image/jpeg";
    let mut source = Cursor::new(include_bytes!("fixtures/no_manifest.jpg").as_slice());

    // A: base manifest
    let mut builder_a = Builder::new();
    builder_a.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    let mut output_a = sign_manifest(&mut builder_a, format, &mut source)?;

    // B: has A as ingredient
    let mut builder_b = Builder::new();
    builder_b.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    output_a.rewind()?;
    builder_b.add_ingredient_from_stream(
        serde_json::json!({"title": "A via B"}).to_string(),
        format,
        &mut output_a,
    )?;
    let mut output_b = sign_manifest(&mut builder_b, format, &mut source)?;

    // C: also has A as ingredient (independent of B)
    let mut builder_c = Builder::new();
    builder_c.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    output_a.rewind()?;
    builder_c.add_ingredient_from_stream(
        serde_json::json!({"title": "A via C"}).to_string(),
        format,
        &mut output_a,
    )?;
    let mut output_c = sign_manifest(&mut builder_c, format, &mut source)?;

    // D: combines B and C (diamond — both share A as ancestor)
    let mut builder_d = Builder::new();
    builder_d.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    output_b.rewind()?;
    builder_d.add_ingredient_from_stream(
        serde_json::json!({"title": "B"}).to_string(),
        format,
        &mut output_b,
    )?;
    output_c.rewind()?;
    let mut ingredient_c = Ingredient::from_stream(format, &mut output_c)?;
    ingredient_c.set_title("C");
    builder_d.add_ingredient(ingredient_c);
    let mut output_d = sign_manifest(&mut builder_d, format, &mut source)?;

    // Read D — this must complete without exponential memory growth
    let reader = Reader::from_stream(format, &mut output_d)?;

    let active = reader
        .active_manifest()
        .expect("should have active manifest");
    // D has 2 ingredients (B and C)
    assert_eq!(active.ingredients().len(), 2, "D should have 2 ingredients");

    // Both B and C should reference manifests that each have A as an ingredient
    for ingredient in active.ingredients() {
        assert!(
            ingredient.manifest_data().is_some(),
            "Ingredient {:?} should have manifest_data populated",
            ingredient.title()
        );
        if let Some(label) = ingredient.active_manifest() {
            let manifest = reader
                .get_manifest(label)
                .unwrap_or_else(|| panic!("should find manifest for {label}"));
            assert_eq!(
                manifest.ingredients().len(),
                1,
                "B and C should each have 1 ingredient (A)"
            );
        }
    }

    Ok(())
}

/// Test mixed v2/v3 ingredient versions in a provenance chain.
///
/// claim_version=1 creates ingredient assertions with the `c2pa_manifest` field (v2 format).
/// Default claim_version (2) creates ingredient assertions with `active_manifest` (v3 format).
/// This verifies `build_ingredient_store` resolves both via the fallback chain.
#[test]
fn test_mixed_v2_v3_ingredient_versions() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    let format = "image/jpeg";
    let mut source = Cursor::new(include_bytes!("fixtures/no_manifest.jpg").as_slice());

    // A: base manifest (v1 claim so it can be an ingredient of both v1 and v2 claims)
    let mut builder_a = Builder::new();
    builder_a.definition.claim_version = Some(1);
    builder_a.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    let mut output_a = sign_manifest(&mut builder_a, format, &mut source)?;

    // B: claim_version=1 → v2 ingredient assertions (c2pa_manifest field)
    let mut builder_b = Builder::new();
    builder_b.definition.claim_version = Some(1);
    builder_b.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    output_a.rewind()?;
    builder_b.add_ingredient_from_stream(
        serde_json::json!({"title": "A via B"}).to_string(),
        format,
        &mut output_a,
    )?;
    let mut output_b = sign_manifest(&mut builder_b, format, &mut source)?;

    // C: default claim_version (2) → v3 ingredient assertions (active_manifest field)
    let mut builder_c = Builder::new();
    builder_c.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    output_a.rewind()?;
    builder_c.add_ingredient_from_stream(
        serde_json::json!({"title": "A via C"}).to_string(),
        format,
        &mut output_a,
    )?;
    let mut output_c = sign_manifest(&mut builder_c, format, &mut source)?;

    // D: combines B (v2 ingredients) and C (v3 ingredients)
    let mut builder_d = Builder::new();
    builder_d.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    output_b.rewind()?;
    builder_d.add_ingredient_from_stream(
        serde_json::json!({"title": "B"}).to_string(),
        format,
        &mut output_b,
    )?;
    output_c.rewind()?;
    let mut ingredient_c = Ingredient::from_stream(format, &mut output_c)?;
    ingredient_c.set_title("C");
    builder_d.add_ingredient(ingredient_c);
    let mut output_d = sign_manifest(&mut builder_d, format, &mut source)?;

    // Read D, convert to builder (exercises build_ingredient_store), re-sign as E
    let reader = Reader::from_stream(format, &mut output_d)?;
    let mut builder_e = reader.into_builder()?;
    builder_e.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    let mut output_e = sign_manifest(&mut builder_e, format, &mut source)?;

    // Read E and verify structure is preserved despite mixed ingredient versions
    let reader_e = Reader::from_stream(format, &mut output_e)?;
    let active_e = reader_e
        .active_manifest()
        .expect("E should have active manifest");

    assert_eq!(
        active_e.ingredients().len(),
        2,
        "E should have 2 ingredients after round-trip with mixed versions"
    );

    for ingredient in active_e.ingredients() {
        if let Some(label) = ingredient.active_manifest() {
            let manifest = reader_e
                .get_manifest(label)
                .unwrap_or_else(|| panic!("should find manifest for {label}"));
            assert_eq!(
                manifest.ingredients().len(),
                1,
                "Each ingredient should have 1 nested ingredient (A) despite mixed versions"
            );
        }
    }

    Ok(())
}

/// Test diamond topology through into_builder round-trip.
///
/// Same diamond shape as above, but additionally converts D's Reader
/// to a Builder and re-signs to verify the round-trip preserves structure.
#[test]
fn test_diamond_topology_into_builder_round_trip() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    let format = "image/jpeg";
    let mut source = Cursor::new(include_bytes!("fixtures/no_manifest.jpg").as_slice());

    // Build diamond: A -> B, A -> C, B+C -> D
    let mut builder_a = Builder::new();
    builder_a.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    let mut output_a = sign_manifest(&mut builder_a, format, &mut source)?;

    let mut builder_b = Builder::new();
    builder_b.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    output_a.rewind()?;
    builder_b.add_ingredient_from_stream(
        serde_json::json!({"title": "A via B"}).to_string(),
        format,
        &mut output_a,
    )?;
    let mut output_b = sign_manifest(&mut builder_b, format, &mut source)?;

    let mut builder_c = Builder::new();
    builder_c.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    output_a.rewind()?;
    builder_c.add_ingredient_from_stream(
        serde_json::json!({"title": "A via C"}).to_string(),
        format,
        &mut output_a,
    )?;
    let mut output_c = sign_manifest(&mut builder_c, format, &mut source)?;

    let mut builder_d = Builder::new();
    builder_d.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    output_b.rewind()?;
    builder_d.add_ingredient_from_stream(
        serde_json::json!({"title": "B"}).to_string(),
        format,
        &mut output_b,
    )?;
    output_c.rewind()?;
    let mut ingredient_c = Ingredient::from_stream(format, &mut output_c)?;
    ingredient_c.set_title("C");
    builder_d.add_ingredient(ingredient_c);
    let mut output_d = sign_manifest(&mut builder_d, format, &mut source)?;

    // Read D, convert to builder, re-sign as E
    let reader = Reader::from_stream(format, &mut output_d)?;
    let mut builder_e = reader.into_builder()?;
    // Prevent auto-capture of source as additional ingredient (test_settings has intent=edit)
    builder_e.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));
    let mut output_e = sign_manifest(&mut builder_e, format, &mut source)?;

    // Read E and verify structure is preserved
    let reader_e = Reader::from_stream(format, &mut output_e)?;
    let active_e = reader_e
        .active_manifest()
        .expect("E should have active manifest");

    // E should have the same 2 ingredients as D (B and C)
    assert_eq!(
        active_e.ingredients().len(),
        2,
        "E should have 2 ingredients after round-trip"
    );

    // Verify each ingredient still has its nested ingredient (A)
    for ingredient in active_e.ingredients() {
        if let Some(label) = ingredient.active_manifest() {
            let manifest = reader_e
                .get_manifest(label)
                .unwrap_or_else(|| panic!("should find manifest for {label}"));
            assert_eq!(
                manifest.ingredients().len(),
                1,
                "Each ingredient should still have 1 nested ingredient (A) after round-trip"
            );
        }
    }

    Ok(())
}
