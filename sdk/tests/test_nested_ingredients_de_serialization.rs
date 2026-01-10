// Copyright 2025 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use std::io::{Cursor, Seek};

use c2pa::{
    assertions::DigitalSourceType, settings::Settings, Builder, BuilderIntent, Reader, Result,
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
    let mut builder = Builder::from_json("{}")?;
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
    let mut builder = Builder::from_json("{}")?;
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
    let mut builder = Builder::from_json("{}")?;
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
    let mut builder = Builder::from_json("{}")?;
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
    let mut builder = Builder::from_json("{}")?;
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
    let mut builder = Builder::from_json("{}")?;
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
    let mut builder = Builder::from_json("{}")?;
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
    let mut builder = Builder::from_json("{}")?;
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
    let mut builder = Builder::from_json("{}")?;
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
        let mut builder = Builder::from_json("{}")?;
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
            "Should have ingredient at depth {}",
            level
        );

        let ingredient = &current_manifest.ingredients()[0];
        let expected_title = format!("Level {}", level);
        assert_eq!(
            ingredient.title(),
            Some(expected_title.as_str()),
            "Ingredient at level {} should have correct title",
            level
        );

        if level > 1 {
            let active_manifest_label = ingredient.active_manifest().unwrap_or_else(|| {
                panic!("Ingredient at level {} should have active manifest", level)
            });
            current_manifest = reader
                .get_manifest(active_manifest_label)
                .unwrap_or_else(|| panic!("Should be able to get manifest at level {}", level));
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
    let mut builder = Builder::from_json("{}")?;
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
    let mut builder = Builder::from_json("{}")?;
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
