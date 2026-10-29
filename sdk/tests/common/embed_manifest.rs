use std::{fs::File, path::Path, sync::Arc};

use c2pa::{
    assertions::{c2pa_action, Action, Actions},
    Builder, Context, Reader, Result, Signer, ValidationState,
};

/// Sign the parent and PNG ingredient used by the embed-manifest integration test.
pub fn sign_embed_manifest(
    context: &Arc<Context>,
    signer: &dyn Signer,
    fixtures: &Path,
    output_path: &Path,
) -> Result<()> {
    let parent_path = fixtures.join("earth_apollo17.jpg");
    let ingredient_path = fixtures.join("libpng-test.png");

    // create a new Manifest
    let mut builder = Builder::from_shared_context(context);

    // allocate actions so we can add them
    let mut actions = Actions::new();

    // add an action assertion stating that we imported this file
    actions = actions.add_action(
        Action::new(c2pa_action::OPENED)
            .set_when("2015-06-26T16:43:23+0200")
            .set_parameter("name".to_owned(), "import")?
            .add_ingredient_id("apollo17")?,
    );

    let ingredient_json = serde_json::json!({
        "name": "Earth from Apollo 17",
        "description": "A photo of Earth taken from Apollo 17",
        "relationship": "parentOf",
        "label": "apollo17"
    });
    // set the parent ingredient
    let mut parent_file = std::fs::File::open(&parent_path)?;
    builder.add_ingredient_from_stream(
        ingredient_json.to_string(),
        "image/jpeg",
        &mut parent_file,
    )?;

    actions = actions.add_action(
        Action::new("c2pa.edit").set_parameter("name".to_owned(), "brightnesscontrast")?,
    );

    // add an action assertion stating that we imported this file
    actions = actions.add_action(
        Action::new(c2pa_action::EDITED)
            .set_parameter("name".to_owned(), "import")?
            .add_ingredient_id("apollo17")?,
    );

    let mut ingredient_file = std::fs::File::open(&ingredient_path)?;
    builder.add_ingredient_from_stream("{}", "image/png", &mut ingredient_file)?;

    builder.add_assertion(Actions::LABEL, &actions)?;

    // sign and embed into the target file
    builder.sign_file(signer, &parent_path, output_path)?;
    Ok(())
}

/// Read the signed asset and check the integration test's manifest expectations.
pub fn verify_embed_manifest(context: &Arc<Context>, path: &Path) -> Result<Reader> {
    let reader =
        Reader::from_shared_context(context).with_stream("image/jpeg", File::open(path)?)?;
    println!("{reader}");

    assert_ne!(
        reader.validation_state(),
        ValidationState::Invalid,
        "Signature or asset validation failed: {reader}"
    );
    let manifest = reader.active_manifest().expect("no manifest in store");
    assert!(manifest.title().is_some());
    assert_eq!(manifest.ingredients().len(), 2);
    Ok(reader)
}
