// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Example App showing how to work archive and restore Builders and ingredients.
use std::io::{Cursor, Read, Seek};

use anyhow::Result;
use c2pa::{
    settings::Settings, validation_results::ValidationState, Builder, DigitalSourceType, Reader,
};
use serde_json::json;

const INGREDIENT_IMAGE: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
const SOURCE_IMAGE: &[u8] = include_bytes!("../tests/fixtures/earth_apollo17.jpg");

fn manifest_def(title: &str, format: &str) -> String {
    json!({
        "title": title,
        "format": format,
        "claim_generator_info": [
            {
                "name": "c2pa test",
                "version": env!("CARGO_PKG_VERSION")
            }
        ]
    })
    .to_string()
}

/// Capture an ingredient from a stream and return the resulting manifest store as a Vec<u8>
///
/// This can be constructed using existing methods with a few tricks
fn capture_ingredient<R>(format: &str, stream: &mut R) -> Result<Vec<u8>>
where
    R: Read + Seek + Send,
{
    let mut builder = Builder::new();

    // we need to manually add the ingredient stream since it has a different format than the output .c2pa
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
    // add the opened action to ensure this is a valid manifest
    builder.add_action(json!(
        {
            "action": "c2pa.opened",
            "parameters": {
                "ingredientIds": ["test_ingredient"],
            }
        }
    ))?;

    // sign a c2pa only manifest store by using a null input stream and application/c2pa as the format.
    let mut null_stream = Cursor::new([]);
    let mut output = Cursor::new(Vec::new());
    builder.sign(
        &Settings::signer()?,
        "application/c2pa",
        &mut null_stream,
        &mut output,
    )?;

    Ok(output.into_inner())
}

fn main() -> Result<()> {
    let format = "image/jpeg";
    let ingredient_name = "Restored Ingredient";
    let mut ingredient_source = Cursor::new(INGREDIENT_IMAGE);

    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    // here we capture an ingredient with it's validation into a c2pa_data object.
    let ingredient_c2pa = capture_ingredient(format, &mut ingredient_source)?;
    // the ingredient_c2pa can be saved to a file or database or wherever you want to keep it
    // for this example we will just keep it in memory and add it to a new manifest

    // Now create a new builder and set the intent to create a new manifest store
    // we will add the ingredient as a componentOf relationship
    let mut builder = Builder::from_json(&manifest_def("Builder Sample", format))?;
    builder.set_intent(c2pa::BuilderIntent::Create(DigitalSourceType::Empty));

    // Now add our saved ingredient as a c2pa stream.
    // When the format is "application/c2pa" we will fetch the parent stream from the manifest.
    builder.add_ingredient_from_stream(
        json!({   // we can override any values in the saved ingredient here
            "title": ingredient_name,
            "relationship": "componentOf",// This relationship will override the one in the saved ingredient
            "label": "component_image"
        })
        .to_string(),
        "application/c2pa",
        &mut Cursor::new(ingredient_c2pa),
    )?;
    builder.add_action(json!(
        {
            "action": "c2pa.placed",
            "parameters": {
                "ingredientIds": ["component_image"],
            }
        }
    ))?;

    //println!("Builder: {builder}");

    // write the manifest builder to a zipped stream
    //let mut archive = Cursor::new(Vec::new());
    //builder.to_archive(&mut archive)?;

    // // write the zipped stream to a file for debugging
    // //let debug_path = format!("{}/../target/test.zip", env!("CARGO_MANIFEST_DIR"));
    // // std::fs::write(debug_path, zipped.get_ref())?;

    // // unzip the manifest builder from the zipped stream
    //archive.rewind()?;
    //let mut builder = Builder::from_archive(&mut archive)?;

    // Now we will sign a new image that will reference the previously captured ingredient
    let signer = Settings::signer()?;
    let mut source = Cursor::new(SOURCE_IMAGE);
    let mut dest = Cursor::new(Vec::new());
    builder.sign(&signer, format, &mut source, &mut dest)?;

    // read and validate the signed manifest store
    dest.rewind()?;

    let reader = Reader::from_stream(format, &mut dest)?;
    println!("{}", reader.json());
    assert_eq!(reader.validation_state(), ValidationState::Trusted);
    assert_eq!(
        reader.active_manifest().unwrap().ingredients()[0]
            .title()
            .unwrap(),
        ingredient_name
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use c2pa_macros::c2pa_test_async;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::*;

    use super::*;

    #[c2pa_test_async]
    async fn test_builder_sample() -> Result<()> {
        main()
    }
}
