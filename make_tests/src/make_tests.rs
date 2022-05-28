// Copyright 2022 Adobe. All rights reserved.
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

//! Constructs a set of test images using a configuration script
//!
use anyhow::{Context, Result};

use c2pa::{
    assertions::{c2pa_action, Action, Actions, CreativeWork, SchemaDotOrgPerson},
    jumbf_io,
    openssl::temp_signer::get_signer_by_alg,
    Error, Ingredient, IngredientOptions, Manifest, ManifestStore,
};

use image::GenericImageView;
use nom::AsBytes;
use tempfile::tempdir;
use twoway::find_bytes;

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;

const IMAGE_WIDTH: u32 = 2048;
const IMAGE_HEIGHT: u32 = 1365;

#[derive(Debug, Deserialize)]
pub struct Recipe {
    pub op: String,
    pub parent: Option<String>,
    pub ingredients: Option<Vec<String>>,
    pub output: String,
}

/// Configuration
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    /// The signing algorithm to use
    pub alg: String,
    /// A url to a time stamp authority if desired
    pub tsa: Option<String>,
    /// The output folder for the generated files
    pub output_path: String,
    /// Extension to add to filenames if none was given
    pub default_ext: String,
    /// A name for a Creative Work Author assertion
    pub author: Option<String>,
    /// the list of recipes for test files
    pub recipes: Vec<Recipe>,
}

// Defaults for Config
impl Default for Config {
    fn default() -> Self {
        Self {
            alg: "ps256".to_owned(),
            tsa: Some("http://timestamp.digicert.com".to_owned()),
            output_path: "target/images".to_owned(),
            default_ext: "jpg".to_owned(),
            author: None,
            recipes: Vec::new(),
        }
    }
}

/// Tool for building test case images for C2PA
pub struct MakeTests {
    config: Config,
    output_dir: PathBuf,
}

impl MakeTests {
    pub fn new(config: Config) -> Self {
        let output = config.output_path.to_owned();
        Self {
            config,
            output_dir: PathBuf::from(output),
        }
    }

    /// Makes a full path from a filename or path
    ///
    /// If there is no parent, prepend the output path
    /// If there is no extension, use the default
    fn make_path(&self, s: &str) -> PathBuf {
        let mut path_buf = PathBuf::from(s);
        // parent() tends to return an empty string instead of None
        let has_path = match path_buf.parent() {
            Some(p) => p.to_string_lossy().len() > 0,
            None => false,
        };
        // if we just have a filename, then assume it is in the output folder
        if !has_path {
            path_buf = PathBuf::from(&self.output_dir);
            path_buf.push(s);
        }
        // add the default extension is none is supplied
        if path_buf.extension().is_none() {
            path_buf.set_extension(&self.config.default_ext);
        }
        path_buf
    }

    /// Patches new content into a file
    ///
    /// # Parameters
    /// path - path to file to be patched
    /// search_bytes - bytes to be replaced
    /// replace_bytes - replacement bytes
    fn patch_file(path: &std::path::Path, search_bytes: &[u8], replace_bytes: &[u8]) -> Result<()> {
        let mut buf = fs::read(path)?;

        if let Some(splice_start) = find_bytes(&buf, search_bytes) {
            buf.splice(
                splice_start..splice_start + search_bytes.len(),
                replace_bytes.iter().cloned(),
            );
        } else {
            return Err(Error::NotFound.into());
        }

        fs::write(path, &buf)?;

        Ok(())
    }

    /// Creates a test image with optional source and ingredients, out to dest
    fn make_image(&self, recipe: &Recipe) -> Result<PathBuf> {
        let src = recipe.parent.as_deref();
        let dst_path = self.make_path(&recipe.output);
        println!("Creating {:?}", dst_path);
        // keep track of all actions here
        let mut actions = Actions::new();

        let options = IngredientOptions {
            make_hash: true,
            title: None,
        };

        let generator = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        let mut manifest = Manifest::new(generator);
        manifest.set_vendor("contentauth".to_owned()); // needed for generating error cases below

        if let Some(user) = self.config.author.as_ref() {
            let creative_work = CreativeWork::new()
                .add_author(SchemaDotOrgPerson::new().set_name(user.to_owned())?)?;

            manifest.add_assertion(&creative_work)?;
        }

        // process parent first
        let mut img = match src {
            Some(src) => {
                let src_path = &self.make_path(src);

                let parent = Ingredient::from_file_with_options(src_path, &options)?;
                actions.add_action(
                    Action::new(c2pa_action::OPENED)
                        .set_parameter("identifier".to_owned(), parent.instance_id().to_owned())?,
                );
                manifest.set_parent(parent)?;

                // load the image for editing
                let mut img =
                    image::open(&src_path).context(format!("opening parent {:?}", src_path))?;

                // adjust brightness to show we made an edit
                img = img.brighten(30);
                actions.add_action(
                    Action::new(c2pa_action::COLOR_ADJUSTMENTS)
                        .set_parameter("name".to_owned(), "brightnesscontrast")?,
                );
                img
            }
            None => {
                // create a default image with a gradient
                let mut img = image::DynamicImage::new_rgb8(IMAGE_WIDTH, IMAGE_HEIGHT);
                if let Some(img_ref) = img.as_mut_rgb8() {
                    //  fill image with a gradient
                    for (x, y, pixel) in img_ref.enumerate_pixels_mut() {
                        let r = (0.3 * x as f32) as u8;
                        let b = (0.3 * y as f32) as u8;
                        *pixel = image::Rgb([r, 100, b]);
                    }
                }
                actions
                    .add_action(Action::new(c2pa_action::CREATED))
                    .add_action(
                        Action::new(c2pa_action::DRAWING)
                            .set_parameter("name".to_owned(), "gradient")?,
                    );

                img
            }
        };

        // then add all ingredients
        if let Some(ing_vec) = &recipe.ingredients {
            // scale ingredients to paste in top row of the image
            let width = match ing_vec.len() as u32 {
                0 | 1 => img.width() / 2,
                _ => img.width() / ing_vec.len() as u32,
            };
            let height = img.height() as u32 / 2;

            let mut x = 0;
            for ing in ing_vec {
                let ing_path = &self.make_path(ing);

                // get the bits of the ingredient, resize it and overlay it on the base image
                let img_ingredient =
                    image::open(&ing_path).context(format!("opening ingredient {:?}", ing_path))?;
                let img_small = img_ingredient.thumbnail(width, height);
                image::imageops::overlay(&mut img, &img_small, x, 0);

                // create and add the ingredient
                let ingredient = Ingredient::from_file_with_options(ing_path, &options)?;
                actions.add_action(
                    Action::new(c2pa_action::PLACED).set_parameter(
                        "identifier".to_owned(),
                        ingredient.instance_id().to_owned(),
                    )?,
                );
                manifest.add_ingredient(ingredient);

                x += width;
            }
            // record what we did as an action (only need to record this once)
            actions.add_action(Action::new(c2pa_action::RESIZED));
        }

        // save the changes to the image as our target file
        img.save(&dst_path)?;

        // add all our actions as an assertion now.
        manifest.add_assertion(&actions)?; // extra get required here, since actions is an array

        // now create store; sign claim and embed in target
        let temp_dir = tempdir()?;
        let (signer, _) =
            get_signer_by_alg(&temp_dir.path(), &self.config.alg, self.config.tsa.clone());

        manifest.embed(&dst_path, &dst_path, signer.as_ref())?;

        Ok(dst_path)
    }

    /// makes an off the golden path image from an existing image with a claim
    fn make_ogp(&self, recipe: &Recipe) -> Result<PathBuf> {
        let src = recipe.parent.as_deref().unwrap_or_default();
        let src_path = &self.make_path(src);
        let dst_path = self.make_path(recipe.output.as_str());
        println!("Creating OGP {:?}", dst_path);

        let jumbf = jumbf_io::load_jumbf_from_file(&PathBuf::from(src_path))
            .context(format!("loading OGP {:?}", src_path))?;
        // save the edited image to our destination file
        let mut img = image::open(&Path::new(src_path))
            .context(format!("loading OGP image{:?}", src_path))?;
        img = img.grayscale();
        img.save(&dst_path)
            .context(format!("saving OGP image{:?}", &dst_path))?;
        // write the original claim data to the edited image
        jumbf_io::save_jumbf_to_file(&jumbf, &PathBuf::from(&dst_path), Some(&dst_path))
            .context(format!("OGP save_jumbf_to_file {:?}", &dst_path))?;
        // The image library does not preserve any metadata so we have to write it ourselves.
        // todo: should preserve all metadata and update instanceId.
        Ok(dst_path)
    }

    /// Generates various error conditions
    fn make_err(&self, recipe: &Recipe) -> Result<PathBuf> {
        let op = recipe.op.as_str();
        let src = recipe.parent.as_deref().unwrap_or_default();
        let dst_path = self.make_path(recipe.output.as_str());
        println!("Creating Error op={} {:?}", op, dst_path);

        let (search_bytes, replace_bytes) = match op {
            // modify the XMP (change xmp magic id value) - this should cause a data hash mismatch (OTGP)
            "dat" => (
                b"W5M0MpCehiHzreSzNTczkc9d".as_bytes(),
                b"W5M0MpCehiHzreSzdeadbeef".as_bytes(),
            ),
            // modify the claim_generator value inside the claim, the claim hash will no longer match the signature
            "sig" => (b"make_tests".as_bytes(), b"make_xxxxx".as_bytes()),
            // modify a value inside an actions assertion, the assertion hash will fail
            "uri" => (
                b"brightnesscontrast".as_bytes(),
                b"brightnessdeadbeef".as_bytes(),
            ),
            // modify a uri to a manifest so the manifest cannot be found (missing manifest)
            "clm" => (
                b"c2pa_manifest\xA3\x63url\x78\x4aself#jumbf=/c2pa/contentauth".as_bytes(),
                b"c2pa_manifest\xA3\x63url\x78\x4aself#jumbf=/c2pa/contentbeef".as_bytes(),
            ),
            // modify the provenance uri so that is references a non-existing manifest
            "prv" => (
                b"dcterms:provenance=\"self#jumbf=/c2pa/contentauth".as_bytes(),
                b"dcterms:provenance=\"self#jumbf=/c2pa/contentbeef".as_bytes(),
            ),
            _ => panic!("bad parameter"),
        };

        std::fs::copy(&self.make_path(src), &dst_path).context("copying for make_err")?;

        Self::patch_file(&dst_path, search_bytes, replace_bytes)
            .context(format!("patching {}", op))?;

        Ok(dst_path)
    }

    /// copies a file from the parent to the output
    fn make_copy(&self, recipe: &Recipe) -> Result<PathBuf> {
        let dst_path = self.make_path(recipe.output.as_str());
        println!("Copying {:?}", dst_path);
        let src = recipe.parent.as_deref().unwrap_or_default();
        let dst = recipe.output.as_str();
        std::fs::copy(src, &dst_path).context(format!("copying {} to {}", src, dst))?;
        Ok(dst_path)
    }

    /// Runs a list of recipes
    pub fn run(&self) -> Result<()> {
        if !self.output_dir.exists() {
            std::fs::create_dir_all(&self.output_dir).context("Can't create output folder")?;
        };

        let recipes = &self.config.recipes;
        for recipe in recipes {
            let dst_path = match recipe.op.as_str() {
                "make" => self.make_image(recipe)?,
                "ogp" => self.make_ogp(recipe)?,
                "dat" | "sig" | "uri" | "clm" | "prv" => self.make_err(recipe)?,
                "copy" => self.make_copy(recipe)?,
                _ => return Err(Error::BadParam(recipe.op.to_string()).into()),
            };
            let manifest_store = ManifestStore::from_file(&dst_path);

            if recipe.op.as_str() != "copy" {
                println!("{}", manifest_store?);
            }
        }
        Ok(())
    }
}
