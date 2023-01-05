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
use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use c2pa::{
    assertions::{c2pa_action, Action, Actions, CreativeWork, SchemaDotOrgPerson},
    create_signer, jumbf_io, Error, Ingredient, IngredientOptions, Manifest, ManifestStore, Signer,
    SigningAlg,
};
use nom::AsBytes;
use serde::Deserialize;
use twoway::find_bytes;

const IMAGE_WIDTH: u32 = 2048;
const IMAGE_HEIGHT: u32 = 1365;

/// Defines an operation for creating a test image
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    /// The operation to perform:
    ///
    /// One of: "copy", "make", "ogp", "dat", "sig", "uri", "clm", "prv"
    pub op: String,
    /// Path or filename of parent
    ///
    /// Assumes output folder if no path
    /// Will add default extension if non specified
    pub parent: Option<String>,
    /// A list of Ingredient paths
    ///
    /// Assumes output folder if no path
    /// Will add default extension if non specified
    pub ingredients: Option<Vec<String>>,
    /// The folder to write files to, will create if it does not exist
    pub output: String,
}

/// Configuration
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The signing algorithm to use
    pub alg: String,
    /// A url to a time stamp authority if desired
    pub tsa_url: Option<String>,
    /// The output folder for the generated files
    pub output_path: String,
    /// Extension to add to filenames if none was given
    pub default_ext: String,
    /// A name for a Creative Work Author assertion
    pub author: Option<String>,
    /// A list of recipes for test files
    pub recipes: Vec<Recipe>,
}

impl Config {
    pub fn get_signer(&self) -> c2pa::Result<Box<dyn Signer>> {
        // sign and embed into the target file
        let alg: SigningAlg = self.alg.parse().map_err(|_| c2pa::Error::UnsupportedType)?;
        let tsa_url = self.tsa_url.as_ref().map(|s| s.to_owned());
        let mut signcert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        signcert_path.push(format!("../sdk/tests/fixtures/certs/{}.pub", self.alg));
        let mut pkey_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pkey_path.push(format!("../sdk/tests/fixtures/certs/{}.pem", alg));
        create_signer::from_files(signcert_path, pkey_path, alg, tsa_url)
    }
}

// Defaults for Config
impl Default for Config {
    fn default() -> Self {
        Self {
            alg: "ps256".to_owned(),
            tsa_url: None,
            output_path: "target/images".to_owned(),
            default_ext: "jpg".to_owned(),
            author: None,
            recipes: Vec::new(),
        }
    }
}

/// Generate a blake3 hash over the image in path using a fixed buffer
fn blake3_hash(path: &Path) -> Result<String> {
    use std::{fs::File, io::Read};
    // Hash an input incrementally.
    let mut hasher = blake3::Hasher::new();
    const BUFFER_LEN: usize = 1024 * 1024;
    let mut buffer = [0u8; BUFFER_LEN];
    let mut file = File::open(path)?;
    loop {
        let read_count = file.read(&mut buffer)?;
        hasher.update(&buffer[..read_count]);
        if read_count != BUFFER_LEN {
            break;
        }
    }
    let hash = hasher.finalize();
    Ok(hash.to_hex().as_str().to_owned())
}

/// Tool for building test case images for C2PA
pub struct MakeTestImages {
    config: Config,
    output_dir: PathBuf,
}

impl MakeTestImages {
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

        struct ImageOptions {}
        impl ImageOptions {
            fn new() -> Self {
                ImageOptions {}
            }
        }

        impl IngredientOptions for ImageOptions {
            fn hash(&self, path: &Path) -> Option<String> {
                blake3_hash(path).ok()
            }
        }

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

                let parent = Ingredient::from_file_with_options(src_path, &ImageOptions::new())?;

                actions = actions.add_action(
                    Action::new(c2pa_action::OPENED).set_instance_id(parent.instance_id()),
                );
                manifest.set_parent(parent)?;

                // load the image for editing
                let mut img =
                    image::open(src_path).context(format!("opening parent {:?}", src_path))?;

                // adjust brightness to show we made an edit
                img = img.brighten(30);
                actions = actions.add_action(
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
                actions = actions
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
            let height = img.height() / 2;

            let mut x = 0;
            for ing in ing_vec {
                let ing_path = &self.make_path(ing);

                // get the bits of the ingredient, resize it and overlay it on the base image
                let img_ingredient =
                    image::open(ing_path).context(format!("opening ingredient {:?}", ing_path))?;
                let img_small = img_ingredient.thumbnail(width, height);
                image::imageops::overlay(&mut img, &img_small, x, 0);

                // create and add the ingredient
                let ingredient =
                    Ingredient::from_file_with_options(ing_path, &ImageOptions::new())?;
                actions = actions.add_action(
                    Action::new(c2pa_action::PLACED).set_instance_id(ingredient.instance_id()),
                );
                manifest.add_ingredient(ingredient);

                x += width as i64;
            }
            // record what we did as an action (only need to record this once)
            actions = actions.add_action(Action::new(c2pa_action::RESIZED));
        }

        // save the changes to the image as our target file
        img.save(&dst_path)?;

        // add all our actions as an assertion now.
        manifest.add_assertion(&actions)?; // extra get required here, since actions is an array

        // now sign manifest and embed in target
        let signer = self.config.get_signer()?;

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
        let mut img =
            image::open(Path::new(src_path)).context(format!("loading OGP image{:?}", src_path))?;
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
            "sig" => (
                b"make_test_images".as_bytes(),
                b"make_test_xxxxxx".as_bytes(),
            ),
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

        std::fs::copy(self.make_path(src), &dst_path).context("copying for make_err")?;

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
            let manifest_store = ManifestStore::from_file(dst_path);

            if recipe.op.as_str() != "copy" {
                println!("{}", manifest_store?);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    const TESTS: &str = r#"{
        "alg": "ps256",
        "tsa_url": "http://timestamp.digicert.com",
        "output_path": "../target/tmp",
        "default_ext": "jpg",
        "author": "Gavin Peacock",
        "recipes": [
            { "op": "copy", "parent": "../sdk/tests/fixtures/IMG_0003.jpg", "output": "A.jpg" },
            { "op": "make", "output": "C" },
            { "op": "ogp", "parent": "C", "output": "XC" },
            { "op": "sig", "parent": "C", "output": "E-sig-C" } 
        ]
    }"#;

    #[test]
    fn test_make_images() {
        let config: Config = serde_json::from_str(TESTS)
            .context("Config file format")
            .expect("serde_json");
        MakeTestImages::new(config).run().expect("running");
    }
}
