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
    collections::HashMap,
    fs,
    io::{Cursor, Seek},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use c2pa::{
    create_signer,
    jumbf_io::{get_supported_types, load_jumbf_from_stream, save_jumbf_to_stream},
    Builder, Error, Ingredient, Reader, Relationship, Signer, SigningAlg,
};
use memchr::memmem;
use nom::AsBytes;
use serde::Deserialize;
use serde_json::json;

use crate::{compare_manifests::compare_folders, make_thumbnail::make_thumbnail_from_stream};

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
    /// A folder to compare the output to
    pub compare_folders: Option<[String; 2]>,
}

impl Config {
    pub fn get_signer(&self) -> c2pa::Result<Box<dyn Signer>> {
        // sign and embed into the target file
        let alg: SigningAlg = self.alg.parse().map_err(|_| c2pa::Error::UnsupportedType)?;
        let tsa_url = self.tsa_url.as_ref().map(|s| s.to_owned());
        let mut signcert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        signcert_path.push(format!("../sdk/tests/fixtures/certs/{}.pub", self.alg));
        let mut pkey_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pkey_path.push(format!("../sdk/tests/fixtures/certs/{alg}.pem"));
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
            compare_folders: None,
        }
    }
}

/// Converts a file extension to a MIME type
fn extension_to_mime(extension: &str) -> Option<&'static str> {
    Some(match extension.to_lowercase().as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "psd" => "image/vnd.adobe.photoshop",
        "tiff" | "tif" => "image/tiff",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "webp" => "image/webp",
        "dng" => "image/dng",
        "heic" => "image/heic",
        "heif" => "image/heif",
        "mp2" | "mpa" | "mpe" | "mpeg" | "mpg" | "mpv2" => "video/mpeg",
        "mp4" => "video/mp4",
        "avif" => "image/avif",
        "mov" | "qt" => "video/quicktime",
        "m4a" => "audio/mp4",
        "mid" | "rmi" => "audio/mid",
        "mp3" => "audio/mpeg",
        "wav" => "audio/vnd.wav",
        "aif" | "aifc" | "aiff" => "audio/aiff",
        "ogg" => "audio/ogg",
        "pdf" => "application/pdf",
        "ai" => "application/postscript",
        _ => return None,
    })
}

fn extension(path: &Path) -> Option<&str> {
    path.extension().and_then(std::ffi::OsStr::to_str)
}

fn file_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(std::ffi::OsStr::to_str)
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

        if let Some(splice_start) = memmem::find(&buf, search_bytes) {
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

    fn add_ingredient_from_file(
        builder: &mut Builder,
        path: &Path,
        relationship: Relationship,
    ) -> Result<String> {
        let mut source = fs::File::open(path).context("opening ingredient")?;
        let name = path
            .file_name()
            .ok_or(Error::BadParam("no filename".to_string()))?
            .to_string_lossy();
        let extension = path
            .extension()
            .ok_or(Error::BadParam("no extension".to_owned()))?
            .to_string_lossy()
            .into_owned();
        let format = extension_to_mime(&extension).unwrap_or("image/jpeg");

        let mut parent = Ingredient::from_stream(format, &mut source)?;
        parent.set_relationship(relationship);
        parent.set_title(name);
        if parent.thumbnail_ref().is_none() {
            source.rewind()?;
            let (format, thumbnail) =
                make_thumbnail_from_stream(format, &mut source).context("making thumbnail")?;
            parent.set_thumbnail(format, thumbnail)?;
        }

        builder.add_ingredient(parent);

        Ok(
            builder.definition.ingredients[builder.definition.ingredients.len() - 1]
                .instance_id()
                .to_string(),
        )
    }

    fn make_image(&self, recipe: &Recipe) -> Result<PathBuf> {
        let src = recipe.parent.as_deref();
        let dst = recipe.output.as_str();
        let dst_path = self.make_path(dst);
        println!("Creating {dst_path:?}");

        let software_agent = format!("{} {}", "Make Test Images", env!("CARGO_PKG_VERSION"));
        // let software_agent = json!({
        //     "name": "Make Test Images",
        //     "version": env!("CARGO_PKG_VERSION")
        // });
        let name = file_name(&dst_path).ok_or(Error::BadParam("no filename".to_string()))?;
        let extension = extension(&dst_path).unwrap_or("jpg");

        let format = extension_to_mime(extension).unwrap_or("image/jpeg");

        let manifest_def = json!({
            "vendor": "contentauth",
            "title": name,
            "format": &format,
            "claim_generator_info": [
                {
                    "name": env!("CARGO_PKG_NAME"),
                    "version": env!("CARGO_PKG_VERSION")
                }
            ]
        })
        .to_string();

        let mut builder = Builder::from_json(&manifest_def)?;

        // keep track of ingredient instances so we don't duplicate them
        let mut ingredient_table = HashMap::new();

        let mut actions = Vec::new();
        if let Some(author) = &self.config.author {
            builder.add_assertion(
                "stds.schema-org.CreativeWork",
                &json!({
                  "@context": "http://schema.org/",
                  "@type": "CreativeWork",
                  "author": [
                    {
                      "@type": "Person",
                      "name": author
                    }
                  ]
                }),
            )?;
        };

        // process parent first
        let mut img = match src {
            Some(src) => {
                let src_path = &self.make_path(src);

                let instance_id =
                    Self::add_ingredient_from_file(&mut builder, src_path, Relationship::ParentOf)?;

                actions.push(json!(
                    {
                        "action": "c2pa.opened",
                        "instanceId": &instance_id,
                    }
                ));

                // keep track of all ingredients we add via the instance Id
                ingredient_table.insert(src, instance_id.to_owned());

                // load the image for editing
                let mut img =
                    image::open(src_path).context(format!("opening parent {src_path:?}"))?;

                // adjust brightness to show we made an edit
                img = img.brighten(30);
                actions.push(json!(
                    {
                        "action": "c2pa.color_adjustments",
                        "parameters": {
                          "name": "brightnesscontrast"
                        }
                      }
                ));
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
                actions.push(json!(
                    {
                        "action": "c2pa.created",
                        "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/algorithmicMedia",
                        "softwareAgent": software_agent,
                        "parameters": {
                          "name": "gradient"
                        }
                    }
                ));
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
                    image::open(ing_path).context(format!("opening ingredient {ing_path:?}"))?;
                let img_small = img_ingredient.thumbnail(width, height);
                image::imageops::overlay(&mut img, &img_small, x, 0);

                // if we have already created an ingredient, get the instanceId, otherwise create a new one
                let instance_id = match ingredient_table.get(ing.as_str()) {
                    Some(id) => id.to_string(),
                    None => {
                        let instance_id = Self::add_ingredient_from_file(
                            &mut builder,
                            ing_path,
                            Relationship::ComponentOf,
                        )?;
                        ingredient_table.insert(ing, instance_id.clone());
                        instance_id
                    }
                };
                actions.push(json!(
                    {
                        "action": "c2pa.placed",
                        "instanceId": instance_id,
                    }
                ));
                x += width as i64;
            }
            // record what we did as an action (only need to record this once)
            actions.push(json!(
                {
                    "action": "c2pa.resized",
                }
            ));
        }

        let mut temp = tempfile::tempfile()?;

        use image::ImageFormat;
        let image_format = ImageFormat::from_extension(extension)
            .ok_or(Error::BadParam("extension not supported".to_owned()))?;
        // save the changes to the image as our target file
        img.write_to(&mut temp, image_format)?;
        temp.rewind()?;

        // add all our actions as an assertion now.
        builder.add_assertion(
            "c2pa.actions",
            &json!(
                {
                    "actions": actions
                }
            ),
        )?;

        // generate a thumbnail and set it in the image
        // make sure do do this last,on the generated image so that it reflects the output
        let (thumb_format, image) =
            make_thumbnail_from_stream(format, &mut temp).context("making thumbnail")?;
        builder.set_thumbnail(&thumb_format, &mut Cursor::new(image))?;

        temp.rewind()?;

        // now sign manifest and embed in target
        let signer = self.config.get_signer()?;

        let mut dest = fs::File::create(&dst_path)?;
        builder
            .sign(signer.as_ref(), format, &mut temp, &mut dest)
            .context("signing")?;

        Ok(dst_path)
    }

    fn manifest_def(title: &str, format: &str) -> String {
        json!({
            "title": title,
            "format": format,
            "claim_generator_info": [
                {
                    "name": "Make Test Images",
                    "version": env!("CARGO_PKG_VERSION")
                }
            ],
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.edited",
                                "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
                                "softwareAgent": {
                                    "name": "My AI Tool",
                                    "version": "0.1.0"
                                }
                            }
                        ]
                    }
                }
            ]
        }).to_string()
    }

    fn sign_image(&self, recipe: &Recipe) -> Result<PathBuf> {
        let src = recipe.parent.as_deref();
        let dst = recipe.output.as_str();
        let dst_path = self.make_path(dst);
        println!("Signing {dst_path:?}");

        let src = match src {
            Some(src) => src,
            None => return Err(Error::BadParam("no parent".to_string()).into()),
        };

        let name = file_name(&dst_path).ok_or(Error::BadParam("no filename".to_string()))?;
        let extension = extension(&dst_path).unwrap_or("jpg");

        let format = extension_to_mime(extension).unwrap_or("image/jpeg");

        let json = Self::manifest_def(name, format);

        let src_path = &self.make_path(src);
        let mut source = fs::File::open(src_path).context("opening ingredient")?;

        let mut builder = Builder::from_json(&json)?;

        let parent_name = file_name(&dst_path).ok_or(Error::BadParam("no filename".to_string()))?;
        builder.add_ingredient_from_stream(
            json!({
                "title": parent_name,
                "relationship": "parentOf"
            })
            .to_string(),
            extension,
            &mut source,
        )?;

        let mut dest = fs::File::create(&dst_path)?;
        let signer = self.config.get_signer()?;
        builder
            .sign(signer.as_ref(), format, &mut source, &mut dest)
            .context("signing")?;

        Ok(dst_path)
    }

    /// makes an off the golden path image from an existing image with a claim
    fn make_ogp(&self, recipe: &Recipe) -> Result<PathBuf> {
        let src = recipe.parent.as_deref().unwrap_or_default();
        let src_path = &self.make_path(src);
        let dst_path = self.make_path(recipe.output.as_str());
        println!("Creating {dst_path:?}");
        let format = src_path
            .extension()
            .ok_or(Error::BadParam("no extension".to_owned()))?
            .to_string_lossy()
            .into_owned();

        let mut source = std::fs::File::open(src_path).context("opening OGP source")?;
        let jumbf = load_jumbf_from_stream(&format, &mut source)
            .context("loading OGP")
            .context(format!("loading OGP {src_path:?}"))?;
        // save the edited image to our destination file
        let mut img =
            image::open(Path::new(src_path)).context(format!("loading OGP image{src_path:?}"))?;
        img = img.grayscale();
        img.save(&dst_path)
            .context(format!("saving OGP image{:?}", &dst_path))?;
        let image = std::fs::read(&dst_path).context("reading OGP image")?;
        let mut dest = std::fs::File::create(&dst_path).context("creating OGP image")?;
        // write the original claim data to the edited image
        save_jumbf_to_stream(&format, &mut Cursor::new(image), &mut dest, &jumbf)
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
        println!("Creating {dst_path:?}");

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
            .context(format!("patching {op}"))?;

        Ok(dst_path)
    }

    /// copies a file from the parent to the output
    fn make_copy(&self, recipe: &Recipe) -> Result<PathBuf> {
        let src = recipe.parent.as_deref().unwrap_or_default();
        let dst = recipe.output.as_str();
        let src_path = &self.make_path(src);
        let dst_path = self.make_path(dst);
        println!("Copying {dst_path:?}");
        let src = recipe.parent.as_deref().unwrap_or_default();
        let dst = recipe.output.as_str();
        if extension(&PathBuf::from(src)) != extension(&PathBuf::from(dst)) {
            let img = image::open(src_path).context(format!("copying {src} to {dst}"))?;
            img.save(&dst_path)
                .context(format!("copying {src} to {dst}"))?;
        } else {
            std::fs::copy(src, &dst_path).context(format!("copying {src} to {dst}"))?;
        }
        Ok(dst_path)
    }

    /// Runs a list of recipes
    pub fn run(&self) -> Result<()> {
        let supported = get_supported_types();
        println!("Supported types: {:#?}", supported);
        if !self.output_dir.exists() {
            std::fs::create_dir_all(&self.output_dir).context("Can't create output folder")?;
        };
        let json_dir = self.output_dir.join("json");
        if !json_dir.exists() {
            std::fs::create_dir_all(&json_dir)?;
        }

        let recipes = &self.config.recipes;
        for recipe in recipes {
            let dst_path = match recipe.op.as_str() {
                "make" => self.make_image(recipe)?,
                "sign" => self.sign_image(recipe)?,
                "ogp" => self.make_ogp(recipe)?,
                "dat" | "sig" | "uri" | "clm" | "prv" => self.make_err(recipe)?,
                "copy" => self.make_copy(recipe)?,
                _ => return Err(Error::BadParam(recipe.op.to_string()).into()),
            };

            if recipe.op.as_str() != "copy" {
                let mut file = std::fs::File::open(&dst_path)?;
                let format = dst_path
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("jpg");
                let reader = Reader::from_stream(format, &mut file)?;
                let json = reader.json();

                let json_path = json_dir
                    .join(dst_path.file_name().unwrap())
                    .with_extension("json");
                std::fs::write(&json_path, json)?;
            }
        }
        //println!("Comparing to {:#?}", self.config.compare_folder);
        if let Some(folders) = &self.config.compare_folders {
            compare_folders(&folders[0], &folders[1])?;
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
