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

const GENERATOR: &str = "make_tests";
const USER: &str = "Joe Bloggs";

const IMAGE_WIDTH: u32 = 2048;
const IMAGE_HEIGHT: u32 = 1365;

/**
Patch new content into a file
path - path to file to be patched
search_bytes - bytes to be replaced
replace_bytes - replacement bytes
*/
pub fn patch_file(path: &std::path::Path, search_bytes: &[u8], replace_bytes: &[u8]) -> Result<()> {
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

pub struct MakeTests {
    output_dir: PathBuf,
}

impl MakeTests {
    pub fn new(path: &Path) -> Self {
        Self {
            output_dir: PathBuf::from(path),
        }
    }

    pub fn output_dir(&self) -> PathBuf {
        self.output_dir.to_owned()
    }

    fn make_path(&self, s: &str) -> PathBuf {
        //let output_dir = unsafe { OUTPUT_FOLDER.as_ref().unwrap().lock().unwrap().to_string() };
        let mut path_buf = PathBuf::from(&self.output_dir);
        path_buf.push(s);
        if path_buf.extension().is_none() {
            path_buf.set_extension("jpg");
        }
        path_buf
    }

    // create a test image with optional source and ingredients, out to dest
    pub fn make_image(
        &self,
        src: Option<&str>,
        ing: Option<&Vec<&str>>,
        dst: &str,
        alg: &str,
        tsa: Option<String>,
    ) -> Result<()> {
        let dst_path = &self.make_path(dst);
        println!("creating {:?}", dst_path);
        // keep track of all actions here
        let mut actions = Actions::new();

        let options = IngredientOptions {
            make_hash: true,
            title: None,
        };

        let mut manifest = Manifest::new(GENERATOR.to_string());
        manifest.set_vendor("contentauth".to_owned()); // needed for generating error cases below

        let creative_work =
            CreativeWork::new().add_author(SchemaDotOrgPerson::new().set_name(USER.to_owned())?)?;

        manifest.add_assertion(&creative_work)?;

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
                    image::open(&src_path).context(format!("opening image A {:?}", src_path))?;

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
        if let Some(ing_vec) = ing {
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
                    image::open(&ing_path).context(format!("opening image I {:?}", ing_path))?;
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
        img.save(dst_path)?;

        // add all our actions as an assertion now.
        manifest.add_assertion(&actions)?; // extra get required here, since actions is an array

        // now create store; sign claim and embed in target
        let temp_dir = tempdir()?;
        let (signer, _) = get_signer_by_alg(&temp_dir.path(), alg, tsa);

        manifest.embed(dst_path, dst_path, signer.as_ref())?;

        println!("{}", ManifestStore::from_file(dst_path)?);

        Ok(())
    }

    // make an off the golden path image from an existing image with a claim
    fn make_ogp(&self, src: &str, dst: &str) -> Result<()> {
        println!("creating OGP {}", dst);
        let src_path = &self.make_path(src);
        let dst_path = &self.make_path(dst);
        let jumbf = jumbf_io::load_jumbf_from_file(&PathBuf::from(src_path))
            .context(format!("loading OGP {:?}", src_path))?;
        // save the edited image to our destination file
        let mut img = image::open(&Path::new(src_path))
            .context(format!("loading OGP image{:?}", src_path))?;
        img = img.grayscale();
        img.save(dst_path)
            .context(format!("saving OGP image{:?}", dst_path))?;
        // write the original claim data to the edited image
        jumbf_io::save_jumbf_to_file(
            &jumbf,
            &PathBuf::from(dst_path),
            Some(&PathBuf::from(dst_path)),
        )
        .context(format!("OGP save_jumbf_to_file {:?}", dst_path))?;
        // The image library does not preserve any metadata so we have to write it ourselves.
        // todo: should preserve all metadata and update instanceId.
        Ok(())
    }

    fn make_err(&self, src: &str, err: &str) -> Result<()> {
        let (search_bytes, replace_bytes) = match err {
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
                b"c2pa_manifest\xA3\x63url\x78\x4aself#jumbf=/c2pa/contentauth".as_bytes(),
            ),
            // modify the provenance uri so that is references a non-existing manifest
            "prv" => (
                b"dcterms:provenance=\"self#jumbf=/c2pa/contentauth".as_bytes(),
                b"dcterms:provenance=\"self#jumbf=/c2pa/contentauth".as_bytes(),
            ),
            _ => panic!("bad parameter"),
        };

        let dst = format!("E-{}-{}", err, src);
        std::fs::copy(&self.make_path(src), &self.make_path(&dst))
            .context("copying for make_err")?;
        patch_file(&self.make_path(&dst), search_bytes, replace_bytes)
            .context(format!("patching {}", err))?;

        Ok(())
    }
}

pub fn make_tests(output_folder: &Path, alg: &str, tsa: Option<String>) -> Result<()> {
    // destination folder for this content
    let mt = MakeTests::new(output_folder);
    let data_dir = mt.output_dir();

    if !data_dir.exists() {
        std::fs::create_dir_all(&data_dir).expect("Can't create C2PA data directory");
    };

    // copy A and I source images into destination folder
    // these images should have no claims
    std::fs::copy("sdk/tests/fixtures/IMG_0003.jpg", &mt.make_path("A.jpg"))
        .context("error copying A")?;
    std::fs::copy("sdk/tests/fixtures/P1000827.jpg", &mt.make_path("I.jpg"))
        .context("error copying I")?;

    // --------------------------------------------------------------------

    //make_cai(None, Some(&vec!["PS.svg"]), "CIPS")?;
    mt.make_image(None, None, "C", alg, tsa.clone())?;
    mt.make_image(Some("A"), None, "CA", alg, tsa.clone())?;
    mt.make_image(Some("CA"), None, "CACA", alg, tsa.clone())?;
    mt.make_image(None, Some(&vec!["I"]), "CI", alg, tsa.clone())?;
    mt.make_image(None, Some(&vec!["I", "I"]), "CII", alg, tsa.clone())?;
    mt.make_image(
        None,
        Some(&vec!["I", "I", "I", "I", "I"]),
        "CIIIII",
        alg,
        tsa.clone(),
    )?;
    mt.make_image(Some("A"), Some(&vec!["I"]), "CAI", alg, tsa.clone())?;
    mt.make_image(Some("A"), Some(&vec!["CA"]), "CAICA", alg, tsa.clone())?;
    mt.make_image(None, Some(&vec!["CA"]), "CICA", alg, tsa.clone())?;
    mt.make_image(Some("CA"), Some(&vec!["CAI"]), "CAICAI", alg, tsa.clone())?;
    mt.make_image(None, Some(&vec!["CA"]), "CICA", alg, tsa.clone())?;
    mt.make_image(
        Some("CAICA"),
        Some(&vec!["CICA"]),
        "CACAICAICICA",
        alg,
        tsa.clone(),
    )?;
    mt.make_image(
        None,
        Some(&vec!["CA", "CA", "CA"]),
        "CICACACA",
        alg,
        tsa.clone(),
    )?;

    mt.make_ogp("CA", "XCA")?;
    mt.make_ogp("CI", "XCI")?;
    mt.make_image(Some("CA"), Some(&vec!["XCI"]), "CAIXCI", alg, tsa.clone())?;
    mt.make_image(
        Some("XCA"),
        Some(&vec!["XCI"]),
        "CAXCAIXCI",
        alg,
        tsa.clone(),
    )?;

    mt.make_err("CA", "dat")?;
    mt.make_err("CA", "sig")?;
    mt.make_err("CA", "uri")?;
    mt.make_err("CAICAI", "clm")?;
    mt.make_err("CA", "prv")?;
    mt.make_image(
        None,
        Some(&vec!["E-sig-CA"]),
        "CIE-sig-CA",
        alg,
        tsa.clone(),
    )?;
    // inject an assertion error into a claim that has an accepted error
    mt.make_err("CIE-sig-CA", "uri")?;

    mt.make_image(
        Some("A"),
        Some(&vec!["C", "A", "I", "CA", "CI", "CAI", "CICA"]),
        "CAIAIIICAICIICAIICICA",
        alg,
        tsa,
    )?;
    // // save the changes to the image and add the claim
    println!("done");
    Ok(())
}
