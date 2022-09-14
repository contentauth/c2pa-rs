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

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use c2pa::{Ingredient, Manifest, ManifestAssertion};
use serde::Deserialize;
use serde_json::Value;

/// Defines the components used to build a claim to embed in a manifest
#[derive(Debug, Deserialize)]
pub struct ManifestConfig {
    /// Optional prefix added to the generated Manifest Label
    ///
    /// This is typically Internet domain name for the vendor (i.e. `adobe`)
    pub vendor: Option<String>,
    /// A User Agent formatted string identifying the software/hardware/system produced this claim
    ///
    /// Spaces are not allowed in names, versions can be specified with product/1.0 syntax
    pub claim_generator: Option<String>,
    /// Optional title to use for this claim, defaults to the output file name
    pub title: Option<String>,
    /// Optional parent ingredient file path
    pub parent: Option<PathBuf>,
    /// A List of verified credentials
    pub credentials: Option<Vec<Value>>,
    /// A list of non-parent ingredients to include
    pub ingredients: Option<Vec<PathBuf>>,
    /// A list of [ManifestAssertion] to add to this created manifest
    pub assertions: Vec<ManifestAssertion>,
    /// An optional base path to use for any relative paths in defined in this structure
    pub base_path: Option<PathBuf>,
    /// Signing algorithm to use - must match the associated certs
    ///
    /// Must be one of [ ps256 | ps384 | ps512 | es256 | es384 | es512 | ed25519 ]
    /// Defaults to es256
    pub alg: Option<String>,
    /// A path to a file containing the private key required for signing
    pub private_key: Option<PathBuf>,
    /// A path to a file containing the signing cert required for signing
    pub sign_cert: Option<PathBuf>,
    /// A Url to a Time Authority to use when signing the manifest
    pub ta_url: Option<String>,
}

impl ManifestConfig {
    /// Returns Assertions for this Manifest
    pub fn assertions(&self) -> &[ManifestAssertion] {
        &self.assertions
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).context("reading manifest configuration")
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let json = fs::read_to_string(&path)?;
        let mut manifest_config = Self::from_json(&json)?;
        if manifest_config.base_path.is_none() {
            let mut base_dir = PathBuf::from(&path);
            base_dir.pop();
            manifest_config.base_path = Some(base_dir)
        }
        Ok(manifest_config)
    }

    // converts any relative paths to absolute from base_path
    pub fn fix_relative_path(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            return PathBuf::from(path);
        }
        match self.base_path.as_deref() {
            Some(base) => {
                let mut p = PathBuf::from(base);
                p.push(path);
                p
            }
            None => PathBuf::from(path),
        }
    }

    /// generates a Manifest from the ManifestConfiguration
    pub fn to_manifest(&self) -> Result<Manifest> {
        // construct a claim generator for this tool
        let mut claim_generator =
            format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

        // if the config has a claim_generator, add it as the first entry
        if let Some(generator) = self.claim_generator.as_deref() {
            claim_generator = format!("{} {}", generator, claim_generator);
        }

        let mut manifest = Manifest::new(claim_generator);

        if let Some(vendor) = self.vendor.as_deref() {
            manifest.set_vendor(vendor);
        }

        // set the new manifest title if specified
        if let Some(ref t) = self.title {
            manifest.set_title(t);
        };

        if let Some(credentials) = self.credentials.as_ref() {
            for credential in credentials {
                manifest.add_verifiable_credential(credential)?;
            }
        }

        // if the config has a parent, set the parent asset
        let parent = self
            .parent
            .as_deref()
            .map(|parent| self.fix_relative_path(parent));

        if let Some(parent) = parent.as_ref() {
            if !parent.exists() {
                bail!("parent file not found {:#?}", parent);
            }
            manifest.set_parent(Ingredient::from_file(parent)?)?;
        }

        // add all the ingredients (config ingredients do not include the parent)
        if let Some(ingredients) = self.ingredients.as_ref() {
            for ingredient in ingredients {
                let path = self.fix_relative_path(ingredient);
                if !path.exists() {
                    bail!("ingredient file not found {:#?}", path);
                }
                let ingredient = Ingredient::from_file(&path)
                    .with_context(|| format!("loading ingredient {:?}", &path))?;
                manifest.add_ingredient(ingredient);
            }
        }

        // add any assertions
        for assertion in self.assertions() {
            manifest.add_labeled_assertion(assertion.label(), &assertion.value()?)?;
        }

        Ok(manifest)
    }
}
