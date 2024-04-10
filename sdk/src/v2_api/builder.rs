// Copyright 2023 Adobe. All rights reserved.
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
    collections::HashMap,
    io::{Read, Seek, Write},
};

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use uuid::Uuid;
use zip::{write::FileOptions, ZipArchive, ZipWriter};

use crate::{
    assertion::AssertionBase,
    assertions::{labels, Actions, CreativeWork, Exif, SoftwareAgent, Thumbnail, User, UserCbor},
    claim::Claim,
    error::{Error, Result},
    ingredient::Ingredient,
    manifest_assertion::ManifestAssertion,
    resource_store::{skip_serializing_resources, ResourceRef, ResourceResolver, ResourceStore},
    salt::DefaultSalt,
    store::Store,
    utils::mime::format_to_mime,
    ClaimGeneratorInfo, ManifestAssertionKind, RemoteSigner, Signer,
};

/// A Manifest Definition
/// This is used to define a manifest and is used to build a ManifestStore
/// A Manifest is a collection of ingredients and assertions
/// It is used to define a claim that can be signed and embedded into a file
#[skip_serializing_none]
#[derive(Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[non_exhaustive]
pub struct ManifestDefinition {
    /// Optional prefix added to the generated Manifest Label
    /// This is typically Internet domain name for the vendor (i.e. `adobe`)
    pub vendor: Option<String>,

    /// Clam Generator Info is always required with at least one entry
    #[serde(default = "default_claim_generator_info")]
    pub claim_generator_info: Vec<ClaimGeneratorInfo>,

    /// A human-readable title, generally source filename.
    pub title: Option<String>,

    /// The format of the source file as a MIME type.
    #[serde(default = "default_format")]
    pub format: String,

    /// Instance ID from `xmpMM:InstanceID` in XMP metadata.
    #[serde(default = "default_instance_id")]
    pub instance_id: String,

    pub thumbnail: Option<ResourceRef>,

    /// A List of ingredients
    #[serde(default = "default_vec::<Ingredient>")]
    pub ingredients: Vec<Ingredient>,

    /// A List of ingredients references to add to the ingredients
    pub ingredient_refs: Option<Vec<ResourceRef>>,

    /// A list of assertions
    #[serde(default = "default_vec::<ManifestAssertion>")]
    pub assertions: Vec<ManifestAssertion>,

    /// A list of redactions - URIs to a redacted assertions
    pub redactions: Option<Vec<String>>,

    pub label: Option<String>,
}

fn default_instance_id() -> String {
    format!("xmp:iid:{}", Uuid::new_v4())
}

fn default_claim_generator_info() -> Vec<ClaimGeneratorInfo> {
    [ClaimGeneratorInfo::default()].to_vec()
}

fn default_format() -> String {
    "application/octet-stream".to_owned()
}

fn default_vec<T>() -> Vec<T> {
    Vec::new()
}

/// A Builder is used to add a signed manifest to an asset.
///
/// # Example: Building and signing a manifest
///
/// ```
/// # use c2pa::Result;
/// use std::path::PathBuf;
///
/// use c2pa::{create_signer, Builder, SigningAlg};
/// use serde::Serialize;
/// use tempfile::tempdir;
///
/// #[derive(Serialize)]
/// struct Test {
///     my_tag: usize,
/// }
///
/// # fn main() -> Result<()> {
/// let mut builder = Builder::from_json(
///     r#"
///   {
///       "claim_generator_info": [
///          {
///             "name": "c2pa_test",
///             "version": "1.0.0"
///          }
///       ],
///       "title": "Test_Manifest"
///    }
/// "#,
/// )?;
/// builder.add_assertion("org.contentauth.test", &Test { my_tag: 42 })?;
///
/// let source = PathBuf::from("tests/fixtures/C.jpg");
/// let dir = tempdir()?;
/// let dest = dir.path().join("test_file.jpg");
///
/// // Create a ps256 signer using certs and key files
/// let signcert_path = "tests/fixtures/certs/ps256.pub";
/// let pkey_path = "tests/fixtures/certs/ps256.pem";
/// let signer = create_signer::from_files(signcert_path, pkey_path, SigningAlg::Ps256, None)?;
///
/// // embed a manifest using the signer
/// builder.sign(
///     "image/jpeg",
///     &mut std::fs::File::open(&source)?,
///     &mut std::fs::File::create(&dest)?,
///     signer.as_ref(),
/// )?;
/// # Ok(())
/// # }
/// ```
#[skip_serializing_none]
#[derive(Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[non_exhaustive]
pub struct Builder {
    #[serde(flatten)]
    pub definition: ManifestDefinition,

    /// container for binary assets (like thumbnails)
    #[serde(skip_deserializing)]
    #[serde(skip_serializing_if = "skip_serializing_resources")]
    resources: ResourceStore,
}

impl AsRef<Builder> for Builder {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Builder {
    pub fn new() -> Self {
        Builder {
            ..Default::default()
        }
    }

    /// use this JSON content to define the manifest
    pub fn with_json(&mut self, json: &str) -> Result<&mut Self> {
        *self = Self::from_json(json)?;
        Ok(self)
    }

    /// creates a new builder from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(Self {
            definition: serde_json::from_str(json).map_err(Error::JsonError)?,
            ..Default::default()
        })
    }

    /// Sets the mime format for this manifest
    pub fn set_format(&mut self, format: &str) -> &mut Self {
        self.definition.format = format.to_string();
        self
    }

    pub fn set_thumbnail<R>(&mut self, format: &str, stream: &mut R) -> Result<&mut Self>
    where
        R: Read + Seek + ?Sized,
    {
        // just read into a buffer until resource store handles reading streams
        let mut resource = Vec::new();
        stream.read_to_end(&mut resource)?;
        // add the resource and set the resource reference
        self.resources
            .add(&self.definition.instance_id.clone(), resource)?;
        self.definition.thumbnail = Some(ResourceRef::new(
            format,
            self.definition.instance_id.clone(),
        ));
        Ok(self)
    }

    /// Adds an assertion to the manifest
    /// # Arguments
    /// * `label` - A label for the assertion
    /// * `data` - The data for the assertion
    /// # Returns
    /// * A mutable reference to the builder
    /// # Errors
    /// * If the assertion is not valid
    pub fn add_assertion<S, T>(&mut self, label: S, data: &T) -> Result<&mut Self>
    where
        S: Into<String>,
        T: Serialize,
    {
        self.definition
            .assertions
            .push(ManifestAssertion::from_labeled_assertion(label, data)?);
        Ok(self)
    }

    /// Adds an ingredient to the manifest
    /// # Arguments
    /// * `ingredient_json` - A JSON string representing the ingredient
    /// * `format` - The format of the ingredient
    /// * `stream` - A stream to read the ingredient from
    /// # Returns
    /// * A mutable reference to the Ingredient
    /// # Errors
    /// * If the ingredient is not valid
    pub fn add_ingredient<'a, T, R>(
        &'a mut self,
        ingredient_json: T,
        format: &str,
        stream: &mut R,
    ) -> Result<&'a mut Ingredient>
    where
        T: Into<String>,
        R: Read + Seek + Send,
    {
        let ingredient: Ingredient = Ingredient::from_json(&ingredient_json.into())?;
        let ingredient = ingredient.with_stream(format, stream)?;
        self.definition.ingredients.push(ingredient);
        #[allow(clippy::unwrap_used)]
        Ok(self.definition.ingredients.last_mut().unwrap()) // ok since we just added it
    }

    /// Adds a resource to the manifest
    /// The id should match up with an identifier in the manifest
    /// # Arguments
    /// * `id` - The identifier for the resource
    /// * `stream` - A stream to read the resource from
    /// # Returns
    /// * A mutable reference to the builder
    /// # Errors
    /// * If the resource is not valid
    pub fn add_resource<R>(&mut self, id: &str, stream: &mut R) -> Result<&mut Self>
    where
        R: Read + Seek + Send,
    {
        if self.resources.exists(id) {
            return Err(Error::BadParam(id.to_string())); // todo add specific error
        }
        let mut buf = Vec::new();
        let _size = stream.read_to_end(&mut buf)?;
        self.resources.add(id, buf)?;
        Ok(self)
    }

    /// Convert the Builder into a zip formatted stream
    /// # Arguments
    /// * `stream` - A stream to write the zip to
    /// # Errors
    /// * If the zip cannot be written
    pub fn zip(&mut self, stream: impl Write + Seek) -> Result<()> {
        drop(
            // this drop seems to be required to force a flush before reading back.
            {
                let mut zip = ZipWriter::new(stream);
                let options =
                    FileOptions::default().compression_method(zip::CompressionMethod::Stored);
                zip.start_file("manifest.json", options)
                    .map_err(|e| Error::OtherError(Box::new(e)))?;
                zip.write_all(&serde_json::to_vec(self)?)?;
                // add a folder to the zip file
                zip.start_file("resources/", options)
                    .map_err(|e| Error::OtherError(Box::new(e)))?;
                for (id, data) in self.resources.resources() {
                    zip.start_file(format!("resources/{}", id), options)
                        .map_err(|e| Error::OtherError(Box::new(e)))?;
                    zip.write_all(data)?;
                }
                for (index, ingredient) in self.definition.ingredients.iter().enumerate() {
                    zip.start_file(format!("ingredients/{}/", index), options)
                        .map_err(|e| Error::OtherError(Box::new(e)))?;
                    for (id, data) in ingredient.resources().resources() {
                        //println!("adding ingredient {}/{}", index, id);
                        zip.start_file(format!("ingredients/{}/{}", index, id), options)
                            .map_err(|e| Error::OtherError(Box::new(e)))?;
                        zip.write_all(data)?;
                    }
                }
                zip.finish()
            }
            .map_err(|e| Error::OtherError(Box::new(e)))?,
        );
        Ok(())
    }

    //#[allow(clippy::unwrap_used)]
    /// Unzip a stream into a Builder
    /// # Arguments
    /// * `stream` - A stream to read the zip from
    /// # Returns
    /// * A new Builder
    /// # Errors
    /// * If the zip cannot be read
    pub fn unzip(stream: impl Read + Seek) -> Result<Self> {
        let mut zip = ZipArchive::new(stream).map_err(|e| Error::OtherError(Box::new(e)))?;
        let mut manifest = zip
            .by_name("manifest.json")
            .map_err(|e| Error::OtherError(Box::new(e)))?;
        let mut manifest_json = Vec::new();
        manifest.read_to_end(&mut manifest_json)?;
        let mut builder: Builder =
            serde_json::from_slice(&manifest_json).map_err(|e| Error::OtherError(Box::new(e)))?;
        drop(manifest);
        for i in 0..zip.len() {
            let mut file = zip
                .by_index(i)
                .map_err(|e| Error::OtherError(Box::new(e)))?;

            if file.name().starts_with("resources/") && file.name() != "resources/" {
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                let id = file
                    .name()
                    .split('/')
                    .nth(1)
                    .ok_or(Error::BadParam("Invalid resource path".to_string()))?;
                //println!("adding resource {}", id);
                builder.resources.add(id, data)?;
            }
            if file.name().starts_with("ingredients/") && file.name() != "ingredients/" {
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                let index: usize = file
                    .name()
                    .split('/')
                    .nth(1)
                    .ok_or_else(|| Error::BadParam("Invalid ingredient path".to_string()))?
                    .parse::<usize>()
                    .map_err(|_| Error::BadParam("Invalid ingredient path".to_string()))?;
                let id = file.name().split('/').nth(2).unwrap_or_default();
                if index >= builder.definition.ingredients.len() {
                    return Err(Error::OtherError(Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Invalid ingredient index {}", index),
                    ))))?; // todo add specific error
                }
                builder.definition.ingredients[index]
                    .resources_mut()
                    .add(id, data)?;
            }
        }
        Ok(builder)
    }

    // Convert a Manifest into a Claim
    fn to_claim(&self) -> Result<Claim> {
        let definition = &self.definition;
        let mut claim_generator_info = definition.claim_generator_info.clone();
        // add the default claim generator info for this library
        claim_generator_info.push(ClaimGeneratorInfo::default());

        // build the claim_generator string since this is required
        let claim_generator: String = claim_generator_info
            .iter()
            .map(|s| {
                let name = s.name.replace(' ', "_");
                if let Some(version) = s.version.as_deref() {
                    format!("{}/{}", name.to_lowercase(), version)
                } else {
                    name
                }
            })
            .collect::<Vec<String>>()
            .join(" ");

        let mut claim = match definition.label.as_ref() {
            Some(label) => Claim::new_with_user_guid(&claim_generator, &label.to_string()),
            None => Claim::new(&claim_generator, definition.vendor.as_deref()),
        };

        // add claim generator info to claim resolving icons
        for info in &claim_generator_info {
            let mut claim_info = info.to_owned();
            if let Some(icon) = claim_info.icon.as_ref() {
                claim_info.icon = Some(icon.to_hashed_uri(&self.resources, &mut claim)?);
            }
            claim.add_claim_generator_info(claim_info);
        }

        // if let Some(remote_op) = &self.remote_manifest {
        //     match remote_op {
        //         RemoteManifest::NoRemote => (),
        //         RemoteManifest::SideCar => claim.set_external_manifest(),
        //         RemoteManifest::Remote(r) => claim.set_remote_manifest(r)?,
        //         RemoteManifest::EmbedWithRemote(r) => claim.set_embed_remote_manifest(r)?,
        //     };
        // }

        if let Some(title) = definition.title.as_ref() {
            claim.set_title(Some(title.to_owned()));
        }
        claim.format = definition.format.to_owned();
        claim.instance_id = definition.instance_id.to_owned();

        if let Some(thumb_ref) = definition.thumbnail.as_ref() {
            // Setting the format to "none" will ensure that no claim thumbnail is added
            if thumb_ref.format != "none" {
                //let data = self.resources.get(&thumb_ref.identifier)?;
                let mut stream = self.resources.open(thumb_ref)?;
                let mut data = Vec::new();
                stream.read_to_end(&mut data)?;
                claim.add_assertion(&Thumbnail::new(
                    &labels::add_thumbnail_format(labels::CLAIM_THUMBNAIL, &thumb_ref.format),
                    data,
                ))?;
            }
        }

        let mut ingredient_map = HashMap::new();
        // add all ingredients to the claim
        for ingredient in &definition.ingredients {
            //let ingredient = ingredient_builder.build(self)?;
            let uri = ingredient.add_to_claim(
                &mut claim,
                definition.redactions.clone(),
                Some(&self.resources),
            )?;
            ingredient_map.insert(ingredient.instance_id().to_string(), uri);
        }

        // add ingredient references, resolving streams and processing them
        if let Some(ingredient_refs) = definition.ingredient_refs.as_ref() {
            for ingredient_ref in ingredient_refs {
                let mut stream = self.resources.open(ingredient_ref)?;
                let mut ingredient = Ingredient::from_stream(&ingredient_ref.format, &mut *stream)?;
                ingredient.set_title(&ingredient_ref.identifier);
                let uri = ingredient.add_to_claim(
                    &mut claim,
                    definition.redactions.clone(),
                    Some(&self.resources),
                )?;
                ingredient_map.insert(ingredient.instance_id().to_string(), uri);
            }
        }

        let salt = DefaultSalt::default();

        // add any additional assertions
        for manifest_assertion in &definition.assertions {
            match manifest_assertion.label() {
                l if l.starts_with(Actions::LABEL) => {
                    let version = labels::version(l);

                    let mut actions: Actions = manifest_assertion.to_assertion()?;

                    let ingredients_key = match version {
                        None | Some(1) => "ingredient",
                        Some(2) => "ingredients",
                        _ => return Err(Error::AssertionUnsupportedVersion),
                    };

                    // fixup parameters field from instance_id to ingredient uri
                    let needs_ingredient: Vec<(usize, crate::assertions::Action)> = actions
                        .actions()
                        .iter()
                        .enumerate()
                        .filter_map(|(i, a)| {
                            if a.instance_id().is_some()
                                && a.get_parameter(ingredients_key).is_none()
                            {
                                Some((i, a.clone()))
                            } else {
                                None
                            }
                        })
                        .collect();

                    for (index, action) in needs_ingredient {
                        if let Some(id) = action.instance_id() {
                            if let Some(hash_url) = ingredient_map.get(id) {
                                let update = match ingredients_key {
                                    "ingredient" => {
                                        action.set_parameter(ingredients_key, hash_url.clone())
                                    }
                                    _ => {
                                        // we only support on instanceId for actions, so only one ingredient on writing
                                        action.set_parameter(ingredients_key, [hash_url.clone()])
                                    }
                                }?;
                                actions = actions.update_action(index, update);
                            }
                        }
                    }

                    if let Some(templates) = actions.templates.as_mut() {
                        for template in templates {
                            // replace icon with hashed_uri
                            template.icon = match template.icon.take() {
                                Some(icon) => {
                                    Some(icon.to_hashed_uri(&self.resources, &mut claim)?)
                                }
                                None => None,
                            };

                            // replace software agent with hashed_uri
                            template.software_agent = match template.software_agent.take() {
                                Some(SoftwareAgent::ClaimGeneratorInfo(mut info)) => {
                                    if let Some(icon) = info.icon.as_mut() {
                                        let icon =
                                            icon.to_hashed_uri(&self.resources, &mut claim)?;
                                        info.set_icon(icon);
                                    }
                                    Some(SoftwareAgent::ClaimGeneratorInfo(info))
                                }
                                agent => agent,
                            };
                        }
                    }

                    // convert icons in software agents to hashed uris
                    let actions_mut = actions.actions_mut();
                    #[allow(clippy::needless_range_loop)]
                    // clippy is wrong here, we reference index twice
                    for index in 0..actions_mut.len() {
                        let action = &actions_mut[index];
                        if let Some(SoftwareAgent::ClaimGeneratorInfo(info)) =
                            action.software_agent()
                        {
                            if let Some(icon) = info.icon.as_ref() {
                                let mut info = info.to_owned();
                                let icon_uri = icon.to_hashed_uri(&self.resources, &mut claim)?;
                                let update = info.set_icon(icon_uri);
                                let mut action = action.to_owned();
                                action = action.set_software_agent(update.to_owned());
                                actions_mut[index] = action;
                            }
                        }
                    }

                    claim.add_assertion(&actions)
                }
                CreativeWork::LABEL => {
                    let cw: CreativeWork = manifest_assertion.to_assertion()?;
                    // insert a credentials field if we have a vc that matches the identifier
                    // todo: this should apply to any person, not just author
                    // if let Some(cw_authors) = cw.author() {
                    //     let mut authors = Vec::new();
                    //     for a in cw_authors {
                    //         authors.push(
                    //             a.identifier()
                    //                 .and_then(|i| {
                    //                     vc_table
                    //                         .get(&i)
                    //                         .map(|uri| a.clone().add_credential(uri.clone()))
                    //                 })
                    //                 .unwrap_or_else(|| Ok(a.clone()))?,
                    //         );
                    //     }
                    //     cw = cw.set_author(&authors)?;
                    // }
                    claim.add_assertion_with_salt(&cw, &salt)
                }
                Exif::LABEL => {
                    let exif: Exif = manifest_assertion.to_assertion()?;
                    claim.add_assertion_with_salt(&exif, &salt)
                }
                _ => match manifest_assertion.kind() {
                    ManifestAssertionKind::Cbor => claim.add_assertion_with_salt(
                        &UserCbor::new(
                            manifest_assertion.label(),
                            serde_cbor::to_vec(&manifest_assertion.value()?)?,
                        ),
                        &salt,
                    ),
                    ManifestAssertionKind::Json => claim.add_assertion_with_salt(
                        &User::new(
                            manifest_assertion.label(),
                            &serde_json::to_string(&manifest_assertion.value()?)?,
                        ),
                        &salt,
                    ),
                    ManifestAssertionKind::Binary => {
                        // todo: Support binary kinds
                        return Err(Error::AssertionEncoding);
                    }
                    ManifestAssertionKind::Uri => {
                        // todo: Support binary kinds
                        return Err(Error::AssertionEncoding);
                    }
                },
            }?;
        }

        Ok(claim)
    }

    // Convert a Manifest into a Store
    fn to_store(&self) -> Result<Store> {
        let claim = self.to_claim()?;
        // commit the claim
        let mut store = Store::new();
        let _provenance = store.commit_claim(claim)?;
        Ok(store)
    }

    #[cfg(feature = "add_thumbnails")]
    fn maybe_add_thumbnail<R>(&mut self, format: &str, stream: &mut R) -> Result<&mut Self>
    where
        R: Read + Seek + ?Sized,
    {
        if self.definition.thumbnail.is_none() {
            stream.rewind()?;
            if let Ok((format, image)) =
                crate::utils::thumbnail::make_thumbnail_from_stream(format, stream)
            {
                stream.rewind()?;
                self.resources
                    .add(&self.definition.instance_id.clone(), image)?;
                self.definition.thumbnail = Some(ResourceRef::new(
                    format,
                    self.definition.instance_id.clone(),
                ));
            }
        }
        Ok(self)
    }

    /// Embed a signed manifest into a stream using a supplied signer.
    /// # Arguments
    /// * `format` - The format of the stream
    /// * `source` - The stream to read from
    /// * `dest` - The stream to write to
    /// * `signer` - The signer to use
    /// # Returns
    /// * The bytes of c2pa_manifest that was embedded
    /// # Errors
    /// * If the manifest cannot be signed
    pub fn sign<R, W>(
        &mut self,
        format: &str,
        source: &mut R,
        dest: &mut W,
        signer: &dyn Signer,
    ) -> Result<Vec<u8>>
    where
        R: Read + Seek + Send,
        W: Write + Read + Seek + Send,
    {
        let format = format_to_mime(format);
        self.definition.format = format.clone();
        // todo:: read instance_id from xmp from stream ?
        self.definition.instance_id = format!("xmp:iid:{}", Uuid::new_v4());

        // generate thumbnail if we don't already have one
        #[cfg(feature = "add_thumbnails")]
        self.maybe_add_thumbnail(&format, source)?;

        // convert the manifest to a store
        let mut store = self.to_store()?;

        // sign and write our store to to the output image file
        store.save_to_stream(&format, source, dest, signer)
    }

    /// Embed a signed manifest into a stream using a supplied remote signer.
    /// # Arguments
    /// * `format` - The format of the stream
    /// * `source` - The stream to read from
    /// * `dest` - The stream to write to
    /// * `signer` - The signer to use
    /// # Returns
    /// * The bytes of c2pa_manifest that was embedded
    /// # Errors
    /// * If the manifest cannot be signed
    pub async fn sign_remote<R, W>(
        &mut self,
        format: &str,
        source: &mut R,
        dest: &mut W,
        signer: &dyn RemoteSigner,
    ) -> Result<Vec<u8>>
    where
        R: Read + Seek + Send,
        W: Write + Read + Seek + Send,
    {
        self.definition.format = format_to_mime(format);
        // todo:: read instance_id from xmp from stream ?
        self.definition.instance_id = format!("xmp:iid:{}", Uuid::new_v4());

        // generate thumbnail if we don't already have one
        #[cfg(feature = "add_thumbnails")]
        self.maybe_add_thumbnail(format, source)?;

        // convert the manifest to a store
        let mut store = self.to_store()?;

        // sign and write our store to to the output image file
        store
            .save_to_stream_remote_signed(format, source, dest, signer)
            .await
    }

    #[cfg(feature = "file_io")]
    /// Sign a file using a supplied signer
    /// # Arguments
    /// * `source` - The path to the file to read from
    /// * `dest` - The path to the file to write to (this must not already exist)
    /// * `signer` - The signer to use
    /// # Returns
    /// * The bytes of c2pa_manifest that was created
    /// # Errors
    /// * If the manifest cannot be signed
    pub fn sign_file<S, D>(&mut self, source: S, dest: D, signer: &dyn Signer) -> Result<Vec<u8>>
    where
        S: AsRef<std::path::Path>,
        D: AsRef<std::path::Path>,
    {
        let source = source.as_ref();
        let dest = dest.as_ref();
        // formats must match but allow extensions to be slightly different (i.e. .jpeg vs .jpg)s
        let format = crate::format_from_path(source).ok_or(crate::Error::UnsupportedType)?;
        let format_dest = crate::format_from_path(dest).ok_or(crate::Error::UnsupportedType)?;
        if format != format_dest {
            return Err(crate::Error::BadParam(
                "Source and destination file formats must match".to_string(),
            ));
        }
        let mut source = std::fs::File::open(source)?;
        if !dest.exists() {
            // ensure the path to the file exists
            if let Some(output_dir) = dest.parent() {
                std::fs::create_dir_all(output_dir)?;
            }
        } else {
            // if the file exists, we need to remove it to avoid appending to it
            return Err(crate::Error::BadParam(
                "Destination file already exists".to_string(),
            ));
        };
        let mut dest = std::fs::File::create(dest)?;

        self.sign(&format, &mut source, &mut dest, signer)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    use std::io::{Cursor, Seek};

    use serde_json::Value;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    use super::*;
    use crate::{
        manifest_assertion::ManifestAssertion, manifest_store::ManifestStore,
        utils::test::temp_signer,
    };
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    const PARENT_JSON: &str = r#"
    {
        "title": "Parent Test",
        "format": "image/jpeg",
        "instance_id": "12345",
        "relationship": "parentOf"
    }
    "#;

    const JSON: &str = r#"
    {
        "vendor": "test",
        "claim_generator_info": [
            {
                "name": "c2pa_test",
                "version": "1.0.0"
            }
        ], 
        "title": "Test_Manifest",
        "format": "image/tiff",
        "instance_id": "1234",
        "thumbnail": {
            "format": "image/jpeg",
            "identifier": "thumbnail1.jpg"
        },
        "ingredients": [
            {
                "title": "Test",
                "format": "image/jpeg",
                "instance_id": "12345",
                "relationship": "componentOf"
            }
        ],
        "ingredient_refs": [
            {
                "format": "image/jpeg",
                "identifier": "thumbnail1.jpg"
            }
        ],
        "assertions": [
            {
                "label": "org.test.assertion",
                "data": "assertion"
            }
        ]
    }
    "#;

    const TEST_IMAGE: &[u8] = include_bytes!("../../tests/fixtures/CA.jpg");

    #[test]
    fn test_manifest_store_builder() {
        let mut image = Cursor::new(TEST_IMAGE);

        let thumbnail_ref = ResourceRef::new("ingredient/jpeg", "5678");

        let mut builder = Builder::new();
        let mut definition = ManifestDefinition {
            claim_generator_info: [ClaimGeneratorInfo::default()].to_vec(),
            format: "image/tiff".to_string(),
            instance_id: "1234".to_string(),
            ..Default::default()
        };
        definition.vendor = Some("test".to_string());
        definition.title = Some("Test_Manifest".to_string());
        definition.thumbnail = Some(thumbnail_ref.clone());

        let ingredient = Ingredient::from_json(PARENT_JSON)
            .unwrap()
            .with_stream("application/jpeg", &mut image)
            .unwrap();
        definition.ingredients.push(ingredient);

        definition.assertions = vec![ManifestAssertion::new(
            "org.test.assertion".to_string(),
            Value::from("assertion"),
        )];
        definition.redactions = Some(vec!["redaction".to_string()]);
        definition.label = Some("ABCDE".to_string());
        builder
            .resources
            .add(&thumbnail_ref.identifier, *b"12345")
            .unwrap();
        builder.definition = definition;

        let definition = &builder.definition;
        assert_eq!(definition.vendor, Some("test".to_string()));
        assert_eq!(definition.title, Some("Test_Manifest".to_string()));
        assert_eq!(definition.format, "image/tiff".to_string());
        assert_eq!(definition.instance_id, "1234".to_string());
        assert_eq!(definition.thumbnail, Some(thumbnail_ref));
        assert_eq!(definition.ingredients[0].title(), "Parent Test".to_string());
        assert_eq!(
            definition.assertions[0].label(),
            "org.test.assertion".to_string()
        );
        assert_eq!(definition.redactions, Some(vec!["redaction".to_string()]));
        assert_eq!(definition.label, Some("ABCDE".to_string()));
        assert_eq!(
            builder
                .resources
                .get(&builder.definition.thumbnail.unwrap().identifier)
                .unwrap()
                .into_owned(),
            b"12345"
        );
    }

    #[test]
    fn test_from_json() {
        // strip whitespace so we can compare later
        let mut stripped_json = JSON.to_string();
        stripped_json.retain(|c| !c.is_whitespace());
        let mut builder = Builder::from_json(&stripped_json).unwrap();
        builder.resources.add("5678", "12345").unwrap();
        let definition = &builder.definition;
        assert_eq!(definition.vendor, Some("test".to_string()));
        assert_eq!(definition.title, Some("Test_Manifest".to_string()));
        assert_eq!(definition.format, "image/tiff".to_string());
        assert_eq!(definition.instance_id, "1234".to_string());
        assert_eq!(
            definition.thumbnail.clone().unwrap().identifier.as_str(),
            "thumbnail1.jpg"
        );
        assert_eq!(definition.ingredients[0].title(), "Test".to_string());
        assert_eq!(
            definition.assertions[0].label(),
            "org.test.assertion".to_string()
        );

        // convert back to json and compare to original
        let builder_json = serde_json::to_string(&builder.definition).unwrap();
        assert_eq!(builder_json, stripped_json);
    }

    // const TEST_IMAGE_TIF: &[u8] = include_bytes!("../../tests/fixtures/TUSCANY.TIF");
    // #[test]
    // fn test_builder_sign_tiff() {
    //     let format = "image/tiff";
    //     let mut source = Cursor::new(TEST_IMAGE_TIF);
    //     let mut dest = Cursor::new(Vec::new());

    //     let mut builder = Builder::from_json(JSON).unwrap();
    //     builder
    //         .add_ingredient(PARENT_JSON, format, &mut source)
    //         .unwrap();

    //     builder
    //         .resources
    //         .add("thumbnail1.jpg", TEST_IMAGE.to_vec())
    //         .unwrap();

    //     // sign the ManifestStoreBuilder and write it to the output stream
    //     let signer = temp_signer();
    //     builder
    //         .sign(format, &mut source, &mut dest, signer.as_ref())
    //         .unwrap();

    //     // read and validate the signed manifest store
    //     dest.rewind().unwrap();
    //     let manifest_store =
    //         crate::ManifestStore::from_stream(format, &mut dest, true).expect("from_bytes");

    //     println!("{}", manifest_store);
    //     assert!(manifest_store.validation_status().is_none());
    //     assert_eq!(
    //         manifest_store.get_active().unwrap().title().unwrap(),
    //         "Test_Manifest"
    //     );
    // }

    #[test]
    fn test_builder_sign() {
        #[derive(Serialize, Deserialize)]
        struct TestAssertion {
            answer: usize,
        }
        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::from_json(JSON).unwrap();
        builder
            .add_ingredient(PARENT_JSON, format, &mut source)
            .unwrap();

        builder
            .resources
            .add("thumbnail1.jpg", TEST_IMAGE.to_vec())
            .unwrap();

        builder
            .add_assertion("org.life.meaning", &TestAssertion { answer: 42 })
            .unwrap();

        // write the manifest builder to a zipped stream
        let mut zipped = Cursor::new(Vec::new());
        builder.zip(&mut zipped).unwrap();

        // write the zipped stream to a file for debugging
        std::fs::write("../target/test.zip", zipped.get_ref()).unwrap();

        // unzip the manifest builder from the zipped stream
        zipped.rewind().unwrap();
        let mut _builder = Builder::unzip(&mut zipped).unwrap();

        // sign the ManifestStoreBuilder and write it to the output stream
        let signer = temp_signer();
        builder
            .sign(format, &mut source, &mut dest, signer.as_ref())
            .unwrap();

        // read and validate the signed manifest store
        dest.rewind().unwrap();
        let manifest_store =
            ManifestStore::from_stream(format, &mut dest, true).expect("from_bytes");

        println!("{}", manifest_store);
        assert!(manifest_store.validation_status().is_none());
        assert!(manifest_store.get_active().is_some());
        let manifest = manifest_store.get_active().unwrap();
        assert_eq!(manifest.title().unwrap(), "Test_Manifest");
        let test_assertion: TestAssertion = manifest.find_assertion("org.life.meaning").unwrap();
        assert_eq!(test_assertion.answer, 42);
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_builder_sign_file() {
        let source = "tests/fixtures/CA.jpg";
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("test_file.jpg");

        let mut builder = Builder::from_json(JSON).unwrap();

        builder
            .resources
            .add("thumbnail1.jpg", TEST_IMAGE.to_vec())
            .unwrap();

        // sign the ManifestStoreBuilder and write it to the output stream
        let signer = temp_signer();
        builder.sign_file(source, &dest, signer.as_ref()).unwrap();

        // read and validate the signed manifest store
        let manifest_store = ManifestStore::from_file(&dest).expect("from_bytes");

        println!("{}", manifest_store);
        assert!(manifest_store.validation_status().is_none());
        assert_eq!(
            manifest_store.get_active().unwrap().title().unwrap(),
            "Test_Manifest"
        );
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_builder_sign_assets() {
        const TESTFILES: &[&str] = &[
            "IMG_0003.jpg",
            "sample1.png",
            "sample1.webp",
            "tuscany.tif",
            "sample1.svg",
            //"APC_0808.dng",
            "sample1.wav",
            "test.avi",
            //"sample1.mp3",
            //"sample1.avif",
            //"sample1.heic",
            //"sample1.heif",
            //"video1.mp4",
            //"cloud_manifest.c2pa",
        ];
        for file_name in TESTFILES {
            let extension = file_name.split('.').last().unwrap();
            let format = extension;

            let path = format!("tests/fixtures/{}", file_name);
            println!("path: {}", path);
            let mut source = std::fs::File::open(path).unwrap();
            let mut dest = Cursor::new(Vec::new());

            let mut builder = Builder::from_json(JSON).unwrap();
            builder
                .add_ingredient(PARENT_JSON, format, &mut source)
                .unwrap();

            builder
                .resources
                .add("thumbnail1.jpg", TEST_IMAGE.to_vec())
                .unwrap();

            // sign the ManifestStoreBuilder and write it to the output stream
            let signer = temp_signer();
            builder
                .sign(format, &mut source, &mut dest, signer.as_ref())
                .unwrap();

            // read and validate the signed manifest store
            dest.rewind().unwrap();
            let manifest_store =
                ManifestStore::from_stream(format, &mut dest, true).expect("from_bytes");

            println!("{}", manifest_store);
            assert!(manifest_store.validation_status().is_none());
            assert_eq!(
                manifest_store.get_active().unwrap().title().unwrap(),
                "Test_Manifest"
            );

            // enable to write the signed manifests to a file for debugging
            // let dest_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            //     .join("../target")
            //     .join("signed")
            //     .join(file_name);

            // std::fs::create_dir_all(dest_path.parent().unwrap()).unwrap();
            // std::fs::write(&dest_path, dest.get_ref()).unwrap();
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn test_builder_remote_sign() {
        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::from_json(JSON).unwrap();
        builder
            .add_ingredient(PARENT_JSON, format, &mut source)
            .unwrap();

        builder
            .resources
            .add("thumbnail1.jpg", TEST_IMAGE.to_vec())
            .unwrap();

        // sign the ManifestStoreBuilder and write it to the output stream
        let signer = crate::utils::test::temp_remote_signer();
        builder
            .sign_remote(format, &mut source, &mut dest, signer.as_ref())
            .await
            .unwrap();

        // read and validate the signed manifest store
        dest.rewind().unwrap();
        let manifest_store =
            ManifestStore::from_stream(format, &mut dest, true).expect("from_bytes");

        println!("{}", manifest_store);
        #[cfg(not(target_arch = "wasm32"))] // skip this until we get wasm async signing working
        assert!(manifest_store.validation_status().is_none());
        assert_eq!(
            manifest_store.get_active().unwrap().title().unwrap(),
            "Test_Manifest"
        );
    }
}
