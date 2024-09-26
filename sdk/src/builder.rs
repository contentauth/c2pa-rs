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

#[cfg(feature = "file_io")]
use std::path::PathBuf;
use std::{
    collections::HashMap,
    io::{Read, Seek, Write},
};

use async_generic::async_generic;
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::skip_serializing_none;
use uuid::Uuid;
use zip::{write::FileOptions, ZipArchive, ZipWriter};

use crate::{
    assertion::AssertionDecodeError,
    assertions::{
        labels, Actions, CreativeWork, DataHash, Exif, Metadata, SoftwareAgent, Thumbnail, User,
        UserCbor,
    },
    claim::Claim,
    error::{Error, Result},
    // manifest_definition::{AssertionData, AssertionDefinition, ManifestDefinition},
    resource_store::{ResourceRef, ResourceResolver, ResourceStore},
    salt::DefaultSalt,
    store::Store,
    utils::mime::format_to_mime,
    AsyncSigner,
    ClaimGeneratorInfo,
    HashRange,
    Ingredient,
    Signer,
};

/// Version of the Builder Archive file
const ARCHIVE_VERSION: &str = "1";

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

    /// Optional manifest metadata
    pub metadata: Option<Vec<Metadata>>,

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

    /// A list of assertions
    #[serde(default = "default_vec::<AssertionDefinition>")]
    pub assertions: Vec<AssertionDefinition>,

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

#[derive(Debug, Deserialize, Serialize, Clone)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[serde(untagged)]
pub enum AssertionData {
    #[cfg_attr(feature = "json_schema", schemars(skip))]
    Cbor(serde_cbor::Value),
    Json(serde_json::Value),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[non_exhaustive]
pub struct AssertionDefinition {
    pub label: String,
    pub data: AssertionData,
}
impl AssertionDefinition {
    pub(crate) fn to_assertion<T: DeserializeOwned>(&self) -> Result<T> {
        match &self.data {
            AssertionData::Json(value) => serde_json::from_value(value.clone()).map_err(|e| {
                Error::AssertionDecoding(AssertionDecodeError::from_err(
                    self.label.to_owned(),
                    None,
                    "application/json".to_owned(),
                    e,
                ))
            }),
            AssertionData::Cbor(value) => {
                serde_cbor::value::from_value(value.clone()).map_err(|e| {
                    Error::AssertionDecoding(AssertionDecodeError::from_err(
                        self.label.to_owned(),
                        None,
                        "application/cbor".to_owned(),
                        e,
                    ))
                })
            }
        }
    }
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
/// use serde_json::json;
/// use tempfile::tempdir;
///
/// #[derive(Serialize)]
/// struct Test {
///     my_tag: usize,
/// }
///
/// # fn main() -> Result<()> {
/// let manifest_json = json!({
///    "claim_generator_info": [
///       {
///           "name": "c2pa_test",
///           "version": "1.0.0"
///       }
///    ],
///    "title": "Test_Manifest"
/// }).to_string();
///
/// let mut builder = Builder::from_json(&manifest_json)?;
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
///     signer.as_ref(),
///     "image/jpeg",
///     &mut std::fs::File::open(&source)?,
///     &mut std::fs::File::create(&dest)?,
/// )?;
/// # Ok(())
/// # }
/// ```
#[skip_serializing_none]
#[derive(Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct Builder {
    #[serde(flatten)]
    pub definition: ManifestDefinition,

    /// Optional remote URL for the manifest
    pub remote_url: Option<String>,

    // If true, the manifest store will not be embedded in the asset on sign
    pub no_embed: bool,

    /// Base path to search for resources.
    #[cfg(feature = "file_io")]
    pub base_path: Option<PathBuf>,

    /// container for binary assets (like thumbnails)
    #[serde(skip)]
    resources: ResourceStore,
}

impl AsRef<Builder> for Builder {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Builder {
    /// Creates a new builder.
    /// # Returns
    /// * A new [`Builder`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a new builder from a JSON [`ManifestDefinition`] string.
    ///
    /// # Arguments
    /// * `json` - A JSON string representing the [`ManifestDefinition`].
    /// # Returns
    /// * A new [`Builder`].
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(Self {
            definition: serde_json::from_str(json).map_err(Error::JsonError)?,
            ..Default::default()
        })
    }

    /// Sets the ClaimGeneratorInfo for this [`Builder`]
    pub fn set_claim_generator_info<I>(&mut self, claim_generator_info: I) -> &mut Self
    where
        I: Into<ClaimGeneratorInfo>,
    {
        self.definition.claim_generator_info = [claim_generator_info.into()].to_vec();
        self
    }

    /// Sets the MIME format for this [`Builder`].
    ///
    /// # Arguments
    /// * `format` - The format of the asset associated with this [`Builder`].
    /// # Returns
    /// * A mutable reference to the [`Builder`].
    pub fn set_format<S: Into<String>>(&mut self, format: S) -> &mut Self {
        self.definition.format = format.into();
        self
    }

    /// Sets the remote_url for this [`Builder`].
    /// The url will be injected into the destination asset when signing.
    /// The signed manifest should be made accessible at that URL for retrieval.
    /// For remote manifests, the no_embed flag should be set to true.
    /// # Arguments
    /// * `url` - The URL where the manifest will be available.
    /// # Returns
    /// * A mutable reference to the [`Builder`].
    pub fn set_remote_url<S: Into<String>>(&mut self, url: S) -> &mut Self {
        self.remote_url = Some(url.into());
        self
    }

    /// Sets the no_embed flag for this [`Builder`].
    /// If true, the manifest store will not be embedded in the destination asset on sign.
    /// This is useful for sidecar and remote manifests.
    /// # Arguments
    /// * `no_embed` - A boolean flag to set the no_embed flag.
    /// # Returns
    /// * A mutable reference to the [`Builder`].
    pub fn set_no_embed(&mut self, no_embed: bool) -> &mut Self {
        self.no_embed = no_embed;
        self
    }

    /// Sets a thumbnail for the [`Builder`].
    ///
    /// The thumbnail should represent the associated asset for this [`Builder`].
    ///
    /// # Arguments
    /// * `format` - The format of the thumbnail.
    /// * `stream` - A stream to read the thumbnail from.
    /// # Returns
    /// * A mutable reference to the [`Builder`].
    /// # Errors
    /// * If the thumbnail is not valid.
    pub fn set_thumbnail<S, R>(&mut self, format: S, stream: &mut R) -> Result<&mut Self>
    where
        S: Into<String>,
        R: Read + Seek + ?Sized,
    {
        // just read into a buffer until resource store handles reading streams
        let mut resource = Vec::new();
        stream.read_to_end(&mut resource)?;
        // add the resource and set the resource reference
        self.resources.add(&self.definition.instance_id, resource)?;
        self.definition.thumbnail = Some(ResourceRef::new(
            format,
            self.definition.instance_id.clone(),
        ));
        Ok(self)
    }

    /// Adds a CBOR assertion to the manifest.
    /// # Arguments
    /// * `label` - A label for the assertion.
    /// * `data` - The data for the assertion. The data is any Serde Serializable type.
    /// # Returns
    /// * A mutable reference to the [`Builder`].
    /// # Errors
    /// * If the assertion is not valid.
    pub fn add_assertion<S, T>(&mut self, label: S, data: &T) -> Result<&mut Self>
    where
        S: Into<String>,
        T: Serialize,
    {
        self.definition.assertions.push(AssertionDefinition {
            label: label.into(),
            data: AssertionData::Cbor(serde_cbor::value::to_value(data)?),
        });
        Ok(self)
    }

    /// Adds a Json assertion to the manifest.
    /// # Arguments
    /// * `label` - A label for the assertion.
    /// * `data` - The data for the assertion. The data is any Serde Serializable type.
    /// # Returns
    /// * A mutable reference to the [`Builder`].
    /// # Errors
    /// * If the assertion is not valid.
    pub fn add_assertion_json<S, T>(&mut self, label: S, data: &T) -> Result<&mut Self>
    where
        S: Into<String>,
        T: Serialize,
    {
        self.definition.assertions.push(AssertionDefinition {
            label: label.into(),
            data: AssertionData::Json(serde_json::to_value(data)?),
        });
        Ok(self)
    }

    /// Adds an [`Ingredient`] to the manifest with JSON and a stream.
    /// # Arguments
    /// * `ingredient_json` - A JSON string representing the [`Ingredient`].
    /// * `format` - The format of the [`Ingredient`].
    /// * `stream` - A stream to read the [`Ingredient`] from.
    /// # Returns
    /// * A mutable reference to the [`Ingredient`].
    /// # Errors
    /// * If the [`Ingredient`] is not valid
    #[async_generic()]
    pub fn add_ingredient_from_stream<'a, T, R>(
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
        let ingredient = if _sync {
            ingredient.with_stream(format, stream)?
        } else {
            ingredient.with_stream_async(format, stream).await?
        };
        self.definition.ingredients.push(ingredient);
        #[allow(clippy::unwrap_used)]
        Ok(self.definition.ingredients.last_mut().unwrap()) // ok since we just added it
    }

    /// Adds an [`Ingredient`] to the manifest from an existing Ingredient.
    pub fn add_ingredient<I>(&mut self, ingredient: I) -> &mut Self
    where
        I: Into<Ingredient>,
    {
        self.definition.ingredients.push(ingredient.into());
        self
    }

    /// Adds a resource to the manifest.
    /// The id should match up with an identifier in the manifest.
    /// # Arguments
    /// * `id` - The identifier for the resource.
    /// * `stream` - A stream to read the resource from.
    /// # Returns
    /// * A mutable reference to the builder.
    /// # Errors
    /// * If the resource is not valid.
    pub fn add_resource(
        &mut self,
        id: &str,
        mut stream: impl Read + Seek + Send,
    ) -> Result<&mut Self> {
        if self.resources.exists(id) {
            return Err(Error::BadParam(id.to_string())); // todo add specific error
        }
        let mut buf = Vec::new();
        let _size = stream.read_to_end(&mut buf)?;
        self.resources.add(id, buf)?;
        Ok(self)
    }

    /// Convert the Builder into a archive formatted stream.
    ///
    /// The archive is a zip formatted stream containing the manifest.json, resources, and ingredients.
    /// # Arguments
    /// * `stream` - A stream to write the zip into.
    /// # Errors
    /// * If the archive cannot be written.
    pub fn to_archive(&mut self, stream: impl Write + Seek) -> Result<()> {
        drop(
            // this drop seems to be required to force a flush before reading back.
            {
                let mut zip = ZipWriter::new(stream);
                let options =
                    FileOptions::default().compression_method(zip::CompressionMethod::Stored);
                // write a version file
                zip.start_file("version.txt", options)
                    .map_err(|e| Error::OtherError(Box::new(e)))?;
                zip.write_all(ARCHIVE_VERSION.as_bytes())?;
                // write the manifest.json file
                zip.start_file("manifest.json", options)
                    .map_err(|e| Error::OtherError(Box::new(e)))?;
                zip.write_all(&serde_json::to_vec(self)?)?;
                // add resource files to a resources folder
                zip.start_file("resources/", options)
                    .map_err(|e| Error::OtherError(Box::new(e)))?;
                for (id, data) in self.resources.resources() {
                    zip.start_file(format!("resources/{}", id), options)
                        .map_err(|e| Error::OtherError(Box::new(e)))?;
                    zip.write_all(data)?;
                }
                // Write the manifest_data files
                // The filename is filesystem safe version of the associated manifest_label
                // with a .c2pa extension inside a "manifests" folder.
                zip.start_file("manifests/", options)
                    .map_err(|e| Error::OtherError(Box::new(e)))?;
                for ingredient in self.definition.ingredients.iter() {
                    if let Some(manifest_label) = ingredient.active_manifest() {
                        if let Some(manifest_data) = ingredient.manifest_data() {
                            // Convert to valid archive / file path name
                            let manifest_name = manifest_label.replace([':'], "_") + ".c2pa";
                            zip.start_file(format!("manifests/{manifest_name}"), options)
                                .map_err(|e| Error::OtherError(Box::new(e)))?;
                            zip.write_all(&manifest_data)?;
                        }
                    }
                }
                zip.finish()
            }
            .map_err(|e| Error::OtherError(Box::new(e)))?,
        );
        Ok(())
    }

    /// Unpacks an archive stream into a Builder.
    /// # Arguments
    /// * `stream` - A stream to read the archive from.
    /// # Returns
    /// * A new Builder.
    /// # Errors
    /// * If the archive cannot be read.
    pub fn from_archive(stream: impl Read + Seek) -> Result<Self> {
        let mut zip = ZipArchive::new(stream).map_err(|e| Error::OtherError(Box::new(e)))?;
        // First read the manifest.json file.
        let mut manifest_file = zip
            .by_name("manifest.json")
            .map_err(|e| Error::OtherError(Box::new(e)))?;
        let mut manifest_buf = Vec::new();
        manifest_file.read_to_end(&mut manifest_buf)?;
        let mut builder: Builder =
            serde_json::from_slice(&manifest_buf).map_err(|e| Error::OtherError(Box::new(e)))?;
        drop(manifest_file);
        // Load all the files in the resources folder.
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

            // Load the c2pa_manifests.
            // We add the manifest data to any ingredient that has a matching active_manfiest label.
            if file.name().starts_with("manifests/") && file.name() != "manifests/" {
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                let manifest_label = file
                    .name()
                    .split('/')
                    .nth(1)
                    .ok_or(Error::BadParam("Invalid manifest path".to_string()))?;
                let manifest_label = manifest_label.replace(['_'], ":");
                for ingredient in builder.definition.ingredients.iter_mut() {
                    if let Some(active_manifest) = ingredient.active_manifest() {
                        if manifest_label.starts_with(active_manifest) {
                            ingredient.set_manifest_data(data.clone())?;
                        }
                    }
                }
            }

            // Keep this for temporary unstable api support (un-versioned).
            // Earlier method used numbered library folders instead of manifests.
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
        let metadata = definition.metadata.clone();
        // add the default claim generator info for this library
        claim_generator_info.push(ClaimGeneratorInfo::default());

        // Build the claim_generator string since this is required
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

        // Add claim metadata
        if let Some(metadata_vec) = metadata {
            for m in metadata_vec {
                claim.add_claim_metadata(m);
            }
        }

        if let Some(remote_url) = &self.remote_url {
            if self.no_embed {
                claim.set_remote_manifest(remote_url)?;
            } else {
                claim.set_embed_remote_manifest(remote_url)?;
            }
        } else if self.no_embed {
            claim.set_external_manifest()
        }

        if let Some(title) = definition.title.as_ref() {
            claim.set_title(Some(title.to_owned()));
        }
        definition.format.clone_into(&mut claim.format);
        definition.instance_id.clone_into(&mut claim.instance_id);

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

        let salt = DefaultSalt::default();

        // add any additional assertions
        for manifest_assertion in &definition.assertions {
            match manifest_assertion.label.as_str() {
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

                    claim.add_assertion_with_salt(&cw, &salt)
                }
                Exif::LABEL => {
                    let exif: Exif = manifest_assertion.to_assertion()?;
                    claim.add_assertion_with_salt(&exif, &salt)
                }
                _ => match &manifest_assertion.data {
                    AssertionData::Json(value) => claim.add_assertion_with_salt(
                        &User::new(&manifest_assertion.label, &serde_json::to_string(&value)?),
                        &salt,
                    ),
                    AssertionData::Cbor(value) => claim.add_assertion_with_salt(
                        &UserCbor::new(&manifest_assertion.label, serde_cbor::to_vec(value)?),
                        &salt,
                    ),
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
        // check settings to see if we should auto generate a thumbnail
        let auto_thumbnail = crate::settings::get_settings_value::<bool>("builder.auto_thumbnail")?;
        if self.definition.thumbnail.is_none() && auto_thumbnail {
            stream.rewind()?;
            if let Ok((format, image)) =
                crate::utils::thumbnail::make_thumbnail_from_stream(format, stream)
            {
                stream.rewind()?;
                self.resources
                    .add(self.definition.instance_id.clone(), image)?;
                self.definition.thumbnail = Some(ResourceRef::new(
                    format,
                    self.definition.instance_id.clone(),
                ));
            }
        }
        Ok(self)
    }

    // Find an assertion in the manifest.
    pub(crate) fn find_assertion<T: DeserializeOwned>(&self, label: &str) -> Result<T> {
        if let Some(manifest_assertion) =
            self.definition.assertions.iter().find(|a| a.label == label)
        {
            manifest_assertion.to_assertion()
        } else {
            Err(Error::NotFound)
        }
    }

    /// Create a placeholder for a hashed data manifest.
    /// This is only used for applications doing their own data_hashed asset management.
    /// # Arguments
    /// * `reserve_size` - The size to reserve for the signature (taken from the signer).
    /// * `format` - The format of the target asset, the placeholder will be preformatted for this format.
    /// # Returns
    /// * The bytes of the c2pa_manifest placeholder.
    /// # Errors
    /// * If the placeholder cannot be created.
    pub fn data_hashed_placeholder(
        &mut self,
        reserve_size: usize,
        format: &str,
    ) -> Result<Vec<u8>> {
        let dh: Result<DataHash> = self.find_assertion(DataHash::LABEL);
        if dh.is_err() {
            let mut ph = DataHash::new("jumbf manifest", "sha256");
            for _ in 0..10 {
                ph.add_exclusion(HashRange::new(0, 2));
            }
            self.add_assertion(labels::DATA_HASH, &ph)?;
        }
        self.definition.format = format.to_string();
        self.definition.instance_id = format!("xmp:iid:{}", Uuid::new_v4());
        let mut store = self.to_store()?;
        let placeholder = store.get_data_hashed_manifest_placeholder(reserve_size, format)?;
        Ok(placeholder)
    }

    /// Create a signed data hashed embeddable manifest using a supplied signer.
    /// This is used to create a manifest that can be embedded into a stream.
    /// It allows the caller to do the embedding.
    /// You must call data_hashed placeholder first to create the placeholder.
    /// The placeholder is then injected into the asset before calculating hashes
    /// A source stream can be passed to generate the hashes, or else the hashes mush be provided.
    ///
    /// # Arguments
    /// * `signer` - The signer to use.
    /// * `data_hash` - The updated data_hash to use for the manifest.
    /// * `format` - The format of the stream.
    /// * `source` - The stream to read from.
    /// # Returns
    /// * The bytes of the c2pa_manifest that was created (prep-formatted)
    #[async_generic(async_signature(
        &mut self,
        signer: &dyn AsyncSigner,
        data_hash: &DataHash,
        format: &str,
    ))]
    pub fn sign_data_hashed_embeddable(
        &mut self,
        signer: &dyn Signer,
        data_hash: &DataHash,
        format: &str,
    ) -> Result<Vec<u8>> {
        let mut store = self.to_store()?;
        if _sync {
            store.get_data_hashed_embeddable_manifest(data_hash, signer, format, None)
        } else {
            store
                .get_data_hashed_embeddable_manifest_async(data_hash, signer, format, None)
                .await
        }
    }

    /// Create a signed box hashed embeddable manifest using a supplied signer.
    /// This is used to create a manifest that can be embedded into a stream.
    /// It allows the caller to do the embedding.
    /// The manifest definition must already include a BoxHash assertion.
    ///
    /// # Arguments
    /// * `signer` - The signer to use.
    /// # Returns
    /// * The bytes of the c2pa_manifest that was created (prep-formatted)
    #[async_generic(async_signature(
        &mut self,
        signer: &dyn AsyncSigner,
        format: &str
    ))]
    pub fn sign_box_hashed_embeddable(
        &mut self,
        signer: &dyn Signer,
        format: &str,
    ) -> Result<Vec<u8>> {
        self.definition.instance_id = format!("xmp:iid:{}", Uuid::new_v4());

        let mut store = self.to_store()?;
        let bytes = if _sync {
            store.get_box_hashed_embeddable_manifest(signer)
        } else {
            store.get_box_hashed_embeddable_manifest_async(signer).await
        }?;
        // get composed version for embedding to JPEG
        Store::get_composed_manifest(&bytes, format)
    }

    /// Embed a signed manifest into a stream using a supplied signer.
    /// # Arguments
    /// * `format` - The format of the stream
    /// * `source` - The stream to read from
    /// * `dest` - The stream to write to
    /// * `signer` - The signer to use
    /// # Returns
    /// * The bytes of c2pa_manifest that was embedded.
    /// # Errors
    /// * If the manifest cannot be signed.
    #[async_generic(async_signature(
        &mut self,
        signer: &dyn AsyncSigner,
        format: &str,
        source: &mut R,
        dest: &mut W,
    ))]
    pub fn sign<R, W>(
        &mut self,
        signer: &dyn Signer,
        format: &str,
        source: &mut R,
        dest: &mut W,
    ) -> Result<Vec<u8>>
    where
        R: Read + Seek + Send,
        W: Write + Read + Seek + Send,
    {
        let format = format_to_mime(format);
        self.definition.format.clone_from(&format);
        // todo:: read instance_id from xmp from stream ?
        self.definition.instance_id = format!("xmp:iid:{}", Uuid::new_v4());

        #[cfg(feature = "file_io")]
        if let Some(base_path) = &self.base_path {
            self.resources.set_base_path(base_path);
        }

        // generate thumbnail if we don't already have one
        #[cfg(feature = "add_thumbnails")]
        self.maybe_add_thumbnail(&format, source)?;

        // convert the manifest to a store
        let mut store = self.to_store()?;

        // sign and write our store to to the output image file
        if _sync {
            store.save_to_stream(&format, source, dest, signer)
        } else {
            store
                .save_to_stream_async(&format, source, dest, signer)
                .await
        }
    }

    #[cfg(feature = "file_io")]
    /// Sign a file using a supplied signer.
    /// # Arguments
    /// * `source` - The path to the file to read from.
    /// * `dest` - The path to the file to write to (this must not already exist).
    /// * `signer` - The signer to use.
    /// # Returns
    /// * The bytes of c2pa_manifest that was created.
    /// # Errors
    /// * If the manifest cannot be signed.
    pub fn sign_file<S, D>(&mut self, signer: &dyn Signer, source: S, dest: D) -> Result<Vec<u8>>
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
        if self.definition.title.is_none() {
            if let Some(title) = dest.file_name() {
                self.definition.title = Some(title.to_string_lossy().to_string());
            }
        }

        let mut dest = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dest)?;
        self.sign(signer, &format, &mut source, &mut dest)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    use std::io::Cursor;

    use serde_json::json;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    use super::*;
    use crate::{
        assertions::BoxHash,
        asset_handlers::jpeg_io::JpegIO,
        hash_stream_by_alg,
        utils::test::{temp_signer, write_jpeg_placeholder_stream},
        Reader,
    };

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    fn parent_json() -> String {
        json!({
            "title": "Parent Test",
            "format": "image/jpeg",
            "instance_id": "12345",
            "relationship": "parentOf"
        })
        .to_string()
    }

    fn manifest_json() -> String {
        json!({
            "vendor": "test",
            "claim_generator_info": [
                {
                    "name": "c2pa_test",
                    "version": "1.0.0"
                }
            ],
            "metadata": [
                {
                    "dateTime": "1985-04-12T23:20:50.52Z",
                    "my_custom_metadata": "my custom metatdata value"
                }
            ],
            "title": "Test_Manifest",
            "format": "image/tiff",
            "instance_id": "1234",
            "thumbnail": {
                "format": "image/jpeg",
                "identifier": "thumbnail.jpg"
            },
            "ingredients": [
                {
                    "title": "Test",
                    "format": "image/jpeg",
                    "instance_id": "12345",
                    "relationship": "componentOf"
                }
            ],
            "assertions": [
                {
                    "label": "org.test.assertion",
                    "data": "assertion"
                }
            ]
        })
        .to_string()
    }

    fn simple_manifest() -> String {
        json!({
            "claim_generator_info": [
                {
                    "name": "c2pa_test",
                    "version": "1.0.0"
                }
            ]
        })
        .to_string()
    }

    #[cfg(not(target_arch = "wasm32"))]
    const TEST_IMAGE_CLEAN: &[u8] = include_bytes!("../tests/fixtures/IMG_0003.jpg");
    const TEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
    const TEST_THUMBNAIL: &[u8] = include_bytes!("../tests/fixtures/thumbnail.jpg");

    #[test]
    /// example of creating a builder directly with a [`ManifestDefinition`]
    fn test_manifest_store_builder() {
        let mut image = Cursor::new(TEST_IMAGE);

        let thumbnail_ref = ResourceRef::new("ingredient/jpeg", "5678");

        let definition = ManifestDefinition {
            vendor: Some("test".to_string()),
            claim_generator_info: [ClaimGeneratorInfo::default()].to_vec(),
            format: "image/tiff".to_string(),
            title: Some("Test_Manifest".to_string()),
            instance_id: "1234".to_string(),
            thumbnail: Some(thumbnail_ref.clone()),
            label: Some("ABCDE".to_string()),
            ..Default::default()
        };

        let mut builder = Builder {
            definition,
            ..Default::default()
        };

        builder
            .add_ingredient_from_stream(parent_json(), "image/jpeg", &mut image)
            .unwrap();

        builder
            .add_assertion("org.test.assertion", &"assertion".to_string())
            .unwrap();

        builder
            .add_resource(&thumbnail_ref.identifier, Cursor::new(b"12345"))
            .unwrap();

        let definition = &builder.definition;
        assert_eq!(definition.vendor, Some("test".to_string()));
        assert_eq!(definition.title, Some("Test_Manifest".to_string()));
        assert_eq!(definition.format, "image/tiff".to_string());
        assert_eq!(definition.instance_id, "1234".to_string());
        assert_eq!(definition.thumbnail, Some(thumbnail_ref));
        assert_eq!(definition.ingredients[0].title(), "Parent Test".to_string());
        assert_eq!(
            definition.assertions[0].label,
            "org.test.assertion".to_string()
        );
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
        let mut stripped_json = manifest_json();
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
            "thumbnail.jpg"
        );
        assert_eq!(definition.ingredients[0].title(), "Test".to_string());
        assert_eq!(
            definition.assertions[0].label,
            "org.test.assertion".to_string()
        );

        assert_eq!(
            definition.metadata.as_ref().unwrap()[0]
                .other()
                .get("my_custom_metadata")
                .unwrap()
                .as_str()
                .unwrap(),
            "mycustommetatdatavalue"
        );

        // convert back to json and compare to original
        let builder_json = serde_json::to_string(&builder.definition).unwrap();
        assert_eq!(builder_json, stripped_json);
    }

    #[test]
    fn test_builder_sign() {
        #[derive(Serialize, Deserialize)]
        struct TestAssertion {
            answer: usize,
        }
        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::from_json(&manifest_json()).unwrap();
        builder
            .add_ingredient_from_stream(parent_json().to_string(), format, &mut source)
            .unwrap();

        builder
            .resources
            .add("thumbnail.jpg", TEST_THUMBNAIL.to_vec())
            .unwrap();

        builder
            .resources
            .add("prompt.txt", "a random prompt")
            .unwrap();

        builder
            .add_assertion("org.life.meaning", &TestAssertion { answer: 42 })
            .unwrap();

        builder
            .add_assertion_json("org.life.meaning.json", &TestAssertion { answer: 42 })
            .unwrap();

        // write the manifest builder to a zipped stream
        let mut zipped = Cursor::new(Vec::new());
        builder.to_archive(&mut zipped).unwrap();

        // write the zipped stream to a file for debugging
        std::fs::write("../target/test.zip", zipped.get_ref()).unwrap();

        // unzip the manifest builder from the zipped stream
        zipped.rewind().unwrap();
        let mut _builder = Builder::from_archive(&mut zipped).unwrap();

        // sign and write to the output stream
        let signer = temp_signer();
        builder
            .sign(signer.as_ref(), format, &mut source, &mut dest)
            .unwrap();

        // read and validate the signed manifest store
        dest.rewind().unwrap();
        let manifest_store = Reader::from_stream(format, &mut dest).expect("from_bytes");

        println!("{}", manifest_store);
        assert!(manifest_store.validation_status().is_none());
        assert!(manifest_store.active_manifest().is_some());
        let manifest = manifest_store.active_manifest().unwrap();
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

        let mut builder = Builder::from_json(&manifest_json()).unwrap();

        builder
            .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
            .unwrap();

        // sign and write to the output stream
        let signer = temp_signer();
        builder.sign_file(signer.as_ref(), source, &dest).unwrap();

        // read and validate the signed manifest store
        let manifest_store = Reader::from_file(&dest).expect("from_bytes");

        println!("{}", manifest_store);
        assert!(manifest_store.validation_status().is_none());
        assert_eq!(
            manifest_store.active_manifest().unwrap().title().unwrap(),
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
            "TUSCANY.TIF",
            "sample1.svg",
            "sample1.wav",
            "test.avi",
            "sample1.mp3",
            "sample1.avif",
            "sample1.heic",
            "sample1.heif",
            "video1.mp4",
            "cloud_manifest.c2pa",
        ];
        for file_name in TESTFILES {
            let extension = file_name.split('.').last().unwrap();
            let format = extension;

            let path = format!("tests/fixtures/{}", file_name);
            println!("path: {}", path);
            let mut source = std::fs::File::open(path).unwrap();
            let mut dest = Cursor::new(Vec::new());

            let mut builder = Builder::from_json(&manifest_json()).unwrap();
            builder
                .add_ingredient_from_stream(parent_json(), format, &mut source)
                .unwrap();

            builder
                .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
                .unwrap();

            // sign and write to the output stream
            let signer = temp_signer();
            builder
                .sign(signer.as_ref(), format, &mut source, &mut dest)
                .unwrap();

            // read and validate the signed manifest store
            dest.rewind().unwrap();
            let manifest_store = Reader::from_stream(format, &mut dest).expect("from_bytes");

            println!("{}", manifest_store);
            if format != "c2pa" {
                // c2pa files will not validate since they have no associated asset
                assert!(manifest_store.validation_status().is_none());
            }
            assert_eq!(
                manifest_store.active_manifest().unwrap().title().unwrap(),
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

        let mut builder = Builder::from_json(&manifest_json()).unwrap();
        builder
            .add_ingredient_from_stream(parent_json(), format, &mut source)
            .unwrap();

        builder
            .resources
            .add("thumbnail.jpg", TEST_THUMBNAIL.to_vec())
            .unwrap();

        // sign the ManifestStoreBuilder and write it to the output stream
        let signer = crate::utils::test::temp_async_remote_signer();
        builder
            .sign_async(signer.as_ref(), format, &mut source, &mut dest)
            .await
            .unwrap();

        // read and validate the signed manifest store
        dest.rewind().unwrap();
        let manifest_store = Reader::from_stream(format, &mut dest).expect("from_bytes");

        //println!("{}", manifest_store);
        #[cfg(not(target_arch = "wasm32"))] // skip this until we get wasm async signing working
        assert_eq!(manifest_store.validation_status(), None);

        assert_eq!(
            manifest_store.active_manifest().unwrap().title().unwrap(),
            "Test_Manifest"
        );
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_builder_remote_url() {
        let mut source = Cursor::new(TEST_IMAGE_CLEAN);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::from_json(&manifest_json()).unwrap();
        builder.remote_url = Some("http://my_remote_url".to_string());
        builder.no_embed = true;

        builder
            .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
            .unwrap();

        // sign the ManifestStoreBuilder and write it to the output stream
        let signer = temp_signer();
        let manifest_data = builder
            .sign(signer.as_ref(), "image/jpeg", &mut source, &mut dest)
            .unwrap();

        // check to make sure we have a remote url and no manifest data
        dest.set_position(0);
        let _err = c2pa::Reader::from_stream("image/jpeg", &mut dest).expect_err("from_bytes");

        // now validate the manifest against the written asset
        dest.set_position(0);
        let reader =
            c2pa::Reader::from_manifest_data_and_stream(&manifest_data, "image/jpeg", &mut dest)
                .expect("from_bytes");

        println!("{}", reader.json());
        assert!(reader.validation_status().is_none());
    }

    #[test]
    fn test_builder_data_hashed_embeddable() {
        const CLOUD_IMAGE: &[u8] = include_bytes!("../tests/fixtures/cloud.jpg");
        let mut input_stream = Cursor::new(CLOUD_IMAGE);

        let signer = temp_signer();

        let mut builder = Builder::from_json(&simple_manifest()).unwrap();

        // get a placeholder the manifest
        let placeholder = builder
            .data_hashed_placeholder(signer.reserve_size(), "image/jpeg")
            .unwrap();

        let mut output_stream = Cursor::new(Vec::new());

        // write a jpeg file with a placeholder for the manifest (returns offset of the placeholder)
        let offset = write_jpeg_placeholder_stream(
            &placeholder,
            "image/jpeg",
            &mut input_stream,
            &mut output_stream,
            None,
        )
        .unwrap();

        println!("offset: {}, size {}", offset, output_stream.get_ref().len());
        // create an hash exclusion for the manifest
        let exclusion = crate::HashRange::new(offset, placeholder.len());
        let exclusions = vec![exclusion];

        let mut dh = DataHash::new("source_hash", "sha256");
        dh.exclusions = Some(exclusions);

        // Hash the bytes excluding the manifest we inserted
        output_stream.rewind().unwrap();
        let hash =
            hash_stream_by_alg("sha256", &mut output_stream, dh.exclusions.clone(), true).unwrap();
        dh.set_hash(hash);

        // get the embeddable manifest, letting API do the hashing
        let signed_manifest: Vec<u8> = builder
            .sign_data_hashed_embeddable(signer.as_ref(), &dh, "image/jpeg")
            .unwrap();

        use std::io::{Seek, SeekFrom, Write};

        output_stream.seek(SeekFrom::Start(offset as u64)).unwrap();
        output_stream.write_all(&signed_manifest).unwrap();
        output_stream.flush().unwrap();

        output_stream.rewind().unwrap();

        let reader = crate::Reader::from_stream("image/jpeg", output_stream).unwrap();
        println!("{reader}");
        #[cfg(not(target_arch = "wasm32"))] // skip this until we get wasm async signing working
        assert!(reader.validation_status().is_none());
    }

    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn test_builder_box_hashed_embeddable() {
        use crate::asset_io::{CAIWriter, HashBlockObjectType};
        const BOX_HASH_IMAGE: &[u8] = include_bytes!("../tests/fixtures/boxhash.jpg");
        const BOX_HASH: &[u8] = include_bytes!("../tests/fixtures/boxhash.json");

        let mut input_stream = Cursor::new(BOX_HASH_IMAGE);

        // get saved box hash settings
        let box_hash: BoxHash = serde_json::from_slice(BOX_HASH).unwrap();

        let mut builder = Builder::from_json(&manifest_json()).unwrap();
        builder
            .add_resource("thumbnail.jpg", Cursor::new(TEST_IMAGE))
            .unwrap();

        builder.add_assertion(labels::BOX_HASH, &box_hash).unwrap();

        let signer = crate::utils::test::temp_async_signer();

        let manifest_bytes = builder
            .sign_box_hashed_embeddable_async(signer.as_ref(), "image/jpeg")
            .await
            .unwrap();

        // insert manifest into output asset
        let jpeg_io = JpegIO {};
        let ol = jpeg_io
            .get_object_locations_from_stream(&mut input_stream)
            .unwrap();
        input_stream.rewind().unwrap();

        let cai_loc = ol
            .iter()
            .find(|o| o.htype == HashBlockObjectType::Cai)
            .unwrap();

        // build new asset in memory inserting new manifest
        let outbuf = Vec::new();
        let mut out_stream = Cursor::new(outbuf);

        // write before
        let mut before = vec![0u8; cai_loc.offset];
        input_stream.read_exact(before.as_mut_slice()).unwrap();
        out_stream.write_all(&before).unwrap();

        // write composed bytes
        out_stream.write_all(&manifest_bytes).unwrap();

        // write bytes after
        let mut after_buf = Vec::new();
        input_stream.read_to_end(&mut after_buf).unwrap();
        out_stream.write_all(&after_buf).unwrap();

        out_stream.rewind().unwrap();

        let _reader = crate::Reader::from_stream_async("image/jpeg", out_stream)
            .await
            .unwrap();
        //println!("{reader}");
        #[cfg(not(target_arch = "wasm32"))] // skip this until we get wasm async signing working
        assert_eq!(_reader.validation_status(), None);
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn test_builder_base_path() {
        let mut source = Cursor::new(TEST_IMAGE_CLEAN);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::from_json(&manifest_json()).unwrap();
        builder.base_path = Some(std::path::PathBuf::from("tests/fixtures"));

        // Ensure that we can zip and unzip, saving the base path
        let mut zipped = Cursor::new(Vec::new());
        builder.to_archive(&mut zipped).unwrap();

        // unzip the manifest builder from the zipped stream
        zipped.rewind().unwrap();
        let mut builder = Builder::from_archive(&mut zipped).unwrap();

        // sign the ManifestStoreBuilder and write it to the output stream
        let signer = temp_signer();
        let _manifest_data = builder
            .sign(signer.as_ref(), "image/jpeg", &mut source, &mut dest)
            .unwrap();

        // read and validate the signed manifest store
        dest.rewind().unwrap();
        let reader = Reader::from_stream("image/jpeg", &mut dest).expect("from_bytes");

        //println!("{}", reader);
        assert!(reader.validation_status().is_none());
        assert_eq!(
            reader
                .active_manifest()
                .unwrap()
                .thumbnail_ref()
                .unwrap()
                .format,
            "image/jpeg",
        );
    }
}
