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
use std::path::{Path, PathBuf};
use std::{
    collections::{HashMap, HashSet},
    io::{Read, Seek, Write},
};

use async_generic::async_generic;
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::skip_serializing_none;
use uuid::Uuid;
use zip::{write::SimpleFileOptions, ZipArchive, ZipWriter};

use crate::assertion::AssertionBase;
#[allow(deprecated)]
use crate::{
    assertion::AssertionDecodeError,
    assertions::{
        c2pa_action, labels, Action, ActionTemplate, Actions, AssertionMetadata, BmffHash, BoxHash,
        CreativeWork, DataHash, DigitalSourceType, EmbeddedData, Exif, Metadata, SoftwareAgent,
        Thumbnail, User, UserCbor,
    },
    cbor_types::value_cbor_to_type,
    claim::Claim,
    error::{Error, Result},
    jumbf_io,
    resource_store::{ResourceRef, ResourceResolver, ResourceStore},
    salt::DefaultSalt,
    settings::{
        self,
        builder::{ActionSettings, ActionTemplateSettings, ClaimGeneratorInfoSettings},
    },
    store::Store,
    utils::mime::format_to_mime,
    AsyncSigner, ClaimGeneratorInfo, HashRange, HashedUri, Ingredient, Relationship, Signer,
};

/// Version of the Builder Archive file
const ARCHIVE_VERSION: &str = "1";

/// Use a ManifestDefinition to define a manifest and to build a `ManifestStore`.
/// A manifest is a collection of ingredients and assertions
/// used to define a claim that can be signed and embedded into a file.
#[skip_serializing_none]
#[derive(Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[non_exhaustive]
pub struct ManifestDefinition {
    /// The version of the claim.  Defaults to 2.
    pub claim_version: Option<u8>,

    /// Optional prefix added to the generated Manifest Label
    /// This is typically a reverse domain name.
    pub vendor: Option<String>,

    /// Claim Generator Info is always required with at least one entry
    #[serde(default = "default_claim_generator_info")]
    pub claim_generator_info: Vec<ClaimGeneratorInfo>,

    /// Optional manifest metadata. This will be deprecated in the future; not recommended to use.
    pub metadata: Option<Vec<AssertionMetadata>>,

    /// A human-readable title, generally source filename.
    pub title: Option<String>,

    /// The format of the source file as a MIME type.
    #[serde(default = "default_format")]
    pub format: String,

    /// Instance ID from `xmpMM:InstanceID` in XMP metadata.
    #[serde(default = "default_instance_id")]
    pub instance_id: String,

    /// An optional ResourceRef to a thumbnail image that represents the asset that was signed.
    /// Must be available when the manifest is signed.
    pub thumbnail: Option<ResourceRef>,

    /// A List of ingredients
    #[serde(default = "default_vec::<Ingredient>")]
    pub ingredients: Vec<Ingredient>,

    /// A list of assertions
    #[serde(default = "default_vec::<AssertionDefinition>")]
    pub assertions: Vec<AssertionDefinition>,

    /// A list of redactions - URIs to redacted assertions.
    pub redactions: Option<Vec<String>>,

    /// Allows you to pre-define the manifest label, which must be unique.
    /// Not intended for general use.  If not set, it will be assigned automatically.
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

/// This allows the assertion to be expressed as CBOR or JSON.
/// The default is CBOR unless you specify that an assertion should be JSON.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[serde(untagged)]
pub enum AssertionData {
    #[cfg_attr(feature = "json_schema", schemars(skip))]
    Cbor(serde_cbor::Value),
    Json(serde_json::Value),
}

/// Defines an assertion that consists of a label that can be either
/// a C2PA-defined assertion label or a custom label in reverse domain format.
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

/// Represents the type of builder flow being used.
///
/// This determines how the builder will be used, such as creating a new asset, opening an existing asset,
/// or updating an existing asset.
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
enum BuilderIntent {
    /// This is a new digital creation, a DigitalSourceType is required.
    ///
    /// The Manifest must not have have a parent ingredient.
    /// A `c2pa.created` action will be added if not provided.
    #[serde(rename = "create")]
    Create(DigitalSourceType),

    /// This is an edit of a pre-existing parent asset.
    ///
    /// The Manifest must have a parent ingredient.
    /// A parent ingredient will be generated from the source stream if not otherwise provided.
    /// A `c2pa.opened action will be tied to the parent ingredient.
    #[serde(rename = "edit")]
    Edit,

    /// A restricted version of [Edit] for non-editorial changes.
    ///
    /// There must be only one ingredient, as a parent.
    /// No changes can be made to the hashed content of the parent.
    /// There are additional restrictions on the types of changes that can be made.
    #[serde(rename = "update")]
    Update,
}

#[allow(unused)] // TEMPORARY: @gpeacock please investigate
#[derive(Serialize, Deserialize)]
struct StructuredAction {
    action: String,
    #[serde(flatten)]
    data: serde_json::Value,
}

/// Use a Builder to add a signed manifest to an asset.
///
/// # Example: Building and signing a manifest
///
/// ```ignore-wasm32
/// use c2pa::Result;
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
/// #[cfg(feature = "file_io")]
/// {
///     let manifest_json = json!({
///        "claim_generator_info": [
///           {
///               "name": "c2pa_test",
///               "version": "1.0.0"
///           }
///        ],
///        "title": "Test_Manifest"
///     }).to_string();
///
///     let mut builder = Builder::from_json(&manifest_json)?;
///     builder.add_assertion("org.contentauth.test", &Test { my_tag: 42 })?;
///
///     let source = PathBuf::from("tests/fixtures/C.jpg");
///     let dir = tempdir()?;
///     let dest = dir.path().join("test_file.jpg");
///
///     // Create a ps256 signer using certs and key files. TO DO: Update example.
///     let signcert_path = "tests/fixtures/certs/ps256.pub";
///     let pkey_path = "tests/fixtures/certs/ps256.pem";
///     let signer = create_signer::from_files(signcert_path, pkey_path, SigningAlg::Ps256, None)?;
///
///     // embed a manifest using the signer
///     builder.sign_file(
///         signer.as_ref(),
///         &source,
///         &dest)?;
///     }
/// # Ok(())
/// # }
/// ```
#[skip_serializing_none]
#[derive(Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct Builder {
    #[serde(flatten)]
    /// A collection of ingredients and assertions used to define a claim that can be signed and embedded into a file.
    /// In most cases, you create this from a JSON manifest definition.
    pub definition: ManifestDefinition,

    /// Optional remote URL for the manifest
    pub remote_url: Option<String>,

    /// If true, the manifest store will not be embedded in the asset on sign
    pub no_embed: bool,

    /// Base path to search for resources.
    #[cfg(feature = "file_io")]
    pub base_path: Option<PathBuf>,

    /// A builder should construct a created, opened or updated manifest.
    intent: Option<BuilderIntent>,

    /// Container for binary assets (like thumbnails).
    #[serde(skip)]
    resources: ResourceStore,
}

impl AsRef<Builder> for Builder {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl Builder {
    /// Creates a new [`Builder`] struct.
    /// # Returns
    /// * A new [`Builder`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a new [`Builder`] for creating a new asset.
    ///
    /// # Arguments
    /// * `source_type` - The type of digital source, such as `DigitalSourceType::Empty` or `DigitalSourceType::TrainedAlgorithmicData`.
    /// # Returns
    /// * A new [`Builder`] with the specified source type.
    /// # Example
    /// ```rust
    /// use c2pa::{Builder, DigitalSourceType};
    /// let builder = Builder::create(DigitalSourceType::Empty);
    /// ```
    pub fn create(source_type: DigitalSourceType) -> Self {
        let mut builder = Self::new();
        builder.intent = Some(BuilderIntent::Create(source_type));
        builder
    }

    /// Creates a new [`Builder`] for for editing an existing asset.
    /// This is experimental and will likely change in the future.
    ///
    /// If a parent ingredient is not provided, it will be generated from the source stream.
    /// and an associated `c2pa.opened` action will be added.
    /// # Returns
    /// * A new [`Builder`] for editing an existing asset.
    pub fn edit() -> Self {
        let mut builder = Self::new();
        builder.intent = Some(BuilderIntent::Edit);
        builder
    }

    // /// Creates a new [`Builder`] for updating an existing asset.
    // /// This is experimental and not fully implemented yet.
    // ///
    // /// This creates an Update manifest, which is a restricted version of an Open manifest.
    // /// The benefit is a smaller manifest with only non-editorial changes.
    // /// It must have a parent and no other ingredients.
    // /// It cannot modify the hashed content of the parent.
    // /// Only a very limited set of actions can be performed.
    // pub fn update() -> Self {
    //     let mut builder = Self::new();
    //     builder.intent = Some(BuilderIntent::Update);
    //     builder
    // }

    /// Creates a new [`Builder`] from a JSON [`ManifestDefinition`] string.
    /// This is experimental and may change in the future.
    ///
    /// # Arguments
    /// * `json` - A JSON string representing the [`ManifestDefinition`].
    /// # Returns
    /// * A new [`Builder`].
    /// # Errors
    /// * Returns an [`Error`] if the JSON is malformed or incorrect.
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(Self {
            definition: serde_json::from_str(json).map_err(Error::JsonError)?,
            ..Default::default()
        })
    }

    /// Returns a [Vec] of mime types that [c2pa-rs] is able to sign.
    pub fn supported_mime_types() -> Vec<String> {
        jumbf_io::supported_builder_mime_types()
    }

    /// Returns the claim version for this builder.
    ///
    /// If not set, defaults to 2.
    pub fn claim_version(&self) -> u8 {
        self.definition.claim_version.unwrap_or(2)
    }

    /// Sets the [`ClaimGeneratorInfo`] for this [`Builder`].
    // TODO: Add example of a good ClaimGeneratorInfo.
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
    /// * `format` - The format (MIME type) of the asset associated with this [`Builder`].
    /// # Returns
    /// * A mutable reference to the [`Builder`].
    pub fn set_format<S: Into<String>>(&mut self, format: S) -> &mut Self {
        self.definition.format = format.into();
        self
    }

    /// ⚠️ **Deprecated Soon**
    /// This method is planned to be deprecated in a future release.
    /// Usage should be limited and temporary.
    ///
    /// Sets the resource directory for this [`Builder`]
    ///
    /// # Arguments
    /// * `base_path` - The directory to search in to find the resources.
    /// # Returns
    /// * A mutable reference to the [`Builder`].
    #[cfg(feature = "file_io")]
    pub fn set_base_path<P: Into<PathBuf>>(&mut self, base_path: P) -> &mut Self {
        self.base_path = Some(base_path.into());
        self
    }

    /// Sets the remote_url for this [`Builder`].
    ///
    /// The URL must return the manifest data and is injected into the destination asset when signing.
    /// For remote-only manifests, set the `no_embed` flag to `true`.
    ///
    /// # Arguments
    /// * `url` - The URL where the manifest will be available.
    /// # Returns
    /// * A mutable reference to the [`Builder`].
    pub fn set_remote_url<S: Into<String>>(&mut self, url: S) -> &mut Self {
        self.remote_url = Some(url.into());
        self
    }

    /// Sets the `no_embed` flag for this [`Builder`].
    ///
    /// If true, the manifest store will not be embedded in the destination asset on sign.
    /// This is useful for sidecar and remote manifests.
    ///
    /// # Arguments
    /// * `no_embed` - A Boolean flag to set the `no_embed` flag.
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
    /// * `stream` - A stream from which to read the thumbnail.
    /// # Returns
    /// * A mutable reference to the [`Builder`].
    /// # Errors
    /// * Returns an [`Error`] if the thumbnail is not valid.
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
    /// In most cases, use this function instead of `add_assertion_json`, unless the assertion must be stored in JSON format.
    ///
    /// # Arguments
    /// * `label` - A label for the assertion.
    /// * `data` - The data for the assertion. The data is any Serde-serializable type.
    /// # Returns
    /// * A mutable reference to the [`Builder`].
    /// # Errors
    /// * Returns an [`Error`] if the assertion is not valid.
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

    /// Adds a JSON assertion to the manifest.
    /// Use only when the assertion must be stored in JSON format.
    ///
    /// # Arguments
    /// * `label` - A label for the assertion.
    /// * `data` - The data for the assertion; must be a Serde-serializable type.
    /// # Returns
    /// * A mutable reference to the [`Builder`].
    /// # Errors
    /// * Returns an [`Error`] if the assertion is not valid.
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

    /// Adds a single action to the manifest.
    /// This is a convenience method for adding an action to the `Actions` assertion.
    ///
    /// # Arguments
    /// * `action` - The action name as a string.
    /// * `data` - The data for the action as a Serde-serializable type.
    /// # Returns
    /// * A mutable reference to the [`Builder`].
    /// # Errors
    /// * Returns an [`Error`] if the action is not valid.
    /// # Example
    /// ```rust
    /// use c2pa::Builder;
    /// use serde_json::json;
    /// let created_action = json!({
    ///    "action": "c2pa.placed",
    ///    "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty"
    /// });
    ///
    /// let mut builder = Builder::new();
    /// builder.add_action(created_action);
    /// ```
    pub fn add_action<T>(&mut self, action: T) -> Result<&mut Self>
    where
        T: Serialize,
    {
        // Allow actions to be a Actions struct, or JSON string, or a serde_json::Value.
        let action_value = serde_json::to_value(action)?;
        let action: Action = serde_json::from_value(action_value).map_err(Error::JsonError)?;

        // if an actions assertion already exists, we will append to it
        // if not, we will create a new one
        let actions = if let Some(pos) = self
            .definition
            .assertions
            .iter()
            .position(|a| a.label == Actions::LABEL)
        {
            // Remove and use the existing actions assertion
            let assertion_def = self.definition.assertions.remove(pos);
            assertion_def.to_assertion()?
        } else {
            Actions::new()
        };

        let actions = actions.add_action(action);

        self.add_assertion(Actions::LABEL, &actions)?;
        Ok(self)
    }

    /// Adds an [`Ingredient`] to the manifest with JSON and a stream.
    // TODO: Add example.
    ///
    /// # Arguments
    /// * `ingredient_json` - A JSON string representing the [`Ingredient`].  This ingredient is merged  with the ingredient specified in the `stream` argument, and these values take precedence.
    /// * `format` - The format of the [`Ingredient`].
    /// * `stream` - A stream from which to read the [`Ingredient`].  This ingredient is merged  with the ingredient specified in the `ingredient_json` argument, whose values take precedence.  You can specify values here that are not specified in `ingredient_json`.
    /// # Returns
    /// * A mutable reference to the [`Ingredient`].
    /// # Errors
    /// * Returns an [`Error`] if the [`Ingredient`] is not valid
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
    ///
    /// The ID must match an identifier in the manifest.
    ///
    /// # Arguments
    /// * `id` - The identifier for the resource.
    /// * `stream` - A stream to read the resource from.
    /// # Returns
    /// * A mutable reference to the Builder.
    /// # Errors
    /// * Returns an [`Error`] if the resource is not valid.
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
    /// The archive is a stream in zip format containing the manifest JSON, resources, and ingredients.
    /// # Arguments
    /// * `stream` - A stream to write the zip into.
    /// # Errors
    /// * Returns an [`Error`] if the archive cannot be written.
    pub fn to_archive(&mut self, stream: impl Write + Seek) -> Result<()> {
        drop(
            // this drop seems to be required to force a flush before reading back.
            {
                let mut zip = ZipWriter::new(stream);
                let options =
                    SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
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
                    zip.start_file(format!("resources/{id}"), options)
                        .map_err(|e| Error::OtherError(Box::new(e)))?;
                    zip.write_all(data)?;
                }
                // Write the manifest_data files
                // The filename is filesystem safe version of the associated manifest_label
                // with a .c2pa extension inside a "manifests" folder.
                zip.start_file("manifests/", options)
                    .map_err(|e| Error::OtherError(Box::new(e)))?;
                for ingredient in self.definition.ingredients.iter() {
                    for (id, data) in ingredient.resources().resources() {
                        zip.start_file(format!("resources/{id}"), options)
                            .map_err(|e| Error::OtherError(Box::new(e)))?;
                        zip.write_all(data)?;
                    }

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
    ///
    /// # Arguments
    /// * `stream` - A stream from which to read the archive.
    /// # Returns
    /// * A new Builder.
    /// # Errors
    /// * Returns an [`Error`] if the archive cannot be read.
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
            // Adds the manifest data to any ingredient that has a matching active_manfiest label.
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
                    return Err(Error::OtherError(Box::new(std::io::Error::other(format!(
                        "Invalid ingredient index {index}"
                    )))))?; // todo add specific error
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
        if claim_generator_info.is_empty() {
            let claim_generator_info_settings = settings::get_settings_value::<
                Option<ClaimGeneratorInfoSettings>,
            >("builder.claim_generator_info");
            match claim_generator_info_settings {
                Ok(Some(claim_generator_info_settings)) => {
                    claim_generator_info.push(claim_generator_info_settings.try_into()?);
                }
                _ => {
                    claim_generator_info.push(ClaimGeneratorInfo::default());
                }
            }
        }

        claim_generator_info[0].insert("org.contentauth.c2pa_rs", env!("CARGO_PKG_VERSION"));

        // Build the claim_generator string since this is required
        let claim_generator: String = if self.claim_version() == 1 {
            claim_generator_info
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
                .join(" ")
        } else {
            "".to_string() // claim_generator is not used in version 2
        };

        let mut claim = match definition.label.as_ref() {
            Some(label) => Claim::new_with_user_guid(
                &claim_generator,
                &label.to_string(),
                self.claim_version().into(),
            )?,
            None => Claim::new(
                &claim_generator,
                definition.vendor.as_deref(),
                self.claim_version().into(),
            ),
        };

        // add claim generator info to claim and resolve icons
        for info in &claim_generator_info {
            let mut claim_info = info.to_owned();
            if let Some(icon) = claim_info.icon.as_ref() {
                claim_info.icon = Some(icon.to_hashed_uri(&self.resources, &mut claim)?);
            }
            claim.add_claim_generator_info(claim_info);
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
        claim.format = Some(definition.format.clone());
        definition.instance_id.clone_into(&mut claim.instance_id);

        let salt = DefaultSalt::default();

        if let Some(thumb_ref) = definition.thumbnail.as_ref() {
            // Setting the format to "none" will ensure that no claim thumbnail is added
            if thumb_ref.format != "none" {
                //let data = self.resources.get(&thumb_ref.identifier)?;
                let mut stream = self.resources.open(thumb_ref)?;
                let mut data = Vec::new();
                stream.read_to_end(&mut data)?;
                let thumbnail = if claim.version() >= 2 {
                    EmbeddedData::new(
                        labels::CLAIM_THUMBNAIL,
                        format_to_mime(&thumb_ref.format),
                        data,
                    )
                } else {
                    Thumbnail::new(
                        &labels::add_thumbnail_format(labels::CLAIM_THUMBNAIL, &thumb_ref.format),
                        data,
                    )
                    .into()
                };
                claim.add_assertion_with_salt(&thumbnail, &salt)?;
            }
        }

        // add all ingredients to the claim
        // We use a map to track the ingredient IDs and their hashed URIs
        let mut ingredient_map = HashMap::new();

        for ingredient in &definition.ingredients {
            // use the label if it exists, otherwise use the instance_id
            let id = match ingredient.label() {
                Some(label) => label.to_string(),
                None => ingredient.instance_id().to_string(),
            };

            // add it to the claim
            let uri = ingredient.add_to_claim(
                &mut claim,
                definition.redactions.clone(),
                Some(&self.resources),
            )?;
            if !id.is_empty() {
                ingredient_map.insert(id, (ingredient.relationship(), uri));
            }
        }

        let mut found_actions = false;
        // add any additional assertions
        for manifest_assertion in &definition.assertions {
            match manifest_assertion.label.as_str() {
                l if l.starts_with(Actions::LABEL) => {
                    found_actions = true;

                    let mut actions: Actions = manifest_assertion.to_assertion()?;

                    Self::add_actions_assertion_settings(&ingredient_map, &mut actions)?;

                    let mut updates = Vec::new();
                    //#[allow(clippy::explicit_counter_loop)]
                    for (index, action) in actions.actions_mut().iter_mut().enumerate() {
                        // find and remove the temporary ingredientIds parameter (This h)
                        let ids = action.extract_ingredient_ids();

                        if let Some(ids) = ids {
                            let mut update = action.clone();
                            let mut uris = Vec::new();
                            for id in ids {
                                if let Some((_relationship, hash_url)) = ingredient_map.get(&id) {
                                    // todo: check for relationship/action mismatches
                                    uris.push(hash_url.clone());
                                } else {
                                    log::error!("Action ingredientId not found: {id}");
                                    if claim.version() >= 2 {
                                        return Err(Error::AssertionSpecificError(format!(
                                            "Action ingredientId not found: {id}"
                                        )));
                                    }
                                }
                            }

                            update = update.set_parameter("ingredients", uris)?;

                            updates.push((index, update));
                        }
                    }
                    for update in updates {
                        actions = actions.update_action(update.0, update.1);
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
                                Some(mut info) => {
                                    if let Some(icon) = info.icon.as_mut() {
                                        let icon =
                                            icon.to_hashed_uri(&self.resources, &mut claim)?;
                                        info.set_icon(icon);
                                    }
                                    Some(info)
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
                #[allow(deprecated)]
                CreativeWork::LABEL => {
                    let cw: CreativeWork = manifest_assertion.to_assertion()?;
                    claim.add_gathered_assertion_with_salt(&cw, &salt)
                }
                Exif::LABEL => {
                    let exif: Exif = manifest_assertion.to_assertion()?;
                    claim.add_gathered_assertion_with_salt(&exif, &salt)
                }
                BoxHash::LABEL => {
                    let box_hash: BoxHash = manifest_assertion.to_assertion()?;
                    claim.add_assertion_with_salt(&box_hash, &salt)
                }
                DataHash::LABEL => {
                    let data_hash: DataHash = manifest_assertion.to_assertion()?;
                    claim.add_assertion_with_salt(&data_hash, &salt)
                }
                BmffHash::LABEL => {
                    let bmff_hash: BmffHash = manifest_assertion.to_assertion()?;
                    claim.add_assertion_with_salt(&bmff_hash, &salt)
                }
                Metadata::LABEL => {
                    // user metadata will go through the fallback path
                    let metadata: Metadata = manifest_assertion.to_assertion()?;
                    claim.add_gathered_assertion_with_salt(&metadata, &salt)
                }
                _ => match &manifest_assertion.data {
                    AssertionData::Json(value) => claim.add_gathered_assertion_with_salt(
                        &User::new(&manifest_assertion.label, &serde_json::to_string(&value)?),
                        &salt,
                    ),
                    AssertionData::Cbor(value) => claim.add_gathered_assertion_with_salt(
                        &UserCbor::new(&manifest_assertion.label, serde_cbor::to_vec(value)?),
                        &salt,
                    ),
                },
            }?;
        }

        if !found_actions {
            let mut actions = Actions::new();
            Self::add_actions_assertion_settings(&ingredient_map, &mut actions)?;

            if !actions.actions().is_empty() {
                claim.add_assertion(&actions)?;
            }
        }

        Ok(claim)
    }

    /// Adds [ActionsSettings][crate::settings::ActionsSettings] to an
    /// [Actions][crate::assertions::Actions] assertion.
    ///
    /// This function takes into account the [Settings][crate::Settings]:
    /// * `builder.actions.auto_opened_action`
    /// * `builder.actions.templates`
    /// * `builder.actions.actions`
    /// * For more, see [Builder::add_auto_actions_assertions]
    fn add_actions_assertion_settings(
        ingredient_map: &HashMap<String, (&Relationship, HashedUri)>,
        actions: &mut Actions,
    ) -> Result<()> {
        if actions.all_actions_included.is_none() {
            let all_actions_included =
                settings::get_settings_value::<bool>("builder.actions.all_actions_included");
            if let Ok(all_actions_included) = all_actions_included {
                actions.all_actions_included = Some(all_actions_included);
            }
        }

        let action_templates = settings::get_settings_value::<Option<Vec<ActionTemplateSettings>>>(
            "builder.actions.templates",
        );
        if let Ok(Some(action_templates)) = action_templates {
            let action_templates = action_templates
                .into_iter()
                .map(|template| template.try_into())
                .collect::<Result<Vec<ActionTemplate>>>()?;
            match actions.templates {
                Some(ref mut templates) => {
                    templates.extend_from_slice(&action_templates);
                }
                None => actions.templates = Some(action_templates),
            }
        }

        let additional_actions =
            settings::get_settings_value::<Option<Vec<ActionSettings>>>("builder.actions.actions");
        if let Ok(Some(additional_actions)) = additional_actions {
            let additional_actions = additional_actions
                .into_iter()
                .map(|action| action.try_into())
                .collect::<Result<Vec<Action>>>()?;

            match actions.actions.is_empty() {
                false => {
                    actions.actions.extend(additional_actions);
                }
                true => actions.actions = additional_actions,
            }
        }
        Self::add_auto_actions_assertions_settings(ingredient_map, actions)
    }

    /// Adds c2pa.created, c2pa.opened, and c2pa.placed actions for the specified [Actions][crate::assertions::Actions]
    /// assertion if the condiitons are applicable as defined in the spec.
    ///
    /// This function takes into account the [Settings][crate::Settings]:
    /// * `builder.actions.auto_created_action`
    /// * `builder.actions.auto_opened_action`
    /// * `builder.actions.auto_placed_action`
    fn add_auto_actions_assertions_settings(
        ingredient_map: &HashMap<String, (&Relationship, HashedUri)>,
        actions: &mut Actions,
    ) -> Result<()> {
        // https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_mandatory_presence_of_at_least_one_actions_assertion
        let auto_created =
            settings::get_settings_value::<bool>("builder.actions.auto_created_action.enabled")?;
        let auto_opened =
            settings::get_settings_value::<bool>("builder.actions.auto_opened_action.enabled")?;
        if auto_created || auto_opened {
            // look for a parentOf relationship ingredient in the ingredient map and return a copy of the hashed URI if found.
            let parent_ingredient_uri = ingredient_map
                .iter()
                .find(|(_, (relationship, _))| *relationship == &Relationship::ParentOf)
                .map(|(_, (_, uri))| uri.clone());

            let action = match (parent_ingredient_uri, auto_created, auto_opened) {
                (Some(parent_ingredient_uri), _, true) => {
                    let action = Action::new(c2pa_action::OPENED);

                    let action =
                        action.set_parameter("ingredients", vec![parent_ingredient_uri])?;

                    let source_type = settings::get_settings_value::<Option<DigitalSourceType>>(
                        "builder.auto_opened_action.source_type",
                    );
                    match source_type {
                        Ok(Some(source_type)) => Some(action.set_source_type(source_type)),
                        _ => Some(action),
                    }
                }
                (None, true, _) => {
                    // The settings ensures this field always exists for the "c2pa.created" action.
                    let source_type = settings::get_settings_value::<Option<DigitalSourceType>>(
                        "builder.actions.auto_created_action.source_type",
                    );
                    match source_type {
                        Ok(Some(source_type)) => {
                            let action = {
                                let action = Action::new(c2pa_action::CREATED);
                                action.set_source_type(source_type)
                            };
                            Some(action)
                        }
                        _ => None,
                    }
                }
                _ => None,
            };

            // If the first action isn't "c2pa.created" or "c2pa.opened" then add ours,
            // or if there are no actions then add our action.
            if let Some(action) = action {
                if let Some(first_action) = actions.actions.first() {
                    if first_action.action() != c2pa_action::CREATED
                        && first_action.action() != c2pa_action::OPENED
                    {
                        actions.actions.insert(0, action);
                    }
                } else if actions.actions.is_empty() {
                    actions.actions.push(action);
                }
            }
        }

        // https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_relationship
        let auto_placed =
            settings::get_settings_value::<bool>("builder.actions.auto_placed_action.enabled")?;
        if auto_placed {
            // Get a list of ingredient URIs referenced by "c2pa.placed" actions.
            let mut referenced_uris = HashSet::new();
            for action in &actions.actions {
                if action.action() == c2pa_action::PLACED {
                    if let Some(ingredient_uris) = action.get_parameter("ingredients") {
                        if let Some(ingredient_uris) =
                            value_cbor_to_type::<Vec<HashedUri>>(ingredient_uris)
                        {
                            for uri in ingredient_uris {
                                referenced_uris.insert(uri.url());
                            }
                        }
                    }
                }
            }

            // If a "ComponentOf" ingredient doesn't have an associated "c2pa.placed" action, create it here.
            for (_id, (relationship, uri)) in ingredient_map.iter() {
                if *relationship == &Relationship::ComponentOf
                    && !referenced_uris.contains(&uri.url())
                {
                    let action = Action::new(c2pa_action::PLACED);

                    let action = action.set_parameter("ingredients", vec![uri])?;

                    let source_type = settings::get_settings_value::<Option<DigitalSourceType>>(
                        "builder.auto_placed_action.source_type",
                    );
                    let action = match source_type {
                        Ok(Some(source_type)) => action.set_source_type(source_type),
                        _ => action,
                    };
                    actions.actions.push(action);
                }
            }
        }
        Ok(())
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

        let auto_thumbnail =
            crate::settings::get_settings_value::<bool>("builder.thumbnail.enabled")?;
        if self.definition.thumbnail.is_none() && auto_thumbnail {
            stream.rewind()?;

            let mut stream = std::io::BufReader::new(stream);
            if let Some((output_format, image)) =
                crate::utils::thumbnail::make_thumbnail_bytes_from_stream(format, &mut stream)?
            {
                stream.rewind()?;

                // Do not write this as a file when reading from files
                let base_path = self.resources.take_base_path();
                self.resources
                    .add(self.definition.instance_id.clone(), image)?;
                if let Some(path) = base_path {
                    self.resources.set_base_path(path)
                }
                self.definition.thumbnail = Some(ResourceRef::new(
                    output_format.to_string(),
                    self.definition.instance_id.clone(),
                ));
            }
        }
        Ok(self)
    }

    /// Maybe add a parent ingredient to the manifest.
    fn maybe_add_parent<R>(&mut self, format: &str, stream: &mut R) -> Result<&mut Self>
    where
        R: Read + Seek + Send,
    {
        // check settings to see if we should add a parent ingredient
        let auto_parent = matches!(
            self.intent,
            Some(BuilderIntent::Edit | BuilderIntent::Update)
        );
        if auto_parent && !self.definition.ingredients.iter().any(|i| i.is_parent()) {
            let parent_def = serde_json::json!({
                "relationship": "parentOf",
            });
            stream.rewind()?;
            self.add_ingredient_from_stream(parent_def.to_string(), format, stream)?;
            stream.rewind()?;
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
    ///
    /// This is only used for applications doing their own data_hashed asset management.
    ///
    /// # Arguments
    /// * `reserve_size` - The size to reserve for the signature (taken from the signer).
    /// * `format` - The format of the target asset, the placeholder will be preformatted for this format.
    /// # Returns
    /// * The bytes of the `c2pa_manifest` placeholder.
    /// # Errors
    /// * Returns an [`Error`] if the placeholder cannot be created.
    pub fn data_hashed_placeholder(
        &mut self,
        reserve_size: usize,
        format: &str,
    ) -> Result<Vec<u8>> {
        let dh: Result<DataHash> = self.find_assertion(DataHash::LABEL);
        if dh.is_err() {
            let mut ph = DataHash::new("jumbf manifest", "sha256");
            for _ in 0..10 {
                ph.add_exclusion(HashRange::new(0u64, 2u64));
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
    ///
    /// This is used to create a manifest that can be embedded into a stream.
    /// It allows the caller to do the embedding.
    /// You must call `data_hashed` placeholder first to create the placeholder.
    /// The placeholder is then injected into the asset before calculating hashes
    /// You must either pass a source stream to generate the hashes or provide the hashes.
    ///
    /// # Arguments
    /// * `signer` - The signer to use.
    /// * `data_hash` - The updated data_hash to use for the manifest.
    /// * `format` - The format of the stream.
    /// * `source` - The stream to read from.
    /// # Returns
    /// * The bytes of the `c2pa_manifest` that was created (prep-formatted).
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
    ///
    /// This is used to create a manifest that can be embedded into a stream.
    /// It allows the caller to do the embedding.
    /// The manifest definition must already include a `BoxHash` assertion.
    ///
    /// # Arguments
    /// * `signer` - The signer to use.
    /// # Returns
    /// * The bytes of the c2pa_manifest that was created (prep-formatted).
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
    ///
    /// # Arguments
    /// * `format` - The format of the stream.
    /// * `source` - The source stream from which to read.
    /// * `dest` - The destination stream to write.
    /// * `signer` - The signer to use.
    /// # Returns
    /// * The bytes of c2pa_manifest that was embedded.
    /// # Errors
    /// * Returns an [`Error`] if the manifest cannot be signed.
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

        self.maybe_add_parent(&format, source)?;

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
    // Internal utility to set format and title based on destination filename.
    //
    // Also sets the instance_id to a new UUID and ensures the destination file does not exist.
    fn set_asset_from_dest<P: AsRef<Path>>(&mut self, dest: P) -> Result<()> {
        let path = dest.as_ref();
        if !path.exists() {
            // ensure the path to the file exists
            if let Some(output_dir) = path.parent() {
                std::fs::create_dir_all(output_dir)?;
            }
        } else {
            // if the file exists, we need to remove it to avoid appending to it
            return Err(crate::Error::BadParam(
                "Destination file already exists".to_string(),
            ));
        };

        self.definition.format =
            crate::format_from_path(path).ok_or(crate::Error::UnsupportedType)?;
        self.definition.instance_id = format!("xmp:iid:{}", Uuid::new_v4());
        if self.definition.title.is_none() {
            if let Some(title) = path.file_name() {
                self.definition.title = Some(title.to_string_lossy().to_string());
            }
        }
        Ok(())
    }

    /// Sign a set of fragmented BMFF files.
    ///
    /// Note: Currently this does not support files with existing C2PA manifest.
    ///
    /// # Arguments
    /// * `signer` - The signer to use.
    /// * `asset_path` - The path to the primary asset file.
    /// * `fragment_paths` - The paths to the fragmented files.
    /// * `output_path` - The path to the output file.
    ///
    /// # Errors
    /// * Returns an [`Error`] if the manifest cannot be signed.
    #[cfg(feature = "file_io")]
    pub fn sign_fragmented_files<P: AsRef<Path>>(
        &mut self,
        signer: &dyn Signer,
        asset_path: P,
        fragment_paths: &Vec<std::path::PathBuf>,
        output_path: P,
    ) -> Result<()> {
        if !output_path.as_ref().exists() {
            // ensure the path exists
            std::fs::create_dir_all(output_path.as_ref())?;
        } else {
            // if the file exists, we need to remove it
            if output_path.as_ref().is_file() {
                return Err(crate::Error::BadParam(
                    "output_path must be a folder".to_string(),
                ));
            } else {
                let file_name = asset_path.as_ref().file_name().unwrap_or_default();
                let mut output_file = output_path.as_ref().to_owned();
                output_file = output_file.join(file_name);
                if output_file.exists() {
                    return Err(crate::Error::BadParam(
                        "Destination file already exists".to_string(),
                    ));
                }
            }
        }

        // convert the manifest to a store
        let mut store = self.to_store()?;

        // sign and write our store to DASH content
        store.save_to_bmff_fragmented(
            asset_path.as_ref(),
            fragment_paths,
            output_path.as_ref(),
            signer,
        )
    }

    #[cfg(feature = "file_io")]
    /// Sign a file using a supplied signer.
    ///
    /// # Arguments
    /// * `source` - The path to the source file to read from.
    /// * `dest` - The path to the destination file to write to (must not already exist).
    /// * `signer` - The signer to use.
    /// # Returns
    /// * The bytes of c2pa_manifest that was created.
    /// # Errors
    /// * Returns an [`Error`] if the manifest cannot be signed or the destination file already exists.
    #[async_generic(async_signature(
        &mut self,
        signer: &dyn AsyncSigner,
        source: S,
        dest: D,
    ))]
    pub fn sign_file<S, D>(&mut self, signer: &dyn Signer, source: S, dest: D) -> Result<Vec<u8>>
    where
        S: AsRef<std::path::Path>,
        D: AsRef<std::path::Path>,
    {
        let source = source.as_ref();
        let dest = dest.as_ref();

        self.set_asset_from_dest(dest)?;

        // formats must match but allow extensions to be slightly different (i.e. .jpeg vs .jpg)s
        let format = crate::format_from_path(source).ok_or(crate::Error::UnsupportedType)?;
        let format_dest = crate::format_from_path(dest).ok_or(crate::Error::UnsupportedType)?;
        if format != format_dest {
            return Err(crate::Error::BadParam(
                "Source and destination file formats must match".to_string(),
            ));
        }
        let mut source = std::fs::File::open(source)?;

        let mut dest = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dest)?;
        if _sync {
            self.sign(signer, &format, &mut source, &mut dest)
        } else {
            self.sign_async(signer, &format, &mut source, &mut dest)
                .await
        }
    }

    /// Converts a manifest into a composed manifest with the specified format.
    ///
    /// This wraps the bytes in the container format of the specified format.
    /// So that it can be directly embedded into a stream of that format.
    ///
    /// # Arguments
    /// * `manifest_bytes` - The bytes of the manifest to convert.
    /// * `format` - The format to convert to.
    /// # Returns
    /// * The bytes of the composed manifest.
    /// # Errors
    /// * Returns an [`Error`] if the manifest cannot be converted.
    pub fn composed_manifest(manifest_bytes: &[u8], format: &str) -> Result<Vec<u8>> {
        Store::get_composed_manifest(manifest_bytes, format)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    use std::{io::Cursor, vec};

    use c2pa_macros::c2pa_test_async;
    use serde_json::json;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::*;

    use super::*;
    #[cfg(feature = "file_io")]
    use crate::utils::test::fixture_path;
    use crate::{
        assertions::{c2pa_action, BoxHash, DigitalSourceType},
        asset_handlers::jpeg_io::JpegIO,
        cbor_types::value_cbor_to_type,
        crypto::raw_signature::SigningAlg,
        hash_stream_by_alg,
        settings::Settings,
        utils::{test::write_jpeg_placeholder_stream, test_signer::test_signer},
        validation_results::ValidationState,
        HashedUri, Reader,
    };

    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    fn parent_json() -> String {
        json!({
            "title": "Parent Test",
            "relationship": "parentOf",
            "label": "CA.jpg",
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
            "title": "Test_Manifest",
            "format": "image/jpeg",
            "instance_id": "1234",
            "thumbnail": {
                "format": "image/jpeg",
                "identifier": "thumbnail.jpg"
            },
            "ingredients": [
                {
                    "title": "Test",
                    "format": "image/jpeg",
                    "relationship": "componentOf",
                    "label": "INGREDIENT_2",
                }
            ],
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.opened",
                                "parameters": {
                                    "ingredientIds": ["CA.jpg"]
                                },
                            },
                            {
                                "action": "c2pa.placed",
                                "parameters": {
                                    "ingredientIds": ["INGREDIENT_2"]
                                },
                            }

                        ]
                    }
                },
                {
                    "label": "org.test.assertion",
                    "data": "assertion"
                }
            ]
        })
        .to_string()
    }

    fn simple_manifest_json() -> String {
        json!({
            "claim_generator_info": [
                {
                    "name": "c2pa_test",
                    "version": "1.0.0"
                }
            ],
            "title": "Test_Manifest",
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty",
                            }
                        ]
                    }
                }
            ]
        })
        .to_string()
    }

    const TEST_IMAGE_CLEAN: &[u8] = include_bytes!("../tests/fixtures/IMG_0003.jpg");
    const TEST_IMAGE_CLOUD: &[u8] = include_bytes!("../tests/fixtures/cloud.jpg");
    const TEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
    const TEST_THUMBNAIL: &[u8] = include_bytes!("../tests/fixtures/thumbnail.jpg");
    const TEST_MANIFEST_CLOUD: &[u8] = include_bytes!("../tests/fixtures/cloud_manifest.c2pa");

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
        assert_eq!(definition.ingredients[0].title(), Some("Parent Test"));
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
        assert_eq!(definition.format, "image/jpeg".to_string());
        assert_eq!(definition.instance_id, "1234".to_string());
        assert_eq!(
            definition.thumbnail.clone().unwrap().identifier.as_str(),
            "thumbnail.jpg"
        );
        assert_eq!(definition.ingredients[0].title(), Some("Test"));
        assert_eq!(definition.assertions[0].label, "c2pa.actions".to_string());
        assert_eq!(
            definition.assertions[1].label,
            "org.test.assertion".to_string()
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
        // #[cfg(not(target_os = "wasi"))] // target directory is outside of sandbox
        // std::fs::write("../target/test.zip", zipped.get_ref()).unwrap();

        // unzip the manifest builder from the zipped stream
        zipped.rewind().unwrap();
        let mut builder = Builder::from_archive(&mut zipped).unwrap();

        // sign and write to the output stream
        let signer = test_signer(SigningAlg::Ps256);
        builder
            .sign(signer.as_ref(), format, &mut source, &mut dest)
            .unwrap();

        // read and validate the signed manifest store
        dest.rewind().unwrap();
        let manifest_store = Reader::from_stream(format, &mut dest).expect("from_bytes");

        println!("{manifest_store}");
        assert_ne!(manifest_store.validation_state(), ValidationState::Invalid);
        assert!(manifest_store.active_manifest().is_some());
        let manifest = manifest_store.active_manifest().unwrap();
        assert_eq!(manifest.title().unwrap(), "Test_Manifest");
        let test_assertion: TestAssertion = manifest.find_assertion("org.life.meaning").unwrap();
        assert_eq!(test_assertion.answer, 42);
    }

    #[test]
    fn test_builder_settings_auto_created() {
        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        Settings::from_toml(
            &toml::toml! {
                [builder.actions.auto_created_action]
                enabled = true
                source_type = (DigitalSourceType::Empty.to_string())
            }
            .to_string(),
        )
        .unwrap();

        let mut output = Cursor::new(Vec::new());
        Builder::new()
            .sign(
                &Settings::signer().unwrap(),
                "image/jpeg",
                &mut Cursor::new(TEST_IMAGE),
                &mut output,
            )
            .unwrap();

        output.rewind().unwrap();
        let reader = Reader::from_stream("image/jpeg", output).unwrap();

        let actions: Actions = reader
            .active_manifest()
            .unwrap()
            .find_assertion(Actions::LABEL)
            .unwrap();

        let action = actions.actions().first().unwrap();
        assert_eq!(action.action(), c2pa_action::CREATED);
    }

    #[test]
    fn test_builder_settings_auto_opened() {
        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        Settings::from_toml(
            &toml::toml! {
                [builder.actions.auto_opened_action]
                enabled = true
            }
            .to_string(),
        )
        .unwrap();

        let mut builder = Builder::new();
        builder
            .add_ingredient_from_stream(parent_json(), "image/jpeg", &mut Cursor::new(TEST_IMAGE))
            .unwrap();

        let mut output = Cursor::new(Vec::new());
        builder
            .sign(
                &Settings::signer().unwrap(),
                "image/jpeg",
                &mut Cursor::new(TEST_IMAGE),
                &mut output,
            )
            .unwrap();

        output.rewind().unwrap();
        let reader = Reader::from_stream("image/jpeg", output).unwrap();

        let actions: Actions = reader
            .active_manifest()
            .unwrap()
            .find_assertion(Actions::LABEL)
            .unwrap();

        let action = actions.actions().first().unwrap();
        assert_eq!(action.action(), c2pa_action::OPENED);

        let ingredient_uris = action.get_parameter("ingredients").unwrap();
        let ingredient_uris = value_cbor_to_type::<Vec<HashedUri>>(ingredient_uris).unwrap();

        // TODO: need API to get uri from ingredient
        // let target_uri = reader
        //     .active_manifest()
        //     .unwrap()
        //     .ingredients()
        //     .first()
        //     .unwrap()
        //     .uri()
        //     .unwrap();
        // let stored_uri = ingredient_uris.first().unwrap().url();
        // assert_eq!(target_uri, &stored_uri);

        let reader_json = reader.json();
        assert!(reader_json.contains(&ingredient_uris.first().unwrap().url()));
    }

    #[test]
    fn test_builder_settings_auto_placed() {
        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        Settings::from_toml(
            &toml::toml! {
                [builder.actions.auto_created_action]
                enabled = true
                source_type = (DigitalSourceType::Empty.to_string())

                [builder.actions.auto_placed_action]
                enabled = true
            }
            .to_string(),
        )
        .unwrap();

        let mut builder = Builder::new();
        builder
            .add_ingredient_from_stream(
                json!({
                    "title": "ComponentOf Test 1",
                    "relationship": "componentOf",
                    "label": "INGREDIENT_1",
                })
                .to_string(),
                "image/jpeg",
                &mut Cursor::new(TEST_IMAGE),
            )
            .unwrap();
        builder
            .add_ingredient_from_stream(
                json!({
                    "title": "ComponentOf Test 2",
                    "relationship": "componentOf",
                    "label": "INGREDIENT_2",
                })
                .to_string(),
                "image/jpeg",
                &mut Cursor::new(TEST_IMAGE),
            )
            .unwrap();

        let mut output = Cursor::new(Vec::new());
        builder
            .sign(
                &Settings::signer().unwrap(),
                "image/jpeg",
                &mut Cursor::new(TEST_IMAGE),
                &mut output,
            )
            .unwrap();

        output.rewind().unwrap();
        let reader = Reader::from_stream("image/jpeg", output).unwrap();

        let actions: Actions = reader
            .active_manifest()
            .unwrap()
            .find_assertion(Actions::LABEL)
            .unwrap();

        let action1 = actions.actions().get(1).unwrap();
        assert_eq!(action1.action(), c2pa_action::PLACED);

        let action2 = actions.actions().get(2).unwrap();
        assert_eq!(action2.action(), c2pa_action::PLACED);

        let reader_json = reader.json();

        for action in [action1, action2] {
            let ingredient_uris = action.get_parameter("ingredients").unwrap();
            let ingredient_uris = value_cbor_to_type::<Vec<HashedUri>>(ingredient_uris).unwrap();

            // TODO: need API to get uri from ingredient
            // let target_uri = reader
            //     .active_manifest()
            //     .unwrap()
            //     .ingredients()
            //     .get(i)
            //     .unwrap()
            //     .uri()
            //     .unwrap();
            // let stored_uri = ingredient_uris.first().unwrap().url();
            // assert_eq!(target_uri, &stored_uri);

            assert!(reader_json.contains(&ingredient_uris.first().unwrap().url()));
        }
    }

    #[test]
    fn test_builder_settings_all_actions_included() {
        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        Settings::from_toml(
            &toml::toml! {
                [builder.actions]
                all_actions_included = true

                [builder.actions.auto_created_action]
                enabled = true
                source_type = (DigitalSourceType::Empty.to_string())
            }
            .to_string(),
        )
        .unwrap();

        let mut output = Cursor::new(Vec::new());
        Builder::new()
            .sign(
                &Settings::signer().unwrap(),
                "image/jpeg",
                &mut Cursor::new(TEST_IMAGE),
                &mut output,
            )
            .unwrap();

        output.rewind().unwrap();
        let reader = Reader::from_stream("image/jpeg", output).unwrap();

        let actions: Actions = reader
            .active_manifest()
            .unwrap()
            .find_assertion(Actions::LABEL)
            .unwrap();

        assert_eq!(actions.all_actions_included, Some(true));
    }

    #[test]
    fn test_builder_settings_action_templates() {
        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        Settings::from_toml(
            &toml::toml! {
                [builder.actions.auto_created_action]
                enabled = true
                source_type = (DigitalSourceType::Empty.to_string())

                [[builder.actions.templates]]
                action = (c2pa_action::EDITED)
                source_type = (DigitalSourceType::Empty.to_string())

                [[builder.actions.templates]]
                action = (c2pa_action::COLOR_ADJUSTMENTS)
                source_type = (DigitalSourceType::TrainedAlgorithmicData.to_string())
            }
            .to_string(),
        )
        .unwrap();

        let mut output = Cursor::new(Vec::new());
        Builder::new()
            .sign(
                &Settings::signer().unwrap(),
                "image/jpeg",
                &mut Cursor::new(TEST_IMAGE),
                &mut output,
            )
            .unwrap();

        output.rewind().unwrap();
        let reader = Reader::from_stream("image/jpeg", output).unwrap();

        let actions: Actions = reader
            .active_manifest()
            .unwrap()
            .find_assertion("c2pa.actions.v2")
            .unwrap();

        let templates = actions.templates.unwrap();
        assert!(templates.len() == 2);

        for template in templates {
            match template.action.as_str() {
                c2pa_action::EDITED => {
                    assert_eq!(template.source_type, Some(DigitalSourceType::Empty));
                }
                c2pa_action::COLOR_ADJUSTMENTS => {
                    assert_eq!(
                        template.source_type,
                        Some(DigitalSourceType::TrainedAlgorithmicData)
                    );
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_builder_settings_actions() {
        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        Settings::from_toml(
            &toml::toml! {
                [builder.actions.auto_created_action]
                enabled = true
                source_type = (DigitalSourceType::Empty.to_string())

                [[builder.actions.actions]]
                action = (c2pa_action::EDITED)
                source_type = (DigitalSourceType::Empty.to_string())

                [[builder.actions.actions]]
                action = (c2pa_action::COLOR_ADJUSTMENTS)
                source_type = (DigitalSourceType::TrainedAlgorithmicData.to_string())
            }
            .to_string(),
        )
        .unwrap();

        let mut output = Cursor::new(Vec::new());
        Builder::new()
            .sign(
                &Settings::signer().unwrap(),
                "image/jpeg",
                &mut Cursor::new(TEST_IMAGE),
                &mut output,
            )
            .unwrap();

        output.rewind().unwrap();
        let reader = Reader::from_stream("image/jpeg", output).unwrap();

        let actions: Actions = reader
            .active_manifest()
            .unwrap()
            .find_assertion(Actions::LABEL)
            .unwrap();

        assert!(actions.actions.len() > 2);

        for action in actions.actions {
            match action.action() {
                c2pa_action::EDITED => {
                    assert_eq!(action.source_type(), Some(&DigitalSourceType::Empty));
                }
                c2pa_action::COLOR_ADJUSTMENTS => {
                    assert_eq!(
                        action.source_type(),
                        Some(&DigitalSourceType::TrainedAlgorithmicData)
                    );
                }
                _ => {}
            }
        }
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_builder_sign_file() {
        use crate::utils::io_utils::tempdirectory;

        let source = "tests/fixtures/CA.jpg";
        let dir = tempdirectory().unwrap();
        let dest = dir.path().join("test_file.jpg");
        let mut parent = std::fs::File::open(source).unwrap();

        let mut builder = Builder::from_json(&manifest_json()).unwrap();
        builder
            .add_ingredient_from_stream(parent_json(), "image/jpeg", &mut parent)
            .unwrap();

        builder
            .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
            .unwrap();

        // sign and write to the output stream
        let signer = test_signer(SigningAlg::Ps256);
        builder.sign_file(signer.as_ref(), source, &dest).unwrap();

        // read and validate the signed manifest store
        let manifest_store = Reader::from_file(&dest).expect("from_bytes");

        println!("{manifest_store}");
        assert_ne!(manifest_store.validation_state(), ValidationState::Invalid);
        assert_eq!(manifest_store.validation_status(), None);
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
            "sample1.m4a",
            "video1_no_manifest.mp4",
            //"cloud_manifest.c2pa", // we need a new test for this since it will always fail
        ];
        for file_name in TESTFILES {
            let extension = file_name.split('.').next_back().unwrap();
            let format = extension;

            let path = format!("tests/fixtures/{file_name}");
            println!("path: {path}");
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
            let signer = test_signer(SigningAlg::Ps256);
            builder
                .sign(signer.as_ref(), format, &mut source, &mut dest)
                .unwrap();

            // read and validate the signed manifest store
            dest.rewind().unwrap();
            let manifest_store = Reader::from_stream(format, &mut dest).expect("from_bytes");

            //println!("{}", manifest_store);
            if format != "c2pa" {
                // c2pa files will not validate since they have no associated asset
                assert_ne!(manifest_store.validation_state(), ValidationState::Invalid);
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

    #[c2pa_test_async]
    #[cfg(feature = "v1_api")]
    async fn test_builder_remote_sign() {
        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::from_json(&simple_manifest_json()).unwrap();
        builder
            .add_ingredient_from_stream(parent_json(), format, &mut source)
            .unwrap();

        builder
            .resources
            .add("thumbnail.jpg", TEST_THUMBNAIL.to_vec())
            .unwrap();

        // sign the Builder and write it to the output stream
        let signer = crate::utils::test::temp_async_remote_signer();
        builder
            .sign_async(signer.as_ref(), format, &mut source, &mut dest)
            .await
            .unwrap();

        // read and validate the signed manifest store
        dest.rewind().unwrap();
        let manifest_store = Reader::from_stream(format, &mut dest).expect("from_bytes");

        assert_eq!(manifest_store.validation_status(), None);

        assert_eq!(
            manifest_store.active_manifest().unwrap().title().unwrap(),
            "Test_Manifest"
        );
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_builder_remote_url() {
        let mut source = Cursor::new(TEST_IMAGE_CLEAN);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::from_json(&simple_manifest_json()).unwrap();
        builder.remote_url = Some("http://my_remote_url".to_string());
        builder.no_embed = true;

        // sign the Builder and write it to the output stream
        let signer = test_signer(SigningAlg::Ps256);
        let manifest_data = builder
            .sign(signer.as_ref(), "image/jpeg", &mut source, &mut dest)
            .unwrap();

        // check to make sure we have a remote url and no manifest data
        dest.set_position(0);
        let _err = Reader::from_stream("image/jpeg", &mut dest).expect_err("from_bytes");

        // now validate the manifest against the written asset
        dest.set_position(0);
        let reader = Reader::from_manifest_data_and_stream(&manifest_data, "image/jpeg", &mut dest)
            .expect("from_bytes");

        println!("{}", reader.json());
        assert_eq!(reader.validation_status(), None);
    }

    #[test]
    fn test_builder_data_hashed_embeddable() {
        const CLOUD_IMAGE: &[u8] = include_bytes!("../tests/fixtures/cloud.jpg");
        let mut input_stream = Cursor::new(CLOUD_IMAGE);

        let signer = test_signer(SigningAlg::Ps256);

        let mut builder = Builder::from_json(&simple_manifest_json()).unwrap();

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
        let exclusion = crate::HashRange::new(offset as u64, placeholder.len() as u64);
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
        assert_eq!(reader.validation_status(), None);
    }

    #[c2pa_test_async]
    #[cfg(any(target_arch = "wasm32", feature = "file_io"))]
    async fn test_builder_box_hashed_embeddable() {
        use crate::asset_io::{CAIWriter, HashBlockObjectType};
        const BOX_HASH_IMAGE: &[u8] = include_bytes!("../tests/fixtures/boxhash.jpg");
        const BOX_HASH: &[u8] = include_bytes!("../tests/fixtures/boxhash.json");

        let mut input_stream = Cursor::new(BOX_HASH_IMAGE);

        // get saved box hash settings
        let box_hash: BoxHash = serde_json::from_slice(BOX_HASH).unwrap();

        let mut builder = Builder::from_json(&simple_manifest_json()).unwrap();

        builder.add_assertion(labels::BOX_HASH, &box_hash).unwrap();

        let signer = crate::utils::test_signer::async_test_signer(SigningAlg::Ed25519);

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
        assert_eq!(_reader.validation_status(), None);
    }

    #[c2pa_test_async]
    #[cfg(any(target_arch = "wasm32", feature = "file_io"))]
    async fn test_builder_box_hashed_embeddable_with_exclusions() {
        use crate::asset_io::{CAIWriter, HashBlockObjectType};
        const BOX_HASH_IMAGE: &[u8] = include_bytes!("../tests/fixtures/boxhash.jpg");
        const BOX_HASH: &[u8] = include_bytes!("../tests/fixtures/boxhash_with_exclusion.json");

        let mut input_stream = Cursor::new(BOX_HASH_IMAGE);

        // get saved box hash settings
        let box_hash: BoxHash = serde_json::from_slice(BOX_HASH).unwrap();

        let mut builder = Builder::from_json(&simple_manifest_json()).unwrap();

        builder.add_assertion(labels::BOX_HASH, &box_hash).unwrap();

        let signer = crate::utils::test_signer::async_test_signer(SigningAlg::Ed25519);

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
        assert_eq!(_reader.validation_status(), None);
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn test_builder_base_path() {
        let mut source = Cursor::new(TEST_IMAGE_CLEAN);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::from_json(&manifest_json()).unwrap();
        builder.base_path = Some(std::path::PathBuf::from("tests/fixtures"));
        builder
            .add_ingredient_from_stream(parent_json().to_string(), "image/jpeg", &mut source)
            .unwrap();

        // Ensure that we can zip and unzip, saving the base path
        let mut zipped = Cursor::new(Vec::new());
        builder.to_archive(&mut zipped).unwrap();

        // unzip the manifest builder from the zipped stream
        zipped.rewind().unwrap();
        let mut builder = Builder::from_archive(&mut zipped).unwrap();

        // sign the Builder and write it to the output stream
        let signer = test_signer(SigningAlg::Ps256);
        let _manifest_data = builder
            .sign(signer.as_ref(), "image/jpeg", &mut source, &mut dest)
            .unwrap();

        // read and validate the signed manifest store
        dest.rewind().unwrap();
        let reader = Reader::from_stream("image/jpeg", &mut dest).expect("from_bytes");

        //println!("{}", reader);
        assert_ne!(reader.validation_state(), ValidationState::Invalid);
        assert_eq!(reader.validation_status(), None);
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

    const MANIFEST_JSON: &str = r#"{
        "claim_generator_info": [
            {
                "name": "test",
                "version": "1.0",
                "icon": {
                    "format": "image/svg+xml",
                    "identifier": "sample1.svg"
                }
            }
        ],
        "format" : "image/jpeg",
        "thumbnail": {
            "format": "image/jpeg",
            "identifier": "IMG_0003.jpg"
        },
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.opened",
                            "parameters": {
                                "description": "import",
                                "ingredientIds": [
                                    "xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738d"
                                ]
                            },
                            "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/algorithmicMedia",
                            "softwareAgent": {
                                "name": "TestApp",
                                "version": "1.0",
                                "icon": {
                                    "format": "image/svg+xml",
                                    "identifier": "sample1.svg"
                                },
                                "something": "else"
                            }
                        },
                        {
                            "action": "c2pa.dubbed",
                            "softwareAgent": {
                                "name": "Test Dubber"
                            },
                            "changes": [
                                {
                                    "region" : [
                                        {
                                            "type" : "temporal",
                                            "time" : {}
                                        },
                                        {
                                            "type": "identified",
                                            "item": {
                                                "identifier": "https://bioportal.bioontology.org/ontologies/FMA",
                                                "value": "lips"
                                            }
                                        }
                                    ],
                                    "description": "lip synced area"
                                }
                            ]
                        }
                    ],
                    "templates": [
                        {
                            "action": "c2pa.opened",
                            "softwareAgent": {
                                "name": "TestApp",
                                "version": "1.0",
                                "icon": {
                                    "format": "image/svg+xml",
                                    "identifier": "sample1.svg"
                                },
                                "something": "else"
                            },
                            "icon": {
                                "format": "image/svg+xml",
                                "identifier": "sample1.svg"
                            }
                        }
                    ]
                }
            }
        ],
        "ingredients": [{
            "title": "A.jpg",
            "format": "image/jpeg",
            "instance_id": "xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738d",
            "document_id": "xmp.did:813ee422-9736-4cdc-9be6-4e35ed8e41cb",
            "relationship": "parentOf",
            "thumbnail": {
                "format": "image/png",
                "identifier": "exp-test1.png"
            }
        },
        {
            "title": "prompt",
            "format": "text/plain",
            "relationship": "inputTo",
            "data": {
                "format": "text/plain",
                "identifier": "prompt.txt"
            },
            "data_types": [
                {
                    "type": "c2pa.types.generator.prompt"
                }
            ]
        },
        {
            "title": "Custom AI Model",
            "format": "application/octet-stream",
            "relationship": "inputTo",
            "data_types": [
                {
                    "type": "c2pa.types.model"
                }
            ]
          }
        ]
    }"#;

    #[test]
    /// tests and illustrates how to add assets to a non-file based manifest by using a stream
    fn from_json_with_stream_full_resources() {
        use crate::utils::test::setup_logger;
        setup_logger();
        use crate::assertions::Relationship;

        let mut builder = Builder::from_json(MANIFEST_JSON).unwrap();
        // add binary resources to manifest and ingredients giving matching the identifiers given in JSON
        builder
            .add_resource("IMG_0003.jpg", Cursor::new(b"jpeg data"))
            .unwrap()
            .add_resource("sample1.svg", Cursor::new(b"svg data"))
            .expect("add resource")
            .add_resource("exp-test1.png", Cursor::new(b"png data"))
            .expect("add_resource")
            .add_resource("prompt.txt", Cursor::new(b"pirate with bird on shoulder"))
            .expect("add_resource");

        //println!("{builder}");

        let image = include_bytes!("../tests/fixtures/earth_apollo17.jpg");
        // convert buffer to cursor with Read/Write/Seek capability
        let mut input = Cursor::new(image.to_vec());

        let signer = test_signer(SigningAlg::Ps256);
        // Embed a manifest using the signer.
        let mut output = Cursor::new(Vec::new());
        builder
            .sign(signer.as_ref(), "jpeg", &mut input, &mut output)
            .expect("builder sign");

        output.set_position(0);
        println!("output len: {}", output.get_ref().len());
        let reader = Reader::from_stream("jpeg", &mut output).expect("from_bytes");
        println!("reader = {reader}");
        let m = reader.active_manifest().unwrap();

        //println!("after = {m}");

        assert!(m.thumbnail().is_some());
        assert!(m.thumbnail_ref().is_some());
        assert_eq!(m.thumbnail_ref().unwrap().format, "image/jpeg");
        let id = m.thumbnail_ref().unwrap().identifier.as_str();
        let mut thumbnail_data = Cursor::new(Vec::new());
        reader.resource_to_stream(id, &mut thumbnail_data).unwrap();
        assert_eq!(thumbnail_data.into_inner(), b"jpeg data");

        assert_eq!(m.ingredients().len(), 3);
        // Validate a prompt ingredient (with data field)
        let prompt = &m.ingredients()[1];
        assert_eq!(prompt.title(), Some("prompt"));
        assert_eq!(prompt.relationship(), &Relationship::InputTo);
        assert!(prompt.data_ref().is_some());
        assert_eq!(prompt.data_ref().unwrap().format, "text/plain");
        let id = prompt.data_ref().unwrap().identifier.as_str();
        let mut prompt_data = Cursor::new(Vec::new());
        reader.resource_to_stream(id, &mut prompt_data).unwrap();
        assert_eq!(prompt_data.into_inner(), b"pirate with bird on shoulder");

        // Validate a custom AI model ingredient.
        assert_eq!(m.ingredients()[2].title(), Some("Custom AI Model"));
        assert_eq!(m.ingredients()[2].relationship(), &Relationship::InputTo);
        assert_eq!(
            m.ingredients()[2].data_types().unwrap()[0].asset_type,
            "c2pa.types.model"
        );

        // validate the claim_generator_info
        let cgi = m.claim_generator_info.as_ref().unwrap();
        assert_eq!(cgi[0].name, "test");
        assert_eq!(cgi[0].version.as_ref().unwrap(), "1.0");
        match cgi[0].icon().unwrap() {
            crate::resource_store::UriOrResource::ResourceRef(resource) => {
                assert_eq!(resource.format, "image/svg+xml");
                let mut icon_data = Cursor::new(Vec::new());
                reader
                    .resource_to_stream(&resource.identifier, &mut icon_data)
                    .unwrap();
                assert_eq!(icon_data.into_inner(), b"svg data");
            }
            _ => unreachable!(),
        }

        // println!("{manifest_store}");
    }

    #[test]
    fn test_composed_manifest() {
        let manifest: &[u8; 4] = b"abcd";
        let format = "image/jpeg";
        let composed = Builder::composed_manifest(manifest, format).unwrap();
        assert_eq!(composed.len(), 16);
    }

    /// example of creating a builder directly with a [`ManifestDefinition`]
    #[c2pa_test_async]
    /// test if the sdk can add a cloud ingredient retrieved from a stream and a cloud manifest
    // This works with or without the fetch_remote_manifests feature
    async fn test_add_cloud_ingredient() {
        // Save original settings
        let original_remote_fetch =
            crate::settings::get_settings_value("verify.remote_manifest_fetch").unwrap_or(true);

        // Set our test settings
        crate::settings::set_settings_value("verify.remote_manifest_fetch", false).unwrap();

        let mut input = Cursor::new(TEST_IMAGE_CLEAN);
        let mut cloud_image = Cursor::new(TEST_IMAGE_CLOUD);

        let definition = ManifestDefinition {
            claim_version: Some(1),
            claim_generator_info: [ClaimGeneratorInfo::default()].to_vec(),
            format: "image/jpeg".to_string(),
            title: Some("Test_Manifest".to_string()),
            ..Default::default()
        };

        let mut builder = Builder {
            definition,
            ..Default::default()
        };

        let parent_json = json!({
            "title": "Parent Test",
            "format": "image/jpeg",
            "instance_id": "12345",
            "relationship": "parentOf",
            "manifest_data": {
                "format": "application/c2pa",
                "identifier": "cloud_manifest"
            }
        })
        .to_string();

        // add the cloud manifest data to the builder
        builder
            .add_resource(
                "cloud_manifest",
                Cursor::new(Cursor::new(TEST_MANIFEST_CLOUD).get_ref()),
            )
            .unwrap();

        builder
            .add_ingredient_from_stream(parent_json, "image/jpeg", &mut cloud_image)
            .unwrap();

        builder
            .add_assertion("org.test.assertion", &"assertion".to_string())
            .unwrap();

        let signer = test_signer(SigningAlg::Ps256);
        // Embed a manifest using the signer.
        let mut output = Cursor::new(Vec::new());
        builder
            .sign(signer.as_ref(), "jpeg", &mut input, &mut output)
            .expect("builder sign");

        output.set_position(0);

        let reader = Reader::from_stream("jpeg", &mut output).expect("from_bytes");
        let m = reader.active_manifest().unwrap();
        assert_eq!(m.ingredients().len(), 1);
        assert!(m.ingredients()[0].active_manifest().is_some());

        // Restore original settings
        crate::settings::set_settings_value("verify.remote_manifest_fetch", original_remote_fetch)
            .unwrap();
    }

    #[test]
    fn test_redaction() {
        Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml")).unwrap();
        //crate::utils::test::setup_logger();

        // the label of the assertion we are going to redact
        const ASSERTION_LABEL: &str = "stds.schema-org.CreativeWork";

        let mut input = Cursor::new(TEST_IMAGE);

        let parent = Reader::from_stream("image/jpeg", &mut input).expect("from_stream");
        let parent_manifest_label = parent.active_label().unwrap();
        // Create a redacted uri for the assertion we are going to redact.
        let redacted_uri =
            crate::jumbf::labels::to_assertion_uri(parent_manifest_label, ASSERTION_LABEL);

        let mut builder = Builder::edit();
        builder.definition.redactions = Some(vec![redacted_uri.clone()]);

        let redacted_action = crate::assertions::Action::new("c2pa.redacted")
            .set_reason("testing".to_owned())
            .set_parameter("redacted".to_owned(), redacted_uri.clone())
            .unwrap();

        builder.add_action(redacted_action).unwrap();

        let signer = test_signer(SigningAlg::Ps256);
        // Embed a manifest using the signer.
        let mut output = Cursor::new(Vec::new());
        builder
            .sign(signer.as_ref(), "image/jpeg", &mut input, &mut output)
            .expect("builder sign");

        output.set_position(0);

        let reader = Reader::from_stream("image/jpeg", &mut output).expect("from_bytes");
        //println!("{reader}");
        let m = reader.active_manifest().unwrap();
        assert_eq!(m.ingredients().len(), 1);
        let parent = reader.get_manifest(parent_manifest_label).unwrap();
        assert_eq!(parent.assertions().len(), 1);
    }

    #[test]
    fn test_supported_mime_types() {
        let mime_types = Builder::supported_mime_types();
        assert!(mime_types.contains(&"image/jpeg".to_string()));
        assert!(mime_types.contains(&"image/png".to_string()));
        assert!(mime_types.contains(&"image/gif".to_string()));
        assert!(mime_types.contains(&"image/webp".to_string()));
        assert!(mime_types.contains(&"image/avif".to_string()));
        assert!(mime_types.contains(&"image/heic".to_string()));
        assert!(mime_types.contains(&"image/heif".to_string()));
    }

    #[cfg(all(feature = "add_thumbnails", feature = "file_io"))]
    #[test]
    fn test_to_archive_and_from_archive_with_ingredient_thumbnail() {
        let mut builder = Builder::from_json(&simple_manifest_json()).unwrap();

        let mut thumbnail = Cursor::new(TEST_THUMBNAIL);
        let mut source = Cursor::new(TEST_IMAGE_CLEAN);

        let signer = test_signer(SigningAlg::Ps256);

        let ingredient_json = r#"{"title": "Test Ingredient"}"#;
        builder
            .add_ingredient_from_stream(ingredient_json, "image/jpeg", &mut thumbnail)
            .unwrap();

        let mut archive = Cursor::new(Vec::new());
        assert!(builder.to_archive(&mut archive).is_ok());

        let mut builder = Builder::from_archive(archive).unwrap();

        let mut output = Cursor::new(Vec::new());

        assert!(builder
            .sign(&signer, "image/jpeg", &mut source, &mut output)
            .is_ok());

        let reader_json = Reader::from_stream("image/jpeg", &mut output)
            .unwrap()
            .json();
        println!("{reader_json}");
        assert!(reader_json.contains("Test Ingredient"));
        assert!(reader_json.contains("thumbnail.ingredient"));
    }

    /// Test Builder add_action with a serde_json::Value
    #[test]
    fn test_builder_add_action_with_value() {
        let mut builder = Builder::new();
        let action = json!({
            "action": "com.example.test-action",
            "parameters": {
                "key1": "value1",
                "key2": "value2"
            }
        });
        builder.add_action(action).unwrap();
        println!("{:#?}", builder.definition);
        assert!(!builder.definition.assertions.is_empty());
    }

    /// Test builder add_action with an Action struct
    #[test]
    fn test_builder_add_action_with_struct() {
        use crate::assertions::Action;
        let mut builder = Builder::new();
        let action = Action::new("com.example.test-action")
            .set_parameter("key1", "value1")
            .unwrap()
            .set_parameter("key2", "value2")
            .unwrap();
        builder.add_action(action).unwrap();
        println!("{:#?}", builder.definition);
        assert!(!builder.definition.assertions.is_empty());
    }
    /// Test builder set_base_path
    #[cfg(feature = "file_io")]
    #[test]
    fn test_builder_set_base_path() {
        let mut builder = Builder::new();
        let ingredient_folder = fixture_path("ingredient");
        builder.set_base_path(&ingredient_folder);
        assert_eq!(builder.base_path.as_ref(), Some(&ingredient_folder));
        let ingredient_json =
            std::fs::read_to_string(ingredient_folder.join("ingredient.json")).unwrap();

        let ingredient = Ingredient::from_json(&ingredient_json).unwrap();
        builder.add_ingredient(ingredient);

        let signer = test_signer(SigningAlg::Ps256);

        let mut source = Cursor::new(TEST_IMAGE_CLEAN);
        let mut dest = Cursor::new(Vec::new());

        builder
            .sign(&signer, "image/jpeg", &mut source, &mut dest)
            .unwrap();

        let reader = Reader::from_stream("jpeg", &mut dest).unwrap();
        let active_manifest = reader.active_manifest().unwrap();
        let ingredient = active_manifest.ingredients().first().unwrap();
        assert_eq!(ingredient.title(), Some("C.jpg"));
    }
}
