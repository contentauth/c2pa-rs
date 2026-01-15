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
    sync::Arc,
};

use async_generic::async_generic;
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::skip_serializing_none;
use uuid::Uuid;
use zip::{write::SimpleFileOptions, ZipArchive, ZipWriter};

#[allow(deprecated)]
use crate::assertions::CreativeWork;
use crate::{
    assertion::{AssertionBase, AssertionDecodeError},
    assertions::{
        c2pa_action, labels, Action, ActionTemplate, Actions, AssertionMetadata, BmffHash, BoxHash,
        DataHash, DigitalSourceType, EmbeddedData, Exif, Metadata, SoftwareAgent, Thumbnail, User,
        UserCbor,
    },
    claim::Claim,
    context::Context,
    error::{Error, Result},
    jumbf_io,
    resource_store::{ResourceRef, ResourceResolver, ResourceStore},
    store::Store,
    utils::{hash_utils::hash_to_b64, mime::format_to_mime},
    AsyncSigner, ClaimGeneratorInfo, HashRange, HashedUri, Ingredient, ManifestAssertionKind,
    Reader, Relationship, Signer,
};

/// Version of the Builder Archive file
const ARCHIVE_VERSION: &str = "1";

/// Sanitizes a path to prevent directory traversal attacks.
///
/// This function validates that the path:
/// - Does not contain '..' components
/// - Does not contain absolute path markers
/// - Does not escape the intended directory structure
///
/// # Arguments
/// * `path` - The path string to sanitize
///
/// # Returns
/// * The sanitized path if valid
///
/// # Errors
/// * Returns an [`Error::BadParam`] if the path contains dangerous components
fn sanitize_archive_path(path: &str) -> Result<String> {
    // Reject empty paths
    if path.is_empty() {
        return Err(Error::BadParam("Empty path not allowed".to_string()));
    }

    // Reject paths that start with '/' (absolute paths)
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(Error::BadParam(format!(
            "Absolute path not allowed: {}",
            path
        )));
    }

    // Check for drive letters on Windows (e.g., "C:")
    if path.len() >= 2 && path.chars().nth(1) == Some(':') {
        return Err(Error::BadParam(format!(
            "Drive letter not allowed: {}",
            path
        )));
    }

    // Split the path and check each component
    let components: Vec<&str> = path.split(&['/', '\\'][..]).collect();

    for component in &components {
        // Reject '..' components
        if *component == ".." {
            return Err(Error::BadParam(format!(
                "Path traversal not allowed: {}",
                path
            )));
        }

        // Reject empty components (which could come from '//')
        if component.is_empty() {
            continue; // Allow empty components from trailing slashes
        }
    }

    // Normalize the path to use forward slashes
    Ok(path.replace('\\', "/"))
}

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

    /// Claim Generator Info is always required with an entry
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

// TryFrom implementations for ManifestDefinition

/// Implement TryFrom for &str (JSON string)
impl TryFrom<&str> for ManifestDefinition {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        serde_json::from_str(value).map_err(Error::JsonError)
    }
}

/// Implement TryFrom for String
impl TryFrom<String> for ManifestDefinition {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        value.as_str().try_into()
    }
}

/// Implement TryFrom for &String
impl TryFrom<&String> for ManifestDefinition {
    type Error = Error;

    fn try_from(value: &String) -> Result<Self> {
        value.as_str().try_into()
    }
}

/// Implement TryFrom for serde_json::Value
impl TryFrom<serde_json::Value> for ManifestDefinition {
    type Error = Error;

    fn try_from(value: serde_json::Value) -> Result<Self> {
        serde_json::from_value(value).map_err(Error::JsonError)
    }
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
#[derive(Debug, Serialize, Clone)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[non_exhaustive]
pub struct AssertionDefinition {
    /// An assertion label in reverse domain format
    pub label: String,
    /// The assertion data
    pub data: AssertionData,
    /// The kind of assertion data, either Cbor or Json (defaults to Cbor)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<ManifestAssertionKind>,
    /// True if this assertion is attributed to the signer (defaults to false)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub created: bool,
}

impl<'de> Deserialize<'de> for AssertionDefinition {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            label: String,
            data: serde_json::Value,
            #[serde(default)]
            kind: Option<ManifestAssertionKind>,
            #[serde(default)]
            created: bool,
        }

        let helper = Helper::deserialize(deserializer)?;

        let data = match helper.kind {
            Some(ManifestAssertionKind::Json) => AssertionData::Json(helper.data),
            Some(ManifestAssertionKind::Cbor) | None => {
                let cbor_val =
                    serde_cbor::value::to_value(helper.data).map_err(serde::de::Error::custom)?;
                AssertionData::Cbor(cbor_val)
            }
            _ => {
                return Err(serde::de::Error::custom(format!(
                    "Unsupported assertion kind for label {}",
                    helper.label
                )));
            }
        };

        Ok(AssertionDefinition {
            label: helper.label,
            data,
            kind: helper.kind,
            created: helper.created,
        })
    }
}

impl AssertionDefinition {
    pub(crate) fn label(&self) -> &str {
        self.label.as_str()
    }

    pub(crate) fn created(&self) -> bool {
        self.created
    }

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
pub enum BuilderIntent {
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

    /// A restricted version of Edit for non-editorial changes.
    ///
    /// There must be only one ingredient, as a parent.
    /// No changes can be made to the hashed content of the parent.
    /// There are additional restrictions on the types of changes that can be made.
    #[serde(rename = "update")]
    Update,
}

/// Use a Builder to add a signed manifest to an asset.
///
/// ## Example: Adding a signed manifest to an asset
///
/// ```
/// # use c2pa::Result;
/// use std::io::Cursor;
///
/// use c2pa::{settings::Settings, Builder, SigningAlg};
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Test {
///     my_tag: usize,
/// }
///
/// # fn main() -> Result<()> {
/// {
///     Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;
///     let mut builder = Builder::from_json(r#"{"title": "Test"}"#)?;
///     builder.add_assertion("org.contentauth.test", &Test { my_tag: 42 })?;
///
///     // embed a manifest using the signer
///     let mut source = std::fs::File::open("tests/fixtures/C.jpg")?;
///     let mut dest = Cursor::new(Vec::new());
///     let signer = Settings::signer()?;
///     let _c2pa_data = builder.sign(&signer, "image/jpeg", &mut source, &mut dest)?;
/// }
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
    #[deprecated(note = "Use set_base_path() instead")]
    pub base_path: Option<PathBuf>,

    /// A builder should construct a created, opened or updated manifest.
    #[deprecated(note = "Use set_intent() to set or intent()")]
    pub intent: Option<BuilderIntent>,

    /// Container for binary assets (like thumbnails).
    #[serde(skip)]
    pub(crate) resources: ResourceStore,

    // Contains the builder context
    #[serde(skip)]
    context: Arc<Context>,
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
        // Legacy behavior: explicitly get global settings for backward compatibility
        // at some point we should remove this and require a Context to be passed in.
        let settings = crate::settings::get_thread_local_settings();
        let context = Context::new().with_settings(settings).unwrap_or_default();
        Self {
            context: Arc::new(context),
            ..Default::default()
        }
    }

    /// Creates a new [`Builder`] struct from a [`Context`].
    ///
    /// This method takes ownership of the Context and wraps it in an Arc internally.
    /// Use this for single-use contexts where you don't need to share the context.
    ///
    /// # Arguments
    /// * `context` - The [`Context`] to use for this [`Builder`].
    ///
    /// # Returns
    /// * A new [`Builder`].
    ///
    /// # Example
    /// ```
    /// # use c2pa::{Context, Builder, Result};
    /// # fn main() -> Result<()> {
    /// let context = Context::new().with_settings(r#"{"verify": {"verify_after_sign": true}}"#)?;
    /// let builder = Builder::from_context(context);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_context(context: Context) -> Self {
        Self {
            context: Arc::new(context),
            ..Default::default()
        }
    }

    /// Creates a new [`Builder`] struct from a shared [`Context`].
    ///
    /// This method allows sharing a single Context across multiple builders or readers.
    /// The Arc is cloned internally, so you pass a reference.
    ///
    /// # Arguments
    /// * `context` - A reference to an `Arc<Context>` to share.
    ///
    /// # Returns
    /// * A new [`Builder`].
    ///
    /// # Example
    /// ```
    /// # use c2pa::{Context, Builder, Result};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<()> {
    /// // Create a shared context once
    /// let ctx = Arc::new(Context::new().with_settings(r#"{"verify": {"verify_after_sign": true}}"#)?);
    ///
    /// // Share it across multiple builders
    /// let builder1 = Builder::from_shared_context(&ctx);
    /// let builder2 = Builder::from_shared_context(&ctx);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_shared_context(context: &Arc<Context>) -> Self {
        Self {
            context: Arc::clone(context),
            ..Default::default()
        }
    }

    /// Returns a reference to the [`Context`] used by this [`Builder`].
    ///
    /// This allows access to settings, signers, and other context configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::{Context, Builder, Result};
    /// # fn main() -> Result<()> {
    /// let context = Context::new();
    /// let builder = Builder::from_context(context);
    ///
    /// // Access settings
    /// let settings = builder.context().settings();
    /// # Ok(())
    /// # }
    /// ```
    pub fn context(&self) -> &Arc<Context> {
        &self.context
    }

    /// Sets the [`BuilderIntent`] for this [`Builder`].
    ///
    /// An intent lets the API know what kind of manifest to create.
    /// Intents are `Create`, `Edit`, or `Update`.
    /// This allows the API to check that you are doing the right thing.
    /// It can also do things for you, like add parent ingredients from the source asset
    /// and automatically add required c2pa.created or c2pa.opened actions.
    /// Create requires a `DigitalSourceType`. It is used for assets without a parent ingredient.
    /// Edit requires a parent ingredient and is used for most assets that are being edited.
    /// Update is a special case with many restrictions but is more compact than Edit.
    /// # Arguments
    /// * `intent` - The [`BuilderIntent`] for this [`Builder`].
    /// # Returns
    /// * A mutable reference to the [`Builder`].
    #[allow(deprecated)]
    pub fn set_intent(&mut self, intent: BuilderIntent) -> &mut Self {
        // Note: We can't modify context.settings anymore since Context is in an Arc
        // The intent is stored in the Builder itself
        self.intent = Some(intent);
        self
    }

    /// Returns the current [`BuilderIntent`] for this [`Builder`], if set.
    /// If not set, it will use the Settings default intent.
    #[allow(deprecated)]
    pub fn intent(&self) -> Option<BuilderIntent> {
        let mut intent = self.intent.clone();
        if intent.is_none() {
            intent = self.context.settings().builder.intent.clone();
        }
        intent
    }

    /// Creates a new [`Builder`] from a JSON [`ManifestDefinition`] string.
    ///
    /// # Arguments
    /// * `json` - A JSON string representing the [`ManifestDefinition`].
    /// # Returns
    /// * A new [`Builder`].
    /// # Errors
    /// * Returns an [`Error`] if the JSON is malformed or incorrect.
    pub fn from_json(json: &str) -> Result<Self> {
        // Legacy behavior: explicitly get global settings for backward compatibility
        let settings = crate::settings::get_thread_local_settings();
        let context = Context::new().with_settings(settings)?;

        Ok(Self {
            definition: serde_json::from_str(json).map_err(Error::JsonError)?,
            context: Arc::new(context),
            ..Default::default()
        })
    }

    /// Sets the [`ManifestDefinition`] for this [`Builder`].
    ///
    /// This method accepts anything that can be converted into a [`ManifestDefinition`],
    /// including JSON strings, [`ManifestDefinition`] objects, and [`serde_json::Value`]s.
    ///
    /// # Arguments
    /// * `definition` - Anything that can be converted into a [`ManifestDefinition`]:
    ///   - A JSON string: `r#"{"title": "My Image"}"#`
    ///   - A `ManifestDefinition` object
    ///   - A `serde_json::Value`
    ///
    /// # Returns
    /// * The modified [`Builder`].
    ///
    /// # Errors
    /// * Returns an [`Error`] if the definition cannot be converted.
    ///
    /// # Notes
    /// * This will overwrite any existing definition in the [`Builder`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::{Builder, ManifestDefinition, Context, Result};
    /// # fn main() -> Result<()> {
    /// // From JSON string
    /// let builder = Builder::new().with_definition(r#"{"title": "My Image"}"#)?;
    ///
    /// // From ManifestDefinition
    /// let mut def = ManifestDefinition::default();
    /// def.title = Some("My Image".to_string());
    /// let builder = Builder::new().with_definition(def)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_definition<D>(mut self, definition: D) -> Result<Self>
    where
        D: TryInto<ManifestDefinition>,
        Error: From<D::Error>,
    {
        self.definition = definition.try_into()?;
        Ok(self)
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
    #[allow(deprecated)]
    pub fn set_base_path<P: Into<PathBuf>>(&mut self, base_path: P) -> &mut Self {
        let base_path = base_path.into();
        // make sure the resource store is updated to the current base path
        #[cfg(feature = "file_io")]
        self.resources.set_base_path(&base_path);

        self.base_path = Some(base_path);
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
    /// * `data` - The data for the assertion. The data can be any Serde-serializable type or an AssertionDefinition.
    /// # Returns
    /// * A mutable reference to the [`Builder`].
    /// # Errors
    /// * Returns an [`Error`] if the assertion is not valid.
    pub fn add_assertion<S, T>(&mut self, label: S, data: &T) -> Result<&mut Self>
    where
        S: Into<String>,
        T: Serialize,
    {
        let created = false;
        self.definition.assertions.push(AssertionDefinition {
            label: label.into(),
            data: AssertionData::Cbor(serde_cbor::value::to_value(data)?),
            kind: None, // defaults to cbor
            created,
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
        let created = false;
        self.definition.assertions.push(AssertionDefinition {
            label: label.into(),
            data: AssertionData::Json(serde_json::to_value(data)?),
            kind: Some(ManifestAssertionKind::Json),
            created,
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
            .position(|a| a.label() == Actions::LABEL)
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
    #[async_generic]
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

        if format == "c2pa" || format == "application/c2pa" {
            let reader = Reader::from_stream(format, stream)?;
            let parent_ingredient = self.add_ingredient_from_reader(&reader)?;
            parent_ingredient.merge(&ingredient);
            return self
                .definition
                .ingredients
                .last_mut()
                .ok_or(Error::IngredientNotFound);
        }

        let ingredient = if _sync {
            ingredient.with_stream(format, stream, &self.context)?
        } else {
            ingredient
                .with_stream_async(format, stream, &self.context)
                .await?
        };

        self.definition.ingredients.push(ingredient);

        self.definition
            .ingredients
            .last_mut()
            .ok_or(Error::IngredientNotFound)
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
        // Sanitize the resource ID to prevent path traversal attacks
        let _sanitized_id = sanitize_archive_path(id)?;

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
    fn old_to_archive(&mut self, stream: impl Write + Seek) -> Result<()> {
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
                    let sanitized_id = sanitize_archive_path(id)?;
                    zip.start_file(format!("resources/{sanitized_id}"), options)
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
                        let sanitized_id = sanitize_archive_path(id)?;
                        zip.start_file(format!("resources/{sanitized_id}"), options)
                            .map_err(|e| Error::OtherError(Box::new(e)))?;
                        zip.write_all(data)?;
                    }

                    if let Some(manifest_label) = ingredient.active_manifest() {
                        if let Some(manifest_data) = ingredient.manifest_data() {
                            // Convert to valid archive / file path name
                            let manifest_name = manifest_label.replace([':'], "_") + ".c2pa";
                            let sanitized_manifest_name = sanitize_archive_path(&manifest_name)?;
                            zip.start_file(format!("manifests/{sanitized_manifest_name}"), options)
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
    fn old_from_archive(stream: impl Read + Seek + Send) -> Result<Self> {
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
                // Validate the full path from the archive to prevent path traversal
                let _sanitized_path = sanitize_archive_path(file.name())?;

                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                let id = file
                    .name()
                    .split('/')
                    .nth(1)
                    .ok_or(Error::BadParam("Invalid resource path".to_string()))?;

                // Additional validation: ensure id itself is safe
                let _sanitized_id = sanitize_archive_path(id)?;

                //println!("adding resource {}", id);
                builder.resources.add(id, data)?;
            }

            // Load the c2pa_manifests.
            // Adds the manifest data to any ingredient that has a matching active_manfiest label.
            if file.name().starts_with("manifests/") && file.name() != "manifests/" {
                // Validate the full path from the archive to prevent path traversal
                let _sanitized_path = sanitize_archive_path(file.name())?;

                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                let manifest_label = file
                    .name()
                    .split('/')
                    .nth(1)
                    .ok_or(Error::BadParam("Invalid manifest path".to_string()))?;

                // Additional validation: ensure manifest_label is safe
                let _sanitized_label = sanitize_archive_path(manifest_label)?;

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
                // Validate the full path from the archive to prevent path traversal
                let _sanitized_path = sanitize_archive_path(file.name())?;

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

                // Additional validation: ensure id is safe
                if !id.is_empty() {
                    let _sanitized_id = sanitize_archive_path(id)?;
                }

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

    /// Convert the Builder into a .c2pa asset.
    ///
    /// This will be stored in the standard application/c2pa .c2pa JUMBF format.
    /// # Arguments
    /// * `stream` - A stream to write the zip into.
    /// # Errors
    /// * Returns an [`Error`] if the archive cannot be written.
    pub fn to_archive(&mut self, mut stream: impl Write + Seek) -> Result<()> {
        if let Some(true) = self.context.settings().builder.generate_c2pa_archive {
            let c2pa_data = self.working_store_sign()?;
            stream.write_all(&c2pa_data)?;
        } else {
            return self.old_to_archive(stream);
        }
        Ok(())
    }

    /// Add manifest store from an archive stream to the [`Builder`].
    ///
    /// Archives contain unsigned working stores (signed with BoxHash placeholder),
    /// so validation is skipped regardless of the Context's `verify_after_reading` setting.
    ///
    /// # Arguments
    /// * `stream` - The stream to read the archive from.
    ///
    /// # Returns
    /// The updated [`Builder`] with the loaded archive content.
    ///
    /// # Errors
    /// Returns an [`Error`] if the archive cannot be read.
    ///
    /// # Example
    /// ```no_run
    /// # use c2pa::{Builder, Context, Result};
    /// # use std::io::Cursor;
    /// # fn main() -> Result<()> {
    /// // Load builder from archive with custom context
    /// let context = Context::new().with_settings(r#"{"verify": {"verify_after_reading": false}}"#)?;
    ///
    /// # let archive_data = vec![]; // placeholder
    /// # let stream = Cursor::new(archive_data);
    /// let builder = Builder::from_context(context).with_archive(stream)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_archive(self, stream: impl Read + Seek + Send) -> Result<Self> {
        let mut stream = stream;
        Self::old_from_archive(&mut stream).or_else(|_| {
            // if the old method fails, try the new method
            // Archives contain unsigned working stores (signed with BoxHash placeholder)

            let mut validation_log = crate::status_tracker::StatusTracker::default();
            stream.rewind()?; // Ensure stream is at the start

            // Create a temporary context with verify_after_reading disabled, since archives
            // contain placeholder signatures that will fail CBOR parsing during verification.
            // The user's context settings will be preserved for the Builder.
            let mut no_verify_settings = self.context.settings().clone();
            no_verify_settings.verify.verify_after_reading = false;

            let temp_context = Context::new().with_settings(no_verify_settings)?;

            // Load the store without verification to avoid CBOR parsing errors on placeholder signatures
            let store = Store::from_stream(
                "application/c2pa",
                &mut stream,
                &mut validation_log,
                &temp_context,
            )?;

            // Now use the user's original context for the Reader and Builder
            let mut reader = Reader::from_shared_context(&self.context);
            reader.with_store(store, &mut validation_log)?;
            reader.into_builder()
        })
    }

    /// Create a [`Builder`] from an archive stream.
    ///
    /// Archives contain unsigned working stores (signed with BoxHash placeholder),
    /// so validation is skipped.
    ///
    /// # Arguments
    /// * `stream` - The stream to read the archive from.
    ///
    /// # Returns
    /// A new Builder with default context.
    ///
    /// # Errors
    /// Returns an [`Error`] if the archive cannot be read.
    ///
    /// # Example
    /// ```no_run
    /// # use c2pa::{Builder, Result};
    /// # use std::io::Cursor;
    /// # fn main() -> Result<()> {
    /// # let archive_data = vec![]; // placeholder
    /// # let stream = Cursor::new(archive_data);
    /// let builder = Builder::from_archive(stream)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_archive(stream: impl Read + Seek + Send) -> Result<Self> {
        Builder::new().with_archive(stream)
    }

    // Convert a Manifest into a Claim
    fn to_claim(&self) -> Result<Claim> {
        // utility function to add created or gathered assertions
        fn add_assertion(
            claim: &mut Claim,
            assertion: &impl AssertionBase,
            created: bool,
        ) -> Result<HashedUri> {
            if created {
                claim.add_created_assertion(assertion)
            } else {
                claim.add_assertion(assertion)
            }
        }

        let definition = &self.definition;
        let mut claim_generator_info = definition.claim_generator_info.clone();

        // add the default claim generator info for this library
        if claim_generator_info.is_empty() {
            let claim_generator_info_settings =
                &self.context.settings().builder.claim_generator_info;
            match claim_generator_info_settings {
                Some(claim_generator_info_settings) => {
                    claim_generator_info.push(claim_generator_info_settings.clone().try_into()?);
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
                // todo: add setting for created added thumbnails
                add_assertion(&mut claim, &thumbnail, false)?;
            }
        }
        // add all ingredients to the claim
        // We use a map to track the ingredient IDs and their hashed URIs
        let mut ingredient_map = HashMap::new();

        for ingredient in &definition.ingredients {
            // use the label if it exists and is not empty, otherwise use the instance_id
            let id = ingredient
                .label()
                .filter(|label| !label.is_empty())
                .map(|label| label.to_string())
                .unwrap_or_else(|| ingredient.instance_id().to_string());

            // add it to the claim
            let uri = ingredient.add_to_claim(
                &mut claim,
                definition.redactions.clone(),
                Some(&self.resources),
                &self.context,
            )?;
            if !id.is_empty() {
                ingredient_map.insert(id, (ingredient.relationship(), uri));
            }
        }

        let mut found_actions = false;
        // add any additional assertions
        for manifest_assertion in &definition.assertions {
            match manifest_assertion.label() {
                l if l.starts_with(Actions::LABEL) => {
                    found_actions = true;

                    let mut actions: Actions = manifest_assertion.to_assertion()?;

                    let mut updates = Vec::new();
                    //#[allow(clippy::explicit_counter_loop)]
                    for (index, action) in actions.actions_mut().iter_mut().enumerate() {
                        // find and remove the temporary ingredientIds parameter
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

                    // Do this at the end of the preprocessing step to ensure all ingredient references
                    // are resolved to their hashed URIs.
                    self.add_actions_assertion_settings(&ingredient_map, &mut actions)?;

                    add_assertion(&mut claim, &actions, manifest_assertion.created())
                }
                #[allow(deprecated)]
                CreativeWork::LABEL => {
                    let cw: CreativeWork = manifest_assertion.to_assertion()?;
                    claim.add_assertion(&cw)
                }
                Exif::LABEL => {
                    let exif: Exif = manifest_assertion.to_assertion()?;
                    add_assertion(&mut claim, &exif, manifest_assertion.created())
                }
                BoxHash::LABEL => {
                    let box_hash: BoxHash = manifest_assertion.to_assertion()?;
                    claim.add_assertion(&box_hash)
                }
                DataHash::LABEL => {
                    let data_hash: DataHash = manifest_assertion.to_assertion()?;
                    claim.add_assertion(&data_hash)
                }
                BmffHash::LABEL => {
                    let bmff_hash: BmffHash = manifest_assertion.to_assertion()?;
                    claim.add_assertion(&bmff_hash)
                }
                Metadata::LABEL => {
                    // user metadata will go through the fallback path
                    let metadata: Metadata = manifest_assertion.to_assertion()?;
                    add_assertion(&mut claim, &metadata, manifest_assertion.created())
                }
                _ => match &manifest_assertion.data {
                    AssertionData::Json(value) => add_assertion(
                        &mut claim,
                        &User::new(manifest_assertion.label(), &serde_json::to_string(&value)?),
                        manifest_assertion.created(),
                    ),
                    AssertionData::Cbor(value) => add_assertion(
                        &mut claim,
                        &UserCbor::new(manifest_assertion.label(), serde_cbor::to_vec(value)?),
                        manifest_assertion.created(),
                    ),
                },
            }?;
        }

        if !found_actions {
            let mut actions = Actions::new();
            self.add_actions_assertion_settings(&ingredient_map, &mut actions)?;

            if !actions.actions().is_empty() {
                // todo: add setting for created added actions
                add_assertion(&mut claim, &actions, false)?;
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
        &self,
        ingredient_map: &HashMap<String, (&Relationship, HashedUri)>,
        actions: &mut Actions,
    ) -> Result<()> {
        if actions.all_actions_included.is_none() {
            actions.all_actions_included =
                self.context.settings().builder.actions.all_actions_included;
        }

        let action_templates = &self.context.settings().builder.actions.templates;

        if let Some(action_templates) = action_templates {
            let action_templates = action_templates
                .iter()
                .map(|template| template.clone().try_into())
                .collect::<Result<Vec<ActionTemplate>>>()?;
            match actions.templates {
                Some(ref mut templates) => {
                    templates.extend_from_slice(&action_templates);
                }
                None => actions.templates = Some(action_templates),
            }
        }

        let additional_actions = &self.context.settings().builder.actions.actions;

        if let Some(additional_actions) = additional_actions {
            let additional_actions = additional_actions
                .iter()
                .map(|action| action.clone().try_into())
                .collect::<Result<Vec<Action>>>()?;

            match actions.actions.is_empty() {
                false => {
                    actions.actions.extend(additional_actions);
                }
                true => actions.actions = additional_actions,
            }
        }
        self.add_auto_actions_assertions_settings(ingredient_map, actions)
    }

    /// Adds c2pa.created, c2pa.opened, and c2pa.placed actions for the specified [Actions][crate::assertions::Actions]
    /// assertion if the conditons are applicable as defined in the spec.
    ///
    /// This function takes into account the [Settings][crate::Settings]:
    /// * `builder.actions.auto_created_action`
    /// * `builder.actions.auto_opened_action`
    /// * `builder.actions.auto_placed_action`
    fn add_auto_actions_assertions_settings(
        &self,
        ingredient_map: &HashMap<String, (&Relationship, HashedUri)>,
        actions: &mut Actions,
    ) -> Result<()> {
        let settings = self.context.settings();
        // https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_mandatory_presence_of_at_least_one_actions_assertion
        let auto_created = settings.builder.actions.auto_created_action.enabled;
        let auto_opened = settings.builder.actions.auto_opened_action.enabled;

        if (self.intent().is_some() || auto_created || auto_opened)
            && !actions.actions.iter().any(|action| {
                action.action() == c2pa_action::CREATED || action.action() == c2pa_action::OPENED
            })
        {
            // look for a parentOf relationship ingredient in the ingredient map and return a copy of the hashed URI if found.
            let parent_ingredient_uri = ingredient_map
                .iter()
                .find(|(_, (relationship, _))| *relationship == &Relationship::ParentOf)
                .map(|(_, (_, uri))| uri.clone());

            let action = match self.intent() {
                Some(BuilderIntent::Create(source_type)) => {
                    if parent_ingredient_uri.is_some() {
                        return Err(Error::BadParam(
                            "Cannot have ParentOf ingredient with a Create intent".to_string(),
                        ));
                    }
                    Some(Action::new(c2pa_action::CREATED).set_source_type(source_type.clone()))
                }
                Some(BuilderIntent::Edit) | Some(BuilderIntent::Update) => {
                    if let Some(parent_ingredient_uri) = parent_ingredient_uri {
                        Some(
                            Action::new(c2pa_action::OPENED)
                                .set_parameter("ingredients", vec![parent_ingredient_uri])?,
                        )
                    } else {
                        return Err(Error::BadParam(
                            "Must have ParentOf ingredient for an Edit or Update intent"
                                .to_string(),
                        ));
                    }
                }
                None => {
                    // handle auto_opened and auto_created settings if no intent was set
                    if auto_opened && parent_ingredient_uri.is_some() {
                        // only add if we have a parent ingredient
                        if let Some(parent_uri) = &parent_ingredient_uri {
                            let mut action = Action::new(c2pa_action::OPENED)
                                .set_parameter("ingredients", vec![parent_uri])?;
                            if let Some(source_type) =
                                &settings.builder.actions.auto_opened_action.source_type
                            {
                                action = action.set_source_type(source_type.clone());
                            }
                            Some(action)
                        } else {
                            None
                        }
                    } else if auto_created {
                        let mut action = Action::new(c2pa_action::CREATED);
                        if let Some(source_type) =
                            &settings.builder.actions.auto_created_action.source_type
                        {
                            action = action.set_source_type(source_type.clone());
                        }
                        Some(action)
                    } else {
                        None
                    }
                }
            };

            // we know there are no other created or opened actions, so we can safely insert at the front
            if let Some(action) = action {
                actions.actions.insert(0, action);
            }
        }

        // https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_relationship
        if settings.builder.actions.auto_placed_action.enabled {
            // Get a list of ingredient URIs referenced by "c2pa.placed" actions.
            let mut referenced_uris = HashSet::new();
            for action in &actions.actions {
                if action.action() == c2pa_action::PLACED {
                    if let Some(parameters) = &action.parameters {
                        if let Some(ingredient_uris) = &parameters.ingredients {
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

                    let action = match settings.builder.actions.auto_placed_action.source_type {
                        Some(ref source_type) => action.set_source_type(source_type.clone()),
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

        let mut store = Store::from_context(&self.context);

        // if this can be an update manifest, then set the update_manifest flag
        if self.intent() == Some(BuilderIntent::Update) {
            store.commit_update_manifest(claim)
        } else {
            store.commit_claim(claim)
        }?;

        Ok(store)
    }

    #[cfg(feature = "add_thumbnails")]
    fn maybe_add_thumbnail<R>(&mut self, format: &str, stream: &mut R) -> Result<&mut Self>
    where
        R: Read + Seek + ?Sized,
    {
        if self.intent() == Some(BuilderIntent::Update) {
            // do not auto add a thumbnail to an update manifest
            return Ok(self);
        }

        // check settings to see if we should auto generate a thumbnail
        let auto_thumbnail = self.context.settings().builder.thumbnail.enabled;

        if self.definition.thumbnail.is_none() && auto_thumbnail {
            stream.rewind()?;

            let mut stream = std::io::BufReader::new(stream);
            if let Some((output_format, image)) =
                crate::utils::thumbnail::make_thumbnail_bytes_from_stream(
                    format,
                    &mut stream,
                    self.context.settings(),
                )?
            {
                stream.rewind()?;

                // Do not write this as a file when reading from files
                #[cfg(feature = "file_io")]
                let base_path = self.resources.take_base_path();
                self.resources
                    .add(self.definition.instance_id.clone(), image)?;
                #[cfg(feature = "file_io")]
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
            self.intent(),
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
        if let Some(manifest_assertion) = self
            .definition
            .assertions
            .iter()
            .find(|a| a.label() == label)
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
            store.get_data_hashed_embeddable_manifest(
                data_hash,
                signer,
                format,
                None,
                &self.context,
            )
        } else {
            store
                .get_data_hashed_embeddable_manifest_async(
                    data_hash,
                    signer,
                    format,
                    None,
                    &self.context,
                )
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
            store.get_box_hashed_embeddable_manifest(signer, &self.context)
        } else {
            store
                .get_box_hashed_embeddable_manifest_async(signer, &self.context)
                .await
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
        #[allow(deprecated)]
        if let Some(base_path) = &self.base_path {
            self.resources.set_base_path(base_path);
        }

        self.maybe_add_parent(&format, source)?;

        // generate thumbnail if we don't already have one
        #[cfg(feature = "add_thumbnails")]
        self.maybe_add_thumbnail(&format, source)?;

        // convert the manifest to a store
        let mut store = self.to_store()?;

        // sign and write our store to to the output image file
        if _sync {
            store.save_to_stream(&format, source, dest, signer, &self.context)
        } else {
            store
                .save_to_stream_async(&format, source, dest, signer, &self.context)
                .await
        }
    }

    /// Save a signed manifest to a stream using the signer from this builder's context.
    ///
    /// This is a convenience method that automatically gets the signer from the builder's
    /// context and signs the manifest. The signer is created from the context's settings
    /// if not explicitly set with [`Context::with_signer()`].
    ///
    /// This provides a simpler alternative to [`sign()`](Self::sign) when you want to use
    /// the context's configured signer rather than providing an explicit signer.
    ///
    /// **Note**: This method is only available for synchronous signing. For async signing,
    /// use [`sign_async()`](Self::sign_async) with an explicit async signer.
    ///
    /// # Arguments
    /// * `format` - The format of the stream.
    /// * `source` - The source stream from which to read.
    /// * `dest` - The destination stream to write.
    ///
    /// # Returns
    /// * The bytes of c2pa_manifest that was embedded.
    ///
    /// # Errors
    /// * Returns [`Error::MissingSignerSettings`] if no signer is configured in the context.
    /// * Returns an [`Error`] if the manifest cannot be signed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use c2pa::{Context, Builder, Result};
    /// # use std::io::Cursor;
    /// # fn main() -> Result<()> {
    /// use serde_json::json;
    ///
    /// // Create context with signer configuration
    /// let context = Context::new().with_settings(json!({
    ///     "builder": {
    ///         "claim_generator_info": {"name": "My App"},
    ///         "intent": "edit"
    ///     }
    /// }))?;
    ///
    /// let mut builder = Builder::from_context(context)
    ///     .with_definition(json!({"title": "My Image"}))?;
    ///
    /// let mut source = std::fs::File::open("tests/fixtures/C.jpg")?;
    /// let mut dest = Cursor::new(Vec::new());
    ///
    /// // Save with automatic signer from context
    /// builder.save_to_stream("image/jpeg", &mut source, &mut dest)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn save_to_stream<R, W>(
        &mut self,
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
        #[allow(deprecated)]
        if let Some(base_path) = &self.base_path {
            self.resources.set_base_path(base_path);
        }

        self.maybe_add_parent(&format, source)?;

        // generate thumbnail if we don't already have one
        #[cfg(feature = "add_thumbnails")]
        self.maybe_add_thumbnail(&format, source)?;

        // convert the manifest to a store
        let mut store = self.to_store()?;

        // Get signer from context
        let signer = self.context.signer()?;

        // sign and write our store to to the output image file
        store.save_to_stream(&format, source, dest, signer, &self.context)
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
            &self.context,
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

    /// Save a signed manifest to a file using the signer from this builder's context.
    ///
    /// This is a convenience method that automatically gets the signer from the builder's
    /// context and signs the manifest. The signer is created from the context's settings
    /// if not explicitly set with [`Context::with_signer()`].
    ///
    /// This provides a simpler alternative to [`sign_file()`](Self::sign_file) when you want
    /// to use the context's configured signer rather than providing an explicit signer.
    ///
    /// **Note**: This method is only available for synchronous signing. For async signing,
    /// use [`sign_file_async()`](Self::sign_file_async) with an explicit async signer.
    ///
    /// # Arguments
    /// * `source` - Path to the source file.
    /// * `dest` - Path to the destination file (must not exist).
    ///
    /// # Returns
    /// * The bytes of c2pa_manifest that was embedded.
    ///
    /// # Errors
    /// * Returns [`Error::MissingSignerSettings`] if no signer is configured in the context.
    /// * Returns an [`Error`] if the manifest cannot be signed or destination file already exists.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use c2pa::{Context, Builder, Result};
    /// # fn main() -> Result<()> {
    /// use serde_json::json;
    ///
    /// let context = Context::new()
    ///     .with_settings(json!({
    ///         "builder": {"claim_generator_info": {"name": "My App"}}
    ///     }))?;
    ///
    /// let mut builder = Builder::from_context(context)
    ///     .with_definition(json!({"title": "My Image"}))?;
    ///
    /// // Save with automatic signer from context
    /// builder.save_to_file("tests/fixtures/C.jpg", "output.jpg")?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "file_io")]
    pub fn save_to_file<S, D>(&mut self, source: S, dest: D) -> Result<Vec<u8>>
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
        self.save_to_stream(&format, &mut source, &mut dest)
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

    /// Add an ingredient to the manifest from a Reader.
    /// # Arguments
    /// * `reader` - The Reader to get the ingredient from.
    /// # Returns
    /// * A reference to the added ingredient.
    pub fn add_ingredient_from_reader(
        &mut self,
        reader: &crate::Reader,
    ) -> Result<&mut Ingredient> {
        let ingredient = reader.to_ingredient()?;
        self.add_ingredient(ingredient);
        self.definition
            .ingredients
            .last_mut()
            .ok_or(Error::IngredientNotFound)
    }

    /// This creates a working store from the builder
    /// The working store is signed with a BoxHash over an empty string
    /// And is returned as a Vec<u8> of the c2pa_manifest bytes
    /// This works as an archive of the store that can be read back to restore the Builder state
    fn working_store_sign(&self) -> Result<Vec<u8>> {
        // first we need to generate a BoxHash over an empty string
        let mut empty_asset = std::io::Cursor::new("");
        let boxes = jumbf_io::get_assetio_handler("application/c2pa")
            .ok_or(Error::UnsupportedType)?
            .asset_box_hash_ref()
            .ok_or(Error::UnsupportedType)?
            .get_box_map(&mut empty_asset)?;
        let box_hash = BoxHash { boxes };

        // then convert the builder to a claim and add the box hash assertion
        let mut claim = self.to_claim()?;
        claim.add_assertion(&box_hash)?;

        // now commit and sign it. The signing will allow us to detect tampering.
        let mut store = Store::new();
        store.commit_claim(claim)?;

        store.get_data_hashed_manifest_placeholder(100, "application/c2pa")
    }
}

impl std::fmt::Display for Builder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut json = serde_json::to_value(self).map_err(|_| std::fmt::Error)?;
        json = hash_to_b64(json);
        let output = serde_json::to_string_pretty(&json).map_err(|_| std::fmt::Error)?;
        f.write_str(&output)
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
        crypto::raw_signature::SigningAlg,
        hash_stream_by_alg,
        settings::Settings,
        utils::{
            test::{test_context, write_jpeg_placeholder_stream},
            test_signer::{async_test_signer, test_signer},
        },
        validation_results::ValidationState,
        Reader,
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
            definition.assertions[0].label(),
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
        assert_eq!(definition.assertions[0].label(), "c2pa.actions".to_string());
        assert_eq!(
            definition.assertions[1].label(),
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

    // Ensure multiple `c2pa.placed` actions aren't created.
    // Source: https://github.com/contentauth/c2pa-rs/pull/1458
    // This makes a created Manifest and includes two ingredients.
    // the first is referenced in the JSON and should not get an auto_placed
    // The second is not referenced and should get one.
    #[test]
    fn test_builder_one_placed_action_via_ingredient_id_ref() {
        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        Settings::from_toml(
            &toml::toml! {
                [builder]
                actions.auto_placed_action.enabled = true
            }
            .to_string(),
        )
        .unwrap();

        let mut output = Cursor::new(Vec::new());
        let mut builder = Builder::from_json(
            &json!({
                "title": "Test Manifest",
                "format": "image/jpeg",
                "ingredients": [
                    {
                        "title": "First Ingredient",
                        "format": "image/jpeg",
                        "relationship": "componentOf",
                        "instance_id": "123"
                    },
                    {
                        "title": "Second Ingredient",
                        "format": "image/png",
                        "relationship": "componentOf",
                        "instance_id": "456"
                    }
                ],
                "assertions": [
                    {
                        "label": "c2pa.actions",
                        "data": {
                            "actions": [
                                {
                                    "action": "c2pa.placed",
                                    "instanceId": "123"
                                }
                            ]
                        }
                    },
                ]
            })
            .to_string(),
        )
        .unwrap();

        builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
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

        assert_eq!(actions.actions.len(), 3);

        let num_placed_actions = actions
            .actions
            .iter()
            .filter(|action| action.action() == c2pa_action::PLACED)
            .count();
        assert_eq!(num_placed_actions, 2);
    }

    #[test]
    fn test_builder_settings_auto_created() {
        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [builder.actions.auto_created_action]
                    enabled = true
                    source_type = (DigitalSourceType::Empty.to_string())
                }
                .to_string(),
            )
            .unwrap();

        let context = Context::new().with_settings(settings).unwrap();

        let mut output = Cursor::new(Vec::new());
        Builder::from_context(context)
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

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [builder.actions.auto_opened_action]
                    enabled = true
                }
                .to_string(),
            )
            .unwrap();

        let context = Context::new().with_settings(settings).unwrap();

        let mut builder = Builder::from_context(context);
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

        let ingredient_uris = action
            .parameters
            .as_ref()
            .unwrap()
            .ingredients
            .as_ref()
            .unwrap();

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

        let settings = Settings::new()
            .with_toml(
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

        let context = Context::new().with_settings(settings).unwrap();

        let mut builder = Builder::from_context(context);
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
            let ingredient_uris = action
                .parameters
                .as_ref()
                .unwrap()
                .ingredients
                .as_ref()
                .unwrap();

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

        let settings = Settings::new()
            .with_toml(
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

        let context = Context::new().with_settings(settings).unwrap();

        let mut output = Cursor::new(Vec::new());
        Builder::from_context(context)
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

        let settings = Settings::new()
            .with_toml(
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

        let context = Context::new().with_settings(settings).unwrap();

        let mut output = Cursor::new(Vec::new());
        Builder::from_context(context)
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

        let settings = Settings::new()
            .with_toml(
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

        let context = Context::new().with_settings(settings).unwrap();

        let mut output = Cursor::new(Vec::new());
        Builder::from_context(context)
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
        crate::utils::test::setup_logger();

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
        assert_eq!(manifest_store.validation_state(), ValidationState::Trusted);
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
                assert_eq!(manifest_store.validation_state(), ValidationState::Trusted);
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

    #[test]
    fn test_builder_data_hashed_embeddable_min() -> Result<()> {
        let signer = Settings::signer().unwrap();

        let mut builder = Builder::from_json(&simple_manifest_json()).unwrap();

        // get a placeholder the manifest
        let placeholder = builder
            .data_hashed_placeholder(signer.reserve_size(), "application/c2pa")
            .unwrap();

        let offset = 0;
        // create an hash exclusion for the manifest
        let exclusion = crate::HashRange::new(offset as u64, placeholder.len() as u64);
        let exclusions = vec![exclusion];

        let mut dh = DataHash::new("source_hash", "sha256");
        dh.exclusions = Some(exclusions);

        // Hash the bytes excluding the manifest we inserted
        let mut output_stream = Cursor::new(placeholder.clone());
        let hash =
            hash_stream_by_alg("sha256", &mut output_stream, dh.exclusions.clone(), true).unwrap();
        dh.set_hash(hash);

        // get the embeddable manifest, letting API do the hashing
        let signed_manifest: Vec<u8> =
            builder.sign_data_hashed_embeddable(signer.as_ref(), &dh, "application/c2pa")?;

        let output_stream = Cursor::new(signed_manifest);

        let reader = crate::Reader::from_stream("application/c2pa", output_stream).unwrap();
        println!("{reader}");
        assert_eq!(reader.validation_status(), None);
        Ok(())
    }

    #[test]
    fn test_builder_box_hashed_embeddable_min() {
        let mut reader = Cursor::new("");
        let c2pa_io = jumbf_io::get_assetio_handler("application/c2pa").unwrap();
        let box_mapper = c2pa_io.asset_box_hash_ref().unwrap();
        let boxes = box_mapper.get_box_map(&mut reader).unwrap();
        // Create the BoxHash object
        let bh = BoxHash { boxes };
        // And generate the box hashes
        //bh.generate_box_hash_from_stream(&mut reader, "sha256", box_mapper, true).unwrap();

        let mut builder = Builder::from_json(&simple_manifest_json()).unwrap();
        builder.add_assertion(labels::BOX_HASH, &bh).unwrap();

        let signer = Settings::signer().unwrap();

        let manifest_bytes = builder
            .sign_box_hashed_embeddable(signer.as_ref(), "application/c2pa")
            .unwrap();

        let output_stream = Cursor::new(manifest_bytes);

        let reader = crate::Reader::from_stream("application/c2pa", output_stream).unwrap();
        println!("{reader}");
        assert_eq!(reader.validation_status(), None);
    }

    #[c2pa_test_async]
    #[cfg(target_arch = "wasm32")]
    async fn test_builder_box_hashed_embeddable() {
        use crate::{
            asset_handlers::jpeg_io::JpegIO,
            asset_io::{CAIWriter, HashBlockObjectType},
        };
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
        use crate::{
            asset_handlers::jpeg_io::JpegIO,
            asset_io::{CAIWriter, HashBlockObjectType},
        };
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
        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        let mut source = Cursor::new(TEST_IMAGE_CLEAN);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::from_json(&manifest_json()).unwrap();
        builder.set_base_path("tests/fixtures");
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
        assert_eq!(reader.validation_state(), ValidationState::Trusted);
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
        let reader = Reader::from_stream("jpeg", &mut output).expect("from_bytes");
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
    async fn test_add_cloud_ingredient() {
        crate::settings::reset_default_settings().ok();

        let mut input = Cursor::new(TEST_IMAGE_CLEAN);
        let mut cloud_image = Cursor::new(TEST_IMAGE_CLOUD);

        let definition = ManifestDefinition {
            claim_version: Some(1),
            claim_generator_info: [ClaimGeneratorInfo::default()].to_vec(),
            format: "image/jpeg".to_string(),
            title: Some("Test_Manifest".to_string()),
            ..Default::default()
        };

        let settings = Settings::default()
            .with_value("verify.verify_timestamp_trust", false)
            .unwrap()
            .with_value("verify.remote_manifest_fetch", false)
            .unwrap();
        let context = Context::default().with_settings(settings).unwrap();

        let mut builder = Builder::from_context(context)
            .with_definition(definition)
            .unwrap();

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
            .add_ingredient_from_stream_async(parent_json, "image/jpeg", &mut cloud_image)
            .await
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

        let reader = Reader::from_stream_async("jpeg", &mut output)
            .await
            .expect("from_bytes");
        let m = reader.active_manifest().unwrap();
        assert_eq!(m.ingredients().len(), 1);
        assert!(m.ingredients()[0].active_manifest().is_some());
    }

    #[test]
    fn test_redaction() {
        let context = test_context();
        //crate::utils::test::setup_logger();

        // the label of the assertion we are going to redact
        const ASSERTION_LABEL: &str = "stds.schema-org.CreativeWork";

        let mut input = Cursor::new(TEST_IMAGE);

        let parent = Reader::from_context(context)
            .with_stream("image/jpeg", &mut input)
            .expect("from_stream");
        let parent_manifest_label = parent.active_label().unwrap();
        // Create a redacted uri for the assertion we are going to redact.
        let redacted_uri =
            crate::jumbf::labels::to_assertion_uri(parent_manifest_label, ASSERTION_LABEL);

        let mut builder = Builder::new();
        builder.set_intent(BuilderIntent::Edit);
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
        println!("{reader}");
        assert_eq!(reader.validation_state(), ValidationState::Trusted);
        let m = reader.active_manifest().unwrap();
        assert_eq!(m.ingredients().len(), 1);
        let parent = reader.get_manifest(parent_manifest_label).unwrap();
        assert_eq!(parent.assertions().len(), 1);
    }

    #[c2pa_test_async]
    async fn test_redaction_async() {
        let context = test_context();

        // the label of the assertion we are going to redact
        const ASSERTION_LABEL: &str = "stds.schema-org.CreativeWork";

        let mut input = Cursor::new(TEST_IMAGE);

        let parent = Reader::from_stream_async("image/jpeg", &mut input)
            .await
            .expect("from_stream");
        let parent_manifest_label = parent.active_label().unwrap();
        // Create a redacted uri for the assertion we are going to redact.
        let redacted_uri =
            crate::jumbf::labels::to_assertion_uri(parent_manifest_label, ASSERTION_LABEL);

        let mut builder = Builder::from_context(context);
        builder.set_intent(BuilderIntent::Edit);
        builder.definition.redactions = Some(vec![redacted_uri.clone()]);

        let redacted_action = crate::assertions::Action::new("c2pa.redacted")
            .set_reason("testing".to_owned())
            .set_parameter("redacted".to_owned(), redacted_uri.clone())
            .unwrap();

        builder.add_action(redacted_action).unwrap();

        let signer = async_test_signer(SigningAlg::Ps256);
        // Embed a manifest using the signer.
        let mut output = Cursor::new(Vec::new());
        builder
            .sign_async(signer.as_ref(), "image/jpeg", &mut input, &mut output)
            .await
            .expect("builder sign");

        output.set_position(0);

        let reader = Reader::from_stream_async("image/jpeg", &mut output)
            .await
            .expect("from_bytes");
        //println!("{reader}");
        assert!(matches!(
            reader.validation_state(),
            ValidationState::Trusted | ValidationState::Valid
        ));
        let m = reader.active_manifest().unwrap();
        assert_eq!(m.ingredients().len(), 1);
        let parent = reader.get_manifest(parent_manifest_label).unwrap();
        assert_eq!(parent.assertions().len(), 1);
    }

    #[test]
    /// this first creates a manifest with an assertion we will later redact
    /// then creates an update manifest that redacts the assertion
    fn test_redaction2() {
        use crate::{assertions::Action, utils::test::setup_logger};
        Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml")).unwrap();

        setup_logger();
        // the label of the assertion we are going to redact
        const ASSERTION_LABEL: &str = "stds.schema-org.CreativeWork";

        let mut source = Cursor::new(TEST_IMAGE_CLEAN);
        let mut dest1 = Cursor::new(Vec::new());

        let definition = ManifestDefinition {
            claim_version: Some(2),
            title: Some("Redacted claim".to_string()),
            ..Default::default()
        };
        let mut builder = Builder {
            definition,
            ..Default::default()
        };

        // Create a parent with a c2pa_action type assertion.
        let created_action = crate::assertions::Action::new(c2pa_action::CREATED)
            .set_source_type(DigitalSourceType::Empty);

        let actions = crate::assertions::Actions::new().add_action(created_action);
        builder.add_assertion(Actions::LABEL, &actions).unwrap();

        builder
            .add_assertion(
                ASSERTION_LABEL,
                &json!({
                    "@context": "https://schema.org",
                    "@type": "CreativeWork",
                    "author": [
                        {
                            "@type": "Person",
                            "name": "Joe Bloggs"
                        }
                    ]
                }),
            )
            .unwrap();

        // sign the Builder and write it to the output stream
        let signer = test_signer(SigningAlg::Ps256);
        let _manifest_data = builder
            .sign(signer.as_ref(), "image/jpeg", &mut source, &mut dest1)
            .unwrap();

        dest1.set_position(0);
        let reader = Reader::from_stream("jpeg", &mut dest1).expect("from_bytes");
        //println!("{reader}");
        assert_eq!(reader.validation_state(), ValidationState::Trusted);
        let parent_manifest_label = reader.active_label().unwrap();

        // We now have the assertion we want to react from, now lets add an update manifest and redact
        let definition = ManifestDefinition {
            claim_version: Some(2),
            title: Some("Redacting claim".to_string()),
            ..Default::default()
        };

        let mut builder2 = Builder {
            definition,
            ..Default::default()
        };

        builder2.set_intent(BuilderIntent::Update);
        // rewind our new asset stream so we can add it as an ingredient
        dest1.set_position(0);

        let redacted_uri =
            crate::jumbf::labels::to_assertion_uri(parent_manifest_label, ASSERTION_LABEL);

        let redacted_action = Action::new("c2pa.redacted")
            .set_reason("testing".to_owned())
            .set_parameter("redacted".to_owned(), redacted_uri.clone())
            .unwrap();

        let actions = Actions::new().add_action(redacted_action);

        builder2.definition.redactions = Some(vec![redacted_uri]);

        builder2.add_assertion(Actions::LABEL, &actions).unwrap();

        let signer = test_signer(SigningAlg::Ps256);

        // rewind our first asset stream again
        dest1.set_position(0);

        // Embed a manifest using the signer.
        let mut output = Cursor::new(Vec::new());
        builder2
            .sign(signer.as_ref(), "jpeg", &mut dest1, &mut output)
            .expect("builder sign");

        output.set_position(0);
        //std::fs::write("redaction2.jpg", output.get_ref()).unwrap();

        let reader = Reader::from_stream("jpeg", &mut output).expect("from_bytes");
        //println!("{reader}");
        assert_eq!(reader.validation_state(), ValidationState::Trusted);
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

    #[test]
    fn test_with_archive() -> Result<()> {
        let mut builder =
            Builder::from_context(Context::new()).with_definition(r#"{"title": "Test Image"}"#)?;

        let mut archive = Cursor::new(Vec::new());
        builder.to_archive(&mut archive)?;

        // Load from archive with custom context
        archive.rewind()?;
        let context = Context::new();

        let loaded_builder = Builder::from_context(context).with_archive(archive)?;

        // Verify the manifest data was loaded with the correct title
        assert_eq!(
            loaded_builder.definition.title,
            Some("Test Image".to_string())
        );

        Ok(())
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

    #[test]
    fn test_builder_add_ingredient_from_reader() -> Result<()> {
        use std::io::Cursor;

        let context = test_context().into_shared();
        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        // first an example of capturing an ingredient as a builder.
        // We create a new builder, and set the Intent to Edit
        // this tells the builder to capture the source file as a parent ingredient
        // if one is not otherwise added.
        let mut builder = Builder::from_shared_context(&context);
        builder.set_intent(BuilderIntent::Edit);
        let signer = &Settings::signer()?;
        // We have a different options here. We can embed the manifest into a destination file
        // or we can bypass the embedding and just get the manifest data back.
        // you can also output to null if you just want the manifest data.
        // Here we embed the manifest into a destination file.
        let _c2pa_data = builder.sign(signer, format, &mut source, &mut dest)?;

        dest.rewind()?;
        // use read_from_manifest_data_and_stream to validate if not embedded.
        let reader = Reader::from_stream(format, &mut dest)?;
        println!("first: {reader}");

        // create a new builder and add our ingredient from the reader.
        let builder2 = &mut Builder::from_shared_context(&context);
        builder2.add_ingredient_from_reader(&reader)?;
        assert!(!builder2.definition.ingredients.is_empty());
        println!("\nbuilder2:{builder2}");
        source.rewind()?;
        let dest2 = &mut Cursor::new(Vec::new());
        builder2.sign(signer, format, &mut source, dest2)?;
        dest2.rewind()?;
        let reader2 = Reader::from_stream(format, dest2)?;
        println!("\nreader2:{reader2}");
        assert_eq!(reader2.active_manifest().unwrap().ingredients().len(), 1);
        Ok(())
    }

    #[test]
    fn test_shared_context() -> Result<()> {
        use std::sync::Arc;

        // Create a context with custom settings once
        let ctx =
            Arc::new(Context::new().with_settings(r#"{"verify": {"verify_after_sign": false}}"#)?);

        // Share it across multiple builders
        let builder1 =
            Builder::from_shared_context(&ctx).with_definition(r#"{"title": "First Image"}"#)?;

        let builder2 =
            Builder::from_shared_context(&ctx).with_definition(r#"{"title": "Second Image"}"#)?;

        // Both builders share the same context settings
        assert_eq!(
            builder1.context().settings().verify.verify_after_sign,
            builder2.context().settings().verify.verify_after_sign
        );
        assert!(!builder1.context().settings().verify.verify_after_sign);

        // Context is immutable - this is the expected behavior
        // If you need different settings, create a different Context

        Ok(())
    }

    #[test]
    fn test_single_use_context() -> Result<()> {
        // Single-use context - no Arc needed!
        let builder = Builder::from_context(
            Context::new().with_settings(r#"{"verify": {"verify_after_sign": true}}"#)?,
        );

        assert!(builder.context().settings().verify.verify_after_sign);

        Ok(())
    }

    #[test]
    fn test_builder_is_send_sync() {
        // Compile-time assertion that Builder is Send + Sync on non-WASM
        // On WASM, MaybeSend/MaybeSync don't require Send + Sync, so these traits
        // won't be implemented, but that's correct for single-threaded WASM
        #[cfg(not(target_arch = "wasm32"))]
        {
            fn assert_send<T: Send>() {}
            fn assert_sync<T: Sync>() {}

            assert_send::<Builder>();
            assert_sync::<Builder>();
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))] // WASM doesn't support threads
    fn test_send_builder_between_threads() -> Result<()> {
        use std::{sync::Arc, thread};

        // Create a builder in the main thread
        let ctx = Arc::new(Context::new());
        let mut builder = Builder::from_shared_context(&ctx)
            .with_definition(r#"{"title": "Created in main thread"}"#)?;

        // Send the builder to another thread (tests Send trait)
        let handle = thread::spawn(move || {
            // Modify the builder in the spawned thread
            builder.definition.title = Some("Modified in spawned thread".to_string());
            builder
        });

        // Receive the builder back
        let builder = handle.join().unwrap();
        assert_eq!(
            builder.definition.title,
            Some("Modified in spawned thread".to_string())
        );

        Ok(())
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))] // WASM doesn't support threads
    fn test_multithreaded_context_sharing() -> Result<()> {
        use std::{sync::Arc, thread};

        // Create a shared context once
        let ctx =
            Arc::new(Context::new().with_settings(r#"{"verify": {"verify_after_sign": false}}"#)?);

        // Spawn multiple threads, each creating a builder with the shared context
        let mut handles = vec![];
        for i in 0..4 {
            let ctx = Arc::clone(&ctx);
            let handle = thread::spawn(move || {
                let builder = Builder::from_shared_context(&ctx)
                    .with_definition(format!(r#"{{"title": "Image {i}"}}"#))
                    .unwrap();

                // Verify the context settings are accessible
                assert!(!builder.context().settings().verify.verify_after_sign);
                assert_eq!(builder.definition.title, Some(format!("Image {i}")));

                i // Return the thread number for verification
            });
            handles.push(handle);
        }

        // Wait for all threads to complete and verify they ran
        let mut results = vec![];
        for handle in handles {
            results.push(handle.join().unwrap());
        }

        // Verify all threads completed successfully
        assert_eq!(results, vec![0, 1, 2, 3]);

        Ok(())
    }

    // #[test]
    // #[should_panic(expected = "GLOBAL SETTINGS CONFIGURED BUT NOT USED")]
    // #[cfg(debug_assertions)]
    // fn test_builder_new_panics_with_global_settings_in_debug() {
    //     // Clean slate
    //     crate::settings::reset_default_settings().unwrap();

    //     // Set global settings
    //     Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))
    //         .expect("should load settings");

    //     // This should panic in debug mode
    //     let _builder = Builder::new();
    // }

    #[test]
    fn test_builder_new_succeeds_without_global_settings() {
        // Clean slate
        crate::settings::reset_default_settings().unwrap();

        // This should NOT panic - global settings are default
        let _builder = Builder::new();

        // Verify it created a pure context
        assert_eq!(
            _builder.context().settings().verify.verify_trust,
            Settings::default().verify.verify_trust
        );
    }

    #[test]
    fn actions_created_assertion() {
        let mut dest = Cursor::new(Vec::new());
        Builder::new()
            .with_definition(
                json!({
                  "assertions": [
                    {
                      "label": "c2pa.actions",
                      "data": {
                        "actions": [
                          {
                            "action": "c2pa.created",
                            "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty"
                          }
                        ]
                      },
                      "created": true
                    }
                  ]
                })
                .to_string(),
            )
            .unwrap()
            .sign(
                &Settings::signer().unwrap(),
                "image/jpeg",
                &mut Cursor::new(TEST_IMAGE),
                &mut dest,
            )
            .unwrap();

        dest.rewind().unwrap();

        let reader = Reader::from_stream("image/jpeg", &mut dest).unwrap();
        let active_manifest = reader.active_manifest().unwrap();

        let actions_assertion = active_manifest
            .assertions()
            .iter()
            .find(|assertion| assertion.label().starts_with(Actions::LABEL))
            .unwrap();
        assert!(actions_assertion.created());
    }
}
