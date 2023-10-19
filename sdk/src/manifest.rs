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

use std::{borrow::Cow, collections::HashMap, io::Cursor};
#[cfg(feature = "file_io")]
use std::{fs::create_dir_all, path::Path};

use log::{debug, error};
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[cfg(feature = "file_io")]
use crate::AsyncSigner;
use crate::{
    assertion::{AssertionBase, AssertionData},
    assertions::{
        labels, Actions, CreativeWork, DataHash, Exif, SoftwareAgent, Thumbnail, User, UserCbor,
    },
    asset_io::{CAIRead, CAIReadWrite},
    claim::{Claim, RemoteManifest},
    error::{Error, Result},
    jumbf,
    resource_store::{skip_serializing_resources, ResourceRef, ResourceStore},
    salt::DefaultSalt,
    store::Store,
    ClaimGeneratorInfo, HashRange, Ingredient, ManifestAssertion, ManifestAssertionKind,
    RemoteSigner, Signer,
};

/// A Manifest represents all the information in a c2pa manifest
#[derive(Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct Manifest {
    /// Optional prefix added to the generated Manifest Label
    /// This is typically Internet domain name for the vendor (i.e. `adobe`)
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor: Option<String>,

    /// A User Agent formatted string identifying the software/hardware/system produced this claim
    /// Spaces are not allowed in names, versions can be specified with product/1.0 syntax
    #[serde(default = "default_claim_generator")]
    pub claim_generator: String,

    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_generator_info: Option<Vec<ClaimGeneratorInfo>>,

    /// A human-readable title, generally source filename.
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,

    /// The format of the source file as a MIME type.
    #[serde(default = "default_format")]
    format: String,

    /// Instance ID from `xmpMM:InstanceID` in XMP metadata.
    #[serde(default = "default_instance_id")]
    instance_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    claim_generator_hints: Option<HashMap<String, Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    thumbnail: Option<ResourceRef>,

    /// A List of ingredients
    #[serde(default = "default_vec::<Ingredient>")]
    ingredients: Vec<Ingredient>,

    /// A List of verified credentials
    #[serde(skip_serializing_if = "Option::is_none")]
    credentials: Option<Vec<Value>>,

    /// A list of assertions
    #[serde(default = "default_vec::<ManifestAssertion>")]
    assertions: Vec<ManifestAssertion>,

    /// A list of redactions - URIs to a redacted assertions
    #[serde(skip_serializing_if = "Option::is_none")]
    redactions: Option<Vec<String>>,

    /// Signature data (only used for reporting)
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_info: Option<SignatureInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,

    /// Indicates where a generated manifest goes
    #[serde(skip)]
    remote_manifest: Option<RemoteManifest>,

    /// container for binary assets (like thumbnails)
    #[serde(skip_deserializing)]
    #[serde(skip_serializing_if = "skip_serializing_resources")]
    resources: ResourceStore,
}

fn default_claim_generator() -> String {
    format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

fn default_instance_id() -> String {
    format!("xmp:iid:{}", Uuid::new_v4())
}

fn default_format() -> String {
    "application/octet-stream".to_owned()
}

fn default_vec<T>() -> Vec<T> {
    Vec::new()
}

impl Manifest {
    /// Create a new Manifest
    /// requires a claim_generator string (User Agent))
    pub fn new<S: Into<String>>(claim_generator: S) -> Self {
        Self {
            claim_generator: claim_generator.into(),
            format: default_format(),
            instance_id: default_instance_id(),
            ..Default::default()
        }
    }

    /// Returns a User Agent formatted string identifying the software/hardware/system produced this claim
    pub fn claim_generator(&self) -> &str {
        self.claim_generator.as_str()
    }

    /// returns the manifest label for this Manifest, as referenced in a ManifestStore
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Returns a MIME content_type for the asset associated with this manifest.
    pub fn format(&self) -> &str {
        &self.format
    }

    /// Returns the instance identifier.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Returns a user-displayable title for this manifest
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Returns thumbnail tuple with Some((format, bytes)) or None
    pub fn thumbnail(&self) -> Option<(&str, Cow<Vec<u8>>)> {
        self.thumbnail
            .as_ref()
            .and_then(|t| Some(t.format.as_str()).zip(self.resources.get(&t.identifier).ok()))
    }

    /// Returns a thumbnail ResourceRef or `None`.
    pub fn thumbnail_ref(&self) -> Option<&ResourceRef> {
        self.thumbnail.as_ref()
    }

    /// Returns immutable [Ingredient]s used by this Manifest
    /// This can include a parent as well as any placed assets
    pub fn ingredients(&self) -> &[Ingredient] {
        &self.ingredients
    }

    /// Returns mutable [Ingredient]s used by this Manifest
    /// This can include a parent as well as any placed assets
    pub fn ingredients_mut(&mut self) -> &mut [Ingredient] {
        &mut self.ingredients
    }

    /// Returns Assertions for this Manifest
    pub fn assertions(&self) -> &[ManifestAssertion] {
        &self.assertions
    }

    /// Returns Verifiable Credentials
    pub fn credentials(&self) -> Option<&[Value]> {
        self.credentials.as_deref()
    }

    /// Sets the vendor prefix to be used when generating manifest labels
    /// Optional prefix added to the generated Manifest Label
    /// This is typically a lower case Internet domain name for the vendor (i.e. `adobe`)
    pub fn set_vendor<S: Into<String>>(&mut self, vendor: S) -> &mut Self {
        self.vendor = Some(vendor.into());
        self
    }

    /// Sets the label for this manifest
    /// A label will be generated if this is not called
    /// This is needed if embedding a URL that references the manifest label
    pub fn set_label<S: Into<String>>(&mut self, label: S) -> &mut Self {
        self.label = Some(label.into());
        self
    }

    /// Sets a human readable name for the product that created this manifest
    pub fn set_claim_generator<S: Into<String>>(&mut self, generator: S) -> &mut Self {
        self.claim_generator = generator.into();
        self
    }

    /// Sets a human-readable title for this ingredient.
    pub fn set_format<S: Into<String>>(&mut self, format: S) -> &mut Self {
        self.format = format.into();
        self
    }

    /// Sets a human-readable title for this ingredient.
    pub fn set_instance_id<S: Into<String>>(&mut self, instance_id: S) -> &mut Self {
        self.instance_id = instance_id.into();
        self
    }

    /// Sets a human-readable title for this ingredient.
    pub fn set_title<S: Into<String>>(&mut self, title: S) -> &mut Self {
        self.title = Some(title.into());
        self
    }

    /// Sets the thumbnail from a ResourceRef.
    pub fn set_thumbnail_ref(&mut self, thumbnail: ResourceRef) -> Result<&mut Self> {
        // verify the resource referenced exists
        if thumbnail.format != "none" && !self.resources.exists(&thumbnail.identifier) {
            return Err(Error::NotFound);
        };
        self.thumbnail = Some(thumbnail);
        Ok(self)
    }

    /// Sets the thumbnail format and image data.
    pub fn set_thumbnail<S: Into<String>, B: Into<Vec<u8>>>(
        &mut self,
        format: S,
        thumbnail: B,
    ) -> Result<&mut Self> {
        let base_id = self
            .label()
            .unwrap_or_else(|| self.instance_id())
            .to_string();
        self.thumbnail = Some(
            self.resources
                .add_with(&base_id, &format.into(), thumbnail)?,
        );
        Ok(self)
    }

    /// If set, the embed calls will create a sidecar .c2pa manifest file next to the output file
    /// No change will be made to the output file
    pub fn set_sidecar_manifest(&mut self) -> &mut Self {
        self.remote_manifest = Some(RemoteManifest::SideCar);
        self
    }

    /// If set, the embed calls will put the remote url into the output file xmp provenance
    /// and create a c2pa manifest file next to the output file
    pub fn set_remote_manifest<S: Into<String>>(&mut self, remote_url: S) -> &mut Self {
        self.remote_manifest = Some(RemoteManifest::Remote(remote_url.into()));
        self
    }

    /// If set, the embed calls will put the remote url into the output file xmp provenance
    /// and will embed the manifest into the output file
    pub fn set_embedded_manifest_with_remote_ref<S: Into<String>>(
        &mut self,
        remote_url: S,
    ) -> &mut Self {
        self.remote_manifest = Some(RemoteManifest::EmbedWithRemote(remote_url.into()));
        self
    }

    pub fn signature_info(&self) -> Option<&SignatureInfo> {
        self.signature_info.as_ref()
    }

    /// Returns the parent ingredient if it exists
    pub fn parent(&self) -> Option<&Ingredient> {
        self.ingredients.iter().find(|i| i.is_parent())
    }

    /// Sets the parent ingredient, assuring it is first and setting the is_parent flag
    pub fn set_parent(&mut self, mut ingredient: Ingredient) -> Result<&mut Self> {
        // there should only be one parent so return an error if we already have one
        if self.parent().is_some() {
            error!("parent already added");
            return Err(Error::BadParam("Parent parent already added".to_owned()));
        }
        ingredient.set_is_parent();
        self.ingredients.insert(0, ingredient);

        Ok(self)
    }

    /// Add an ingredient removing duplicates (consumes the asset)
    pub fn add_ingredient(&mut self, ingredient: Ingredient) -> &mut Self {
        self.ingredients.push(ingredient);
        self
    }

    /// Adds assertion using given label and any serde serializable
    /// The data for predefined assertions must be in correct format
    ///
    /// # Example: Creating a custom assertion from a serde_json object.
    ///```
    /// # use c2pa::Result;
    /// use c2pa::Manifest;
    /// use serde_json::json;
    /// # fn main() -> Result<()> {
    /// let mut manifest = Manifest::new("my_app");
    /// let value = json!({"my_tag": "Anything I want"});
    /// manifest.add_labeled_assertion("org.contentauth.foo", &value)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_labeled_assertion<S: Into<String>, T: Serialize>(
        &mut self,
        label: S,
        data: &T,
    ) -> Result<&mut Self> {
        self.assertions
            .push(ManifestAssertion::from_labeled_assertion(label, data)?);
        Ok(self)
    }

    /// Adds ManifestAssertions from existing assertions
    /// The data for standard assertions must be in correct format
    ///
    /// # Example: Creating a from an Actions object.
    ///```
    /// # use c2pa::Result;
    /// use c2pa::{
    ///     assertions::{c2pa_action, Action, Actions},
    ///     Manifest,
    /// };
    /// # fn main() -> Result<()> {
    /// let mut manifest = Manifest::new("my_app");
    /// let actions = Actions::new().add_action(Action::new(c2pa_action::EDITED));
    /// manifest.add_assertion(&actions)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_assertion<T: Serialize + AssertionBase>(&mut self, data: &T) -> Result<&mut Self> {
        self.assertions
            .push(ManifestAssertion::from_assertion(data)?);
        Ok(self)
    }

    /// Retrieves an assertion by label if it exists or Error::NotFound
    ///
    /// Example: Find an Actions Assertion
    /// ```
    /// # use c2pa::Result;
    /// use c2pa::{
    ///     assertions::{c2pa_action, Action, Actions},
    ///     Manifest,
    /// };
    /// # fn main() -> Result<()> {
    /// let mut manifest = Manifest::new("my_app");
    /// let actions = Actions::new().add_action(Action::new(c2pa_action::EDITED));
    /// manifest.add_assertion(&actions)?;
    ///
    /// let actions: Actions = manifest.find_assertion(Actions::LABEL)?;
    /// for action in actions.actions {
    ///     println!("{}", action.action());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn find_assertion<T: DeserializeOwned>(&self, label: &str) -> Result<T> {
        if let Some(manifest_assertion) = self.assertions.iter().find(|a| a.label() == label) {
            manifest_assertion.to_assertion()
        } else {
            Err(Error::NotFound)
        }
    }

    /// Retrieves an assertion by label and instance if it exists or Error::NotFound
    pub fn find_assertion_with_instance<T: DeserializeOwned>(
        &self,
        label: &str,
        instance: usize,
    ) -> Result<T> {
        if let Some(manifest_assertion) = self
            .assertions
            .iter()
            .find(|a| a.label() == label && a.instance() == instance)
        {
            manifest_assertion.to_assertion()
        } else {
            Err(Error::NotFound)
        }
    }

    /// Redacts an assertion from the parent [Ingredient] of this manifest using the provided
    /// assertion label.
    pub fn add_redaction<S: Into<String>>(&mut self, label: S) -> Result<&mut Self> {
        // todo: any way to verify if this assertion exists in the parent claim here?
        match self.redactions.as_mut() {
            Some(redactions) => redactions.push(label.into()),
            None => self.redactions = Some([label.into()].to_vec()),
        }
        Ok(self)
    }

    /// Add verifiable credentials
    pub fn add_verifiable_credential<T: Serialize>(&mut self, data: &T) -> Result<&mut Self> {
        let value = serde_json::to_value(data).map_err(|_err| Error::AssertionEncoding)?;
        match self.credentials.as_mut() {
            Some(credentials) => credentials.push(value),
            None => self.credentials = Some([value].to_vec()),
        }
        Ok(self)
    }

    /// Sets the signature information for the report
    fn set_signature(
        &mut self,
        issuer: Option<&String>,
        time: Option<&String>,
        cert_serial: Option<&String>,
    ) -> &mut Self {
        self.signature_info = Some(SignatureInfo {
            issuer: issuer.cloned(),
            time: time.cloned(),
            cert_serial_number: cert_serial.cloned(),
        });
        self
    }

    /// Returns the name of the signature issuer
    pub fn issuer(&self) -> Option<String> {
        self.signature_info.to_owned().and_then(|sig| sig.issuer)
    }

    /// Returns the time that the manifest was signed
    pub fn time(&self) -> Option<String> {
        self.signature_info.to_owned().and_then(|sig| sig.time)
    }

    /// Return an immutable reference to the manifest resources
    pub fn resources(&self) -> &ResourceStore {
        &self.resources
    }

    /// Return a mutable reference to the manifest resources
    pub fn resources_mut(&mut self) -> &mut ResourceStore {
        &mut self.resources
    }

    /// Creates a Manifest from a JSON string formatted as a Manifest
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_slice(json.as_bytes()).map_err(Error::JsonError)
    }

    /// Setting a base path will make the manifest use resource files instead of memory buffers
    ///
    /// The files will be relative to the given base path
    /// Ingredients resources will also be relative to this path
    #[cfg(feature = "file_io")]
    pub fn with_base_path<P: AsRef<Path>>(&mut self, base_path: P) -> Result<&Self> {
        create_dir_all(&base_path)?;
        self.resources.set_base_path(base_path.as_ref());
        for i in 0..self.ingredients.len() {
            // todo: create different subpath for each ingredient?
            self.ingredients[i].with_base_path(base_path.as_ref())?;
        }
        Ok(self)
    }

    // Generates a Manifest given a store and a manifest label
    pub(crate) fn from_store(
        store: &Store,
        manifest_label: &str,
        #[cfg(feature = "file_io")] resource_path: Option<&Path>,
    ) -> Result<Self> {
        let claim = store
            .get_claim(manifest_label)
            .ok_or_else(|| Error::ClaimMissing {
                label: manifest_label.to_owned(),
            })?;

        // extract vendor from claim label
        let claim_generator = claim.claim_generator().to_owned();

        let mut manifest = Manifest::new(claim_generator);

        #[cfg(feature = "file_io")]
        if let Some(base_path) = resource_path {
            manifest.with_base_path(base_path)?;
        }

        if let Some(info_vec) = claim.claim_generator_info() {
            let mut generators = Vec::new();
            for claim_info in info_vec {
                let mut info = claim_info.to_owned();
                if let Some(icon) = claim_info.icon.as_ref() {
                    info.set_icon(icon.to_resource_ref(manifest.resources_mut(), claim)?);
                }
                generators.push(info);
            }
            manifest.claim_generator_info = Some(generators);
        }

        manifest.set_label(claim.label());
        manifest.resources.set_label(claim.label()); // default manifest for relative urls
        manifest.claim_generator_hints = claim.get_claim_generator_hint_map().cloned();

        // get credentials converting from AssertionData to Value
        let credentials: Vec<Value> = claim
            .get_verifiable_credentials()
            .iter()
            .filter_map(|d| match d {
                AssertionData::Json(s) => serde_json::from_str(s).ok(),
                _ => None,
            })
            .collect();

        if !credentials.is_empty() {
            manifest.credentials = Some(credentials);
        }

        manifest.redactions = claim.redactions().map(|rs| {
            rs.iter()
                .filter_map(|r| jumbf::labels::assertion_label_from_uri(r))
                .collect()
        });

        if let Some(title) = claim.title() {
            manifest.set_title(title);
        }
        manifest.set_format(claim.format());
        manifest.set_instance_id(claim.instance_id());

        for assertion in claim.assertions() {
            let claim_assertion = store.get_claim_assertion_from_uri(
                &jumbf::labels::to_absolute_uri(claim.label(), &assertion.url()),
            )?;
            let assertion = claim_assertion.assertion();
            let label = claim_assertion.label();
            let base_label = assertion.label();
            debug!("assertion = {}", &label);
            match base_label.as_ref() {
                base if base.starts_with(labels::ACTIONS) => {
                    let mut actions = Actions::from_assertion(assertion)?;

                    for action in actions.actions_mut() {
                        if let Some(SoftwareAgent::ClaimGeneratorInfo(info)) =
                            action.software_agent_mut()
                        {
                            if let Some(icon) = info.icon.as_mut() {
                                let icon = icon.to_resource_ref(manifest.resources_mut(), claim)?;
                                info.set_icon(icon);
                            }
                        }
                    }

                    // convert icons in templates to resource refs
                    if let Some(templates) = actions.templates.as_mut() {
                        for template in templates {
                            // replace icon with resource ref
                            template.icon = match template.icon.take() {
                                Some(icon) => {
                                    Some(icon.to_resource_ref(manifest.resources_mut(), claim)?)
                                }
                                None => None,
                            };

                            // replace software agent with resource ref
                            template.software_agent = match template.software_agent.take() {
                                Some(SoftwareAgent::ClaimGeneratorInfo(mut info)) => {
                                    if let Some(icon) = info.icon.as_mut() {
                                        let icon =
                                            icon.to_resource_ref(manifest.resources_mut(), claim)?;
                                        info.set_icon(icon);
                                    }
                                    Some(SoftwareAgent::ClaimGeneratorInfo(info))
                                }
                                agent => agent,
                            };
                        }
                    }
                    let manifest_assertion = ManifestAssertion::from_assertion(&actions)?
                        .set_instance(claim_assertion.instance());
                    manifest.assertions.push(manifest_assertion);
                }
                base if base.starts_with(labels::INGREDIENT) => {
                    // note that we use the original label here, not the base label
                    let assertion_uri = jumbf::labels::to_assertion_uri(claim.label(), &label);
                    let ingredient = Ingredient::from_ingredient_uri(
                        store,
                        manifest_label,
                        &assertion_uri,
                        #[cfg(feature = "file_io")]
                        resource_path,
                    )?;
                    manifest.add_ingredient(ingredient);
                }
                labels::DATA_HASH | labels::BMFF_HASH | labels::BOX_HASH => {
                    // do not include data hash when reading manifests
                }
                label if label.starts_with(labels::CLAIM_THUMBNAIL) => {
                    let thumbnail = Thumbnail::from_assertion(assertion)?;
                    let id = jumbf::labels::to_assertion_uri(claim.label(), label);
                    let id = jumbf::labels::to_relative_uri(&id);
                    manifest.thumbnail = Some(manifest.resources.add_uri(
                        &id,
                        &thumbnail.content_type,
                        thumbnail.data,
                    )?);
                }
                _ => {
                    // inject assertions for all other assertions
                    match assertion.decode_data() {
                        AssertionData::Json(_) | AssertionData::Cbor(_) => {
                            let value = assertion.as_json_object()?;
                            let ma = ManifestAssertion::new(base_label, value)
                                .set_instance(claim_assertion.instance())
                                .set_kind(ManifestAssertionKind::Json);

                            manifest.assertions.push(ma);
                        }

                        // todo: support binary forms
                        AssertionData::Binary(_x) => {}
                        AssertionData::Uuid(_, _) => {}
                    }
                }
            }
        }

        let issuer = claim.signing_issuer();
        let signing_time = claim
            .signing_time()
            .map(|signing_time| signing_time.to_rfc3339());

        if issuer.is_some() || signing_time.is_some() {
            debug!(
                "added signature issuer={:?} time={:?}",
                issuer, signing_time
            );
            manifest.set_signature(
                issuer.as_ref(),
                signing_time.as_ref(),
                claim.signing_cert_serial().as_ref(),
            );
        }

        Ok(manifest)
    }

    /// Sets the asset field from data in a file
    /// the information in the claim should reflect the state of the asset it is embedded in
    /// this method can be used to ensure that data is correct
    /// it will extract filename,format and xmp info and generate a thumbnail
    #[cfg(feature = "file_io")]
    pub fn set_asset_from_path<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        // Gather the information we need from the target path
        let ingredient = Ingredient::from_file_info(path.as_ref());

        self.set_format(ingredient.format());
        self.set_instance_id(ingredient.instance_id());

        // if there is already an asset title preserve it
        if self.title().is_none() {
            self.set_title(ingredient.title());
        }

        // if a thumbnail is not already defined, create one here
        if self.thumbnail_ref().is_none() {
            #[cfg(feature = "add_thumbnails")]
            if let Ok((format, image)) = crate::utils::thumbnail::make_thumbnail(path.as_ref()) {
                // Do not write this as a file when reading from files
                let base_path = self.resources_mut().take_base_path();
                self.set_thumbnail(format, image)?;
                if let Some(path) = base_path {
                    self.resources_mut().set_base_path(path)
                }
            }
        }
        Ok(())
    }

    // Convert a Manifest into a Claim
    pub(crate) fn to_claim(&self) -> Result<Claim> {
        // add library identifier to claim_generator
        let generator = format!(
            "{} {}/{}",
            &self.claim_generator,
            crate::NAME,
            crate::VERSION
        );

        let mut claim = match self.label() {
            Some(label) => Claim::new_with_user_guid(&generator, &label.to_string()),
            None => Claim::new(&generator, self.vendor.as_deref()),
        };

        if let Some(info_vec) = self.claim_generator_info.as_ref() {
            for info in info_vec {
                let mut claim_info = info.to_owned();
                if let Some(icon) = claim_info.icon.as_ref() {
                    claim_info.icon = Some(icon.to_hashed_uri(self.resources(), &mut claim)?);
                }
                claim.add_claim_generator_info(claim_info);
            }
        }

        if let Some(remote_op) = &self.remote_manifest {
            match remote_op {
                RemoteManifest::NoRemote => (),
                RemoteManifest::SideCar => claim.set_external_manifest(),
                RemoteManifest::Remote(r) => claim.set_remote_manifest(r)?,
                RemoteManifest::EmbedWithRemote(r) => claim.set_embed_remote_manifest(r)?,
            };
        }

        if let Some(title) = self.title() {
            claim.set_title(Some(title.to_owned()));
        }
        claim.format = self.format().to_owned();
        claim.instance_id = self.instance_id().to_owned();

        if let Some(thumb_ref) = self.thumbnail_ref() {
            // Setting the format to "none" will ensure that no claim thumbnail is added
            if thumb_ref.format != "none" {
                let data = self.resources.get(&thumb_ref.identifier)?;
                claim.add_assertion(&Thumbnail::new(
                    &labels::add_thumbnail_format(labels::CLAIM_THUMBNAIL, &thumb_ref.format),
                    data.into_owned(),
                ))?;
            }
        }

        // add any verified credentials - needs to happen early so we can reference them
        let mut vc_table = HashMap::new();
        if let Some(verified_credentials) = self.credentials.as_ref() {
            for vc in verified_credentials {
                let vc_str = &vc.to_string();
                let id = Claim::vc_id(vc_str)?;
                vc_table.insert(id, claim.add_verifiable_credential(vc_str)?);
            }
        }

        let mut ingredient_map = HashMap::new();
        // add all ingredients to the claim
        for ingredient in &self.ingredients {
            let uri = ingredient.add_to_claim(&mut claim, self.redactions.clone())?;
            ingredient_map.insert(ingredient.instance_id(), uri);
        }

        let salt = DefaultSalt::default();

        // add any additional assertions
        for manifest_assertion in &self.assertions {
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
                                    Some(icon.to_hashed_uri(self.resources(), &mut claim)?)
                                }
                                None => None,
                            };

                            // replace software agent with hashed_uri
                            template.software_agent = match template.software_agent.take() {
                                Some(SoftwareAgent::ClaimGeneratorInfo(mut info)) => {
                                    if let Some(icon) = info.icon.as_mut() {
                                        let icon =
                                            icon.to_hashed_uri(self.resources(), &mut claim)?;
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
                                let icon_uri = icon.to_hashed_uri(self.resources(), &mut claim)?;
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
                    let mut cw: CreativeWork = manifest_assertion.to_assertion()?;
                    // insert a credentials field if we have a vc that matches the identifier
                    // todo: this should apply to any person, not just author
                    if let Some(cw_authors) = cw.author() {
                        let mut authors = Vec::new();
                        for a in cw_authors {
                            authors.push(
                                a.identifier()
                                    .and_then(|i| {
                                        vc_table
                                            .get(&i)
                                            .map(|uri| a.clone().add_credential(uri.clone()))
                                    })
                                    .unwrap_or_else(|| Ok(a.clone()))?,
                            );
                        }
                        cw = cw.set_author(&authors)?;
                    }
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
    pub(crate) fn to_store(&self) -> Result<Store> {
        let claim = self.to_claim()?;
        // commit the claim
        let mut store = Store::new();
        let _provenance = store.commit_claim(claim)?;
        Ok(store)
    }

    // factor out this code to set up the destination path with a file
    // so we can use set_asset_from_path to initialize the right fields in Manifest
    #[cfg(feature = "file_io")]
    fn embed_prep<P: AsRef<Path>>(&mut self, source_path: P, dest_path: P) -> Result<P> {
        let mut copied = false;

        if !source_path.as_ref().exists() {
            let path = source_path.as_ref().to_string_lossy().into_owned();
            return Err(Error::FileNotFound(path));
        }
        // we need to copy the source to target before setting the asset info
        if !dest_path.as_ref().exists() {
            // ensure the path to the file exists
            if let Some(output_dir) = dest_path.as_ref().parent() {
                create_dir_all(output_dir)?;
            }
            std::fs::copy(&source_path, &dest_path)?;
            copied = true;
        }
        // first add the information about the target file
        self.set_asset_from_path(dest_path.as_ref())?;

        if copied {
            Ok(dest_path)
        } else {
            Ok(source_path)
        }
    }

    /// Embed a signed manifest into the target file using a supplied signer.
    ///
    /// # Example: Embed a manifest in a file
    ///
    /// ```
    /// # use c2pa::Result;
    /// use c2pa::{create_signer, Manifest, SigningAlg};
    /// use serde::Serialize;
    ///
    /// #[derive(Serialize)]
    /// struct Test {
    ///     my_tag: usize,
    /// }
    ///
    /// # fn main() -> Result<()> {
    /// let mut manifest = Manifest::new("my_app".to_owned());
    /// manifest.add_labeled_assertion("org.contentauth.test", &Test { my_tag: 42 })?;
    ///
    /// // Create a PS256 signer using certs and public key files.
    /// let signcert_path = "tests/fixtures/certs/ps256.pub";
    /// let pkey_path = "tests/fixtures/certs/ps256.pem";
    /// let signer = create_signer::from_files(signcert_path, pkey_path, SigningAlg::Ps256, None)?;
    ///
    /// // Embed a manifest using the signer.
    /// manifest.embed("tests/fixtures/C.jpg", "../target/test_file.jpg", &*signer)?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "file_io")]
    pub fn embed<P: AsRef<Path>>(
        &mut self,
        source_path: P,
        dest_path: P,
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        // Add manifest info for this target file
        let source_path = self.embed_prep(source_path.as_ref(), dest_path.as_ref())?;

        // convert the manifest to a store
        let mut store = self.to_store()?;

        // sign and write our store to to the output image file
        store.save_to_asset(source_path.as_ref(), signer, dest_path.as_ref())
    }

    /// Embed a signed manifest into a stream using a supplied signer.
    /// returns the bytes of the  manifest that was embedded
    pub fn embed_from_memory(
        &mut self,
        format: &str,
        asset: &[u8],
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        // first make a copy of the asset that will contain our modified result
        // todo:: see if we can pass a trait with to_vec support like we to for Strings
        let asset = asset.to_vec();
        let mut stream = std::io::Cursor::new(asset);
        let mut output_stream = Cursor::new(Vec::new());
        self.embed_to_stream(format, &mut stream, &mut output_stream, signer)?;
        Ok(output_stream.into_inner())
    }

    /// Embed a signed manifest into a stream using a supplied signer.
    ///
    /// Returns the bytes of the new asset
    #[deprecated(since = "0.27.2", note = "use embed_to_stream instead")]
    pub fn embed_stream(
        &mut self,
        format: &str,
        stream: &mut dyn CAIRead,
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        // sign and write our store to to the output image file
        let output_vec: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(output_vec);

        self.embed_to_stream(format, stream, &mut output_stream, signer)?;

        Ok(output_stream.into_inner())
    }

    /// Embed a signed manifest into a stream using a supplied signer.
    ///
    /// Returns the bytes of c2pa_manifest that was embedded.
    pub fn embed_to_stream(
        &mut self,
        format: &str,
        source: &mut dyn CAIRead,
        dest: &mut dyn CAIReadWrite,
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        self.set_format(format);
        // todo:: read instance_id from xmp from stream
        self.set_instance_id(format!("xmp:iid:{}", Uuid::new_v4()));

        // generate thumbnail if we don't already have one
        #[cfg(feature = "add_thumbnails")]
        {
            if self.thumbnail_ref().is_none() {
                if let Ok((format, image)) =
                    crate::utils::thumbnail::make_thumbnail_from_stream(format, source)
                {
                    self.set_thumbnail(format, image)?;
                }
            }
        }

        // convert the manifest to a store
        let mut store = self.to_store()?;

        // sign and write our store to to the output image file
        store.save_to_stream(format, source, dest, signer)
    }

    /// Embed a signed manifest into a stream using a supplied signer.
    /// returns the  asset generated and bytes of the manifest that was embedded
    //#[cfg(feature = "remote_wasm_sign")]
    pub async fn embed_from_memory_remote_signed(
        &mut self,
        format: &str,
        asset: &[u8],
        signer: &dyn RemoteSigner,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        self.set_format(format);
        // todo:: read instance_id from xmp from stream
        self.set_instance_id(format!("xmp:iid:{}", Uuid::new_v4()));

        // generate thumbnail if we don't already have one
        #[allow(unused_mut)] // so that this builds with WASM
        let mut stream = std::io::Cursor::new(asset);
        #[cfg(feature = "add_thumbnails")]
        {
            if self.thumbnail_ref().is_none() {
                if let Ok((format, image)) =
                    crate::utils::thumbnail::make_thumbnail_from_stream(format, &mut stream)
                {
                    self.set_thumbnail(format, image)?;
                }
            }
        }
        let asset = stream.into_inner();

        // convert the manifest to a store
        let mut store = self.to_store()?;

        // sign and write our store to to the output image file
        let (output_asset, output_manifest) = store
            .save_to_memory_remote_signed(format, asset, signer)
            .await?;

        Ok((output_asset, output_manifest))
    }

    /// Embed a signed manifest into the target file using a supplied [`AsyncSigner`].
    #[cfg(feature = "file_io")]
    pub async fn embed_async_signed<P: AsRef<Path>>(
        &mut self,
        source_path: P,
        dest_path: P,
        signer: &dyn AsyncSigner,
    ) -> Result<Vec<u8>> {
        // Add manifest info for this target file
        let source_path = self.embed_prep(source_path.as_ref(), dest_path.as_ref())?;
        // convert the manifest to a store
        let mut store = self.to_store()?;
        // sign and write our store to to the output image file
        store
            .save_to_asset_async(source_path.as_ref(), signer, dest_path.as_ref())
            .await
    }

    /// Embed a signed manifest into the target file using a supplied [`RemoteSigner`].
    #[cfg(feature = "file_io")]
    pub async fn embed_remote_signed<P: AsRef<Path>>(
        &mut self,
        source_path: P,
        dest_path: P,
        signer: &dyn RemoteSigner,
    ) -> Result<Vec<u8>> {
        // Add manifest info for this target file
        let source_path = self.embed_prep(source_path.as_ref(), dest_path.as_ref())?;
        // convert the manifest to a store
        let mut store = self.to_store()?;
        // sign and write our store to to the output image file
        store
            .save_to_asset_remote_signed(source_path.as_ref(), signer, dest_path.as_ref())
            .await
    }

    /// Removes any existing manifest from a file
    ///
    /// This should only be used for special cases, such as converting an embedded manifest
    /// to a cloud manifest
    #[cfg(feature = "file_io")]
    pub fn remove_manifest<P: AsRef<Path>>(asset_path: P) -> Result<()> {
        use crate::jumbf_io::remove_jumbf_from_file;
        remove_jumbf_from_file(asset_path.as_ref())
    }

    /// Generates a data hashed placeholder manifest for a file
    ///
    /// The return value is pre-formatted for insertion into a file of the given format
    /// For JPEG it is a series of App11 JPEG segments containing space for a manifest
    /// This is used to create a properly formatted file ready for signing
    pub fn data_hash_placeholder(&mut self, signer: &dyn Signer, format: &str) -> Result<Vec<u8>> {
        let dh: Result<DataHash> = self.find_assertion(DataHash::LABEL);
        if dh.is_err() {
            let mut ph = DataHash::new("jumbf manifest", "sha256");
            for _ in 0..10 {
                ph.add_exclusion(HashRange::new(0, 2));
            }
            self.add_assertion(&ph)?;
        }

        let mut store = self.to_store()?;
        let placeholder =
            store.get_data_hashed_manifest_placeholder(signer.reserve_size(), format)?;
        Ok(placeholder)
    }

    /// Generates an data hashed embeddable manifest for a file
    ///
    /// The return value is pre-formatted for insertion into a file of the given format
    /// For JPEG it is a series of App11 JPEG segments containing a signed manifest
    /// This can directly replace a placeholder manifest to create a properly signed asset
    /// The data hash must contain exclusions and may contain pre-calculated hashes
    /// if an asset reader is provided, it will be used to calculate the data hash
    pub fn data_hash_embeddable_manifest(
        &mut self,
        dh: &DataHash,
        signer: &dyn Signer,
        format: &str,
        mut asset_reader: Option<&mut dyn CAIRead>,
    ) -> Result<Vec<u8>> {
        let mut store = self.to_store()?;
        if let Some(asset_reader) = asset_reader.as_deref_mut() {
            asset_reader.rewind()?;
        }
        let cm = store.get_data_hashed_embeddable_manifest(dh, signer, format, asset_reader)?;
        Ok(cm)
    }

    /// Generates a signed box hashed manifest, optionally preformatted for embedding
    ///
    /// The manifest must include a box hash assertion with correct hashes
    pub fn box_hash_embeddable_manifest(
        &mut self,
        signer: &dyn Signer,
        format: Option<&str>,
    ) -> Result<Vec<u8>> {
        let mut store = self.to_store()?;
        let mut cm = store.get_box_hashed_embeddable_manifest(signer)?;
        if let Some(format) = format {
            cm = store.get_composed_manifest(&cm, format)?;
        }
        Ok(cm)
    }
}

impl std::fmt::Display for Manifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string_pretty(self).unwrap_or_default();
        f.write_str(&json)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
/// Holds information about a signature
pub struct SignatureInfo {
    /// human readable issuing authority for this signature
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,

    /// The serial number of the certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_serial_number: Option<String>,

    /// the time the signature was created
    #[serde(skip_serializing_if = "Option::is_none")]
    time: Option<String>,
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    #[cfg(feature = "file_io")]
    use tempfile::tempdir;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use crate::{
        assertions::{c2pa_action, Action, Actions},
        utils::test::{temp_remote_signer, temp_signer, TEST_VC},
        Ingredient, Manifest, Result,
    };
    #[cfg(feature = "file_io")]
    use crate::{
        assertions::{labels::ACTIONS, DataHash},
        error::Error,
        hash_utils::HashRange,
        resource_store::ResourceRef,
        status_tracker::{DetailedStatusTracker, StatusTracker},
        store::Store,
        utils::test::{
            fixture_path, temp_dir_path, temp_fixture_path, write_jpeg_placeholder_file,
            TEST_SMALL_JPEG,
        },
        validation_status,
    };

    // example of random data structure as an assertion
    #[derive(serde::Serialize)]
    struct MyStruct {
        l1: String,
        l2: u32,
    }

    fn test_manifest() -> Manifest {
        Manifest::new("test".to_owned())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn from_file() {
        let mut manifest = test_manifest();
        let source_path = fixture_path(TEST_SMALL_JPEG);
        manifest
            .set_vendor("vendor".to_owned())
            .set_parent(Ingredient::from_file(&source_path).expect("from_file"))
            .expect("set_parent");

        let vc: serde_json::Value = serde_json::from_str(TEST_VC).unwrap();
        manifest
            .add_verifiable_credential(&vc)
            .expect("verifiable_credential");

        manifest
            .add_labeled_assertion(
                "my.assertion",
                &MyStruct {
                    l1: "some data".to_owned(),
                    l2: 5,
                },
            )
            .expect("add_assertion");

        let actions = Actions::new().add_action(
            Action::new(c2pa_action::EDITED)
                .set_parameter("name".to_owned(), "gaussian_blur")
                .unwrap(),
        );

        manifest.add_assertion(&actions).expect("add_assertion");

        manifest.add_ingredient(Ingredient::from_file(&source_path).expect("from_file"));

        // generate json and omit binary thumbnails for printout
        let mut json = serde_json::to_string_pretty(&manifest).expect("error to json");
        while let Some(index) = json.find("\"thumbnail\": [") {
            if let Some(idx2) = json[index..].find(']') {
                json = format!(
                    "{}\"thumbnail\": \"<omitted>\"{}",
                    &json[..index],
                    &json[index + idx2 + 1..]
                );
            }
        }

        // copy an image to use as our target
        let dir = tempdir().expect("temp dir");
        let test_output = dir.path().join("wc_embed_test.jpg");

        //embed a claim generated from this manifest
        let signer = temp_signer();

        let _store = manifest
            .embed(&source_path, &test_output, signer.as_ref())
            .expect("embed");

        assert_eq!(manifest.format(), "image/jpeg");
        assert_eq!(manifest.title(), Some("wc_embed_test.jpg"));
        if cfg!(feature = "add_thumbnails") {
            assert!(manifest.thumbnail().is_some());
        } else {
            assert!(manifest.thumbnail().is_none());
        }
        let ingredient = Ingredient::from_file(&test_output).expect("load_from_asset");
        assert!(ingredient.active_manifest().is_some());
    }

    #[test]
    #[cfg(feature = "file_io")]
    /// test assertion validation on actions, should generate an error
    fn ws_bad_assertion() {
        // copy an image to use as our target for embedding
        let ap = fixture_path(TEST_SMALL_JPEG);
        let temp_dir = tempdir().expect("temp dir");
        let test_output = temp_dir_path(&temp_dir, "ws_bad_assertion.jpg");
        std::fs::copy(ap, test_output).expect("copy");

        let mut manifest = test_manifest();

        manifest
            .add_labeled_assertion(
                "c2pa.actions",
                &MyStruct {
                    // add something that isn't an actions struct
                    l1: "some data".to_owned(),
                    l2: 5,
                },
            )
            .expect("add_assertion");

        // convert to store
        let result = manifest.to_store();

        println!("{result:?}");
        assert!(result.is_err())
    }

    #[test]
    fn test_verifiable_credential() {
        let mut manifest = test_manifest();
        let vc: serde_json::Value = serde_json::from_str(TEST_VC).unwrap();
        manifest
            .add_verifiable_credential(&vc)
            .expect("verifiable_credential");
        let store = manifest.to_store().expect("to_store");
        let claim = store.provenance_claim().unwrap();
        assert!(!claim.get_verifiable_credentials().is_empty());
    }

    #[test]
    fn test_assertion_user_cbor() {
        use crate::{assertions::UserCbor, Manifest};

        const LABEL: &str = "org.cai.test";
        const DATA: &str = r#"{ "l1":"some data", "l2":"some other data" }"#;
        let json: serde_json::Value = serde_json::from_str(DATA).unwrap();
        let data = serde_cbor::to_vec(&json).unwrap();
        let cbor = UserCbor::new(LABEL, data);
        let mut manifest = test_manifest();
        manifest.add_assertion(&cbor).expect("add_assertion");
        manifest.add_assertion(&cbor).expect("add_assertion");
        let store = manifest.to_store().expect("to_store");

        let _manifest2 = Manifest::from_store(
            &store,
            &store.provenance_label().unwrap(),
            #[cfg(feature = "file_io")]
            None,
        )
        .expect("from_store");
        println!("{store}");
        println!("{_manifest2:?}");
        let cbor2: UserCbor = manifest.find_assertion(LABEL).expect("get_assertion");
        assert_eq!(cbor, cbor2);
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_redaction() {
        const ASSERTION_LABEL: &str = "stds.schema-org.CreativeWork";

        let temp_dir = tempdir().expect("temp dir");
        let output = temp_fixture_path(&temp_dir, TEST_SMALL_JPEG);
        let output2 = temp_fixture_path(&temp_dir, TEST_SMALL_JPEG);

        let mut manifest = test_manifest();

        manifest
            .add_labeled_assertion(
                ASSERTION_LABEL,
                &serde_json::json! (
                {
                    "@context": "https://schema.org",
                    "@type": "CreativeWork",
                    "author": [
                      {
                        "@type": "Person",
                        "name": "Joe Bloggs"
                      },

                    ]
                  }),
            )
            .expect("add_assertion");

        let signer = temp_signer();

        let c2pa_data = manifest
            .embed(&output, &output, signer.as_ref())
            .expect("embed");
        let mut validation_log = DetailedStatusTracker::new();

        let store1 = Store::load_from_memory("c2pa", &c2pa_data, true, &mut validation_log)
            .expect("load from memory");
        let claim1_label = store1.provenance_label().unwrap();
        let claim = store1.provenance_claim().unwrap();
        assert!(claim.get_claim_assertion(ASSERTION_LABEL, 0).is_some()); // verify the assertion is there

        // create a new claim and make the previous file a parent
        let mut manifest2 = test_manifest();
        manifest2
            .set_parent(Ingredient::from_file(&output).expect("from_file"))
            .expect("set_parent");

        // redact the assertion
        manifest2
            .add_redaction(ASSERTION_LABEL)
            .expect("add_redaction");

        //embed a claim in output2
        let signer = temp_signer();
        let _store2 = manifest2
            .embed(&output2, &output2, signer.as_ref())
            .expect("embed");

        let mut report = DetailedStatusTracker::new();
        let store3 = Store::load_from_asset(&output2, true, &mut report).unwrap();
        let claim2 = store3.provenance_claim().unwrap();

        // assert!(!claim2.get_verifiable_credentials().is_empty());

        // test that the redaction is in the new claim and the assertion is removed from the first one

        assert!(claim2.redactions().is_some());
        assert!(!claim2.redactions().unwrap().is_empty());
        assert!(!report.get_log().is_empty());
        let redacted_uri = &claim2.redactions().unwrap()[0];

        let claim1 = store3.get_claim(&claim1_label).unwrap();
        assert!(claim1.get_claim_assertion(redacted_uri, 0).is_none());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_action_assertion_redaction_error() {
        let temp_dir = tempdir().expect("temp dir");
        let parent_output = temp_fixture_path(&temp_dir, TEST_SMALL_JPEG);

        // Create parent with a c2pa_action type assertion.
        let mut parent_manifest = test_manifest();
        let actions = Actions::new().add_action(
            Action::new(c2pa_action::FILTERED)
                .set_parameter("name".to_owned(), "gaussian blur")
                .unwrap()
                .set_when("2015-06-26T16:43:23+0200"),
        );
        parent_manifest
            .add_assertion(&actions)
            .expect("add_assertion");

        let signer = temp_signer();
        parent_manifest
            .embed(&parent_output, &parent_output, signer.as_ref())
            .expect("embed");

        // Add parent_manifest as an ingredient of the new manifest and redact the assertion `c2pa.actions`.
        let mut manifest = test_manifest();
        manifest
            .set_parent(Ingredient::from_file(&parent_output).expect("from_file"))
            .expect("set_parent");
        assert!(manifest.add_redaction(ACTIONS).is_ok());

        // Attempt embedding the manifest with the invalid redaction.
        let redact_output = temp_fixture_path(&temp_dir, TEST_SMALL_JPEG);
        let embed_result = manifest.embed(&redact_output, &redact_output, signer.as_ref());
        assert!(matches!(
            embed_result.err().unwrap(),
            Error::AssertionInvalidRedaction
        ));
    }

    #[test]
    fn manifest_assertion_instances() {
        let mut manifest = Manifest::new("test".to_owned());
        let actions = Actions::new().add_action(Action::new(c2pa_action::EDITED));
        // add three assertions with the same label
        manifest.add_assertion(&actions).expect("add_assertion");
        manifest.add_assertion(&actions).expect("add_assertion");
        manifest.add_assertion(&actions).expect("add_assertion");

        // convert to a store and read back again
        let store = manifest.to_store().expect("to_store");
        println!("{store}");
        let active_label = store.provenance_label().unwrap();

        let manifest2 = Manifest::from_store(
            &store,
            &active_label,
            #[cfg(feature = "file_io")]
            None,
        )
        .expect("from_store");
        println!("{manifest2}");

        // now check to see if we have three separate assertions with different instances
        let action2: Result<Actions> = manifest2.find_assertion_with_instance(Actions::LABEL, 2);
        assert!(action2.is_ok());
        assert_eq!(action2.unwrap().actions()[0].action(), c2pa_action::EDITED);
    }

    #[cfg(all(feature = "file_io", feature = "openssl_sign"))]
    #[actix::test]
    async fn test_embed_async_sign() {
        let temp_dir = tempdir().expect("temp dir");
        let output = temp_fixture_path(&temp_dir, TEST_SMALL_JPEG);

        let async_signer =
            crate::openssl::temp_signer_async::AsyncSignerAdapter::new(crate::SigningAlg::Ps256);

        let mut manifest = test_manifest();
        manifest
            .embed_async_signed(&output, &output, &async_signer)
            .await
            .expect("embed");
        let manifest_store = crate::ManifestStore::from_file(&output).expect("from_file");
        assert!(manifest_store.active_label().is_some());
        assert_eq!(
            manifest_store.get_active().unwrap().title().unwrap(),
            TEST_SMALL_JPEG
        );
    }

    #[cfg(all(feature = "file_io", feature = "openssl_sign"))]
    #[actix::test]
    async fn test_embed_remote_sign() {
        let temp_dir = tempdir().expect("temp dir");
        let output = temp_fixture_path(&temp_dir, TEST_SMALL_JPEG);

        let remote_signer = temp_remote_signer();

        let mut manifest = test_manifest();
        manifest
            .embed_remote_signed(&output, &output, remote_signer.as_ref())
            .await
            .expect("embed");
        let manifest_store = crate::ManifestStore::from_file(&output).expect("from_file");
        assert!(manifest_store.active_label().is_some());
        assert_eq!(
            manifest_store.get_active().unwrap().title().unwrap(),
            TEST_SMALL_JPEG
        );
    }

    #[cfg(all(feature = "file_io", feature = "xmp_write"))]
    #[test]
    fn test_embed_user_label() {
        let temp_dir = tempdir().expect("temp dir");
        let output = temp_fixture_path(&temp_dir, TEST_SMALL_JPEG);

        let signer = temp_signer();

        let mut manifest = test_manifest();
        manifest.set_label("MyLabel");
        manifest
            .embed(&output, &output, signer.as_ref())
            .expect("embed");
        let manifest_store = crate::ManifestStore::from_file(&output).expect("from_file");
        assert_eq!(manifest_store.active_label(), Some("MyLabel"));
        assert_eq!(
            manifest_store.get_active().unwrap().title().unwrap(),
            TEST_SMALL_JPEG
        );
    }

    #[cfg(all(feature = "file_io", feature = "xmp_write"))]
    #[test]
    fn test_embed_sidecar_user_label() {
        let temp_dir = tempdir().expect("temp dir");
        let output = temp_fixture_path(&temp_dir, TEST_SMALL_JPEG);
        let sidecar = output.with_extension("c2pa");
        let fp = format!("file:/{}", sidecar.to_str().unwrap());
        let url = url::Url::parse(&fp).unwrap();

        let signer = temp_signer();

        let mut manifest = test_manifest();
        manifest.set_label("MyLabel");
        manifest.set_remote_manifest(url);
        let c2pa_data = manifest
            .embed(&output, &output, signer.as_ref())
            .expect("embed");

        //let manifest_store = crate::ManifestStore::from_file(&sidecar).expect("from_file");
        let manifest_store = crate::ManifestStore::from_bytes("application/c2pa", &c2pa_data, true)
            .expect("from_bytes");
        assert_eq!(manifest_store.active_label(), Some("MyLabel"));
        assert_eq!(
            manifest_store.get_active().unwrap().title().unwrap(),
            TEST_SMALL_JPEG
        );
    }

    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn test_embed_jpeg_stream_wasm() {
        use crate::assertions::User;
        let image = include_bytes!("../tests/fixtures/earth_apollo17.jpg");
        // convert buffer to cursor with Read/Write/Seek capability

        let mut manifest = Manifest::new("my_app".to_owned());
        manifest.set_title("EmbedStream");
        manifest
            .add_assertion(&User::new(
                "org.contentauth.mylabel",
                r#"{"my_tag":"Anything I want"}"#,
            ))
            .unwrap();

        // add a parent ingredient
        let mut ingredient = Ingredient::from_memory_async("jpeg", image)
            .await
            .expect("from_stream_async");
        ingredient.set_title("parent.jpg");
        manifest.set_parent(ingredient).expect("set_parent");

        let signer = temp_remote_signer();

        // Embed a manifest using the signer.
        let (out_vec, _out_manifest) = manifest
            .embed_from_memory_remote_signed("jpeg", image, signer.as_ref())
            .await
            .expect("embed_stream");

        // try to load the image
        let manifest_store =
            crate::ManifestStore::from_bytes("image/jpeg", &out_vec, true).unwrap();

        /* to be enabled later
                // try to load the manifest
                let mut validation_log = DetailedStatusTracker::new();
                Store::from_jumbf(&out_manifest, &mut validation_log).expect("manifest_load_error");
        */
        println!("It worked: {manifest_store}\n");
    }

    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn test_embed_png_stream_wasm() {
        use crate::assertions::User;
        let image = include_bytes!("../tests/fixtures/libpng-test.png");
        // convert buffer to cursor with Read/Write/Seek capability

        let mut manifest = Manifest::new("my_app".to_owned());
        manifest.set_title("EmbedStream");
        manifest
            .add_assertion(&User::new(
                "org.contentauth.mylabel",
                r#"{"my_tag":"Anything I want"}"#,
            ))
            .unwrap();

        let signer = temp_remote_signer();

        // Embed a manifest using the signer.
        let (out_vec, _out_manifest) = manifest
            .embed_from_memory_remote_signed("png", image, signer.as_ref())
            .await
            .expect("embed_stream");

        // try to load the image
        let manifest_store = crate::ManifestStore::from_bytes("image/png", &out_vec, true).unwrap();

        /* to be enabled later
                // try to load the manifest
                let mut validation_log = DetailedStatusTracker::new();
                Store::from_jumbf(&out_manifest, &mut validation_log).expect("manifest_load_error");
        */

        println!("It worked: {manifest_store}\n");
    }

    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn test_embed_webp_stream_wasm() {
        use crate::assertions::User;
        let image = include_bytes!("../tests/fixtures/mars.webp");
        // convert buffer to cursor with Read/Write/Seek capability

        let mut manifest = Manifest::new("my_app".to_owned());
        manifest.set_title("EmbedStream");
        manifest
            .add_assertion(&User::new(
                "org.contentauth.mylabel",
                r#"{"my_tag":"Anything I want"}"#,
            ))
            .unwrap();

        let signer = temp_remote_signer();

        // Embed a manifest using the signer.
        let (out_vec, _out_manifest) = manifest
            .embed_from_memory_remote_signed("image/webp", image, signer.as_ref())
            .await
            .expect("embed_stream");

        // try to load the image
        let manifest_store =
            crate::ManifestStore::from_bytes("image/webp", &out_vec, true).unwrap();

        /* to be enabled later
                // try to load the manifest
                let mut validation_log = DetailedStatusTracker::new();
                Store::from_jumbf(&out_manifest, &mut validation_log).expect("manifest_load_error");
        */

        println!("It worked: {manifest_store}\n");
    }

    #[test]
    fn test_embed_stream() {
        use crate::assertions::User;
        let image = include_bytes!("../tests/fixtures/earth_apollo17.jpg");
        // convert buffer to cursor with Read/Write/Seek capability
        let mut stream = std::io::Cursor::new(image.to_vec());
        // let mut image = image.to_vec();
        // let mut stream = std::io::Cursor::new(image.as_mut_slice());

        let mut manifest = Manifest::new("my_app".to_owned());
        manifest.set_title("EmbedStream");
        manifest
            .add_assertion(&User::new(
                "org.contentauth.mylabel",
                r#"{"my_tag":"Anything I want"}"#,
            ))
            .unwrap();

        let signer = temp_signer();
        let mut output = Cursor::new(Vec::new());
        // Embed a manifest using the signer.
        manifest
            .embed_to_stream("jpeg", &mut stream, &mut output, signer.as_ref())
            .expect("embed_stream");

        let manifest_store = crate::ManifestStore::from_bytes("jpeg", &output.into_inner(), true)
            .expect("from_bytes");
        assert_eq!(
            manifest_store.get_active().unwrap().title().unwrap(),
            "EmbedStream"
        );
        #[cfg(feature = "add_thumbnails")]
        assert!(manifest_store.get_active().unwrap().thumbnail().is_some());
        //println!("{manifest_store}");main
    }
    #[cfg(feature = "file_io")]
    #[actix::test]
    /// Verify that an ingredient with error is reported on the ingredient and not on the manifest_store
    async fn test_embed_with_ingredient_error() {
        let temp_dir = tempdir().expect("temp dir");
        let output = temp_fixture_path(&temp_dir, TEST_SMALL_JPEG);

        let signer = temp_signer();

        let mut manifest = test_manifest();
        let ingredient =
            Ingredient::from_file(fixture_path("XCA.jpg")).expect("getting ingredient");
        assert!(ingredient.validation_status().is_some());
        assert_eq!(
            ingredient.validation_status().unwrap()[0].code(),
            validation_status::ASSERTION_DATAHASH_MISMATCH
        );
        manifest.add_ingredient(ingredient);
        manifest
            .embed(&output, &output, signer.as_ref())
            .expect("embed");
        let manifest_store = crate::ManifestStore::from_file(&output).expect("from_file");
        println!("{manifest_store}");
        let manifest = manifest_store.get_active().unwrap();
        let ingredient_status = manifest.ingredients()[0].validation_status();
        assert_eq!(
            ingredient_status.unwrap()[0].code(),
            validation_status::ASSERTION_DATAHASH_MISMATCH
        );
        assert_eq!(manifest.title().unwrap(), TEST_SMALL_JPEG);
        assert!(manifest_store.validation_status().is_none())
    }

    #[cfg(all(feature = "file_io", feature = "xmp_write"))]
    #[test]
    fn test_embed_sidecar_with_parent_manifest() {
        let temp_dir = tempdir().expect("temp dir");
        let source = fixture_path("XCA.jpg");
        let output = temp_dir.path().join("XCAplus.jpg");
        let sidecar = output.with_extension("c2pa");
        let fp = format!("file:/{}", sidecar.to_str().unwrap());
        let url = url::Url::parse(&fp).unwrap();

        let signer = temp_signer();

        let parent = Ingredient::from_file(fixture_path("XCA.jpg")).expect("getting parent");
        let mut manifest = test_manifest();
        manifest.set_parent(parent).expect("setting parent");
        manifest.set_remote_manifest(url);
        let _c2pa_data = manifest
            .embed(&source, &output, signer.as_ref())
            .expect("embed");

        //let manifest_store = crate::ManifestStore::from_file(&sidecar).expect("from_file");
        let manifest_store = crate::ManifestStore::from_file(&output).expect("from_file");
        assert_eq!(
            manifest_store.get_active().unwrap().title().unwrap(),
            "XCAplus.jpg"
        );
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn test_embed_user_thumbnail() {
        let temp_dir = tempdir().expect("temp dir");
        let output = temp_fixture_path(&temp_dir, TEST_SMALL_JPEG);

        let signer = temp_signer();

        let mut manifest = test_manifest();
        let thumb_data = vec![1, 2, 3];
        manifest
            .set_thumbnail("image/jpeg", thumb_data.clone())
            .expect("set_thumbnail");
        manifest
            .embed(&output, &output, signer.as_ref())
            .expect("embed");
        let manifest_store = crate::ManifestStore::from_file(&output).expect("from_file");
        let active_manifest = manifest_store.get_active().unwrap();
        let (format, image) = active_manifest.thumbnail().unwrap();
        assert_eq!(format, "image/jpeg");
        assert_eq!(image.into_owned(), thumb_data);
    }

    #[cfg(feature = "file_io")]
    const MANIFEST_JSON: &str = r#"{
        "claim_generator": "test",
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
                            "instanceId": "xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738d",
                            "parameters": {
                                "description": "import"
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
              "identifier": "prompt.txt",
              "data_types": [
                {
                  "type": "c2pa.types.generator.prompt"
                }
              ]
            }
          }
        ]
    }"#;

    #[test]
    #[cfg(feature = "openssl_sign")]
    /// tests and illustrates how to add assets to a non-file based manifest by using a stream
    fn from_json_with_stream() {
        use crate::assertions::Relationship;

        let mut manifest = Manifest::from_json(MANIFEST_JSON).unwrap();
        // add binary resources to manifest and ingredients giving matching the identifiers given in JSON
        manifest
            .resources_mut()
            .add("IMG_0003.jpg", *b"my value")
            .unwrap()
            .add("sample1.svg", *b"my value")
            .expect("add resource");
        manifest.ingredients_mut()[0]
            .resources_mut()
            .add("exp-test1.png", *b"my value")
            .expect("add_resource");
        manifest.ingredients_mut()[1]
            .resources_mut()
            .add("prompt.txt", *b"pirate with bird on shoulder")
            .expect("add_resource");

        println!("{manifest}");

        let image = include_bytes!("../tests/fixtures/earth_apollo17.jpg");
        // convert buffer to cursor with Read/Write/Seek capability
        let mut input = std::io::Cursor::new(image.to_vec());

        let signer = temp_signer();
        // Embed a manifest using the signer.
        let mut output = Cursor::new(Vec::new());
        manifest
            .embed_to_stream("jpeg", &mut input, &mut output, signer.as_ref())
            .expect("embed_stream");

        let manifest_store = crate::ManifestStore::from_bytes("jpeg", &output.into_inner(), true)
            .expect("from_bytes");
        println!("manifest_store = {manifest_store}");
        let m = manifest_store.get_active().unwrap();

        //println!("after = {m}");

        assert!(m.thumbnail().is_some());
        let (format, image) = m.thumbnail().unwrap();
        assert_eq!(format, "image/jpeg");
        assert_eq!(image.to_vec(), b"my value");
        assert_eq!(m.ingredients().len(), 2);
        assert_eq!(m.ingredients()[1].relationship(), &Relationship::InputTo);
        assert!(m.ingredients()[1].data_ref().is_some());
        assert_eq!(m.ingredients()[1].data_ref().unwrap().format, "text/plain");
        let id = m.ingredients()[1].data_ref().unwrap().identifier.as_str();
        assert_eq!(
            m.ingredients()[1].resources().get(id).unwrap().into_owned(),
            b"pirate with bird on shoulder"
        );
        // println!("{manifest_store}");
    }

    #[test]
    #[cfg(feature = "openssl_sign")]
    /// tests and illustrates how to add assets to a non-file based manifest by using a memory buffer
    fn from_json_with_memory() {
        use crate::assertions::Relationship;

        let mut manifest = Manifest::from_json(MANIFEST_JSON).unwrap();
        // add binary resources to manifest and ingredients giving matching the identifiers given in JSON
        manifest
            .resources_mut()
            .add("IMG_0003.jpg", *b"my value")
            .unwrap()
            .add("sample1.svg", *b"my value")
            .expect("add resource");
        manifest.ingredients_mut()[0]
            .resources_mut()
            .add("exp-test1.png", *b"my value")
            .expect("add_resource");
        manifest.ingredients_mut()[1]
            .resources_mut()
            .add("prompt.txt", *b"pirate with bird on shoulder")
            .expect("add_resource");

        println!("{manifest}");

        let image = include_bytes!("../tests/fixtures/earth_apollo17.jpg");

        let signer = temp_signer();
        // Embed a manifest using the signer.
        let output_image = manifest
            .embed_from_memory("jpeg", image, signer.as_ref())
            .expect("embed_stream");

        let manifest_store =
            crate::ManifestStore::from_bytes("jpeg", &output_image, true).expect("from_bytes");
        println!("manifest_store = {manifest_store}");
        let m = manifest_store.get_active().unwrap();

        assert!(m.thumbnail().is_some());
        let (format, image) = m.thumbnail().unwrap();
        assert_eq!(format, "image/jpeg");
        assert_eq!(image.to_vec(), b"my value");
        assert_eq!(m.ingredients().len(), 2);
        assert_eq!(m.ingredients()[1].relationship(), &Relationship::InputTo);
        assert!(m.ingredients()[1].data_ref().is_some());
        assert_eq!(m.ingredients()[1].data_ref().unwrap().format, "text/plain");
        let id = m.ingredients()[1].data_ref().unwrap().identifier.as_str();
        assert_eq!(
            m.ingredients()[1].resources().get(id).unwrap().into_owned(),
            b"pirate with bird on shoulder"
        );
        // println!("{manifest_store}");
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn from_json_with_files() {
        let mut manifest = Manifest::from_json(MANIFEST_JSON).unwrap();
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/fixtures"); // the path we want to read files from
        manifest.with_base_path(path).expect("with_files");
        // convert the manifest to a store
        let store = manifest.to_store().expect("to store");
        let mut resource_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        resource_path.push("../target/tmp/manifest");
        let m2 = Manifest::from_store(
            &store,
            &store.provenance_label().unwrap(),
            Some(&resource_path),
        )
        .expect("from store");
        println!("{m2}");
        assert!(m2.thumbnail().is_some());
        assert!(m2.ingredients()[0].thumbnail().is_some());
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn test_embed_from_json() {
        let mut fixtures = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fixtures.push("tests/fixtures"); // the path we want to read files from

        let temp_dir = tempdir().expect("temp dir");
        let output = temp_fixture_path(&temp_dir, TEST_SMALL_JPEG);

        let signer = temp_signer();

        let mut manifest = Manifest::from_json(MANIFEST_JSON).expect("from_json");
        manifest.with_base_path(fixtures).expect("with_base");
        manifest
            .embed(&output, &output, signer.as_ref())
            .expect("embed");

        let manifest_store = crate::ManifestStore::from_file(&output).expect("from_file");
        println!("{manifest_store}");
        let active_manifest = manifest_store.get_active().unwrap();
        let (format, _) = active_manifest.thumbnail().unwrap();
        assert_eq!(format, "image/jpeg");
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn test_embed_webp_from_json() {
        use crate::utils::test::TEST_WEBP;

        let mut fixtures = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fixtures.push("tests/fixtures"); // the path we want to read files from

        let temp_dir = tempdir().expect("temp dir");
        let output = temp_fixture_path(&temp_dir, TEST_WEBP);

        let signer = temp_signer();

        let mut manifest = Manifest::from_json(MANIFEST_JSON).expect("from_json");
        manifest.with_base_path(fixtures).expect("with_base");
        manifest
            .embed(&output, &output, signer.as_ref())
            .expect("embed");

        let manifest_store = crate::ManifestStore::from_file(&output).expect("from_file");
        println!("{manifest_store}");
        let active_manifest = manifest_store.get_active().unwrap();
        let (format, _) = active_manifest.thumbnail().unwrap();
        assert_eq!(format, "image/jpeg");
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_create_file_based_ingredient() {
        let mut fixtures = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fixtures.push("tests/fixtures");

        let temp_dir = tempdir().expect("temp dir");
        let output = temp_fixture_path(&temp_dir, TEST_SMALL_JPEG);

        let mut manifest = Manifest::new("claim_generator");
        manifest.with_base_path(fixtures).expect("with_base");
        // verify we can't set a references that don't exist
        assert!(manifest
            .set_thumbnail_ref(ResourceRef::new("image/jpg", "foo"))
            .is_err());
        assert!(manifest.thumbnail_ref().is_none());
        // verify we can set a references that do exist
        assert!(manifest
            .set_thumbnail_ref(ResourceRef::new("image/jpeg", "C.jpg"))
            .is_ok());
        assert!(manifest.thumbnail_ref().is_some());

        let signer = temp_signer();
        manifest
            .embed(&output, &output, signer.as_ref())
            .expect("embed");
    }

    #[test]
    #[cfg(all(feature = "file_io", feature = "add_thumbnails"))]
    fn test_create_no_claim_thumbnail() {
        let mut fixtures = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fixtures.push("tests/fixtures");

        let temp_dir = tempdir().expect("temp dir");
        let output = temp_fixture_path(&temp_dir, TEST_SMALL_JPEG);

        let mut manifest = Manifest::new("claim_generator");

        // Set format to none to force no claim thumbnail generated
        assert!(manifest
            .set_thumbnail_ref(ResourceRef::new("none", "none"))
            .is_ok());
        // verify there is a thumbnail ref
        assert!(manifest.thumbnail_ref().is_some());
        // verify there is no thumbnail
        assert!(manifest.thumbnail().is_none());

        let signer = temp_signer();
        manifest
            .embed(&output, &output, signer.as_ref())
            .expect("embed");

        let manifest_store = crate::ManifestStore::from_file(&output).expect("from_file");
        println!("{manifest_store}");
        let active_manifest = manifest_store.get_active().unwrap();
        assert!(active_manifest.thumbnail_ref().is_none());
        assert!(active_manifest.thumbnail().is_none());
    }

    #[test]
    fn test_missing_thumbnail() {
        const MANIFEST_JSON: &str = r#"
            {
                "claim_generator": "test",
                "format" : "image/jpeg",
                "thumbnail": {
                    "format": "image/jpeg",
                    "identifier": "does_not_exist.jpg"
                }
            }
        "#;

        let mut manifest = Manifest::from_json(MANIFEST_JSON).expect("from_json");

        let mut source = std::io::Cursor::new(vec![1, 2, 3]);
        let mut dest = std::io::Cursor::new(Vec::new());
        let signer = temp_signer();
        let result =
            manifest.embed_to_stream("image/jpeg", &mut source, &mut dest, signer.as_ref());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("resource not found: does_not_exist.jpg"));
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_data_hash_embeddable_manifest() {
        let ap = fixture_path("cloud.jpg");

        let signer = temp_signer();

        let mut manifest = Manifest::new("claim_generator");

        // get a placeholder the manifest
        let placeholder = manifest
            .data_hash_placeholder(signer.as_ref(), "jpeg")
            .unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "boxhash-out.jpg");
        let mut output_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&output)
            .unwrap();

        // write a jpeg file with a placeholder for the manifest (returns offset of the placeholder)
        let offset =
            write_jpeg_placeholder_file(&placeholder, &ap, &mut output_file, None).unwrap();

        // build manifest to insert in the hole

        // create an hash exclusion for the manifest
        let exclusion = HashRange::new(offset, placeholder.len());
        let exclusions = vec![exclusion];

        let mut dh = DataHash::new("source_hash", "sha256");
        dh.exclusions = Some(exclusions);

        let signed_manifest = manifest
            .data_hash_embeddable_manifest(
                &dh,
                signer.as_ref(),
                "image/jpeg",
                Some(&mut output_file),
            )
            .unwrap();

        use std::io::{Seek, SeekFrom, Write};

        // path in new composed manifest
        output_file.seek(SeekFrom::Start(offset as u64)).unwrap();
        output_file.write_all(&signed_manifest).unwrap();

        let manifest_store = crate::ManifestStore::from_file(&output).expect("from_file");
        println!("{manifest_store}");
        assert!(manifest_store.validation_status().is_none());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_box_hash_embeddable_manifest() {
        let asset_bytes = include_bytes!("../tests/fixtures/boxhash.jpg");
        let box_hash_data = include_bytes!("../tests/fixtures/boxhash.json");
        let box_hash: crate::assertions::BoxHash = serde_json::from_slice(box_hash_data).unwrap();

        let mut manifest = Manifest::new("test_app".to_owned());
        manifest.set_title("BoxHashTest").set_format("image/jpeg");

        manifest
            .add_labeled_assertion(crate::assertions::labels::BOX_HASH, &box_hash)
            .unwrap();

        let signer = temp_signer();

        let embeddable = manifest
            .box_hash_embeddable_manifest(signer.as_ref(), None)
            .expect("embeddable_manifest");

        // Validate the embeddable manifest against the asset bytes
        let manifest_store = crate::ManifestStore::from_manifest_and_asset_bytes(
            &embeddable,
            "image/jpeg",
            asset_bytes,
        )
        .unwrap();
        println!("{manifest_store}");
        assert!(!manifest_store.manifests().is_empty());
        assert!(manifest_store.validation_status().is_none());
    }
}
