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

use std::collections::HashMap;
#[cfg(feature = "file_io")]
use std::path::Path;

use log::{debug, error, warn};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    assertion::{AssertionBase, AssertionData},
    assertions::{labels, Actions, CreativeWork, Exif, Thumbnail, User, UserCbor},
    claim::{Claim, RemoteManifest},
    error::{Error, Result},
    jumbf,
    salt::DefaultSalt,
    store::Store,
    Ingredient, ManifestAssertion, ManifestAssertionKind,
};
#[cfg(feature = "sign")]
use crate::{asset_io::CAIReadWrite, Signer};
#[cfg(all(feature = "async_signer", feature = "file_io"))]
use crate::{AsyncSigner, RemoteSigner};

/// Function that is used by serde to determine whether or not we should serialize
/// thumbnail data based on the `serialize_thumbnails` flag.
/// (Serialization is disabled by default.)
fn skip_serializing_thumbnails(value: &Option<(String, Vec<u8>)>) -> bool {
    !cfg!(feature = "serialize_thumbnails") || value.is_none()
}

/// A Manifest represents all the information in a c2pa manifest
#[derive(Debug, Deserialize, Serialize)]
pub struct Manifest {
    /// Optional prefix added to the generated Manifest Label
    /// This is typically Internet domain name for the vendor (i.e. `adobe`)
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor: Option<String>,

    /// A User Agent formatted string identifying the software/hardware/system produced this claim
    /// Spaces are not allowed in names, versions can be specified with product/1.0 syntax
    pub claim_generator: String,

    /// A human-readable title, generally source filename.
    title: Option<String>,

    /// The format of the source file as a MIME type.
    format: String,

    /// Instance ID from `xmpMM:InstanceID` in XMP metadata.
    instance_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    claim_generator_hints: Option<HashMap<String, Value>>,

    #[serde(skip_serializing_if = "skip_serializing_thumbnails")]
    thumbnail: Option<(String, Vec<u8>)>,

    /// A List of ingredients
    ingredients: Vec<Ingredient>,

    /// A List of verified credentials
    #[serde(skip_serializing_if = "Option::is_none")]
    credentials: Option<Vec<Value>>,

    /// A list of assertions
    assertions: Vec<ManifestAssertion>,

    /// A list of redactions - URIs to a redacted assertions
    #[serde(skip_serializing_if = "Option::is_none")]
    redactions: Option<Vec<String>>,

    /// Signature data (only used for reporting)
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_info: Option<SignatureInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,

    #[serde(skip_deserializing, skip_serializing)]
    remote_manifest: Option<RemoteManifest>,
}

impl Manifest {
    /// Create a new Manifest
    /// requires a claim_generator string (User Agent))
    pub fn new<S: Into<String>>(claim_generator: S) -> Self {
        Self {
            vendor: None,
            title: None,
            format: "application/octet-stream".to_owned(),
            instance_id: format!("xmp:iid:{}", Uuid::new_v4()),
            claim_generator: claim_generator.into(),
            claim_generator_hints: None,
            thumbnail: None,
            ingredients: Vec::new(),
            assertions: Vec::new(),
            redactions: None,
            credentials: None,
            signature_info: None,
            label: None,
            remote_manifest: None,
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

    /// Returns a tuple with thumbnail format and image bytes or `None`.
    pub fn thumbnail(&self) -> Option<(&str, &[u8])> {
        self.thumbnail
            .as_ref()
            .map(|(format, image)| (format.as_str(), image.as_ref()))
    }

    /// Returns the [Ingredient]s used by this Manifest
    /// This can include a parent as well as any placed assets
    pub fn ingredients(&self) -> &[Ingredient] {
        &self.ingredients
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

    /// Sets the thumbnail format and image data.
    pub fn set_thumbnail<S: Into<String>>(&mut self, format: S, thumbnail: Vec<u8>) -> &mut Self {
        self.thumbnail = Some((format.into(), thumbnail));
        self
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

    /// Sets the parent ingredient, assuring it is first and setting the is_parent flag
    pub fn set_parent(&mut self, mut ingredient: Ingredient) -> Result<&mut Self> {
        // there should only be one parent so return an error if we already have one
        if self.ingredients.iter().any(|i| i.is_parent()) {
            error!("parent already added");
            return Err(Error::BadParam("Parent parent already added".to_owned()));
        }
        // if the hash of our new ingredient does not match any of the ingredients
        // then add it
        if !self
            .ingredients
            .iter()
            .any(|i| ingredient.hash().is_some() && i.hash() == ingredient.hash())
        {
            debug!("ingredients:set_is_parent {:?}", ingredient.title());
            ingredient.set_is_parent();
            self.ingredients.insert(0, ingredient);
        } else {
            // dup so just keep the ingredient instead of adding the parent
            warn!("duplicate parent {}", ingredient.title());
        }

        Ok(self)
    }

    /// Add an ingredient removing duplicates (consumes the asset)
    pub fn add_ingredient(&mut self, ingredient: Ingredient) -> &mut Self {
        // if the hash of the new asset does not match any of the ingredients
        // then add it
        if !self
            .ingredients
            .iter()
            .any(|i| ingredient.hash().is_some() && i.hash() == ingredient.hash())
        {
            debug!("Manifest:add_ingredient {:?}", ingredient.title());
            self.ingredients.push(ingredient);
        } else {
            warn!("duplicate ingredient {}", ingredient.title());
        }
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
    ///     assertions::{Actions, Action, c2pa_action},
    ///     Manifest
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
    ///     assertions::{Actions, Action, c2pa_action},
    ///     Manifest
    /// };
    /// # fn main() -> Result<()> {
    /// let mut manifest = Manifest::new("my_app");
    /// let actions = Actions::new().add_action(Action::new(c2pa_action::EDITED));
    /// manifest.add_assertion(&actions)?;
    ///
    /// let actions: Actions = manifest.find_assertion(Actions::LABEL)?;
    /// for action in actions.actions {
    ///    println!("{}", action.action());
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
    fn set_signature(&mut self, issuer: Option<&String>, time: Option<&String>) -> &mut Self {
        self.signature_info = Some(SignatureInfo {
            issuer: issuer.cloned(),
            time: time.cloned(),
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

    // Generates a Manifest given a store and a manifest label
    pub(crate) fn from_store(store: &Store, manifest_label: &str) -> Result<Self> {
        let claim = store
            .get_claim(manifest_label)
            .ok_or_else(|| Error::ClaimMissing {
                label: manifest_label.to_owned(),
            })?;

        // extract vendor from claim label
        let claim_generator = claim.claim_generator().to_owned();
        let mut manifest = Manifest::new(claim_generator);

        manifest.set_label(claim.label());
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

        // let title = claim.title().map_or("".to_owned(), |s| s.to_owned());
        // let format = claim.format().to_owned();
        // let instance_id = claim.instance_id().to_owned();
        if let Some(title) = claim.title() {
            manifest.set_title(title);
        }
        manifest.set_format(claim.format());
        manifest.set_instance_id(claim.instance_id());

        //let mut asset = Ingredient::new(&title, &format, &instance_id);

        for claim_assertion in claim.claim_assertion_store().iter() {
            let assertion = claim_assertion.assertion();
            let label = claim_assertion.label();
            let base_label = assertion.label();
            debug!("assertion = {}", label);
            match base_label.as_ref() {
                labels::INGREDIENT => {
                    let assertion_uri = jumbf::labels::to_assertion_uri(claim.label(), &label);
                    let ingredient = Ingredient::from_ingredient_uri(store, &assertion_uri)?;
                    manifest.add_ingredient(ingredient);
                }
                label if label.starts_with(labels::CLAIM_THUMBNAIL) => {
                    let thumbnail = Thumbnail::from_assertion(assertion)?;
                    manifest.set_thumbnail(thumbnail.content_type, thumbnail.data);
                }
                _ => {
                    // inject assertions for all other assertions
                    match assertion.decode_data() {
                        AssertionData::Json(_x) => {
                            let value = assertion.as_json_object()?;
                            let ma = ManifestAssertion::new(base_label, value)
                                .set_instance(claim_assertion.instance())
                                .set_kind(ManifestAssertionKind::Json);
                            manifest.assertions.push(ma);
                        }
                        AssertionData::Cbor(_x) => {
                            let value = assertion.as_json_object()?; //todo: should this be cbor?
                            let ma = ManifestAssertion::new(base_label, value)
                                .set_instance(claim_assertion.instance());

                            manifest.assertions.push(ma);
                        }
                        // todo: support binary forms
                        AssertionData::Binary(_x) => {}
                        AssertionData::Uuid(_, _) => {}
                    }
                }
            }
        }

        // manifest.set_asset(asset);

        let issuer = claim.signing_issuer();
        let signing_time = claim
            .signing_time()
            .map(|signing_time| signing_time.to_rfc3339());

        if issuer.is_some() || signing_time.is_some() {
            debug!(
                "added signature issuer={:?} time={:?}",
                issuer, signing_time
            );
            manifest.set_signature(issuer.as_ref(), signing_time.as_ref());
        }

        Ok(manifest)
    }

    /// Sets the asset field from data in a file
    /// the information in the claim should reflect the state of the asset it is embedded in
    /// this method can be used to ensure that data is correct
    /// it will extract filename,format and xmp info and generate a thumbnail
    #[cfg(feature = "file_io")]
    pub fn set_asset_from_path<P: AsRef<Path>>(&mut self, path: P) {
        // Gather the information we need from the target path
        let ingredient = Ingredient::from_file_info(path.as_ref());

        self.set_format(ingredient.format());
        self.set_instance_id(ingredient.instance_id());

        // if there is already an asset title preserve it
        if self.title().is_none() {
            self.set_title(ingredient.title());
        }

        // if a thumbnail is not already defined, create one here
        if self.thumbnail().is_none() {
            #[cfg(feature = "add_thumbnails")]
            if let Ok((format, image)) = crate::utils::thumbnail::make_thumbnail(path.as_ref()) {
                self.set_thumbnail(format, image);
            }
        }
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
        if let Some((format, image)) = self.thumbnail() {
            claim.add_assertion(&Thumbnail::new(
                &labels::add_thumbnail_format(labels::CLAIM_THUMBNAIL, format),
                image.to_vec(),
            ))?;
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
            ingredient_map.insert(
                ingredient.instance_id(),
                ingredient.add_to_claim(&mut claim, self.redactions.clone())?,
            );
        }

        let salt = DefaultSalt::default();

        // add any additional assertions
        for manifest_assertion in &self.assertions {
            match manifest_assertion.label() {
                Actions::LABEL => {
                    let mut actions: Actions = manifest_assertion.to_assertion()?;

                    // fixup parameters field from instance_id to ingredient uri
                    let needs_ingredient: Vec<(usize, crate::assertions::Action)> = actions
                        .actions()
                        .iter()
                        .enumerate()
                        .filter_map(|(i, a)| {
                            if a.instance_id().is_some() && a.get_parameter("ingredient").is_none()
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
                                let update =
                                    action.set_parameter("ingredient", hash_url.clone())?;
                                actions = actions.update_action(index, update);
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
            std::fs::copy(&source_path, &dest_path)?;
            copied = true;
        }
        // first add the information about the target file
        self.set_asset_from_path(dest_path.as_ref());

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
    /// use c2pa::{
    ///     assertions::User,
    ///     create_signer,
    ///     Manifest,
    ///     SigningAlg,
    /// };
    /// # fn main() -> Result<()> {
    /// let mut manifest = Manifest::new("my_app".to_owned());
    /// manifest.add_assertion(&User::new("org.contentauth.mylabel", r#"{"my_tag":"Anything I want"}"#))?;
    ///
    /// let source = "tests/fixtures/C.jpg";
    /// let dest = "../target/test_file.jpg";
    ///
    /// // Create a PS256 signer using certs and public key files.
    /// let signcert_path = "tests/fixtures/certs/ps256.pub";
    /// let pkey_path = "tests/fixtures/certs/ps256.pem";
    /// let signer = create_signer::from_files(signcert_path, pkey_path, SigningAlg::Ps256, None)?;
    ///
    /// // Embed a manifest using the signer.
    /// manifest.embed(&source, &dest, &*signer)?;
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
    #[cfg(feature = "sign")]
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
        self.embed_stream(format, &mut stream, signer)?;
        Ok(stream.into_inner())
    }

    /// Embed a signed manifest into a stream using a supplied signer.
    /// returns the bytes of the  manifest that was embedded
    #[cfg(feature = "sign")]
    pub fn embed_stream(
        &mut self,
        format: &str,
        stream: &mut dyn CAIReadWrite,
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        self.set_format(format);
        // todo:: read instance_id from xmp from stream
        self.set_instance_id(format!("xmp:iid:{}", Uuid::new_v4()));

        // generate thumbnail if we don't already have one
        if self.thumbnail().is_none() {
            #[cfg(feature = "add_thumbnails")]
            if let Ok((format, image)) =
                crate::utils::thumbnail::make_thumbnail_from_stream(format, stream)
            {
                self.set_thumbnail(format, image);
            }
        }

        // convert the manifest to a store
        let mut store = self.to_store()?;

        // sign and write our store to to the output image file
        store.save_to_stream(format, stream, signer)
    }

    /// Embed a signed manifest into the target file using a supplied [`AsyncSigner`].
    #[cfg(feature = "file_io")]
    #[cfg(feature = "async_signer")]
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
    #[cfg(all(feature = "file_io", feature = "async_signer"))]
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
    #[cfg(feature = "file_io")]
    pub fn remove_manifest<P: AsRef<Path>>(asset_path: P) -> Result<()> {
        use crate::jumbf_io::remove_jumbf_from_file;
        remove_jumbf_from_file(asset_path.as_ref())
    }
}

impl std::fmt::Display for Manifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string_pretty(self).unwrap_or_default();
        f.write_str(&json)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
/// Holds information about a signature
pub struct SignatureInfo {
    /// human readable issuing authority for this signature
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    /// the time the signature was created
    #[serde(skip_serializing_if = "Option::is_none")]
    time: Option<String>,
}
#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    #[cfg(feature = "file_io")]
    use tempfile::tempdir;

    #[cfg(feature = "sign")]
    use crate::utils::test::temp_signer;
    #[cfg(feature = "file_io")]
    use crate::{
        assertions::labels::ACTIONS,
        error::Error,
        status_tracker::{DetailedStatusTracker, StatusTracker},
        store::Store,
        utils::test::{fixture_path, temp_dir_path, temp_fixture_path, TEST_SMALL_JPEG},
        validation_status, Ingredient,
    };
    use crate::{
        assertions::{c2pa_action, Action, Actions},
        utils::test::TEST_VC,
        Manifest, Result,
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
            .embed(&source_path, &test_output, &signer)
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

        println!("{:?}", result);
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

        let _manifest2 =
            Manifest::from_store(&store, &store.provenance_label().unwrap()).expect("from_store");
        println!("{}", store);
        println!("{:?}", _manifest2);
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

        let c2pa_data = manifest.embed(&output, &output, &signer).expect("embed");
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
        let _store2 = manifest2.embed(&output2, &output2, &signer).expect("embed");

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
            .embed(&parent_output, &parent_output, &signer)
            .expect("embed");

        // Add parent_manifest as an ingredient of the new manifest and redact the assertion `c2pa.actions`.
        let mut manifest = test_manifest();
        manifest
            .set_parent(Ingredient::from_file(&parent_output).expect("from_file"))
            .expect("set_parent");
        assert!(manifest.add_redaction(ACTIONS).is_ok());

        // Attempt embedding the manifest with the invalid redaction.
        let redact_output = temp_fixture_path(&temp_dir, TEST_SMALL_JPEG);
        let embed_result = manifest.embed(&redact_output, &redact_output, &signer);
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
        println!("{}", store);
        let active_label = store.provenance_label().unwrap();
        let manifest2 = Manifest::from_store(&store, &active_label).expect("from_store");
        println!("{}", manifest2);
        // now check to see if we have three separate assertions with different instances
        let action2: Result<Actions> = manifest2.find_assertion_with_instance(Actions::LABEL, 2);
        assert!(action2.is_ok());
        assert_eq!(action2.unwrap().actions()[0].action(), c2pa_action::EDITED);
    }

    #[cfg(all(feature = "file_io", feature = "async_signer"))]
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

    #[cfg(all(feature = "file_io", feature = "async_signer"))]
    #[actix::test]
    async fn test_embed_remote_sign() {
        struct MyRemoteSigner {}

        #[async_trait::async_trait]
        impl crate::signer::RemoteSigner for MyRemoteSigner {
            async fn sign_remote(&self, claim_bytes: &[u8]) -> Result<Vec<u8>> {
                let signer = crate::openssl::temp_signer_async::AsyncSignerAdapter::new(
                    crate::SigningAlg::Ps256,
                );

                // this would happen on some remote server
                crate::cose_sign::cose_sign_async(&signer, claim_bytes, self.reserve_size()).await
            }
            fn reserve_size(&self) -> usize {
                10000
            }
        }

        let temp_dir = tempdir().expect("temp dir");
        let output = temp_fixture_path(&temp_dir, TEST_SMALL_JPEG);

        let remote_signer = MyRemoteSigner {};

        let mut manifest = test_manifest();
        manifest
            .embed_remote_signed(&output, &output, &remote_signer)
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
        manifest.embed(&output, &output, &signer).expect("embed");
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
        let c2pa_data = manifest.embed(&output, &output, &signer).expect("embed");

        //let manifest_store = crate::ManifestStore::from_file(&sidecar).expect("from_file");
        let manifest_store =
            crate::ManifestStore::from_bytes("c2pa", &c2pa_data, true).expect("from_bytes");
        assert_eq!(manifest_store.active_label(), Some("MyLabel"));
        assert_eq!(
            manifest_store.get_active().unwrap().title().unwrap(),
            TEST_SMALL_JPEG
        );
    }

    #[test]
    #[cfg(feature = "sign")]
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
        // Embed a manifest using the signer.
        manifest
            .embed_stream("jpeg", &mut stream, &signer)
            .expect("embed_stream");

        // get the updated image
        let image = stream.into_inner();

        let manifest_store =
            crate::ManifestStore::from_bytes("jpeg", &image, true).expect("from_bytes");
        assert_eq!(
            manifest_store.get_active().unwrap().title().unwrap(),
            "EmbedStream"
        );
        #[cfg(feature = "add_thumbnails")]
        assert!(manifest_store.get_active().unwrap().thumbnail().is_some());

        println!("{}", manifest_store);
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
        manifest.embed(&output, &output, &signer).expect("embed");
        let manifest_store = crate::ManifestStore::from_file(&output).expect("from_file");
        println!("{}", manifest_store);
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
        let _c2pa_data = manifest.embed(&source, &output, &signer).expect("embed");

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
        manifest.set_thumbnail("image/jpeg", vec![1, 2, 3]);
        manifest.embed(&output, &output, &signer).expect("embed");
        let manifest_store = crate::ManifestStore::from_file(&output).expect("from_file");
        let active_manifest = manifest_store.get_active().unwrap();
        let (format, thumb) = active_manifest.thumbnail().unwrap();
        assert_eq!(format, "image/jpeg");
        assert_eq!(thumb, vec![1, 2, 3]);
    }
}
