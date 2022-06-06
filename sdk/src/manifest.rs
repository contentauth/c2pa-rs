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

#[cfg(feature = "file_io")]
use crate::utils::thumbnail::make_thumbnail;
use crate::{
    assertion::{AssertionBase, AssertionData},
    assertions::{labels, Actions, CreativeWork, Thumbnail, User, UserCbor},
    claim::Claim,
    error::{Error, Result},
    jumbf,
    salt::DefaultSalt,
    store::Store,
    Ingredient, ManifestAssertion, ManifestAssertionKind,
};

#[cfg(feature = "file_io")]
use crate::Signer;
use log::{debug, error, warn};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
#[cfg(feature = "file_io")]
use std::path::Path;

const GH_UA: &str = "Sec-CH-UA";

/// A Manifest represents all the information in a c2pa manifest
#[derive(Debug, Deserialize, Serialize)]
pub struct Manifest {
    /// Optional prefix added to the generated Manifest Label
    /// This is typically Internet domain name for the vendor (i.e. `adobe`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,

    /// A User Agent formatted string identifying the software/hardware/system produced this claim
    /// Spaces are not allowed in names, versions can be specified with product/1.0 syntax
    pub claim_generator: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    claim_generator_hints: Option<HashMap<String, Value>>,

    /// Information about the asset associated with this manifest
    #[serde(skip_serializing_if = "Option::is_none")]
    asset: Option<Ingredient>,

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
}

impl Manifest {
    /// Create a new Manifest
    /// requires a claim_generator string (User Agent))
    pub fn new(claim_generator: String) -> Self {
        Self {
            vendor: None,
            claim_generator,
            claim_generator_hints: None,
            asset: None,
            ingredients: Vec::new(),
            assertions: Vec::new(),
            redactions: None,
            credentials: None,
            signature_info: None,
        }
    }

    pub fn claim_generator(&self) -> &str {
        self.claim_generator.as_str()
    }

    /// Returns an [Ingredient] reference to the asset associated with this manifest
    pub fn asset(&self) -> Option<&Ingredient> {
        self.asset.as_ref()
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
    pub fn set_vendor(&mut self, vendor: String) -> &mut Self {
        self.vendor = Some(vendor);
        self
    }

    /// Sets a human readable name for the product that created this manifest
    pub fn set_claim_generator(&mut self, generator: String) -> &mut Self {
        self.claim_generator = generator;
        self
    }

    /// Sets an ingredient as the container asset
    pub fn set_asset(&mut self, ingredient: Ingredient) -> &mut Self {
        self.asset = Some(ingredient);
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

    /// Adds assertion using given label - the data for predefined assertions must be in correct format
    pub fn add_labeled_assertion<S: Into<String>, T: Serialize>(
        &mut self,
        label: S,
        data: &T,
    ) -> Result<&mut Self> {
        self.assertions
            .push(ManifestAssertion::from_labeled_assertion(label, data)?);
        Ok(self)
    }

    /// Adds assertions, data for predefined assertions must be in correct format
    pub fn add_assertion<T: Serialize + AssertionBase>(&mut self, data: &T) -> Result<&mut Self> {
        self.assertions
            .push(ManifestAssertion::from_assertion(data)?);
        Ok(self)
    }

    /// Retrieves an assertion by label if it exists or Error::NotFound
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

    // keep this private until we support it externally
    #[allow(dead_code)]
    pub(crate) fn add_redaction(&mut self, label: &str) -> Result<&mut Self> {
        // todo: any way to verify if this assertion exists in the parent claim here?
        match self.redactions.as_mut() {
            Some(redactions) => redactions.push(label.to_string()),
            None => self.redactions = Some([label.to_string()].to_vec()),
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
    pub fn set_signature(&mut self, issuer: Option<&String>, time: Option<&String>) -> &mut Self {
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

        manifest.claim_generator_hints = claim.get_claim_generator_hint_map().cloned();

        // get credentials converting from AssertionData to Value
        manifest.credentials = Some(
            claim
                .get_verifiable_credentials()
                .iter()
                .filter_map(|d| match d {
                    AssertionData::Json(s) => serde_json::from_str(s).ok(),
                    _ => None,
                })
                .collect(),
        );

        manifest.redactions = claim.redactions().map(|rs| {
            rs.iter()
                .filter_map(|r| jumbf::labels::assertion_label_from_uri(r))
                .collect()
        });

        let title = claim.title().map_or("".to_owned(), |s| s.to_owned());
        let format = claim.format().to_owned();
        let instance_id = claim.instance_id().to_owned();

        let mut asset = Ingredient::new(&title, &format, &instance_id);

        for claim_assertion in claim.claim_assertion_store().iter() {
            let assertion = claim_assertion.assertion();
            let label = assertion.label();
            debug!("assertion = {}", label);
            match label.as_ref() {
                labels::INGREDIENT => {
                    let assertion_uri = jumbf::labels::to_assertion_uri(claim.label(), &label);
                    let ingredient = Ingredient::from_ingredient_uri(store, &assertion_uri)?;
                    manifest.add_ingredient(ingredient);
                }
                // Actions::LABEL => {
                //     let actions = Actions::from_assertion(assertion)?;
                //     let ma = ManifestAssertion::new(label, value)
                //                 .set_instance(claim_assertion.instance())
                //                 .set_kind(ManifestAssertionKind::Cbor);

                //     manifest.add_assertion(&actions)?.set_instance(claim_assertion.instance()); // assertion.as_json_object()?)?;
                // }
                label if label.starts_with(labels::CLAIM_THUMBNAIL) => {
                    let thumbnail = Thumbnail::from_assertion(assertion)?;
                    asset.set_thumbnail(thumbnail.content_type, thumbnail.data);
                }
                _ => {
                    // inject assertions for all json data
                    match assertion.decode_data() {
                        AssertionData::Json(_x) => {
                            let value = assertion.as_json_object()?;
                            let ma = ManifestAssertion::new(label, value)
                                .set_instance(claim_assertion.instance())
                                .set_kind(ManifestAssertionKind::Json);
                            manifest.assertions.push(ma);
                        }
                        AssertionData::Cbor(_x) => {
                            let value = assertion.as_json_object()?; //todo: should this be cbor?
                            let ma = ManifestAssertion::new(label, value)
                                .set_instance(claim_assertion.instance());

                            manifest.assertions.push(ma);
                        }
                        AssertionData::Binary(_x) => {
                            //let _value = Value::String("<omitted>".to_owned());
                            // claim_report.add_assertion(&label, &value)?;
                        }
                        AssertionData::Uuid(_, _) => {}
                    }
                }
            }
        }

        manifest.set_asset(asset);

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
        let mut ingredient = Ingredient::from_file_info(path.as_ref());

        if let Ok((format, image)) = make_thumbnail(path.as_ref()) {
            ingredient.set_thumbnail(format, image);
        }

        // if there is already an asset title preserve it
        if let Some(title) = self.asset.as_ref().map(|i| i.title()) {
            ingredient.set_title(title.to_string());
        };

        // set asset to newly created ingredient
        self.asset = Some(ingredient);
    }

    // Convert a Manifest into a Store
    pub(crate) fn to_store(&self) -> Result<Store> {
        // add library identifier to claim_generator
        let generator = format!(
            "{} {}/{}",
            &self.claim_generator,
            crate::NAME,
            crate::VERSION
        );
        let mut claim = Claim::new(&generator, self.vendor.as_deref());

        // add any verified credentials - needs to happen early so we can reference them
        let mut vc_table = HashMap::new();
        if let Some(verified_credentials) = self.credentials.as_ref() {
            for vc in verified_credentials {
                let vc_str = &vc.to_string();
                let id = Claim::vc_id(vc_str)?;
                vc_table.insert(id, claim.add_verifiable_credential(vc_str)?);
            }
        }

        // if the Manifest has an asset field use it to set these claim fields
        if let Some(asset) = self.asset.as_ref() {
            claim.set_title(Some(asset.title().to_owned()));
            claim.format = asset.format().to_owned();
            claim.instance_id = asset.instance_id().to_owned();
            if let Some((format, image)) = asset.thumbnail() {
                claim.add_assertion(&Thumbnail::new(
                    &labels::add_thumbnail_format(labels::CLAIM_THUMBNAIL, format),
                    image.to_vec(),
                ))?;
            }
        }

        // add all ingredients to the claim
        for ingredient in &self.ingredients {
            ingredient.add_to_claim(&mut claim, self.redactions.clone())?;
        }

        // add a claim_generator_hint for the version of the library used to create the claim
        let lib_hint = format!("\"{}\";v=\"{}\"", crate::NAME, crate::VERSION);
        claim.add_claim_generator_hint(GH_UA, Value::from(lib_hint));

        let salt = DefaultSalt::default();

        // add any additional assertions
        for assertion in &self.assertions {
            match assertion.label() {
                Actions::LABEL => {
                    let actions: Actions = assertion.to_assertion()?;
                    // todo: fixup parameters field from instance_id to ingredient uri for
                    // c2pa.transcoded, c2pa.repackaged, and c2pa.placed action
                    claim.add_assertion(&actions)
                }
                CreativeWork::LABEL => {
                    let mut cw: CreativeWork = assertion.to_assertion()?;
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
                _ => match assertion.kind() {
                    ManifestAssertionKind::Cbor => claim.add_assertion_with_salt(
                        &UserCbor::new(assertion.label(), serde_cbor::to_vec(&assertion.data())?),
                        &salt,
                    ),
                    ManifestAssertionKind::Json => claim.add_assertion_with_salt(
                        &User::new(
                            assertion.label(),
                            &serde_json::to_string(&assertion.data())?,
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

        // commit the claim
        let mut store = Store::new();
        let _provenance = store.commit_claim(claim)?;

        Ok(store)
    }

    /// Embed a signed manifest into the target file using a supplied signer
    #[cfg(feature = "file_io")]
    pub fn embed(
        &mut self,
        source_path: &Path,
        dest_path: &Path,
        signer: &dyn Signer,
    ) -> Result<Store> {
        if !source_path.exists() {
            let path = source_path.to_string_lossy().into_owned();
            return Err(Error::FileNotFound(path));
        }
        // we need to copy the source to target before setting the asset info
        if !dest_path.exists() {
            std::fs::copy(&source_path, &dest_path)?;
        }
        // first add the information about the target file
        self.set_asset_from_path(dest_path);
        // convert the manifest to a store
        let mut store = self.to_store()?;
        // sign and write our store to to the output image file
        store.save_to_asset(source_path, signer, dest_path.as_ref())?;

        // todo: update xmp
        Ok(store)
    }

    /// Embed a signed manifest into the target file using a supplied async signer
    #[cfg(feature = "file_io")]
    #[cfg(feature = "async_signer")]
    pub async fn embed_async<P: AsRef<Path>>(
        &mut self,
        target_path: &P,
        signer: &dyn crate::signer::AsyncSigner,
    ) -> Result<Store> {
        // first add the information about the target file
        self.set_asset_from_path(target_path);
        // convert the manifest to a store
        let mut store = self.to_store()?;
        // sign and write our store to to the output image file
        store
            .save_to_asset_async(target_path.as_ref(), signer, target_path.as_ref())
            .await?;

        // todo: update xmp
        Ok(store)
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

    use crate::{
        assertions::{c2pa_action, Action, Actions},
        utils::test::TEST_VC,
        Manifest, Result,
    };

    #[cfg(feature = "file_io")]
    use crate::{
        openssl::temp_signer::get_signer,
        status_tracker::{DetailedStatusTracker, StatusTracker},
        store::Store,
        utils::test::{fixture_path, temp_dir_path, temp_fixture_path, TEST_SMALL_JPEG},
        Ingredient,
    };

    #[cfg(feature = "file_io")]
    use tempfile::tempdir;

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
        let (signer, _) = get_signer(&dir.path());

        let _store = manifest
            .embed(&source_path, &test_output, &signer)
            .expect("embed");

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
        std::fs::copy(&ap, &test_output).expect("copy");

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
        use crate::assertions::UserCbor;
        use crate::Manifest;
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

        let (signer, _) = get_signer(&temp_dir.path());

        let store1 = manifest.embed(&output, &output, &signer).expect("embed");
        let claim1_label = store1.provenance_label().unwrap();
        let claim = store1.provenance_claim().unwrap();
        assert!(claim.get_claim_assertion(ASSERTION_LABEL, 0).is_some()); // verify the assertion is there

        // create a new claim and make the previous file a parent
        let mut manifest2 = test_manifest();
        manifest2
            .set_parent(Ingredient::from_file(&output).expect("from_file"))
            .expect("set_parent");

        // todo: add a test to validate that actions assertions cannot be redacted
        // let mut actions = Actions::new();
        // actions.add_action(Action::new(C2PA_ACTION_EDITED).parameters("gaussian_blur"));
        // ws.add_assertion("c2pa.actions", &actions).expect("add_assertion"); // must use .get() with Actions

        // redact the assertion
        manifest2
            .add_redaction(ASSERTION_LABEL)
            .expect("add_redaction");
        let temp_dir = tempdir().expect("temp dir");

        //embed a claim in output2
        let (signer, _) = get_signer(&temp_dir.path());

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
        assert!(!action2.is_err());
        assert_eq!(action2.unwrap().actions()[0].action(), c2pa_action::EDITED);
    }
}
