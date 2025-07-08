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

//! Exif Assertion
use std::collections::HashMap;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    assertion::{Assertion, AssertionBase, AssertionJson},
    assertions::labels,
    Error, Result,
};

/// The EXIF assertion (part of CAWG metadata specification).
///
/// This does not yet define or validate individual fields, but will ensure the correct assertion structure.
// NOTE: Hidden because it's now part of standard metadata assertions.
#[doc(hidden)]
#[derive(Serialize, Deserialize, Debug)]
pub struct Exif {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    object_context: Option<Value>,
    #[serde(flatten)]
    value: HashMap<String, Value>,
}

impl Exif {
    // A label for our assertion, use reverse domain name syntax
    pub const LABEL: &'static str = labels::EXIF;

    pub fn new() -> Self {
        Self {
            object_context: Some(json!({
              "dc": "http://purl.org/dc/elements/1.1/",
              "exifEX": "http://cipa.jp/exif/2.32/",
              "exif": "http://ns.adobe.com/exif/1.0/",
              "tiff": "http://ns.adobe.com/tiff/1.0/",
              "xmp": "http://ns.adobe.com/xap/1.0/",
              "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
            })),
            value: HashMap::new(),
        }
    }

    /// sets the @context field for Schema dot org.
    pub fn set_context(mut self, context: Value) -> Self {
        self.object_context = Some(context);
        self
    }

    /// get values by key as an instance of type `T`.
    /// This return T is owned, not a reference
    /// # Errors
    ///
    /// This conversion can fail if the structure of the field at key does not match the
    /// structure expected by `T`
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.value
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// insert key / value pair of instance of type `T`
    /// # Errors
    ///
    /// This conversion can fail if `T`'s implementation of `Serialize` decides to
    /// fail, or if `T` contains a map with non-string keys.
    pub fn insert<S: Into<String>, T: Serialize>(mut self, key: S, value: T) -> Result<Self> {
        self.value.insert(key.into(), serde_json::to_value(value)?);
        Ok(self)
    }

    // add a value to a Vec stored at key
    pub fn insert_push<S: Into<String>, T: Serialize + DeserializeOwned>(
        self,
        key: S,
        value: T,
    ) -> Result<Self> {
        let key = key.into();
        Ok(match self.get(&key) as Option<Vec<T>> {
            Some(mut v) => {
                v.push(value);
                self
            }
            None => self.insert(&key, Vec::from([value]))?,
        })
    }

    /// creates the struct from a correctly formatted JSON string
    pub fn from_json_str(json: &str) -> Result<Self> {
        serde_json::from_slice(json.as_bytes()).map_err(Error::JsonError)
    }
}

// Implementing default is a good idea
impl Default for Exif {
    fn default() -> Self {
        Self::new()
    }
}

// Implement as AssertionJson
impl AssertionJson for Exif {}

impl AssertionBase for Exif {
    // A label for our assertion, use reverse domain name syntax
    const LABEL: &'static str = labels::EXIF;

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_json_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_json_assertion(assertion)
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::builder::Builder;

    const SPEC_EXAMPLE: &str = r#"{
        "@context" : {
          "dc": "http://purl.org/dc/elements/1.1/",
          "exifEX": "http://cipa.jp/exif/2.32/",
          "exif": "http://ns.adobe.com/exif/1.0/",
          "tiff": "http://ns.adobe.com/tiff/1.0/",
          "xmp": "http://ns.adobe.com/xap/1.0/",
          "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
        },
        "exif:GPSVersionID": "2.2.0.0",
        "exif:GPSLatitude": "39,21.102N",
        "exif:GPSLongitude": "74,26.5737W",
        "exif:GPSAltitudeRef": 0,
        "exif:GPSAltitude": "100963/29890",
        "exif:GPSTimeStamp": "2019-09-22T18:22:57Z",
        "exif:GPSSpeedRef": "K",
        "exif:GPSSpeed": "4009/161323",
        "exif:GPSImgDirectionRef": "T",
        "exif:GPSImgDirection": "296140/911",
        "exif:GPSDestBearingRef": "T",
        "exif:GPSDestBearing": "296140/911",
        "exif:GPSHPositioningError": "13244/2207",
        "exif:ExposureTime": "1/100",
        "exif:FNumber": 4.0,
        "exif:ColorSpace": 1,
        "exif:DigitalZoomRatio": 2.0,
        "tiff:Make": "CameraCompany",
        "tiff:Model": "Shooter S1",
        "exifEX:LensMake": "CameraCompany",
        "exifEX:LensModel": "17.0-35.0 mm",
        "exifEX:LensSpecification": { "@list": [ 1.55, 4.2, 1.6, 2.4 ] }
      }"#;

    #[test]
    fn exif_new() {
        let mut builder = Builder::new();

        let original = Exif::new()
            .insert("exif:GPSLatitude", "39,21.102N")
            .unwrap();
        builder
            .add_assertion(Exif::LABEL, &original)
            .expect("adding assertion");
        let exif: Exif = builder.find_assertion(Exif::LABEL).expect("find_assertion");
        let latitude: String = exif.get("exif:GPSLatitude").unwrap();
        assert_eq!(&latitude, "39,21.102N")
    }

    #[test]
    fn exif_from_json() {
        let mut builder = Builder::new();
        let original = Exif::from_json_str(SPEC_EXAMPLE).expect("from_json");
        builder
            .add_assertion(Exif::LABEL, &original)
            .expect("adding assertion");
        let exif: Exif = builder.find_assertion(Exif::LABEL).expect("find_assertion");
        let latitude: String = exif.get("exif:GPSLatitude").unwrap();
        assert_eq!(&latitude, "39,21.102N")
    }

    #[test]
    fn exif_to_assertion() {
        let original = Exif::from_json_str(SPEC_EXAMPLE).expect("from_json");
        let assertion = original.to_assertion().expect("to_assertion");
        assert_eq!(assertion.content_type(), "application/json");
        let result = Exif::from_assertion(&assertion).expect("from_assertion");
        let latitude: String = result.get("exif:GPSLatitude").unwrap();
        assert_eq!(&latitude, "39,21.102N")
    }
}
