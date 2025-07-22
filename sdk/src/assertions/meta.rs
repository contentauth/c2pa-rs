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

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionJson},
    assertions::labels,
    Error, Result,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct Meta {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    context: Option<Value>,
    #[serde(flatten)]
    pub(crate) value: HashMap<String, Value>,
}

impl Meta {
    pub fn new(json: &str) -> Result<Self> {
        serde_json::from_slice(json.as_bytes()).map_err(Error::JsonError)
    }

    pub fn set_context(mut self, context: Value) -> Self {
        self.context = Some(context);
        self
    }

    pub fn insert<S: Into<String>, T: Serialize>(mut self, key: S, value: T) -> Result<Self> {
        self.value.insert(key.into(), serde_json::to_value(value)?);
        Ok(self)
    }

    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.value
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }
}

impl AssertionJson for Meta {}

impl AssertionBase for Meta {
    const LABEL: &'static str = labels::METADATA;

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

    use crate::{assertions::meta::Meta, Manifest};

    const SPEC_EXAMPLE: &str = r#"{
        "@context" : {
            "exif": "http://ns.adobe.com/exif/1.0/",
            "exifEX": "http://cipa.jp/exif/2.32/",
            "tiff": "http://ns.adobe.com/tiff/1.0/",
            "Iptc4xmpExt": "http://iptc.org/std/Iptc4xmpExt/2008-02-29/",
            "photoshop" : "http://ns.adobe.com/photoshop/1.0/"
        },
        "photoshop:DateCreated": "Aug 31, 2022",
        "Iptc4xmpExt:DigitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",
        "exif:GPSVersionID": "2.2.0.0",
        "exif:GPSLatitude": "39,21.102N",
        "exif:GPSLongitude": "74,26.5737W",
        "exif:GPSAltitudeRef": 0,
        "exif:GPSAltitude": "100963/29890",
        "exif:GPSTimeStamp": "18:22:57",
        "exif:GPSDateStamp": "2019:09:22",
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
    fn metadata_from_json() {
        let mut manifest = Manifest::new("test".to_owned());
        let original = Meta::new(SPEC_EXAMPLE).unwrap();
        manifest.add_assertion(&original);
        println!("{}", manifest);
    }
}
