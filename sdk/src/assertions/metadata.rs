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

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionJson},
    assertions::labels,
    Error,
};

const ASSERTION_CREATION_VERSION: usize = 1;

/// A `Metadata` assertion provides structured metadata using JSON-LD format for
/// both standardized C2PA metadata and custom metadata schemas.
///
/// This assertion contains a context object defining namespace mappings and a set
///of metadata fields. For `c2pa.metadata` assertions, only specific schemas and fields
/// are allowed as defined in the C2PA specification.
///
/// <https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_metadata_assertions>
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Metadata {
    /// JSON-LD context mapping prefixes to namespace URIs.
    #[serde(rename = "@context")]
    pub context: HashMap<String, String>,
    /// Metadata fields with namespace prefixes.
    #[serde(flatten)]
    pub value: HashMap<String, Value>,

    /// Custom assertion label (not serialized into content).
    #[serde(skip)]
    custom_metadata_label: Option<String>,
}

impl Metadata {
    /// Creates a new metadata assertion from a JSON-LD string.
    pub fn new(metadata_label: &str, jsonld: &str) -> Result<Self, Error> {
        let metadata = serde_json::from_slice::<Metadata>(jsonld.as_bytes())
            .map_err(|e| Error::BadParam(format!("Invalid JSON format: {e}")))?;

        // is this a standard c2pa.metadata assertion or a custom field
        let custom_metadata_label = if metadata_label != labels::METADATA {
            Some(metadata_label.to_owned())
        } else {
            None
        };

        Ok(Self {
            context: metadata.context,
            value: metadata.value,
            custom_metadata_label,
        })
    }

    /// Validates that each field in the assertion has a namespace within the '@context'.
    /// For 'c2pa.metadata' assertions, ensures only allowed fields are present.
    ///
    /// See <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_c2pa_metadata_validation>.
    /// # Returns
    /// * Returns `true` if the metadata assertion passes validation.
    pub fn is_valid(&self) -> bool {
        if self.context.is_empty() {
            return false;
        }

        if self.label() == labels::METADATA {
            for (namespace, uri) in &self.context {
                if let Some(expected_uri) = ALLOWED_SCHEMAS.get(namespace.as_str()) {
                    if uri != expected_uri {
                        // check the backcompat list
                        if let Some(bcl) = BACKCOMPAT_LIST.get(namespace.as_str()) {
                            if !bcl.iter().any(|v| v == uri) {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                }
            }
        }

        for label in self.value.keys() {
            if let Some((prefix, _)) = label.split_once(':') {
                if !self.context.contains_key(prefix) {
                    return false;
                }
            }
            if self.label() == labels::METADATA && !ALLOWED_FIELDS.contains(&label.as_str()) {
                return false;
            }
        }
        true
    }

    /// Get the label for the metadata
    pub fn get_label(&self) -> &str {
        self.label()
    }
}

impl AssertionJson for Metadata {}

impl AssertionBase for Metadata {
    const LABEL: &'static str = labels::METADATA;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    fn label(&self) -> &str {
        match &self.custom_metadata_label {
            Some(cm) => cm,
            None => Self::LABEL,
        }
    }

    fn to_assertion(&self) -> Result<Assertion, Error> {
        Self::to_json_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self, Error> {
        let mut metadata = Self::from_json_assertion(assertion)?;

        metadata.custom_metadata_label =
            (assertion.label() != labels::METADATA).then(|| assertion.label().to_owned());

        Ok(metadata)
    }
}

lazy_static! {
    /// The c2pa.metadata assertion shall only contain certain schemas.
    ///
    /// See <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#metadata_annex>.
    static ref ALLOWED_SCHEMAS: HashMap<&'static str, &'static str> = vec![
        ("xmp", "http://ns.adobe.com/xap/1.0/"),
        ("xmpMM", "http://ns.adobe.com/xap/1.0/mm/"),
        ("xmpTPg", "http://ns.adobe.com/xap/1.0/t/pg/"),
        ("crs", "http://ns.adobe.com/camera-raw-settings/1.0/"),
        ("pdf", "http://ns.adobe.com/pdf/1.3/"),
        ("dc", "http://purl.org/dc/elements/1.1/"),
        ("Iptc4xmpExt", "http://iptc.org/std/Iptc4xmpExt/2008-02-29/"),
        ("exif", "http://ns.adobe.com/exif/1.0/"),
        ("exifEX", "http://cipa.jp/exif/1.0/"),
        ("photoshop", "http://ns.adobe.com/photoshop/1.0/"),
        ("tiff", "http://ns.adobe.com/tiff/1.0/"),
        ("xmpDM", "http://ns.adobe.com/xmp/1.0/DynamicMedia/"),
        ("plus", "http://ns.useplus.org/ldf/xmp/1.0/"),
    ]
    .into_iter()
    .collect();

    // list is to support versions that have changed since the current spec
    static ref BACKCOMPAT_LIST: HashMap<&'static str, Vec<&'static str>> = vec![
        ("exifEX", vec!["http://cipa.jp/exif/1.0/exifEX", "http://cipa.jp/exif/2.32/"])
    ]
    .into_iter()
    .collect();
}

/// The c2pa.metadata assertion shall only contain certain fields.
///
/// See <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#metadata_annex>.
static ALLOWED_FIELDS: [&str; 292] = [
    // xmp:
    "xmp:CreateDate",
    "xmp:CreatorTool",
    "xmp:Identifier",
    "xmp:Label",
    "xmp:MetadataDate",
    "xmp:ModifyDate",
    "xmp:Rating",
    "xmp:BaseURL",
    "xmp:Nickname",
    "xmp:Thumbnails",
    // xmpMM:
    "xmpMM:DerivedFrom",
    "xmpMM:DocumentID",
    "xmpMM:InstanceID",
    "xmpMM:OriginalDocumentID",
    "xmpMM:RenditionClass",
    "xmpMM:RenditionParams",
    "xmpMM:History",
    "xmpMM:Ingredients",
    "xmpMM:Pantry",
    "xmpMM:ManagedFrom",
    "xmpMM:Manager",
    "xmpMM:ManageTo",
    "xmpMM:ManageUI",
    "xmpMM:ManagerVariant",
    "xmpMM:VersionID",
    "xmpMM:Versions",
    // xmpTPg:
    "xmpTPg:Colorants",
    "xmpTPg:Fonts",
    "xmpTPg:MaxPageSize",
    "xmpTPg:NPages",
    "xmpTPg:PlateNames",
    // crs:
    "crs:AutoBrightness",
    "crs:AutoContrast",
    "crs:AutoExposure",
    "crs:AutoShadows",
    "crs:BlueHue",
    "crs:BlueSaturation",
    "crs:Brightness",
    "crs:CameraProfile",
    "crs:ChromaticAberrationB",
    "crs:ChromaticAberrationR",
    "crs:ColorNoiseReduction",
    "crs:Contrast",
    "crs:CropTop",
    "crs:CropLeft",
    "crs:CropBottom",
    "crs:CropRight",
    "crs:CropAngle",
    "crs:CropWidth",
    "crs:CropHeight",
    "crs:CropUnits",
    "crs:Exposure",
    "crs:GreenHue",
    "crs:GreenSaturation",
    "crs:HasCrop",
    "crs:HasSettings",
    "crs:LuminanceSmoothing",
    "crs:RawFileName",
    "crs:RedHue",
    "crs:RedSaturation",
    "crs:Saturation",
    "crs:Shadows",
    "crs:ShadowTint",
    "crs:Sharpness",
    "crs:Temperature",
    "crs:Tint",
    "crs:ToneCurve",
    "crs:ToneCurveName",
    "crs:Version",
    "crs:VignetteAmount",
    "crs:VignetteMidpoint",
    "crs:WhiteBalance",
    // pdf:
    "pdf:Keywords",
    "pdf:PDFVersion",
    "pdf:Producer",
    "pdf:Trapped",
    // dc:
    "dc:coverage",
    "dc:date",
    "dc:format",
    "dc:identifier",
    "dc:language",
    "dc:relation",
    "dc:type",
    // Iptc4xmpExt:
    "Iptc4xmpExt:DigImageGUID",
    "Iptc4xmpExt:DigitalSourceType",
    "Iptc4xmpExt:EventId",
    "Iptc4xmpExt:Genre",
    "Iptc4xmpExt:ImageRating",
    "Iptc4xmpExt:ImageRegion",
    "Iptc4xmpExt:RegistryId",
    "Iptc4xmpExt:LocationCreated",
    "Iptc4xmpExt:LocationShown",
    "Iptc4xmpExt:MaxAvailHeight",
    "Iptc4xmpExt:MaxAvailWidth",
    // exif:
    "exif:ApertureValue",
    "exif:BrightnessValue",
    "exif:CFAPattern",
    "exif:ColorSpace",
    "exif:CompressedBitsPerPixel",
    "exif:Contrast",
    "exif:CustomRendered",
    "exif:DateTimeDigitized",
    "exif:DateTimeOriginal",
    "exif:DeviceSettingDescription",
    "exif:DigitalZoomRatio",
    "exif:ExifVersion",
    "exif:ExposureBiasValue",
    "exif:ExposureIndex",
    "exif:ExposureMode",
    "exif:ExposureProgram",
    "exif:ExposureTime",
    "exif:FileSource",
    "exif:Flash",
    "exif:FlashEnergy",
    "exif:FlashpixVersion",
    "exif:FNumber",
    "exif:FocalLength",
    "exif:FocalLengthIn35mmFilm",
    "exif:FocalPlaneResolutionUnit",
    "exif:FocalPlaneXResolution",
    "exif:FocalPlaneYResolution",
    "exif:GainControl",
    "exif:ImageUniqueID",
    "exif:ISOSpeedRatings",
    "exif:LightSource",
    "exif:MaxApertureValue",
    "exif:MeteringMode",
    "exif:OECF",
    "exif:OffsetTimeOriginal",
    "exif:PixelXDimension",
    "exif:PixelYDimension",
    "exif:RelatedSoundFile",
    "exif:Saturation",
    "exif:SceneCaptureType",
    "exif:SceneType",
    "exif:SensingMethod",
    "exif:Sharpness",
    "exif:ShutterSpeedValue",
    "exif:SpatialFrequencyResponse",
    "exif:SpectralSensitivity",
    "exif:SubjectArea",
    "exif:SubjectDistance",
    "exif:SubjectDistanceRange",
    "exif:SubjectLocation",
    "exif:WhiteBalance",
    "exif:GPSAltitude",
    "exif:GPSAltitudeRef",
    "exif:GPSDateStamp",
    "exif:GPSDestBearing",
    "exif:GPSDestBearingRef",
    "exif:GPSDestDistance",
    "exif:GPSDestDistanceRef",
    "exif:GPSDestLatitude",
    "exif:GPSDestLongitude",
    "exif:GPSDifferential",
    "exif:GPSDOP",
    "exif:GPSHPositioningError",
    "exif:GPSImgDirection",
    "exif:GPSImgDirectionRef",
    "exif:GPSLatitude",
    "exif:GPSLongitude",
    "exif:GPSMapDatum",
    "exif:GPSMeasureMode",
    "exif:GPSProcessingMethod",
    "exif:GPSSatellites",
    "exif:GPSSpeed",
    "exif:GPSSpeedRef",
    "exif:GPSStatus",
    "exif:GPSTimeStamp",
    "exif:GPSTrack",
    "exif:GPSTrackRef",
    "exif:GPSVersionID",
    // exifEX:
    "exifEX:BodySerialNumber",
    "exifEX:Gamma",
    "exifEX:InteroperabilityIndex",
    "exifEX:ISOSpeed",
    "exifEX:ISOSpeedLatitudeyyy",
    "exifEX:ISOSpeedLatitudezzz",
    "exifEX:LensMake",
    "exifEX:LensModel",
    "exifEX:LensSerialNumber",
    "exifEX:LensSpecification",
    "exifEX:PhotographicSensitivity",
    "exifEX:RecommendedExposureIndex",
    "exifEX:SensitivityType",
    "exifEX:StandardOutput-Sensitivity",
    // photoshop:
    "photoshop:Category",
    "photoshop:City",
    "photoshop:ColorMode",
    "photoshop:Country",
    "photoshop:DateCreated",
    "photoshop:DocumentAncestors",
    "photoshop:History",
    "photoshop:ICCProfile",
    "photoshop:State",
    "photoshop:SupplementalCategories",
    "photoshop:TextLayers",
    "photoshop:TransmissionReference",
    "photoshop:Urgency",
    // tiff:
    "tiff:BitsPerSample",
    "tiff:Compression",
    "tiff:DateTime",
    "tiff:ImageLength",
    "tiff:ImageWidth",
    "tiff:Make",
    "tiff:Model",
    "tiff:Orientation",
    "tiff:PhotometricInterpretation",
    "tiff:PlanarConfiguration",
    "tiff:PrimaryChromaticities",
    "tiff:ReferenceBlackWhite",
    "tiff:ResolutionUnit",
    "tiff:SamplesPerPixel",
    "tiff:Software",
    "tiff:TransferFunction",
    "tiff:WhitePoint",
    "tiff:XResolution",
    "tiff:YResolution",
    "tiff:YCbCrCoefficients",
    "tiff:YCbCrPositioning",
    "tiff:YCbCrSubSampling",
    // xmpDM:
    "xmpDM:absPeakAudioFilePath",
    "xmpDM:album",
    "xmpDM:altTapeName",
    "xmpDM:altTimecode",
    "xmpDM:audioChannelType",
    "xmpDM:audioCompressor",
    "xmpDM:audioSampleRate",
    "xmpDM:audioSampleType",
    "xmpDM:beatSpliceParams",
    "xmpDM:cameraAngle",
    "xmpDM:cameraLabel",
    "xmpDM:cameraModel",
    "xmpDM:cameraMove",
    "xmpDM:comment",
    "xmpDM:contributedMedia",
    "xmpDM:duration",
    "xmpDM:fileDataRate",
    "xmpDM:genre",
    "xmpDM:good",
    "xmpDM:instrument",
    "xmpDM:introTime",
    "xmpDM:key",
    "xmpDM:logComment",
    "xmpDM:loop",
    "xmpDM:numberOfBeats",
    "xmpDM:markers",
    "xmpDM:outCue",
    "xmpDM:projectName",
    "xmpDM:projectRef",
    "xmpDM:pullDown",
    "xmpDM:relativePeakAudioFilePath",
    "xmpDM:relativeTimestamp",
    "xmpDM:releaseDate",
    "xmpDM:resampleParams",
    "xmpDM:scaleType",
    "xmpDM:scene",
    "xmpDM:shotDate",
    "xmpDM:shotDay",
    "xmpDM:shotLocation",
    "xmpDM:shotName",
    "xmpDM:shotNumber",
    "xmpDM:shotSize",
    "xmpDM:speakerPlacement",
    "xmpDM:startTimecode",
    "xmpDM:stretchMode",
    "xmpDM:takeNumber",
    "xmpDM:tapeName",
    "xmpDM:tempo",
    "xmpDM:timeScaleParams",
    "xmpDM:timeSignature",
    "xmpDM:trackNumber",
    "xmpDM:Tracks",
    "xmpDM:videoAlphaMode",
    "xmpDM:videoAlphaPremultipleColor",
    "xmpDM:videoAlphaUnityIsTransparent",
    "xmpDM:videoColorSpace",
    "xmpDM:videoCompressor",
    "xmpDM:videoFieldOrder",
    "xmpDM:videoFrameRate",
    "xmpDM:videoFrameSize",
    "xmpDM:videoPixelAspectRatio",
    "xmpDM:videoPixelDepth",
    "xmpDM:partOfCompilation",
    "xmpDM:lyrics",
    "xmpDM:discNumber",
    // plus:
    "plus:FileNameAsDelivered",
    "plus:FirstPublicationDate",
    "plus:ImageFileFormatAsDelivered",
    "plus:ImageFileSizeAsDelivered",
    "plus:ImageType",
    "plus:Version",
];

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use crate::{
        assertion::AssertionBase,
        assertions::{
            labels::{CAWG_METADATA, METADATA},
            metadata::Metadata,
        },
    };

    const SPEC_EXAMPLE: &str = r#"{
        "@context" : {
            "exif": "http://ns.adobe.com/exif/1.0/",
            "exifEX": "http://cipa.jp/exif/1.0/",
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

    const CAWG_METADATA_EXAMPLE: &str = r#" {
        "@context" : {
            "dc" : "http://purl.org/dc/elements/1.1/"
        },
        "dc:created": "2025 August 13", 
        "dc:creator": [
             "John Doe"
        ]
        }
        "#;

    const CUSTOM_METADATA: &str = r#" {
        "@context" : {
            "bar": "http://foo.com/bar/1.0/"
        },
        "bar:baz" : "foo"
        }
        "#;

    const MISSING_CONTEXT: &str = r#" {
        "@context" : {
            "exif": "http://ns.adobe.com/exif/1.0/"
        },
        "exif:GPSVersionID": "2.2.0.0",
        "exif:GPSLatitude": "39,21.102N",
        "exif:GPSLongitude": "74,26.5737W",
        "tiff:Make": "CameraCompany",
        "tiff:Model": "Shooter S1"
        }
        "#;
    const EMPTY_CONTEXT: &str = r#" {
        "@context" : {
        }
        }
        "#;

    const MISMATCH_URI: &str = r#" {
        "@context" : {
            "exif": "http://ns.adobe.com/exif/10.0/"
        },
        "exif:GPSVersionID": "2.2.0.0",
        "exif:GPSLatitude": "39,21.102N",
        "exif:GPSLongitude": "74,26.5737W"
        }
        "#;

    const BACKCOMPAT: &str = r#" {
        "@context" : {
            "exif": "http://ns.adobe.com/exif/1.0/",
            "exifEX": "http://cipa.jp/exif/2.32/",
            "tiff": "http://ns.adobe.com/tiff/1.0/",
            "Iptc4xmpExt": "http://iptc.org/std/Iptc4xmpExt/2008-02-29/",
            "photoshop" : "http://ns.adobe.com/photoshop/1.0/"
        },
        "photoshop:DateCreated": "Aug 31, 2022",
        "Iptc4xmpExt:DigitalSourceType": "https://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",
        "exif:GPSVersionID": "2.2.0.0",
        "exif:GPSLatitude": "39,21.102N",
        "exif:GPSLongitude": "74,26.5737W",
        "exif:GPSAltitudeRef": 0,
        "exif:GPSAltitude": "100963/29890",
        "exifEX:LensSpecification": { "@list": [ 1.55, 4.2, 1.6, 2.4 ] }
    }
    "#;

    #[test]
    fn metadata_from_json() {
        let metadata = Metadata::new(METADATA, SPEC_EXAMPLE).unwrap();
        assert!(metadata.is_valid());
    }

    #[test]
    fn assertion_round_trip() {
        let metadata = Metadata::new(METADATA, SPEC_EXAMPLE).unwrap();
        let assertion = metadata.to_assertion().unwrap();
        let result = Metadata::from_assertion(&assertion).unwrap();
        assert_eq!(metadata, result);
    }

    #[test]
    fn backcompat() {
        let metadata = Metadata::new(METADATA, BACKCOMPAT).unwrap();
        assert!(metadata.is_valid());
    }

    #[test]
    fn assertion_custom_round_trip() {
        let metadata = Metadata::new("custom.metadata", CUSTOM_METADATA).unwrap();
        let assertion = metadata.to_assertion().unwrap();
        let result = Metadata::from_assertion(&assertion).unwrap();
        assert_eq!(metadata, result);
    }

    #[test]
    fn test_custom_validation() {
        let mut metadata = Metadata::new("custom.metadata", CUSTOM_METADATA).unwrap();
        assert!(metadata.is_valid());
        // c2pa.metadata has restrictions on fields
        metadata.custom_metadata_label = Some(METADATA.to_owned());
        assert!(!metadata.is_valid());
    }

    #[test]
    fn test_cawg_metadata() {
        let metadata = Metadata::new(CAWG_METADATA, CAWG_METADATA_EXAMPLE).unwrap();
        assert!(metadata.is_valid());
    }

    #[test]
    fn test_field_not_in_context() {
        let mut metadata = Metadata::new("custom.metadata", MISSING_CONTEXT).unwrap();
        assert!(!metadata.is_valid());
        metadata.custom_metadata_label = Some(METADATA.to_owned());
        assert!(!metadata.is_valid());
    }

    #[test]
    fn test_uri_is_not_allowed() {
        let mut metadata = Metadata::new(METADATA, MISMATCH_URI).unwrap();
        assert!(!metadata.is_valid());
        // custom metadata does not have restriction on uris
        metadata.custom_metadata_label = Some("custom.metadata".to_owned());
        assert!(metadata.is_valid());
    }

    #[test]
    fn test_empty_context() {
        let metadata = Metadata::new(METADATA, EMPTY_CONTEXT).unwrap();
        assert!(!metadata.is_valid());
    }
}
