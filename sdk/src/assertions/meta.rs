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
    Error, Result,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct Meta {
    #[serde(rename = "@context")]
    context: HashMap<String, String>,
    #[serde(flatten)]
    pub(crate) value: HashMap<String, Value>,
}

impl Meta {
    pub fn new(json: &str) -> Result<Self> {
        serde_json::from_slice(json.as_bytes()).map_err(Error::JsonError)
    }

    pub fn is_valid(&self) -> bool {
        for (namespace, url) in &self.context {
            if let Some(expected_url) = SCHEMA_URLS.get(namespace.as_str()) {
                if url != expected_url {return  false}
            }
        }

         for label in self.value.keys() {
                if let Some((prefix, property)) = label.split_once(":") {
                    if let Some(allowed_vals) = ALLOWED_SCHEMAS.get(prefix) {
                        if !allowed_vals.contains(&property) {
                            return false
                        }
                    }
                }
            }
        true
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

lazy_static! {
    static ref SCHEMA_URLS: HashMap<&'static str, &'static str> = vec![
        ("xmp", "http://ns.adobe.com/xap/1.0/"),
        ("xmpMM", "http://ns.adobe.com/xap/1.0/mm/"),
        ("xmpTPg", "http://ns.adobe.com/xap/1.0/t/pg/"),
        ("crs", "http://ns.adobe.com/camera-raw-settings/1.0/"),
        ("pdf", "http://ns.adobe.com/pdf/1.3/"),
        ("dc", "http://purl.org/dc/elements/1.1/"),
        ("Iptc4xmpExt", "http://iptc.org/std/Iptc4xmpExt/2008-02-29/"),
        ("exif", "http://ns.adobe.com/exif/1.0/"),
        ("exifEX", "http://cipa.jp/exif/1.0/exifEX"),
        ("photoshop", "http://ns.adobe.com/photoshop/1.0/"),
        ("tiff", "http://ns.adobe.com/tiff/1.0/"),
        ("xmpDM", "http://ns.adobe.com/xmp/1.0/DynamicMedia/"),
        ("plus", "http://ns.useplus.org/ldf/xmp/1.0/"),
    ]
    .into_iter()
    .collect();
}

lazy_static! {
    static ref ALLOWED_SCHEMAS: HashMap<&'static str, Vec<&'static str>> = vec![
        (
            "xmp",
            vec![
                "CreateDate",
                "CreatorTool",
                "Identifier",
                "Label",
                "MetadataDate",
                "ModifyDate",
                "Rating",
                "BaseURL",
                "Nickname",
                "Thumbnails",
            ]
        ),
        (
            "xmpMM",
            vec![
                "DerivedFrom",
                "DocumentID",
                "InstanceID",
                "OriginalDocumentID",
                "RenditionClass",
                "RenditionParams",
                "History",
                "Ingredients",
                "Pantry",
                "ManagedFrom",
                "Manager",
                "ManageTo",
                "ManageUI",
                "ManagerVariant",
                "VersionID",
                "Versions",
            ]
        ),
        (
            "xmpTPg",
            vec!["Colorants", "Fonts", "MaxPageSize", "NPages", "PlateNames",]
        ),
        (
            "crs",
            vec![
                "AutoBrightness",
                "AutoContrast",
                "AutoExposure",
                "AutoShadows",
                "BlueHue",
                "BlueSaturation",
                "Brightness",
                "CameraProfile",
                "ChromaticAberrationB",
                "ChromaticAberrationR",
                "ColorNoiseReduction",
                "Contrast",
                "CropTop",
                "CropLeft",
                "CropBottom",
                "CropRight",
                "CropAngle",
                "CropWidth",
                "CropHeight",
                "CropUnits",
                "Exposure",
                "GreenHue",
                "GreenSaturation",
                "HasCrop",
                "HasSettings",
                "LuminanceSmoothing",
                "RawFileName",
                "RedHue",
                "RedSaturation",
                "Saturation",
                "Shadows",
                "ShadowTint",
                "Sharpness",
                "Temperature",
                "Tint",
                "ToneCurve",
                "ToneCurveName",
                "Version",
                "VignetteAmount",
                "VignetteMidpoint",
                "WhiteBalance",
            ]
        ),
        (
            "pdf",
            vec!["Keywords", "PDFVersion", "Producer", "Trapped",]
        ),
        (
            "dc",
            vec![
                "coverage",
                "date",
                "format",
                "identifier",
                "language",
                "relation",
                "type",
            ]
        ),
        (
            "Iptc4xmpExt",
            vec![
                "DigImageGUID",
                "DigitalSourceType",
                "EventId",
                "Genre",
                "ImageRating",
                "ImageRegion",
                "RegistryId",
                "LocationCreated",
                "LocationShown",
                "MaxAvailHeight",
                "MaxAvailWidth",
            ]
        ),
        (
            "exif",
            vec![
                "ApertureValue",
                "BrightnessValue",
                "CFAPattern",
                "ColorSpace",
                "CompressedBitsPerPixel",
                "Contrast",
                "CustomRendered",
                "DateTimeDigitized",
                "DateTimeOriginal",
                "DeviceSettingDescription",
                "DigitalZoomRatio",
                "ExifVersion",
                "ExposureBiasValue",
                "ExposureIndex",
                "ExposureMode",
                "ExposureProgram",
                "ExposureTime",
                "FileSource",
                "Flash",
                "FlashEnergy",
                "FlashpixVersion",
                "FNumber",
                "FocalLength",
                "FocalLengthIn35mmFilm",
                "FocalPlaneResolutionUnit",
                "FocalPlaneXResolution",
                "FocalPlaneYResolution",
                "GainControl",
                "ImageUniqueID",
                "ISOSpeedRatings",
                "LightSource",
                "MaxApertureValue",
                "MeteringMode",
                "OECF",
                "OffsetTimeOriginal",
                "PixelXDimension",
                "PixelYDimension",
                "RelatedSoundFile",
                "Saturation",
                "SceneCaptureType",
                "SceneType",
                "SensingMethod",
                "Sharpness",
                "ShutterSpeedValue",
                "SpatialFrequencyResponse",
                "SpectralSensitivity",
                "SubjectArea",
                "SubjectDistance",
                "SubjectDistanceRange",
                "SubjectLocation",
                "WhiteBalance",
                "GPSAltitude",
                "GPSAltitudeRef",
                "GPSDateStamp",
                "GPSDestBearing",
                "GPSDestBearingRef",
                "GPSDestDistance",
                "GPSDestDistanceRef",
                "GPSDestLatitude",
                "GPSDestLongitude",
                "GPSDifferential",
                "GPSDOP",
                "GPSHPositioningError",
                "GPSImgDirection",
                "GPSImgDirectionRef",
                "GPSLatitude",
                "GPSLongitude",
                "GPSMapDatum",
                "GPSMeasureMode",
                "GPSProcessingMethod",
                "GPSSatellites",
                "GPSSpeed",
                "GPSSpeedRef",
                "GPSStatus",
                "GPSTimeStamp",
                "GPSTrack",
                "GPSTrackRef",
                "GPSVersionID",
            ]
        ),
        (
            "exifEX",
            vec![
                "BodySerialNumber",
                "Gamma",
                "InteroperabilityIndex",
                "ISOSpeed",
                "ISOSpeedLatitudeyyy",
                "ISOSpeedLatitudezzz",
                "LensMake",
                "LensModel",
                "LensSerialNumber",
                "LensSpecification",
                "PhotographicSensitivity",
                "RecommendedExposureIndex",
                "SensitivityType",
                "StandardOutput-Sensitivity",
            ]
        ),
        (
            "photoshop",
            vec![
                "Category",
                "City",
                "ColorMode",
                "Country",
                "DateCreated",
                "DocumentAncestors",
                "History",
                "ICCProfile",
                "State",
                "SupplementalCategories",
                "TextLayers",
                "TransmissionReference",
                "Urgency",
            ]
        ),
        (
            "tiff",
            vec![
                "BitsPerSample",
                "Compression",
                "DateTime",
                "ImageLength",
                "ImageWidth",
                "Make",
                "Model",
                "Orientation",
                "PhotometricInterpretation",
                "PlanarConfiguration",
                "PrimaryChromaticities",
                "ReferenceBlackWhite",
                "ResolutionUnit",
                "SamplesPerPixel",
                "Software",
                "TransferFunction",
                "WhitePoint",
                "XResolution",
                "YResolution",
                "YCbCrCoefficients",
                "YCbCrPositioning",
                "YCbCrSubSampling",
            ]
        ),
        (
            "xmpDM",
            vec![
                "absPeakAudioFilePath",
                "album",
                "altTapeName",
                "altTimecode",
                "audioChannelType",
                "audioCompressor",
                "audioSampleRate",
                "audioSampleType",
                "beatSpliceParams",
                "cameraAngle",
                "cameraLabel",
                "cameraModel",
                "cameraMove",
                "comment",
                "contributedMedia",
                "duration",
                "fileDataRate",
                "genre",
                "good",
                "instrument",
                "introTime",
                "key",
                "logComment",
                "loop",
                "numberOfBeats",
                "markers",
                "outCue",
                "projectName",
                "projectRef",
                "pullDown",
                "relativePeakAudioFilePath",
                "relativeTimestamp",
                "releaseDate",
                "resampleParams",
                "scaleType",
                "scene",
                "shotDate",
                "shotDay",
                "shotLocation",
                "shotName",
                "shotNumber",
                "shotSize",
                "speakerPlacement",
                "startTimecode",
                "stretchMode",
                "takeNumber",
                "tapeName",
                "tempo",
                "timeScaleParams",
                "timeSignature",
                "trackNumber",
                "Tracks",
                "videoAlphaMode",
                "videoAlphaPremultipleColor",
                "videoAlphaUnityIsTransparent",
                "videoColorSpace",
                "videoCompressor",
                "videoFieldOrder",
                "videoFrameRate",
                "videoFrameSize",
                "videoPixelAspectRatio",
                "videoPixelDepth",
                "partOfCompilation",
                "lyrics",
                "discNumber",
            ]
        ),
        (
            "plus",
            vec![
                "FileNameAsDelivered",
                "FirstPublicationDate",
                "ImageFileFormatAsDelivered",
                "ImageFileSizeAsDelivered",
                "ImageType",
                "Version",
            ]
        ),
    ]
    .into_iter()
    .collect();
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use crate::{assertions::meta::Meta, Manifest};

    const SPEC_EXAMPLE: &str = r#"{
        "@context" : {
            "exif": "http://ns.adobe.com/exif/1.0/",
            "exifEX": "http://cipa.jp/exif/1.0/exifEX",
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
        assert!(original.is_valid());
        manifest.add_assertion(&original).unwrap();
        println!("{}", manifest);
    }
}
