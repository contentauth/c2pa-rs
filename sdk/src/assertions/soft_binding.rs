use serde::{Deserialize, Serialize};

use super::labels;
use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::region_of_interest::RegionOfInterest,
    cbor_types::{DateT, UriT},
    Result,
};

/// Snapshot of the C2PA soft binding algorithm registry.
///
/// Source: <https://github.com/c2pa-org/softbinding-algorithm-list>
///
/// New entries are periodically added to the external registry; update this
/// list to stay current. Last update was on 2024-06-05 of: <https://github.com/c2pa-org/softbinding-algorithm-list/blob/main/softbinding-algorithm-list.json>.
pub(crate) const SOFT_BINDING_ALGS: &[&str] = &[
    "com.digimarc.validate.1",
    "org.atsc.a336",
    "io.iscc.v0",
    "com.adobe.trustmark.Q",
    "com.adobe.trustmark.C",
    "com.adobe.icn.dense",
    "ai.steg.api",
    "ai.trufo.gen1.image",
    "ai.trufo.gen1.image-lite",
    "app.overlai.watermark.1",
    "tv.kinetiq.watercast.48.1",
    "castLabs.watermark.1",
    "com.adobe.trustmark.P",
    "com.imatag.lamark.v1",
    "com.nagra.nexguard.watermark.1",
    "com.mentaport.watermark.1",
    "com.digicaps.fingerprint.1",
    "com.sonicorigin.watermark.1",
    "com.microsoft.invismark.1",
    "com.microsoft.wavmark.1",
    "ai.contentlens.image.basewmk",
    "ai.contentlens.image.ensemblewmk",
    "ai.contentlens.image.customwmk",
    "ai.contentlens.audio.mono",
    "ai.contentlens.audio.stereo",
    "es.lumatrace",
    "com.markany.watermark.1",
    "com.verimatrix.watermark.1",
    "com.writerslogic.zwc-watermark.1",
    "com.aiwatermark.videoseal.1",
    "com.aiwatermark.pixelseal.1",
    "com.aiwatermark.audioseal.1",
    "eu.sasha.softbinding.v1",
    "ai.verda.watermark.image.1",
    "ai.verda.watermark.video.1",
    "ai.verda.watermark.audio.1",
    "com.evixar.eaw.1",
    "com.evixar.efp.type3.1",
    "com.cognitive-proof.vsrmark.1",
    "me.deepmark.audio.vigil.128",
    "com.writerslogic.text-fingerprint.1",
    "com.writerslogic.zwc-watermark.2",
    "com.writerslogic.text-structure.1",
    "com.writerslogic.text-minhash.1",
];

/// The data structure used to store one or more soft bindings across some or all of the asset's content.
///
/// See [Soft binding assertion - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#soft_binding_assertion).
#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct SoftBinding {
    /// A string identifying the soft binding algorithm and version of that algorithm used to compute the value,
    /// taken from the [C2PA soft binding algorithm list](https://github.com/c2pa-org/softbinding-algorithm-list).
    ///
    /// If this field is absent, the algorithm is taken from the `alg_soft` value of the enclosing structure.
    /// If both are present, the field in this structure is used. If no value is present in any of these places,
    /// this structure is invalid; there is no default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// A list of details about the soft binding.
    pub blocks: Vec<SoftBindingBlock>,

    /// A human-readable description of what this hash covers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// A string describing parameters of the soft binding algorithm.
    #[serde(rename = "alg-params", skip_serializing_if = "Option::is_none")]
    pub alg_params: Option<serde_bytes::ByteBuf>,

    #[serde(default, with = "serde_bytes")]
    pad: Vec<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pad2: Option<serde_bytes::ByteBuf>,

    #[serde(skip_serializing)]
    url: Option<UriT>,
}

#[allow(unused)]
impl SoftBinding {
    /// A file or http(s) URL to where the bytes that are being hashed lived.
    ///
    /// This is useful for cases where the data lives in a different file chunk or side-car
    /// than the claim.
    #[deprecated = "deprecated in c2pa v1.3, use the asset reference assertion instead"]
    pub fn url(&self) -> Option<&UriT> {
        self.url.as_ref()
    }

    /// Zero-filled bytes used for filling up space.
    ///
    /// This field is not applicable to `c2pa-rs` as it employs a single step processing approach to precompute assertion sizes, unlike the
    /// "[Multiple Step Processing](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_multiple_step_processing)"
    /// approach described by the spec.
    pub fn pad(&self) -> &[u8] {
        &self.pad
    }

    /// Zero-filled bytes used for filling up space.
    ///
    /// See [`SoftBinding::pad`] for more information.
    pub fn pad2(&self) -> Option<&[u8]> {
        self.pad2.as_ref().map(|bytes| bytes.as_slice())
    }
}

/// Details about the soft binding, including the referenced value and scope.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SoftBindingBlock {
    /// The scope of the soft binding where it is applicable.
    pub scope: SoftBindingScope,

    /// In algorithm specific format, the value of the soft binding computed over this block of digital content.
    #[serde(default, with = "serde_bytes")]
    pub value: Vec<u8>,
}

/// Soft binding scope, specifying specifically where in an asset the soft binding is applicable.
#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct SoftBindingScope {
    /// For temporal assets, the timespan in which the soft binding is applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timespan: Option<SoftBindingTimespan>,

    /// Region of interest in regard to the soft binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<RegionOfInterest>,

    #[serde(skip_serializing)]
    #[serde(default, with = "serde_bytes")]
    extent: Option<serde_bytes::ByteBuf>,
}

#[allow(unused)]
impl SoftBindingScope {
    /// In algorithm specific format, the part of the digital content over which the soft binding value has been computed.
    #[deprecated = "deprecated in c2pa v2.1, use the `region` field instead"]
    pub fn extent(&self) -> Option<&[u8]> {
        self.extent.as_ref().map(|b| b.as_slice())
    }
}

/// Soft binding timespan for temporal assets.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SoftBindingTimespan {
    /// Start of the time range (as milliseconds from media start) over which the soft binding value has been computed.
    pub start: u64,

    /// End of the time range (as milliseconds from media start) over which the soft binding value has been computed.
    pub end: u64,
}

// A parsed C2PA soft binding algorithm registry.
// Use this to parse a list of soft binding algorithms from a JSON string and
// to build a list of soft binding algorithms.  Use this function to parse the official C2PA
//soft binding algorithm registry from the JSON file at <https://github.com/c2pa-org/softbinding-algorithm-list/blob/main/softbinding-algorithm-list.json>
// to build a list of soft binding algorithms.  The list can be used to validate soft binding algorithms in C2PA assertions.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(transparent)]
#[allow(unused)]
struct SoftBindingList(pub Vec<SoftBindingAlgorithm>);

#[allow(unused)]
impl SoftBindingList {
    /// Parse a JSON string containing a soft binding algorithm list.
    pub fn from_json_str(json: &str) -> Result<Self> {
        let list: Self = serde_json::from_str(json)?;
        list.validate()?;
        Ok(list)
    }

    fn validate(&self) -> Result<()> {
        for algorithm in &self.0 {
            algorithm.validate()?;
        }
        Ok(())
    }

    /// Returns a list of soft binding algorithms strings from a vector of `SoftBindingAlgorithm` entries using the `alg` field.
    pub fn algorithm_strings(&self) -> Vec<String> {
        self.0.iter().map(|alg| alg.alg.clone()).collect()
    }
}

// A single soft binding algorithm entry.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[allow(unused)]
struct SoftBindingAlgorithm {
    pub identifier: u16,

    #[serde(default)]
    pub deprecated: bool,

    pub alg: String,

    #[serde(rename = "type")]
    pub alg_type: SoftBindingAlgorithmType,

    #[serde(rename = "decodedMediaTypes", skip_serializing_if = "Option::is_none")]
    pub decoded_media_types: Option<Vec<SoftBindingMediaType>>,

    #[serde(rename = "encodedMediaTypes", skip_serializing_if = "Option::is_none")]
    pub encoded_media_types: Option<Vec<String>>,

    #[serde(rename = "entryMetadata")]
    pub entry_metadata: SoftBindingEntryMetadata,

    #[serde(
        rename = "softBindingResolutionApis",
        skip_serializing_if = "Option::is_none"
    )]
    pub soft_binding_resolution_apis: Option<Vec<UriT>>,
}

#[allow(unused)]
impl SoftBindingAlgorithm {
    fn validate(&self) -> Result<()> {
        if self
            .decoded_media_types
            .as_ref()
            .map(Vec::is_empty)
            .unwrap_or(false)
        {
            return Err(crate::error::Error::ValidationRule(
                "decodedMediaTypes must be a non-empty array when present".to_owned(),
            ));
        }

        if self
            .encoded_media_types
            .as_ref()
            .map(Vec::is_empty)
            .unwrap_or(false)
        {
            return Err(crate::error::Error::ValidationRule(
                "encodedMediaTypes must be a non-empty array when present".to_owned(),
            ));
        }

        if self.decoded_media_types.is_none() && self.encoded_media_types.is_none() {
            return Err(crate::error::Error::ValidationRule(
                "soft binding algorithm entry must include decodedMediaTypes or encodedMediaTypes"
                    .to_owned(),
            ));
        }

        if let Some(apis) = &self.soft_binding_resolution_apis {
            if apis.is_empty() {
                return Err(crate::error::Error::ValidationRule(
                    "softBindingResolutionApis must be a non-empty array when present".to_owned(),
                ));
            }
            for api in apis {
                url::Url::parse(api.as_ref()).map_err(|_| {
                    crate::error::Error::ValidationRule(format!(
                        "softBindingResolutionApis contains invalid URI: {}",
                        api.as_ref()
                    ))
                })?;
            }
        }

        self.entry_metadata.validate()
    }
}

/// Metadata for a soft binding algorithm entry.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[allow(unused)]
struct SoftBindingEntryMetadata {
    pub description: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub categories: Option<Vec<String>>,

    #[serde(rename = "dateEntered")]
    pub date_entered: DateT,

    pub contact: String,

    #[serde(rename = "informationalUrl")]
    pub informational_url: UriT,
}

impl SoftBindingEntryMetadata {
    fn validate(&self) -> Result<()> {
        url::Url::parse(self.informational_url.as_ref()).map_err(|_| {
            crate::error::Error::ValidationRule(format!(
                "entryMetadata.informationalUrl is not a valid URI: {}",
                self.informational_url.as_ref()
            ))
        })?;
        Ok(())
    }
}

// The type of soft binding algorithm.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
#[allow(unused)]
enum SoftBindingAlgorithmType {
    Watermark,
    Fingerprint,
}

// Target media types for soft binding algorithms.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
#[allow(unused)]
enum SoftBindingMediaType {
    Application,
    Audio,
    Image,
    Model,
    Text,
    Video,
}

impl SoftBinding {
    pub const LABEL: &'static str = labels::SOFT_BINDING;
}

impl AssertionBase for SoftBinding {
    const LABEL: &'static str = Self::LABEL;

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

impl AssertionCbor for SoftBinding {}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_json_round_trip() {
        let json = serde_json::json!({
            "alg": "phash",
            "pad": [0],
            "url": "http://example.c2pa.org/media.mp4",
            "blocks": [
                {
                    "scope": {
                        "timespan": {
                            "end": 133016,
                            "start": 0,
                        }
                    },
                    "value": "dmFsdWUxCg=="
                },
                {
                    "scope": {
                        "timespan": {
                            "end": 245009,
                            "start": 133017,
                        }
                    },
                    "value": "ZG1Gc2RXVXlDZz09=="
                }
            ]
        });

        let mut original: SoftBinding = serde_json::from_value(json).unwrap();
        let assertion = original.to_assertion().unwrap();
        let result = SoftBinding::from_assertion(&assertion).unwrap();

        // Deprecated fields shouldn't be serialized.
        original.url = None;

        assert_eq!(result, original);
    }

    #[test]
    fn test_soft_binding_list_json_parse() {
        let json = r#"[
            {
                "identifier": 1,
                "alg": "com.example.watermark.alg1",
                "type": "watermark",
                "decodedMediaTypes": ["image"],
                "entryMetadata": {
                    "description": "Example watermarking algorithm",
                    "dateEntered": "2025-01-01T00:00:00Z",
                    "contact": "contact@example.com",
                    "informationalUrl": "https://example.com/softbinding/alg1"
                }
            }
        ]"#;

        let list = SoftBindingList::from_json_str(json).unwrap();
        assert_eq!(list.0.len(), 1);
        let algorithm = &list.0[0];
        assert_eq!(algorithm.identifier, 1);
        assert_eq!(algorithm.alg, "com.example.watermark.alg1");
        assert!(matches!(
            algorithm.alg_type,
            SoftBindingAlgorithmType::Watermark
        ));
        assert_eq!(
            algorithm.decoded_media_types.as_ref().unwrap(),
            &[SoftBindingMediaType::Image]
        );

        // get the algorithm strings
        let alg_strings = list.algorithm_strings();
        assert_eq!(alg_strings, vec!["com.example.watermark.alg1"]);
    }
}
