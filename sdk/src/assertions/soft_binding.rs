use serde::{Deserialize, Serialize};

use super::labels;
use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::region_of_interest::RegionOfInterest,
    cbor_types::UriT,
    Result,
};

const ASSERTION_CREATION_VERSION: usize = 1;

/// The data structure used to store one or more soft bindings across some or all of the asset's content.
///
/// https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#soft_binding_assertion
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
    pub blocks: Vec<SoftBindingBlockMap>,

    /// A human-readable description of what this hash covers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// A string describing parameters of the soft binding algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg_params: Option<String>,

    /// A file or http(s) URL to where the bytes that are being hashed lived.
    ///
    /// This is useful for cases where the data lives in a different file chunk or side-car
    /// than the claim.
    #[deprecated]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<UriT>,

    /// Zero-filled bytes used for filling up space.
    #[serde(with = "serde_bytes")]
    pub pad: Vec<u8>,

    /// Zero-filled bytes used for filling up space.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pad2: Option<serde_bytes::ByteBuf>,
}

/// Details about the soft binding, including the referenced value and scope.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SoftBindingBlockMap {
    /// The scope of the soft binding where it is applicable.
    pub scope: SoftBindingScopeMap,

    /// In algorithm specific format, the value of the soft binding computed over this block of digital content.
    pub value: String,
}

/// Soft binding scope, specifying specifically where in an asset the soft binding is applicable.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SoftBindingScopeMap {
    /// In algorithm specific format, the part of the digital content over which the soft binding value has been computed.
    #[deprecated]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extent: Option<String>,

    /// For temporal assets, the timespan in which the soft binding is applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timespan: Option<SoftBindingTimespanMap>,

    /// Region of interest in regard to the soft binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<RegionOfInterest>,
}

/// Soft binding timespan for temporal assets.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SoftBindingTimespanMap {
    /// Start of the time range (as milliseconds from media start) over which the soft binding value has been computed.
    pub start: usize,

    /// End of the time range (as milliseconds from media start) over which the soft binding value has been computed.
    pub end: usize,
}

impl SoftBinding {
    pub const LABEL: &'static str = labels::SOFT_BINDING;
}

impl AssertionBase for SoftBinding {
    const LABEL: &'static str = Self::LABEL;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

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

        let original: SoftBinding = serde_json::from_value(json).unwrap();
        let assertion = original.to_assertion().unwrap();
        let result = SoftBinding::from_assertion(&assertion).unwrap();

        assert_eq!(result, original);
    }
}
