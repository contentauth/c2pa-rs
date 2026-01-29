use c2pa_cbor::Value as CborValue;
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize}; //,  Deserializer, Serializer};
use serde_json::Value;

use crate::{
    assertion::{AssertionBase, AssertionDecodeError},
    assertions::labels,
    error::{Error, Result},
};

/// Assertions in C2PA can be stored in several formats
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub enum ManifestAssertionKind {
    Cbor,
    Json,
    Binary,
    Uri,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[serde(untagged)]
pub(crate) enum ManifestData {
    Json(Value), // { label: String, instance: usize, data: Value },
    #[cfg_attr(feature = "json_schema", schemars(skip))]
    Cbor(CborValue),
    Binary(Vec<u8>), // ) { label: String, instance: usize, data: Value },
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
/// A labeled container for an Assertion value in a Manifest
pub struct ManifestAssertion {
    /// An assertion label in reverse domain format
    label: String,
    /// The data of the assertion as Value
    pub(crate) data: ManifestData,
    /// There can be more than one assertion for any label
    #[serde(skip_serializing_if = "Option::is_none")]
    instance: Option<usize>,
    /// The [ManifestAssertionKind] for this assertion (as stored in c2pa content)
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<ManifestAssertionKind>,
    /// True if this assertion is attributed to the signer
    /// This maps to a created vs a gathered assertion. (defaults to false)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    created: bool,
}

impl ManifestAssertion {
    /// Create with label and value
    pub fn new(label: String, data: Value) -> Self {
        Self {
            label,
            // Note this means by default, here we get JSON encoding for assertions
            data: ManifestData::Json(data),
            instance: None,
            kind: None,
            created: false,
        }
    }

    /// Create with label and CBOR value (to preserve native encoding
    pub fn new_from_cbor(label: String, data: CborValue) -> Self {
        Self {
            label,
            data: ManifestData::Cbor(data),
            instance: None,
            kind: Some(ManifestAssertionKind::Cbor),
            created: false,
        }
    }

    /// An assertion label in reverse domain format
    pub fn label(&self) -> &str {
        &self.label
    }

    /// An assertion label in reverse domain format with appended instance number
    /// The instance number follows two underscores and is only added when the instance is > 1
    /// This is a c2pa spec internal standard format
    pub fn label_with_instance(&self) -> String {
        match self.instance {
            Some(i) if i > 1 => format!("{}__{}", self.label, i),
            _ => self.label.to_owned(),
        }
    }

    /// Returns true if this assertion is created (as opposed to gathered)
    pub fn created(&self) -> bool {
        self.created
    }

    /// The data of the assertion as a serde_Json::Value
    /// This will return UnsupportedType if the assertion data is binary
    pub fn value(&self) -> Result<&Value> {
        match &self.data {
            ManifestData::Json(d) => Ok(d),
            _ => Err(Error::UnsupportedType),
        }
    }

    /// The data of the assertion as u8 binary vector
    /// This will return UnsupportedType if the assertion data is Json/String
    pub fn binary(&self) -> Result<&[u8]> {
        match &self.data {
            ManifestData::Binary(b) => Ok(b),
            _ => Err(Error::UnsupportedType),
        }
    }

    /// The instance number of this assertion
    /// If the same label is used for multiple assertions, incremental instances are added
    /// The first instance is always 1 and increased by 1 per duplicated label
    pub fn instance(&self) -> usize {
        self.instance.unwrap_or(labels::instance(&self.label))
    }

    /// The ManifestAssertionKind for this assertion
    /// This refers to how the format of the assertion inside a C2PA manifest
    /// The default is ManifestAssertionKind::Cbor
    pub fn kind(&self) -> &ManifestAssertionKind {
        match self.kind.as_ref() {
            Some(kind) => kind,
            None => &ManifestAssertionKind::Cbor,
        }
    }

    /// This can be used to set an instance number, but generally should not be used
    /// Instance numbers will be assigned automatically when the assertions are embedded
    pub(crate) fn set_instance(mut self, instance: usize) -> Self {
        self.instance = if instance > 0 { Some(instance) } else { None };
        self
    }

    /// Allows overriding the default [ManifestAssertionKind] to Json
    /// For assertions like Schema.org that require being stored in Json format
    pub(crate) fn set_kind(mut self, kind: ManifestAssertionKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Allows setting whether this assertion is created (as opposed to gathered)
    pub(crate) fn set_created(mut self, created: bool) -> Self {
        self.created = created;
        self
    }

    /// Creates a ManifestAssertion from an AssertionBase object
    ///
    /// # Example: Creating a custom assertion an Action assertion
    ///
    /// ```
    /// # use c2pa::Result;
    /// use c2pa::{
    ///     assertions::{c2pa_action, Action, Actions},
    ///     ManifestAssertion,
    /// };
    /// # fn main() -> Result<()> {
    /// let actions = Actions::new().add_action(Action::new(c2pa_action::EDITED));
    /// let _ma = ManifestAssertion::from_assertion(&actions)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_assertion<T: Serialize + AssertionBase>(data: &T) -> Result<Self> {
        Ok(Self::new(
          data.label().to_owned(),
          serde_json::to_value(data).map_err(|err| Error::AssertionEncoding(err.to_string()))?,
        ))
    }

    /// Creates a ManifestAssertion from an AssertionBase object, preserving CBOR encoding
    pub fn from_assertion_cbor<T: Serialize + AssertionBase>(data: &T) -> Result<Self> {
        let cbor_value = c2pa_cbor::value::to_value(data)
            .map_err(|err| Error::AssertionEncoding(err.to_string()))?;
        Ok(Self::new_from_cbor(data.label().to_owned(), cbor_value))
    }

    /// Creates an Assertion object from a ManifestAssertion
    ///
    /// # Example: extracting an Actions Assertion
    /// ```
    /// # use c2pa::Result;
    /// use c2pa::{
    ///     assertions::{c2pa_action, Action, Actions},
    ///     ManifestAssertion,
    /// };
    /// # fn main() -> Result<()> {
    /// let actions = Actions::new().add_action(Action::new(c2pa_action::EDITED));
    /// let manifest_assertion = ManifestAssertion::from_assertion(&actions)?;
    ///
    /// let actions: Actions = manifest_assertion.to_assertion()?;
    /// for action in actions.actions {
    ///     println!("{}", action.action());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_assertion<T: DeserializeOwned>(&self) -> Result<T> {
        // First what kind of data we may have stored
        match &self.data {
            ManifestData::Cbor(cbor_value) => {
                // Direct deserialization from CBOR
                c2pa_cbor::from_value(cbor_value.clone()).map_err(|e| {
                    Error::AssertionDecoding(AssertionDecodeError::from_err(
                        self.label.to_owned(),
                        None,
                        "application/cbor".to_owned(),
                        e,
                    ))
                })
            }
            ManifestData::Json(_) => {
                // Check the kind field to determine how to deserialize
                match self.kind() {
                    ManifestAssertionKind::Cbor => {
                        // For CBOR assertions stored as JSON, transcode from JSON back to CBOR
                        // Note this is lossy!
                        let json_value = self.value()?.to_owned();
                        let cbor_bytes = c2pa_cbor::value::to_value(&json_value).map_err(|e| {
                            Error::AssertionDecoding(AssertionDecodeError::from_err(
                                self.label.to_owned(),
                                None,
                                "application/cbor".to_owned(),
                                e,
                            ))
                        })?;
                        c2pa_cbor::from_value(cbor_bytes).map_err(|e| {
                            Error::AssertionDecoding(AssertionDecodeError::from_err(
                                self.label.to_owned(),
                                None,
                                "application/cbor".to_owned(),
                                e,
                            ))
                        })
                    }
                    _ => {
                        // For JSON and other types, use JSON deserialization
                        serde_json::from_value(self.value()?.to_owned()).map_err(|e| {
                            Error::AssertionDecoding(AssertionDecodeError::from_json_err(
                                self.label.to_owned(),
                                None,
                                "application/json".to_owned(),
                                e,
                            ))
                        })
                    }
                }
            }
            ManifestData::Binary(_) => Err(Error::UnsupportedType),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::assertions::{c2pa_action, Action, Actions};

    #[test]
    fn test_manifest_assertion() {
        let actions = Actions::new().add_action(Action::new(c2pa_action::EDITED));
        let value = serde_json::to_value(actions).unwrap();
        let mut ma = ManifestAssertion::new(Actions::LABEL.to_owned(), value);
        assert_eq!(ma.label(), Actions::LABEL);

        ma = ma.set_instance(0);
        assert_eq!(ma.instance, None);
        ma = ma.set_instance(1);
        assert_eq!(ma.instance(), 1);
        ma = ma.set_instance(2);
        assert_eq!(ma.instance(), 2);
        assert_eq!(ma.kind(), &ManifestAssertionKind::Cbor);
        ma = ma.set_kind(ManifestAssertionKind::Json);
        assert_eq!(ma.kind(), &ManifestAssertionKind::Json);

        let actions = Actions::new().add_action(Action::new(c2pa_action::EDITED));
        let ma2 = ManifestAssertion::from_assertion(&actions).expect("from_assertion");
        let _actions2: Actions = ma2.to_assertion().expect("to_assertion");
    }

    /// Test that CBOR newtype structs (like TimeStamp) are deserialized as CBORwhen kind=Cbor is set.
    ///
    /// If CBOR type isn't checked and CBOR isn't used, the test will fail with error:
    /// "invalid type: sequence, expected a map" (likely because somewhere it fell back to JSON deserialization).
    #[test]
    fn test_cbor_newtype_struct_with_hashmap() {
        use crate::assertions::TimeStamp;

        // Create an assertion that needs to be CBOR
        let mut timestamp = TimeStamp::new();
        timestamp.add_timestamp("manifest1", &[1, 2, 3, 4]);
        timestamp.add_timestamp("manifest2", &[5, 6, 7, 8]);

        let cbor_bytes = c2pa_cbor::to_vec(&timestamp).expect("serialize to CBOR");

        // Transcode CBOR to JSON to mimic a roundtrip
        let cbor_value: c2pa_cbor::Value =
            c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize CBOR to Value");
        let json_value =
            serde_json::to_value(&cbor_value).expect("transcode CBOR Value to JSON Value");

        let ma = ManifestAssertion::new("c2pa.time-stamp".to_string(), json_value)
            .set_kind(ManifestAssertionKind::Cbor);

        let deserialized: TimeStamp = ma.to_assertion().expect("deserialize with kind=Cbor");

        // Roundtrip
        assert_eq!(deserialized.get_timestamp("manifest1").unwrap(), &[1, 2, 3, 4]);
        assert_eq!(deserialized.get_timestamp("manifest2").unwrap(), &[5, 6, 7, 8]);
    }

    /// Test that verifies the behavior difference between kind=None and kind=Cbor.
    /// When kind is not explicitly set (None), the code defaults to JSON deserialization.
    /// If the kind is not set when needed, errors like "invalid type: sequence, expected a map" may be observed
    #[test]
    fn test_cbor_assertion_kind_matters() {
        use crate::assertions::Actions;

        let actions = Actions::new().add_action(Action::new(c2pa_action::EDITED));

        // Serialize to CBOR and transcode to JSON (that is what happens internally in ManifestAssertion)
        let cbor_bytes = c2pa_cbor::to_vec(&actions).expect("serialize to CBOR");
        let cbor_value: c2pa_cbor::Value =
            c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize CBOR to Value");
        let json_value = serde_json::to_value(&cbor_value).expect("transcode to JSON Value");

        // No kind...
        let ma_no_kind = ManifestAssertion::new(Actions::LABEL.to_string(), json_value.clone());
        assert_eq!(
            ma_no_kind.kind(),
            &ManifestAssertionKind::Cbor,
            "Default kind for Actions should be Cbor (set by from_assertion)"
        );

        // With kind...
        let ma_with_kind = ManifestAssertion::new(Actions::LABEL.to_string(), json_value)
            .set_kind(ManifestAssertionKind::Cbor);
        assert_eq!(ma_with_kind.kind(), &ManifestAssertionKind::Cbor);

        // The explicit kind makes sure we have correct deserialization semantics too!
        let _actions1: Actions = ma_no_kind
            .to_assertion()
            .expect("Should work with default kind");
        let _actions2: Actions = ma_with_kind
            .to_assertion()
            .expect("Should work with explicit kind=Cbor");
    }

    /// Test that verifies the kind field is preserved through the full cycle
    #[test]
    fn test_kind_field_preservation_roundtrip() {
        use crate::assertions::TimeStamp;

        let mut timestamp = TimeStamp::new();
        timestamp.add_timestamp("test", &[1, 2, 3]);

        let cbor_bytes = c2pa_cbor::to_vec(&timestamp).unwrap();

        // Mimic internal storage behavior for rountrip mimicking
        let cbor_value: c2pa_cbor::Value = c2pa_cbor::from_slice(&cbor_bytes).unwrap();
        let json_value = serde_json::to_value(&cbor_value).unwrap();

        // Create ManifestAssertion with kind=Cbor
        let ma = ManifestAssertion::new("c2pa.time-stamp".to_string(), json_value)
            .set_kind(ManifestAssertionKind::Cbor);

        assert_eq!(ma.kind(), &ManifestAssertionKind::Cbor);

        //Deserialize. If kind is not respected, falls back to JSON and will error with the invalid map/string error
        let result: Result<TimeStamp> = ma.to_assertion();
        assert!(
            result.is_ok(),
            "Should successfully deserialize when kind=Cbor is set"
        );
    }

    /// Test that from_assertion_cbor preserves native CBOR encoding without lossy transcoding
    #[test]
    fn test_from_assertion_cbor_preserves_encoding() {
        use crate::assertions::TimeStamp;

        let mut timestamp = TimeStamp::new();
        timestamp.add_timestamp("manifest1", &[1, 2, 3, 4]);
        timestamp.add_timestamp("manifest2", &[5, 6, 7, 8]);

        // Use the new CBOR-preserving constructor
        let ma = ManifestAssertion::from_assertion_cbor(&timestamp).expect("from_assertion_cbor");

        // Verify it's stored as CBOR, not JSON
        assert!(matches!(ma.data, ManifestData::Cbor(_)));
        assert_eq!(ma.kind(), &ManifestAssertionKind::Cbor);

        // Deserialize should work perfectly without any transcoding
        let deserialized: TimeStamp = ma.to_assertion().expect("to_assertion");

        // Verify data integrity
        assert_eq!(deserialized.get_timestamp("manifest1").unwrap(), &[1, 2, 3, 4]);
        assert_eq!(deserialized.get_timestamp("manifest2").unwrap(), &[5, 6, 7, 8]);
    }
}
