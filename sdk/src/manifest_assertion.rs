#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize}; //,  Deserializer, Serializer};
use serde_json::Value;

use crate::{
    assertion::{AssertionBase, AssertionDecodeError},
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
enum ManifestData {
    Json(Value),     // { label: String, instance: usize, data: Value },
    Binary(Vec<u8>), // ) { label: String, instance: usize, data: Value },
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
/// A labeled container for an Assertion value in a Manifest
pub struct ManifestAssertion {
    /// An assertion label in reverse domain format
    label: String,
    /// The data of the assertion as Value
    data: ManifestData,
    /// There can be more than one assertion for any label
    #[serde(skip_serializing_if = "Option::is_none")]
    instance: Option<usize>,
    /// The [ManifestAssertionKind] for this assertion (as stored in c2pa content)
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<ManifestAssertionKind>,
}

impl ManifestAssertion {
    /// Create with label and value
    pub fn new(label: String, data: Value) -> Self {
        Self {
            label,
            data: ManifestData::Json(data),
            instance: None,
            kind: None,
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

    /// The data of the assertion as a serde_Json::Value
    /// This will return UnsupportedType if the assertion data is binary
    pub fn value(&self) -> Result<&Value> {
        match &self.data {
            ManifestData::Json(d) => Ok(d),
            ManifestData::Binary(_) => Err(Error::UnsupportedType),
        }
    }

    /// The data of the assertion as u8 binary vector
    /// This will return UnsupportedType if the assertion data is Json/String
    pub fn binary(&self) -> Result<&[u8]> {
        match &self.data {
            ManifestData::Json(_) => Err(Error::UnsupportedType),
            ManifestData::Binary(b) => Ok(b),
        }
    }

    /// The instance number of this assertion
    /// If the same label is used for multiple assertions, incremental instances are added
    /// The first instance is always 1 and increased by 1 per duplicated label
    pub fn instance(&self) -> usize {
        self.instance.unwrap_or(1)
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
    pub fn set_kind(mut self, kind: ManifestAssertionKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Creates a ManifestAssertion with the given label and any serde serializable object
    ///
    /// # Example: Creating a custom assertion from a serde_json object.
    ///
    ///```
    /// # use c2pa::Result;
    /// use c2pa::ManifestAssertion;
    /// use serde_json::json;
    /// # fn main() -> Result<()> {
    /// let value = json!({"my_tag": "Anything I want"});
    /// let _ma = ManifestAssertion::from_labeled_assertion("org.contentauth.foo", &value)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_labeled_assertion<S: Into<String>, T: Serialize>(
        label: S,
        data: &T,
    ) -> Result<Self> {
        Ok(Self::new(
            label.into(),
            serde_json::to_value(data).map_err(|_err| Error::AssertionEncoding)?,
        ))
    }

    /// Creates a ManifestAssertion from an AssertionBase object
    ///
    /// # Example: Creating a custom assertion an Action assertion
    ///
    ///```
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
            serde_json::to_value(data).map_err(|_err| Error::AssertionEncoding)?,
        ))
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

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::assertions::{c2pa_action, Action, Actions};

    #[test]
    fn test_from_labeled() {
        let data = serde_json::json!({"mytag": "mydata"});
        let ma = ManifestAssertion::from_labeled_assertion("org.contentauth.foo", &data)
            .expect("from_labeled_assertion");
        assert_eq!(ma.label(), "org.contentauth.foo");
        assert!(ma.value().is_ok());
    }

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
        let actions2: Actions = ma2.to_assertion().expect("to_assertion");
        let actions3 = ManifestAssertion::from_labeled_assertion("foo".to_owned(), &actions2)
            .expect("from_labeled_assertion");
        assert_eq!(actions3.label(), "foo");
    }
}
