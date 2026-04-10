// Copyright 2023 Adobe. All rights reserved.
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
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::resource_store::UriOrResource;

mod arc_str_serde {
    use std::{fmt, sync::Arc};

    use serde::{
        de::{Deserializer, Error, Visitor},
        Deserialize, Serializer,
    };

    pub(super) struct ArcStrVisitor;

    impl<'de> Visitor<'de> for ArcStrVisitor {
        type Value = Arc<str>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string")
        }

        fn visit_str<E: Error>(self, v: &str) -> Result<Arc<str>, E> {
            Ok(Arc::from(v))
        }

        fn visit_borrowed_str<E: Error>(self, v: &'de str) -> Result<Arc<str>, E> {
            Ok(Arc::from(v))
        }

        fn visit_string<E: Error>(self, v: String) -> Result<Arc<str>, E> {
            Ok(Arc::from(v))
        }
    }

    pub fn serialize<S: Serializer>(value: &Arc<str>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Arc<str>, D::Error> {
        deserializer.deserialize_str(ArcStrVisitor)
    }

    #[derive(Debug)]
    pub(super) struct ArcStrWrapper(pub Arc<str>);

    impl<'de> Deserialize<'de> for ArcStrWrapper {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            d.deserialize_str(ArcStrVisitor).map(ArcStrWrapper)
        }
    }
}

mod arc_str_opt_serde {
    use std::sync::Arc;

    use serde::{Deserialize, Deserializer, Serializer};

    use super::arc_str_serde::ArcStrWrapper;

    pub fn serialize<S: Serializer>(
        value: &Option<Arc<str>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => serializer.serialize_str(v),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Arc<str>>, D::Error> {
        Option::<ArcStrWrapper>::deserialize(deserializer).map(|opt| opt.map(|w| w.0))
    }
}

/// Description of the claim generator, or the software used in generating the claim.
///
/// String fields are stored as `Arc<str>` so one `ClaimGeneratorInfo` can be shared
/// across threads and builders without re-allocating the backing strings on each
/// clone. This is intended for multi-threaded signing pipelines (batch image
/// signing, per-frame video workflows) where the generator identity is constant
/// for the lifetime of the application.
///
/// This structure is also used for actions softwareAgent.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct ClaimGeneratorInfo {
    /// A human readable string naming the claim_generator
    #[serde(with = "arc_str_serde")]
    #[cfg_attr(feature = "json_schema", schemars(with = "String"))]
    pub name: Arc<str>,
    /// A human readable string of the product's version
    #[serde(
        default,
        with = "arc_str_opt_serde",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "json_schema", schemars(with = "Option<String>"))]
    pub version: Option<Arc<str>>,
    /// hashed URI to the icon (either embedded or remote)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<UriOrResource>,
    /// A human readable string of the OS the claim generator is running on.
    /// CrJSON schema uses `operating_system`; C2PA CBOR may use `schema.org.SoftwareApplication.operatingSystem`.
    #[serde(
        default,
        with = "arc_str_opt_serde",
        alias = "schema.org.SoftwareApplication.operatingSystem",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "json_schema", schemars(with = "Option<String>"))]
    pub operating_system: Option<Arc<str>>,
    // Any other values that are not part of the standard
    #[serde(flatten)]
    pub(crate) other: HashMap<String, Value>,
}

fn interned_defaults() -> &'static (Arc<str>, Arc<str>) {
    static DEFAULTS: OnceLock<(Arc<str>, Arc<str>)> = OnceLock::new();
    DEFAULTS.get_or_init(|| {
        (
            Arc::from(crate::NAME),
            Arc::from(env!("CARGO_PKG_VERSION")),
        )
    })
}

impl Default for ClaimGeneratorInfo {
    fn default() -> Self {
        let (name, version) = interned_defaults();
        Self {
            name: Arc::clone(name),
            version: Some(Arc::clone(version)),
            icon: None,
            operating_system: None,
            other: HashMap::new(),
        }
    }
}

impl ClaimGeneratorInfo {
    pub fn new<S: Into<Arc<str>>>(name: S) -> Self {
        Self {
            name: name.into(),
            version: None,
            icon: None,
            operating_system: None, // todo: decide if we want to fill in this value
            other: HashMap::new(),
        }
    }

    /// Returns the software agent that performed the action.
    pub fn icon(&self) -> Option<&UriOrResource> {
        self.icon.as_ref()
    }

    /// Sets the name of the generator.
    pub fn set_name<S: Into<Arc<str>>>(&mut self, name: S) -> &mut Self {
        self.name = name.into();
        self
    }

    /// Sets the version of the generator.
    pub fn set_version<S: Into<Arc<str>>>(&mut self, version: S) -> &mut Self {
        self.version = Some(version.into());
        self
    }

    /// Sets the icon of the generator.
    pub fn set_icon<S: Into<UriOrResource>>(&mut self, uri_or_resource: S) -> &mut Self {
        self.icon = Some(uri_or_resource.into());
        self
    }

    /// Sets the operating system of the generator.
    pub fn set_operating_system<S: Into<Arc<str>>>(&mut self, os: S) -> &mut Self {
        self.operating_system = Some(os.into());
        self
    }

    /// Adds a new key/value pair to the generator info.
    pub fn insert<K, V>(&mut self, key: K, value: V) -> &Self
    where
        K: Into<String>,
        V: Into<Value>,
    {
        self.other.insert(key.into(), value.into());
        self
    }

    /// Gets additional values by key.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.other.get(key)
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use std::{sync::Arc, thread};

    use super::*;
    use crate::{hashed_uri::HashedUri, resource_store::ResourceRef};

    #[test]
    fn test_resource_ref() {
        let mut g = super::ClaimGeneratorInfo::new("test");
        g.set_version("1.0")
            .set_icon(ResourceRef::new("image/svg", "myicon"));

        let json = serde_json::to_string_pretty(&g).expect("Failed to serialize");
        println!("{json}");

        let result: ClaimGeneratorInfo =
            serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(g, result);
    }

    #[test]
    fn test_hashed_uri() {
        let mut g = super::ClaimGeneratorInfo::new("test");
        g.set_version("1.0").set_icon(HashedUri::new(
            "self#jumbf=c2pa.databoxes.data_box".to_string(),
            None,
            b"hashed",
        ));

        let json = serde_json::to_string_pretty(&g).expect("Failed to serialize");
        println!("{json}");

        let result: ClaimGeneratorInfo =
            serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(g, result);
    }

    #[test]
    fn test_shared_across_threads() {
        let mut with_version = ClaimGeneratorInfo::new("shared_generator");
        with_version.set_version("2.3.1");

        let shared = Arc::new(with_version);
        let expected_name = Arc::clone(&shared.name);
        let expected_version = Arc::clone(shared.version.as_ref().expect("version set above"));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let info = Arc::clone(&shared);
                let expected_name = Arc::clone(&expected_name);
                let expected_version = Arc::clone(&expected_version);
                thread::spawn(move || {
                    let cloned = (*info).clone();
                    assert_eq!(&*cloned.name, "shared_generator");
                    assert_eq!(cloned.version.as_deref(), Some("2.3.1"));
                    assert!(
                        Arc::ptr_eq(&cloned.name, &expected_name),
                        "name should be refcount-shared, not duplicated"
                    );
                    assert!(
                        Arc::ptr_eq(
                            cloned.version.as_ref().expect("version preserved"),
                            &expected_version
                        ),
                        "version should be refcount-shared, not duplicated"
                    );
                })
            })
            .collect();

        for h in handles {
            h.join().expect("worker panicked");
        }
    }

    #[test]
    fn test_roundtrip_byte_stable_json() {
        let mut g = ClaimGeneratorInfo::new("stability_test");
        g.set_version("1.0.0").set_operating_system("linux");

        let first = serde_json::to_vec(&g).expect("serialize");
        let parsed: ClaimGeneratorInfo = serde_json::from_slice(&first).expect("deserialize");
        let second = serde_json::to_vec(&parsed).expect("re-serialize");

        assert_eq!(first, second, "JSON serialization is not byte-stable");
    }

    #[test]
    fn test_roundtrip_byte_stable_cbor() {
        let mut g = ClaimGeneratorInfo::new("stability_test");
        g.set_version("1.0.0").set_operating_system("linux");

        let first = c2pa_cbor::ser::to_vec(&g).expect("cbor serialize");
        let parsed: ClaimGeneratorInfo =
            c2pa_cbor::from_slice(&first).expect("cbor deserialize");
        let second = c2pa_cbor::ser::to_vec(&parsed).expect("cbor re-serialize");

        assert_eq!(first, second, "CBOR serialization is not byte-stable");
        assert_eq!(g, parsed);
    }

    #[test]
    fn test_operating_system_alias_deserialize() {
        let json = r#"{"name":"alias_test","schema.org.SoftwareApplication.operatingSystem":"macos"}"#;
        let parsed: ClaimGeneratorInfo =
            serde_json::from_str(json).expect("deserialize with alias key");
        assert_eq!(parsed.operating_system.as_deref(), Some("macos"));
    }

    #[test]
    fn test_deserialize_missing_optional_fields() {
        let json = r#"{"name":"minimal"}"#;
        let parsed: ClaimGeneratorInfo =
            serde_json::from_str(json).expect("deserialize minimal");
        assert_eq!(&*parsed.name, "minimal");
        assert!(parsed.version.is_none());
        assert!(parsed.operating_system.is_none());
        assert!(parsed.icon.is_none());
        assert!(parsed.other.is_empty());
    }

    #[test]
    fn test_default_memoized() {
        let a = ClaimGeneratorInfo::default();
        let b = ClaimGeneratorInfo::default();
        assert!(Arc::ptr_eq(&a.name, &b.name));
        assert!(Arc::ptr_eq(
            a.version.as_ref().unwrap(),
            b.version.as_ref().unwrap()
        ));
    }
}
