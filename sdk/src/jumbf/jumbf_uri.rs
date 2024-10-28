// Copyright 2024 Adobe. All rights reserved.
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

#![deny(missing_docs)]

// "self#jumbf=/c2pa/contentauth:urn:uuid:e46d3d9f-deaf-46b1-8cff-9dc9cd637f90/c2pa.assertions/c2pa.thumbnail.claim.jpeg"
// "self#jumbf=c2pa.assertions/c2pa.thumbnail.claim.jpeg"
// "self#jumbf=/c2pa/contentauth:urn:uuid:e46d3d9f-deaf-46b1-8cff-9dc9cd637f90/c2pa.signature
// "self#jumbf=c2pa.signature"

use std::{fmt, str::FromStr, convert::TryFrom};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JumbfUriError {
    InvalidScheme,
    InvvalidManifestLabel,
    InvalidSectionLabel,
    InvalidPath,
}

pub enum UriType {
    Manifest,
    Assertion,
    DataBox,
    Credential,
    Signature,
}

impl FromStr for UriType{
    type Err = ();

    fn from_str(input: &str) -> Result<UriType, Self::Err> {
        match input {
            "c2pa.manifest"  => Ok(UriType::Manifest),
            "c2pa.assertions" => Ok(UriType::Assertion),
            "c2pa.databoxes" => Ok(UriType::DataBox),
            "c2pa.credentials" => Ok(UriType::Credential),
            "c2pa.signature" => Ok(UriType::Signature),
            _   => Err(()),
        }
    }
}


#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JumbfUri {
    Manifest(String),
    Assertion(String, String),
    DataBox(String, String),
    Credential(String, String),
    Signature(String),
    RelativeAssertion(String),
    RelativeDataBox(String),
    RelativeCredential(String),
    RelativeSignature,
}

impl JumbfUri {
    pub const JUMBF_PREFIX: &'static str = "self#jumbf";
    pub const C2PA_PREFIX: &'static str = "c2pa";
    pub const C2PA_ASSERTIONS: &'static str = "c2pa.assertions";
    pub const C2PA_CREDENTIALS: &'static str = "c2pa.credentials";
    pub const C2PA_SIGNATURE: &'static str = "c2pa.signature";
    pub const C2PA_DATABOXES: &'static str = "c2pa.databoxes";

    /// Parse a JUMBF URI.
    pub fn parse(uri: &str) -> Result<JumbfUri, JumbfUriError> {
        // first validate the JUMBF URI prefix.
        let uri_parts: Vec<&str> = uri.split('=').collect();
        if uri_parts.len() != 2 || uri_parts[0] != JumbfUri::JUMBF_PREFIX {
            return Err(JumbfUriError::InvalidScheme);
        }
        // now validate the path portion of the URI.
        let parts: Vec<&str> = uri_parts[1].split('/').collect(); // split the path into parts
        let parts_count = parts.len();
        if parts_count < 1 {
            return Err(JumbfUriError::InvalidPath);
        }

        // Check if this is an absolute JUMBF URI.
        if parts_count > 2 && parts[0].len() == 0 && parts[1] == JumbfUri::C2PA_PREFIX {
            let manifest_label = parts[2].to_string(); 
            // todo: Validate the format of the manifest label for spec consistency.
            if parts_count > 3 {
                let section_label = parts[3].to_string();
                let item_label = if parts_count > 4 {Some(parts[4].to_string())} else {None};
                if parts_count > 5 {
                    return Err(JumbfUriError::InvalidPath);
                }
                Ok(match section_label.as_str() {
                    JumbfUri::C2PA_ASSERTIONS => {
                        if let Some(item_label) = item_label {
                            Self::Assertion(manifest_label,item_label)
                        } else {
                            return Err(JumbfUriError::InvalidPath);
                        }
                    }
                    Self::C2PA_DATABOXES => {
                        if let Some(item_label) = item_label {
                            Self::DataBox(manifest_label, item_label)
                        } else {
                            return Err(JumbfUriError::InvalidPath);
                        }
                    }
                    Self::C2PA_CREDENTIALS => {
                        if let Some(item_label) = item_label {
                            Self::Credential(manifest_label, item_label)
                        } else {
                            return Err(JumbfUriError::InvalidPath);
                        }
                    }
                    Self::C2PA_SIGNATURE => {
                        if item_label.is_some() {
                            return Err(JumbfUriError::InvalidPath);
                        }
                        Self::Signature(manifest_label)
                    }
                    _ => return Err(JumbfUriError::InvalidSectionLabel),
                })
            } else {
                Ok(Self::Manifest(manifest_label))
            }
        } else {
            let section_label = parts[0].to_string(); 
            let item_label = if parts_count > 1 {Some(parts[1].to_string())} else {None};
            Ok(match section_label.as_str() {
                JumbfUri::C2PA_ASSERTIONS => {
                    if let Some(item_label) = item_label {
                        Self::RelativeAssertion(item_label)
                    } else {
                        return Err(JumbfUriError::InvalidPath);
                    }
                }
                Self::C2PA_DATABOXES => {
                    if let Some(item_label) = item_label {
                        Self::RelativeDataBox(item_label)
                    } else {
                        return Err(JumbfUriError::InvalidPath);
                    }
                }
                Self::C2PA_CREDENTIALS => {
                    if let Some(item_label) = item_label {
                        Self::RelativeCredential(item_label)
                    } else {
                        return Err(JumbfUriError::InvalidPath);
                    }
                }
                Self::C2PA_SIGNATURE => {
                    if item_label.is_some() {
                        return Err(JumbfUriError::InvalidPath);
                    }
                    Self::RelativeSignature
                }
                _ => return Err(JumbfUriError::InvalidSectionLabel),
            })

        }
    }

    /// Try to parse a Jumbf URI.
    pub fn try_from_uri(uri: &str) -> Result<JumbfUri, JumbfUriError> {
        JumbfUri::parse(uri) 
    }

    /// Create a Jumbf URI from a manifest label.
    pub fn from_manifest<S:Into<String>>(manifest_label: S) -> JumbfUri {
        JumbfUri::Manifest(manifest_label.into())
    }

    /// Create a Jumbf URI from an assertion label.
    pub fn from_assertion<S, T>(manifest_label: S, assertion_label: T) -> JumbfUri 
    where S: Into<String>, T: Into<String> {
        JumbfUri::Assertion(manifest_label.into(), assertion_label.into())
    }

    pub fn from_data_box<S, T>(manifest_label: S, item_label:T) -> JumbfUri 
    where S: Into<String>, T: Into<String> {
        JumbfUri::DataBox(manifest_label.into(), item_label.into())
    }

    pub fn from_credential(manifest_label: &str, item_label: &str) -> JumbfUri {
        JumbfUri::Credential(manifest_label.to_string(), item_label.to_string())
    }

    pub fn from_signature(manifest_label: &str) -> JumbfUri {
        JumbfUri::Signature(manifest_label.to_string())
    }

    pub fn manifest_label(&self) -> Option<&str> {
        match self {
            JumbfUri::Manifest(label) => Some(label.as_str()),
            Self::Assertion(label, _) => Some(label.as_str()),
            Self::DataBox(label, _) => Some(label.as_str()),
            Self::Credential(label, _) => Some(label.as_str()),
            Self::Signature(label) => Some(label.as_str()),
            _ => None,
        }
    }

     pub fn section_label(&self) -> Option<&str> {
        match self {
            JumbfUri::Assertion(_, label) => Some(label.as_str()),
            JumbfUri::DataBox(_, label) => Some(label.as_str()),
            JumbfUri::Credential(_, label) => Some(label.as_str()),
            _ => None,
        }
     }

     pub fn item_label(&self) -> Option<&str> {
        match self {
            JumbfUri::Assertion(_, label) => Some(label.as_str()),
            JumbfUri::DataBox(_, label) => Some(label.as_str()),
            JumbfUri::Credential(_, label) => Some(label.as_str()),
            _ => None,
        }
     }

    pub fn to_uri(&self) -> String {
        self.to_string()
    }

    pub fn to_relative(&self) -> Self {
        match self {
            Self::Assertion(_, item_label) => Self::RelativeAssertion(item_label.to_owned()),
            Self::DataBox(_, item_label) => Self::RelativeDataBox(item_label.to_owned()),
            Self::Credential(_, item_label) => Self::RelativeCredential(item_label.to_owned()),
            Self::Signature(_) => Self::RelativeSignature,
            // Self::Manifest(_) => panic!("Invalid JumbfUri type"),
            _ => self.to_owned()
        }
    }

    pub fn to_absolute<S:Into<String>>(&self, manifest_label: S) -> Self {
        match self {
            Self::RelativeAssertion(item_label) => Self::Assertion(manifest_label.into(), item_label.to_owned()),
            Self::RelativeDataBox(item_label) => Self::DataBox(manifest_label.into(), item_label.to_owned()),
            Self::RelativeCredential(item_label) => Self::Credential(manifest_label.into(), item_label.to_owned()),
            Self::RelativeSignature => Self::Signature(manifest_label.into()),
            _ => self.to_owned()
        }
    }

    pub fn to_relative_uri(&self) -> String {
        self.to_relative().to_string()
    }

    pub fn to_absolute_uri<S:Into<String>>(&self, manifest_label: S) -> String {
        self.to_absolute(manifest_label).to_string()
    }

}

impl TryFrom<&str> for JumbfUri {
    type Error = JumbfUriError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl fmt::Display for JumbfUri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}=", JumbfUri::JUMBF_PREFIX)?;
        match self {
            JumbfUri::Manifest(manifest_label) => {
                write!(f, "/{}/{}", Self::C2PA_PREFIX, manifest_label)?;
            }
            JumbfUri::Assertion(manifest_label, assertion_label) => {
                write!(f, "/{}/{}/{}/{}", JumbfUri::C2PA_PREFIX, manifest_label, Self::C2PA_ASSERTIONS, assertion_label)?;
            }
            JumbfUri::DataBox(manifest_label, databox_label) => {
                write!(f, "/{}/{}/{}/{}", JumbfUri::C2PA_PREFIX, manifest_label, Self::C2PA_DATABOXES, databox_label)?;
            }
            JumbfUri::Credential(manifest_label, credential_label) => {
                write!(f, "/{}/{}/{}/{}", JumbfUri::C2PA_PREFIX, manifest_label, Self::C2PA_CREDENTIALS, credential_label)?;
            }
            JumbfUri::Signature(manifest_label) => {
                write!(f, "/{}/{}", JumbfUri::C2PA_PREFIX, manifest_label)?;
            }
            JumbfUri::RelativeAssertion(assertion_label) => {
                write!(f, "{}/{}", Self::C2PA_ASSERTIONS, assertion_label)?;
            }
            JumbfUri::RelativeDataBox(box_label) => {
                write!(f, "{}/{}", Self::C2PA_DATABOXES, box_label)?;
            }
            JumbfUri::RelativeCredential(section_label) => {
                write!(f, "{}/{}", Self::C2PA_CREDENTIALS, section_label)?;
            }
            JumbfUri::RelativeSignature => {
                write!(f, "{}", JumbfUri::C2PA_SIGNATURE)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_absolute_jumbf_uri() {
        let uri = "self#jumbf=/c2pa/contentauth:urn:uuid:e46d3d9f-deaf-46b1-8cff-9dc9cd637f90/c2pa.assertions/c2pa.thumbnail.claim.jpeg";
        let jumbf_uri = JumbfUri::parse(uri).unwrap();
        assert_eq!(
            jumbf_uri.manifest_label(),
            Some("contentauth:urn:uuid:e46d3d9f-deaf-46b1-8cff-9dc9cd637f90")
        );
        assert_eq!(jumbf_uri.section_label(), Some("c2pa.assertions"));
        assert_eq!(
            jumbf_uri.item_label(),
            Some("c2pa.thumbnail.claim.jpeg")
        );
    }

    #[test]
    fn test_relative_jumbf_uri() {
        let uri = "self#jumbf=c2pa.assertions/c2pa.thumbnail.claim.jpeg";
        let jumbf_uri = JumbfUri::parse(uri).unwrap();
        assert_eq!(jumbf_uri.manifest_label(), None);
        assert_eq!(jumbf_uri.section_label(), Some("c2pa.assertions"));
        assert_eq!(
            jumbf_uri.item_label(),
            Some("c2pa.thumbnail.claim.jpeg")
        );
    }

    #[test]
    fn test_try_from_absolute_jumbf_uri() {
        let uri = "self#jumbf=/c2pa/contentauth:urn:uuid:e46d3d9f-deaf-46b1-8cff-9dc9cd637f90/c2pa.assertions/c2pa.thumbnail.claim.jpeg";
        let jumbf_uri = JumbfUri::try_from(uri).unwrap();
        assert_eq!(
            jumbf_uri.manifest_label(),
            Some("contentauth:urn:uuid:e46d3d9f-deaf-46b1-8cff-9dc9cd637f90")
        );
        assert_eq!(jumbf_uri.section_label(), Some("c2pa.assertions"));
        assert_eq!(
            jumbf_uri.item_label(),
            Some("c2pa.thumbnail.claim.jpeg")
        );
    }

    #[test]
    fn test_display_absolute_jumbf_uri() {
        let uri = "self#jumbf=/c2pa/contentauth:urn:uuid:e46d3d9f-deaf-46b1-8cff-9dc9cd637f90/c2pa.assertions/c2pa.thumbnail.claim.jpeg";
        let jumbf_uri = JumbfUri::try_from(uri).unwrap();
        assert_eq!(jumbf_uri.to_string(), uri);
    }

    #[test]
    fn test_manifest_uri() {
        assert_eq!(
            JumbfUri::from_manifest("acme::urn:uuid::123:456:789").to_uri(),
            "self#jumbf=/c2pa/acme::urn:uuid::123:456:789"
        );
    }

    #[test]
    fn test_assertion_uri() {
        assert_eq!(
        JumbfUri::from_assertion("acme::urn:uuid::123:456:789", "c2pa.thumbnail.claim.jpeg").to_uri(),
        "self#jumbf=/c2pa/acme::urn:uuid::123:456:789/c2pa.assertions/c2pa.thumbnail.claim.jpeg"
    );
    }

    #[test]
    fn test_signature_uri() {
        assert_eq!(
            JumbfUri::from_signature("acme::urn:uuid::123:456:789").to_uri(),
            "self#jumbf=/c2pa/acme::urn:uuid::123:456:789/c2pa.signature"
        );
    }

    #[test]
    fn test_verifiable_credential_uri() {
        assert_eq!(
            JumbfUri::from_credential("acme::urn:uuid::123:456:789", "12315142234@acme.com")
                .to_string(),
            "self#jumbf=/c2pa/acme::urn:uuid::123:456:789/c2pa.credentials/12315142234@acme.com"
        );
    }

    #[test]
    fn test_relative_uri() {
        assert_eq!(
        JumbfUri::try_from("self#jumbf=/c2pa/acme::urn:uuid::123:456:789/c2pa.assertions/c2pa.thumbnail.claim.jpeg").unwrap().to_relative_uri(),
        "self#jumbf=c2pa.assertions/c2pa.thumbnail.claim.jpeg"
    );
    }
}
