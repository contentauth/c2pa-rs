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

#![deny(missing_docs)]

//! Labels for JUMBF boxes as defined in C2PA 1.0 Specification.
//!
//! See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_c2pa_box_details>.

/// Label for the C2PA manifest store.
///
/// This value should be used when possible, since it may contain a version suffix
/// when needed to support a future version of the spec.
///
/// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_c2pa_box_details>.
pub const MANIFEST_STORE: &str = "c2pa";

/// Label for the C2PA assertion store box.
///
/// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_c2pa_box_details>.
pub const ASSERTIONS: &str = "c2pa.assertions";

/// Label for the C2PA claim box.
///
/// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_c2pa_box_details>.
pub const CLAIM: &str = "c2pa.claim";

/// Label for the C2PA claim signature box.
///
/// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_c2pa_box_details>.
pub const SIGNATURE: &str = "c2pa.signature";

/// Label for the credentials store box.
///
/// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_credential_storage>.
pub const CREDENTIALS: &str = "c2pa.credentials";

/// Label for the DataBox box.
///
/// See <https://c2pa.org/specifications/specifications/1.3/specs/C2PA_Specification.html#_data_boxes>.
pub const DATABOX: &str = "c2pa.data";

/// Label for the DataBox store box.
///
/// See <https://c2pa.org/specifications/specifications/1.3/specs/C2PA_Specification.html#_data_storage>.
pub const DATABOXES: &str = "c2pa.databoxes";

const JUMBF_PREFIX: &str = "self#jumbf";

// Converts a manifest label to a JUMBF URI.
pub(crate) fn to_manifest_uri(manifest_label: &str) -> String {
    format!("{JUMBF_PREFIX}=/{MANIFEST_STORE}/{manifest_label}")
}

// Converts a manifest label and an assertion label into a JUMBF URI.
pub(crate) fn to_assertion_uri(manifest_label: &str, assertion_label: &str) -> String {
    format!(
        "{}/{}/{}",
        to_manifest_uri(manifest_label),
        ASSERTIONS,
        assertion_label
    )
}

// Converts a manifest label to a JUMBF URI for its signature.
pub(crate) fn to_signature_uri(manifest_label: &str) -> String {
    format!("{}/{}", to_manifest_uri(manifest_label), SIGNATURE)
}

// Converts a manifest label and an assertion label to a JUMBF
// verifiable credential URL.
pub(crate) fn to_verifiable_credential_uri(manifest_label: &str, vc_id: &str) -> String {
    // TO CONSIDER: Does this now belong in jumbf::labels?
    format!(
        "{}/{}/{}",
        to_manifest_uri(manifest_label),
        CREDENTIALS,
        vc_id
    )
}

// Converts a manifest label and a DataBox label to a JUMBF
// HashedURI.
pub(crate) fn to_databox_uri(manifest_label: &str, databox_id: &str) -> String {
    // TO CONSIDER: Does this now belong in jumbf::labels?
    format!(
        "{}/{}/{}",
        to_manifest_uri(manifest_label),
        DATABOXES,
        databox_id
    )
}

// Split off JUMBF prefix.
pub(crate) fn to_normalized_uri(uri: &str) -> String {
    let uri_parts: Vec<&str> = uri.split('=').collect();

    let output = if uri_parts.len() == 1 {
        uri_parts[0].to_string()
    } else {
        uri_parts[1].to_string()
    };

    // Add leading "/" if needed.
    let mut manifest_store_part = MANIFEST_STORE.to_string();
    manifest_store_part.push('/');

    if !output.is_empty() && output.starts_with(&manifest_store_part) {
        format!("{}{}", "/", output)
    } else {
        output
    }
}

// Converts a possibly relative JUMBF URI to an absolute URI to the manifest store.
pub(crate) fn to_absolute_uri(manifest_label: &str, uri: &str) -> String {
    let raw_uri = to_normalized_uri(uri);
    let parts: Vec<&str> = raw_uri.split('/').collect();
    if parts.len() > 2 && parts[1] == MANIFEST_STORE {
        uri.to_string()
    } else {
        format!("{}/{}", to_manifest_uri(manifest_label), raw_uri)
    }
}

// Converts an absolute JUMBF URI to a URI relative to the manifest store.
pub(crate) fn to_relative_uri(uri: &str) -> String {
    let raw_uri = to_normalized_uri(uri);
    let parts: Vec<&str> = raw_uri.split('/').collect();

    if parts.len() > 4 && parts[1] == MANIFEST_STORE {
        format!("{}={}", JUMBF_PREFIX, parts[3..].join("/"))
    } else {
        // Doesn't look like an absolute URI, so we'll return it as-is.
        uri.to_string()
    }
}

// Given a JUMBF URI, return the manifest label contained within it.
pub(crate) fn manifest_label_from_uri(uri: &str) -> Option<String> {
    let raw_uri = to_normalized_uri(uri);
    let parts: Vec<&str> = raw_uri.split('/').collect();
    if parts.len() > 2 && parts[1] == MANIFEST_STORE {
        Some(parts[2].to_string())
    } else {
        None
    }
}

// Extract an assertion label from a JUMBF URI.
pub(crate) fn assertion_label_from_uri(uri: &str) -> Option<String> {
    let raw_uri = to_normalized_uri(uri);
    let parts: Vec<&str> = raw_uri.split('/').collect();
    if parts.len() > 4 && parts[1] == MANIFEST_STORE && parts[3] == ASSERTIONS {
        Some(parts[4].to_string())
    } else if parts[0] == ASSERTIONS {
        Some(parts[1].to_string())
    } else {
        None
    }
}

// Extract the box the label points to.
pub(crate) fn box_name_from_uri(uri: &str) -> Option<String> {
    let raw_uri = to_normalized_uri(uri);
    let parts: Vec<&str> = raw_uri.split('/').collect();

    parts.last().map(|b| b.to_string())
}

// Struct deconstructed manifest label
pub(crate) struct ManifestParts {
    pub guid: String,
    pub is_v1: bool,
    pub vendor: Option<String>,
    pub version: Option<String>,
}

// Given a JUMBF URI, return the manifest parts contained within it.
pub(crate) fn manifest_label_to_parts(uri: &str) -> Option<ManifestParts> {
    if let Some(manifest) = manifest_label_from_uri(uri) {
        let parts: Vec<&str> = manifest.split(":").collect();
        if parts.len() < 3 {
            return None;
        }

        let guid;
        let mut vendor = None;
        let mut version = None;
        let is_v1;

        if parts[0] == "urn" || parts[1] == "urn" {
            if parts[0] == "urn" {
                is_v1 = parts[1] == "uuid";

                guid = parts[2].to_owned();

                if !is_v1 {
                    if parts.len() > 5 {
                        return None;
                    }

                    if parts.len() > 3 && !parts[3].is_empty() {
                        vendor = Some(parts[3].to_owned());
                    }

                    if parts.len() > 4 && !parts[4].is_empty() {
                        version = Some(parts[4].to_owned());
                    }
                }

                return Some(ManifestParts {
                    guid,
                    is_v1,
                    vendor,
                    version,
                });
            } else if parts[2] == "uuid" {
                // this must be a 1.x path to begin with a vendor
                if parts.len() != 4 {
                    return None;
                }

                is_v1 = true;
                vendor = Some(parts[0].to_owned());
                guid = parts[3].to_owned();

                return Some(ManifestParts {
                    guid,
                    is_v1,
                    vendor,
                    version,
                });
            }
        }
    }

    None
}
#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_manifest_uri() {
        assert_eq!(
            to_manifest_uri("acme::urn:uuid::123:456:789"),
            "self#jumbf=/c2pa/acme::urn:uuid::123:456:789"
        );
    }

    #[test]
    fn test_assertion_uri() {
        assert_eq!(
            to_assertion_uri("acme::urn:uuid::123:456:789", "c2pa.thumbnail.claim.jpeg"),
            "self#jumbf=/c2pa/acme::urn:uuid::123:456:789/c2pa.assertions/c2pa.thumbnail.claim.jpeg"
        );
    }

    #[test]
    fn test_signature_uri() {
        assert_eq!(
            to_signature_uri("acme::urn:uuid::123:456:789"),
            "self#jumbf=/c2pa/acme::urn:uuid::123:456:789/c2pa.signature"
        );
    }

    #[test]
    fn test_verifiable_credential_uri() {
        assert_eq!(
            to_verifiable_credential_uri("acme::urn:uuid::123:456:789", "12315142234@acme.com"),
            "self#jumbf=/c2pa/acme::urn:uuid::123:456:789/c2pa.credentials/12315142234@acme.com"
        );
    }

    #[test]
    fn test_relative_uri() {
        assert_eq!(
            to_relative_uri(
                "self#jumbf=/c2pa/acme::urn:uuid::123:456:789/c2pa.assertions/c2pa.thumbnail.claim.jpeg"
            ),
            "self#jumbf=c2pa.assertions/c2pa.thumbnail.claim.jpeg"
        );
    }

    #[test]
    fn test_paths() {
        let manifest = "acme::urn:uuid::123:456:789";
        let assertion = "c2pa.thumbnail.claim.jpeg";
        let empty_uri = "";
        let absolute_uri = to_manifest_uri(manifest);

        let raw_uri = to_normalized_uri(&absolute_uri);

        let raw_uri_no_slash =
            to_normalized_uri(&format!("{JUMBF_PREFIX}={MANIFEST_STORE}/{manifest}"));

        let raw_empty_uri = to_normalized_uri(empty_uri);

        assert_eq!(raw_uri, raw_uri_no_slash);
        assert_eq!(raw_empty_uri, "");

        let manifest_label_from_absolute = manifest_label_from_uri(&absolute_uri);
        let manifest_label_from_nomalized = manifest_label_from_uri(&raw_uri);

        assert_eq!(manifest_label_from_absolute, manifest_label_from_nomalized);

        let assertion_uri = to_assertion_uri(manifest, assertion);

        assert_eq!(
            Some(manifest.to_string()),
            manifest_label_from_uri(&assertion_uri)
        );
        assert_eq!(
            Some(assertion.to_string()),
            assertion_label_from_uri(&assertion_uri)
        );
        assert_eq!(assertion_label_from_uri(&absolute_uri), None);

        let assertion_relative = to_relative_uri(&assertion_uri);

        assert_eq!(
            assertion_relative,
            format!("{JUMBF_PREFIX}={ASSERTIONS}/{assertion}")
        );
        assert_eq!(
            Some(assertion.to_string()),
            assertion_label_from_uri(&assertion_relative)
        );
    }

    #[test]
    fn test_manifest_parts() {
        let l1 = to_manifest_uri("urn:c2pa:F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4");
        let l2 = to_manifest_uri("urn:c2pa:F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4:acme");
        let l3 = to_manifest_uri("urn:c2pa:F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4:acme:2_1");
        let l4 = to_manifest_uri("urn:c2pa:F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4::2_1");
        let l5 = to_manifest_uri("urn:uuid:F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4");
        let l6 = to_manifest_uri("acme:urn:uuid:F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4");
        let l7 = to_manifest_uri("urn:c2pa:F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4:acme:2_1:extra");
        let l8 = to_manifest_uri("acme:urn:uuid:F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4:2_1");

        let l1_mp = manifest_label_to_parts(&l1).unwrap();
        assert_eq!(l1_mp.guid, "F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4");
        assert!(!l1_mp.is_v1);
        assert_eq!(l1_mp.vendor, None);
        assert_eq!(l1_mp.version, None);

        let l2_mp = manifest_label_to_parts(&l2).unwrap();
        assert_eq!(l2_mp.guid, "F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4");
        assert!(!l2_mp.is_v1);
        assert_eq!(l2_mp.vendor, Some("acme".to_owned()));
        assert_eq!(l2_mp.version, None);

        let l3_mp = manifest_label_to_parts(&l3).unwrap();
        assert_eq!(l3_mp.guid, "F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4");
        assert!(!l3_mp.is_v1);
        assert_eq!(l3_mp.vendor, Some("acme".to_owned()));
        assert_eq!(l3_mp.version, Some("2_1".to_owned()));

        let l4_mp = manifest_label_to_parts(&l4).unwrap();
        assert_eq!(l4_mp.guid, "F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4");
        assert!(!l4_mp.is_v1);
        assert_eq!(l4_mp.vendor, None);
        assert_eq!(l4_mp.version, Some("2_1".to_owned()));

        let l5_mp = manifest_label_to_parts(&l5).unwrap();
        assert_eq!(l5_mp.guid, "F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4");
        assert!(l5_mp.is_v1);
        assert_eq!(l5_mp.vendor, None);
        assert_eq!(l5_mp.version, None);

        let l6_mp = manifest_label_to_parts(&l6).unwrap();
        assert_eq!(l6_mp.guid, "F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4");
        assert!(l6_mp.is_v1);
        assert_eq!(l6_mp.vendor, Some("acme".to_owned()));
        assert_eq!(l6_mp.version, None);

        assert!(manifest_label_to_parts(&l7).is_none());

        assert!(manifest_label_to_parts(&l8).is_none());
    }
}
