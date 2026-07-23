// Copyright 2026 Adobe. All rights reserved.
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

use std::{collections::HashMap, io::Read};

use asn1_rs::FromDer as _;
use serde::{Deserialize, Serialize};
use x509_parser::prelude::X509Certificate;

// Standard X.509 subject attribute OIDs (RFC 5280 / ITU-T X.520)
const OID_CN: &str = "2.5.4.3";
const OID_O: &str = "2.5.4.10";
const OID_OU: &str = "2.5.4.11";
const OID_C: &str = "2.5.4.6";

/// Distinguished Name fields identifying a product's certificate subject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistinguishedName {
    #[serde(rename = "CN")]
    pub common_name: String,
    #[serde(rename = "O")]
    pub organization: String,
    #[serde(rename = "OU", default)]
    pub organizational_unit: String,
    #[serde(rename = "C")]
    pub country: String,
}

/// Assurance level and attestation methods for a conforming product.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assurance {
    #[serde(rename = "maxAssuranceLevel")]
    pub max_assurance_level: u32,
    #[serde(rename = "attestationMethods", default)]
    pub attestation_methods: Vec<String>,
}

/// Product details for a conforming product entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Product {
    #[serde(rename = "productType")]
    pub product_type: String,
    #[serde(rename = "DN")]
    pub dn: DistinguishedName,
    #[serde(rename = "minVersion", default)]
    pub min_version: String,
    pub assurance: Assurance,
}

/// Media type lists keyed by category (e.g. `"image"`, `"video"`, `"audio"`).
pub type MediaTypeMap = HashMap<String, Vec<String>>;

/// The generate/validate container capabilities of a conforming product.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Containers {
    #[serde(default)]
    pub generate: MediaTypeMap,
    #[serde(default)]
    pub validate: MediaTypeMap,
}

/// Key dates in the lifecycle of a conformance record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceDates {
    pub creation: String,
    pub conformance: String,
    #[serde(rename = "earliestPublicDisclosure")]
    pub earliest_public_disclosure: String,
    #[serde(rename = "lastModification")]
    pub last_modification: String,
}

/// A single entry from the C2PA conforming-products list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformingProduct {
    #[serde(rename = "recordId")]
    pub record_id: String,
    pub applicant: String,
    pub status: String,
    pub product: Product,
    #[serde(rename = "specVersion")]
    pub spec_version: Vec<String>,
    #[serde(rename = "conformanceProgramVersion")]
    pub conformance_program_version: String,
    pub containers: Containers,
    pub dates: ConformanceDates,
}

/// Parses a JSON reader containing the C2PA conforming-products list and returns
/// the entries as a `Vec<ConformingProduct>`.
///
/// The expected input is the top-level JSON array from:
/// <https://github.com/c2pa-org/conformance-public/blob/main/conforming-products/conforming-products-list.json>
///
/// # Errors
/// Returns a `serde_json::Error` if the input is not valid JSON or does not
/// match the expected schema.
#[allow(dead_code)]
pub fn read_conforming_products(reader: impl Read) -> serde_json::Result<Vec<ConformingProduct>> {
    serde_json::from_reader(reader)
}

/// Searches `products` for an entry whose `product.dn` matches the subject
/// Distinguished Name of the DER-encoded X.509 certificate `cert_der`.
///
/// Matching rules:
/// - `CN` and `O` must be present in the certificate and equal the product
///   entry's values (case-sensitive).
/// - `OU`: if the product entry's `OU` is non-empty it must match the value
///   found in the certificate; an empty `OU` in the product entry is treated
///   as "not required".
/// - `C`: same wildcard rule as `OU`.
///
/// Returns `None` if `cert_der` cannot be parsed or no entry matches.
#[allow(dead_code)]
pub fn find_conforming_product_for_cert<'a>(
    cert_der: &[u8],
    products: &'a [ConformingProduct],
) -> Option<&'a ConformingProduct> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;

    let mut cn = String::new();
    let mut o = String::new();
    let mut ou = String::new();
    let mut c = String::new();

    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            let Ok(val) = attr.as_str() else { continue };
            match attr.attr_type().to_string().as_str() {
                OID_CN => cn = val.to_string(),
                OID_O => o = val.to_string(),
                OID_OU => ou = val.to_string(),
                OID_C => c = val.to_string(),
                _ => {}
            }
        }
    }

    products.iter().find(|p| {
        let dn = &p.product.dn;
        p.status == "conformant"
            && dn.common_name == cn
            && dn.organization == o
            && (dn.organizational_unit.is_empty() || dn.organizational_unit == ou)
            && (dn.country.is_empty() || dn.country == c)
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    // ---------------------------------------------------------------------------
    // Test cert builder
    // ---------------------------------------------------------------------------

    /// Builds a minimal self-signed DER certificate with the given subject DN
    /// fields. The cert is valid X.509 DER (properly signed with Ed25519) so
    /// x509_parser can parse it without errors.
    ///
    /// `ou` and `c` may be empty — if so they are omitted from the subject.
    fn make_test_cert_der(cn: &str, o: &str, ou: &str, c: &str) -> Vec<u8> {
        use chrono::Utc;
        use ed25519_dalek::{Signer as _, SigningKey};
        use rasn::types::{Any, BitString, ObjectIdentifier, PrintableString, SetOf};
        use rasn_pkix::{
            AlgorithmIdentifier, AttributeTypeAndValue, Certificate, Name,
            RelativeDistinguishedName, SubjectPublicKeyInfo, TbsCertificate, Time, Validity,
            Version,
        };

        // Deterministic key so tests are reproducible.
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let vk = key.verifying_key();

        let ed_oid = ObjectIdentifier::new(vec![1u32, 3, 101, 112]).unwrap();
        let alg = AlgorithmIdentifier {
            algorithm: ed_oid,
            parameters: None,
        };
        let spki = SubjectPublicKeyInfo {
            algorithm: alg.clone(),
            subject_public_key: BitString::from_slice(vk.as_bytes()),
        };

        let make_rdn = |oid_parts: &[u32], val: &str| -> RelativeDistinguishedName {
            let ps = PrintableString::try_from(val.to_string()).unwrap();
            let v = rasn::der::encode(&ps).unwrap();
            let attr = AttributeTypeAndValue {
                r#type: ObjectIdentifier::new(oid_parts.to_vec()).unwrap(),
                value: Any::new(v),
            };
            let mut set = SetOf::new();
            set.insert(attr);
            RelativeDistinguishedName::from(set)
        };

        let mut rdns = vec![
            make_rdn(&[2, 5, 4, 3], cn), // CN
            make_rdn(&[2, 5, 4, 10], o), // O
        ];
        if !ou.is_empty() {
            rdns.push(make_rdn(&[2, 5, 4, 11], ou)); // OU
        }
        if !c.is_empty() {
            rdns.push(make_rdn(&[2, 5, 4, 6], c)); // C
        }
        let subject = Name::RdnSequence(rdns);

        let now = Utc::now();
        let validity = Validity {
            not_before: Time::Utc(now - chrono::Duration::days(1)),
            not_after: Time::Utc(now + chrono::Duration::days(365)),
        };

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: rasn::types::Integer::from(1i64),
            signature: alg.clone(),
            issuer: subject.clone(),
            validity,
            subject,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };

        let tbs_der = rasn::der::encode(&tbs).unwrap();
        let sig = key.sign(&tbs_der);

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: alg,
            signature_value: BitString::from_slice(sig.to_bytes().as_slice()),
        };

        rasn::der::encode(&cert).unwrap()
    }

    // ---------------------------------------------------------------------------
    // Sample JSON fixture
    // ---------------------------------------------------------------------------

    const SAMPLE: &str = r#"[
      {
        "recordId": "0198a1b2-c3d4-7e5f-a6b7-c8d9e0f1a2b3",
        "applicant": "My Company Inc",
        "status": "conformant",
        "product": {
          "productType": "generatorProduct",
          "DN": { "CN": "MyApplication", "O": "My Company Inc", "OU": "", "C": "US" },
          "minVersion": "68566598",
          "assurance": {
            "maxAssuranceLevel": 2,
            "attestationMethods": ["Android_KeyAttestation"]
          }
        },
        "specVersion": ["2.2"],
        "conformanceProgramVersion": "0.1",
        "containers": {
          "generate": { "image": ["image/jpeg"] },
          "validate": {}
        },
        "dates": {
          "creation": "2025-06-26",
          "conformance": "2025-06-27",
          "earliestPublicDisclosure": "2025-08-21",
          "lastModification": "2025-06-27"
        }
      },
      {
        "recordId": "0199c4d5-e6f7-7a8b-9c0d-e1f2a3b4c5d6",
        "applicant": "My Company Inc",
        "status": "conformant",
        "product": {
          "productType": "generatorProduct",
          "DN": { "CN": "MyService", "O": "My Company Inc", "OU": "MyOrgId", "C": "US" },
          "minVersion": "",
          "assurance": { "maxAssuranceLevel": 1 }
        },
        "specVersion": ["2.2"],
        "conformanceProgramVersion": "0.1",
        "containers": {
          "generate": { "image": ["image/jpeg", "image/png"], "video": ["video/mp4"], "audio": ["audio/wav"] },
          "validate": { "image": ["image/jpeg", "image/png"], "video": ["video/mp4"], "audio": ["audio/wav"] }
        },
        "dates": {
          "creation": "2025-07-18",
          "conformance": "2025-07-22",
          "earliestPublicDisclosure": "2025-08-21",
          "lastModification": "2025-07-22"
        }
      }
    ]"#;

    #[test]
    fn parses_sample_list() {
        let products = read_conforming_products(SAMPLE.as_bytes()).unwrap();
        assert_eq!(products.len(), 2);

        let first = &products[0];
        assert_eq!(first.record_id, "0198a1b2-c3d4-7e5f-a6b7-c8d9e0f1a2b3");
        assert_eq!(first.applicant, "My Company Inc");
        assert_eq!(first.status, "conformant");
        assert_eq!(first.product.product_type, "generatorProduct");
        assert_eq!(first.product.dn.common_name, "MyApplication");
        assert_eq!(first.product.assurance.max_assurance_level, 2);
        assert_eq!(
            first.product.assurance.attestation_methods,
            ["Android_KeyAttestation"]
        );
        assert_eq!(first.spec_version, ["2.2"]);
        assert_eq!(
            first.containers.generate.get("image").unwrap(),
            &["image/jpeg"]
        );
        assert!(first.containers.validate.is_empty());

        let second = &products[1];
        assert_eq!(second.product.assurance.attestation_methods.len(), 0);
        assert_eq!(
            second.containers.generate.get("video").unwrap(),
            &["video/mp4"]
        );
    }

    // ---------------------------------------------------------------------------
    // find_conforming_product_for_cert tests
    // ---------------------------------------------------------------------------

    /// SAMPLE entry 0: CN="MyApplication", O="My Company Inc", OU="" (wildcard), C="US"
    /// SAMPLE entry 1: CN="MyService", O="My Company Inc",
    ///                 OU="MyOrgId", C="US"

    #[test]
    fn find_match_cn_o_only_when_ou_c_wildcarded() {
        // Entry 0 has empty OU so the cert doesn't need to carry an OU.
        // The cert has C="US" which matches, and no OU which is fine because
        // the product's OU is empty.
        let cert = make_test_cert_der("MyApplication", "My Company Inc", "", "US");
        let products: Vec<ConformingProduct> = serde_json::from_str(SAMPLE).unwrap();
        let found = find_conforming_product_for_cert(&cert, &products);
        assert!(found.is_some());
        assert_eq!(
            found.unwrap().record_id,
            "0198a1b2-c3d4-7e5f-a6b7-c8d9e0f1a2b3"
        );
    }

    #[test]
    fn find_match_with_all_four_dn_fields() {
        // Entry 1 requires OU="MyOrgId".
        let cert = make_test_cert_der("MyService", "My Company Inc", "MyOrgId", "US");
        let products: Vec<ConformingProduct> = serde_json::from_str(SAMPLE).unwrap();
        let found = find_conforming_product_for_cert(&cert, &products);
        assert!(found.is_some());
        assert_eq!(
            found.unwrap().record_id,
            "0199c4d5-e6f7-7a8b-9c0d-e1f2a3b4c5d6"
        );
    }

    #[test]
    fn no_match_wrong_cn() {
        let cert = make_test_cert_der("Unknown Product", "My Company Inc", "", "US");
        let products: Vec<ConformingProduct> = serde_json::from_str(SAMPLE).unwrap();
        assert!(find_conforming_product_for_cert(&cert, &products).is_none());
    }

    #[test]
    fn no_match_wrong_organization() {
        let cert = make_test_cert_der("MyApplication", "Other Corp", "", "US");
        let products: Vec<ConformingProduct> = serde_json::from_str(SAMPLE).unwrap();
        assert!(find_conforming_product_for_cert(&cert, &products).is_none());
    }

    #[test]
    fn no_match_when_required_ou_missing_from_cert() {
        // Entry 1 requires OU="MyOrgId"; a cert without OU must not match.
        let cert = make_test_cert_der(
            "MyService",
            "My Company Inc",
            "", // OU absent from cert
            "US",
        );
        let products: Vec<ConformingProduct> = serde_json::from_str(SAMPLE).unwrap();
        assert!(find_conforming_product_for_cert(&cert, &products).is_none());
    }

    #[test]
    fn no_match_wrong_country() {
        // C="GB" must not match entries that require C="US".
        let cert = make_test_cert_der("MyApplication", "My Company Inc", "", "GB");
        let products: Vec<ConformingProduct> = serde_json::from_str(SAMPLE).unwrap();
        assert!(find_conforming_product_for_cert(&cert, &products).is_none());
    }

    #[test]
    fn no_match_when_status_not_conformant() {
        let cert = make_test_cert_der("MyApplication", "My Company Inc", "", "US");
        // Same DN as entry 0 but with a non-conformant status.
        let json = SAMPLE.replace(
            r#""status": "conformant",
        "product": {
          "productType": "generatorProduct",
          "DN": { "CN": "MyApplication""#,
            r#""status": "revoked",
        "product": {
          "productType": "generatorProduct",
          "DN": { "CN": "MyApplication""#,
        );
        let products: Vec<ConformingProduct> = serde_json::from_str(&json).unwrap();
        assert!(find_conforming_product_for_cert(&cert, &products).is_none());
    }

    #[test]
    fn returns_none_for_invalid_der() {
        let products: Vec<ConformingProduct> = serde_json::from_str(SAMPLE).unwrap();
        assert!(find_conforming_product_for_cert(b"not a cert", &products).is_none());
    }

    #[test]
    fn returns_none_for_empty_product_list() {
        let cert = make_test_cert_der("MyApplication", "My Company Inc", "", "US");
        assert!(find_conforming_product_for_cert(&cert, &[]).is_none());
    }
}
