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

//! Test-only OCSP helpers: decode and re-encode the bundled "good" fixture and,
//! with the OpenSSL backend, a responder that signs arbitrary response data with an
//! ephemeral key, so tests can produce responses that are fresh, expired or not yet
//! valid relative to the current time.

#![allow(clippy::unwrap_used)]

use rasn_ocsp::{BasicOcspResponse, OcspResponse};
#[cfg(feature = "openssl")]
pub(crate) use responder::TestResponder;

const GOOD_RESPONSE: &[u8] =
    include_bytes!("../../../tests/fixtures/crypto/ocsp/response_good.der");

/// The `response_good.der` fixture's `BasicOcspResponse`, to be modified and re-signed.
pub(crate) fn good_basic_response() -> BasicOcspResponse {
    let response: OcspResponse = rasn::der::decode(GOOD_RESPONSE).unwrap();
    rasn::der::decode(&response.bytes.unwrap().response).unwrap()
}

/// Wraps `basic` in the fixture's `OcspResponse` envelope and encodes it.
pub(crate) fn encode_response(basic: &BasicOcspResponse) -> Vec<u8> {
    let mut response: OcspResponse = rasn::der::decode(GOOD_RESPONSE).unwrap();
    response.bytes.as_mut().unwrap().response = rasn::der::encode(basic).unwrap().into();
    rasn::der::encode(&response).unwrap()
}

#[cfg(feature = "openssl")]
mod responder {
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, Private},
        sign::Signer,
        x509::{
            extension::{
                AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
                SubjectKeyIdentifier,
            },
            X509Builder, X509Name, X509NameBuilder, X509,
        },
    };
    use rasn_ocsp::BasicOcspResponse;

    use super::encode_response;

    // 2020-01-01T00:00:00Z, so certificates are also valid at historical
    // time-stamp times used by tests.
    const NOT_BEFORE_UNIX: i64 = 1_577_836_800;

    pub(crate) struct TestResponder {
        key: PKey<Private>,
        cert: X509,
    }

    fn generate_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    fn name(common_name: &str) -> X509Name {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, common_name)
            .unwrap();
        name.build()
    }

    fn cert_builder(subject: &X509Name, issuer: &X509Name, key: &PKey<Private>) -> X509Builder {
        let mut serial = BigNum::new().unwrap();
        serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(subject).unwrap();
        builder.set_issuer_name(issuer).unwrap();
        builder.set_pubkey(key).unwrap();
        builder
            .set_not_before(&Asn1Time::from_unix(NOT_BEFORE_UNIX as _).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        builder
    }

    impl TestResponder {
        /// Creates a responder whose certificate meets the C2PA end-entity profile
        /// (issued by an ephemeral CA, with an authority key identifier and the OCSP
        /// signing EKU).
        pub(crate) fn new() -> Self {
            let ca_key = generate_key();
            let ca_name = name("C2PA Test OCSP CA");
            let mut ca = cert_builder(&ca_name, &ca_name, &ca_key);
            ca.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            ca.append_extension(KeyUsage::new().critical().key_cert_sign().build().unwrap())
                .unwrap();
            let ski = SubjectKeyIdentifier::new()
                .build(&ca.x509v3_context(None, None))
                .unwrap();
            ca.append_extension(ski).unwrap();
            ca.sign(&ca_key, MessageDigest::sha256()).unwrap();
            let ca = ca.build();

            let key = generate_key();
            let mut builder = cert_builder(&name("C2PA Test OCSP Responder"), &ca_name, &key);
            builder
                .append_extension(BasicConstraints::new().critical().build().unwrap())
                .unwrap();
            builder
                .append_extension(
                    KeyUsage::new()
                        .critical()
                        .digital_signature()
                        .build()
                        .unwrap(),
                )
                .unwrap();
            builder
                .append_extension(
                    ExtendedKeyUsage::new()
                        .critical()
                        .other("1.3.6.1.5.5.7.3.9")
                        .build()
                        .unwrap(),
                )
                .unwrap();
            let aki = AuthorityKeyIdentifier::new()
                .keyid(false)
                .build(&builder.x509v3_context(Some(&ca), None))
                .unwrap();
            builder.append_extension(aki).unwrap();
            builder.sign(&ca_key, MessageDigest::sha256()).unwrap();

            Self {
                key,
                cert: builder.build(),
            }
        }

        /// PEM of the responder certificate, for adding to a trust policy as an
        /// end-entity credential.
        pub(crate) fn cert_pem(&self) -> Vec<u8> {
            self.cert.to_pem().unwrap()
        }

        /// Signs `basic` with this responder, embedding its certificate, and returns
        /// the encoded `OcspResponse`.
        pub(crate) fn sign(&self, mut basic: BasicOcspResponse) -> Vec<u8> {
            basic.certs = Some(vec![
                rasn::der::decode(&self.cert.to_der().unwrap()).unwrap()
            ]);
            // ecdsa-with-SHA256
            basic.signature_algorithm.algorithm = rasn::types::ObjectIdentifier::new_unchecked(
                vec![1, 2, 840, 10045, 4, 3, 2].into(),
            );
            basic.signature_algorithm.parameters = None;

            let mut signer = Signer::new(MessageDigest::sha256(), &self.key).unwrap();
            signer
                .update(&rasn::der::encode(&basic.tbs_response_data).unwrap())
                .unwrap();
            basic.signature = rasn::types::BitString::from_vec(signer.sign_to_vec().unwrap());

            encode_response(&basic)
        }
    }
}
