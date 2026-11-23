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

//! Test-only OCSP helpers for signed issuer and delegated responses, with
//! arbitrary response data and validity windows, under either crypto backend.

#![allow(clippy::unwrap_used)]

use der::{
    asn1::{Any, BitString, OctetString},
    Decode, Encode,
};
#[cfg(feature = "openssl")]
pub(crate) use responder::TestResponder;

use crate::crypto::ocsp::asn1::{BasicOcspResponse, ResponderId, Response};

const GOOD_RESPONSE: &[u8] =
    include_bytes!("../../../tests/fixtures/crypto/ocsp/response_good.der");

pub(crate) fn ocsp_time(datetime: chrono::DateTime<chrono::Utc>) -> super::asn1::GeneralizedTime {
    super::asn1::GeneralizedTime::from_der(
        &Any::new(
            der::Tag::GeneralizedTime,
            datetime.format("%Y%m%d%H%M%S%.fZ").to_string().as_bytes(),
        )
        .unwrap()
        .to_der()
        .unwrap(),
    )
    .unwrap()
}

/// The `response_good.der` fixture's `BasicOcspResponse`, to be modified and re-signed.
pub(crate) fn good_basic_response() -> BasicOcspResponse {
    let response = Response::from_der(GOOD_RESPONSE).unwrap();
    BasicOcspResponse::from_der(response.response_bytes.unwrap().response.as_bytes()).unwrap()
}

/// Wraps `basic` in the fixture's `OcspResponse` envelope and encodes it.
pub(crate) fn encode_response(basic: &BasicOcspResponse) -> Vec<u8> {
    let mut response = Response::from_der(GOOD_RESPONSE).unwrap();
    response.response_bytes.as_mut().unwrap().response =
        OctetString::new(basic.to_der().unwrap()).unwrap();
    response.to_der().unwrap()
}

/// Backend-independent issuer-signed responses with a real signed leaf/CA chain.
pub(crate) struct IssuerResponder {
    key: ed25519_dalek::SigningKey,
    pub(crate) chain: Vec<Vec<u8>>,
}

impl IssuerResponder {
    pub(crate) fn new() -> Self {
        use ed25519_dalek::Signer;
        use x509_cert::{
            der::{
                asn1::{BitString, ObjectIdentifier, OctetString},
                Decode as DecodeDer07, Encode as EncodeDer07,
            },
            spki::AlgorithmIdentifierOwned,
            Certificate,
        };

        let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let mut chain: Vec<Certificate> = pem::parse_many(include_bytes!(
            "../../../tests/fixtures/crypto/ocsp/ocsp_chain.pem"
        ))
        .unwrap()
        .into_iter()
        .map(|p| Certificate::from_der(p.contents()).unwrap())
        .collect();

        let algorithm = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.3.101.112"),
            parameters: None,
        };

        chain[1].tbs_certificate.subject_public_key_info.algorithm = algorithm.clone();
        chain[1]
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key = BitString::from_bytes(&key.verifying_key().to_bytes()).unwrap();

        let key_usage = BitString::new(1, vec![0x06]).unwrap();
        chain[1]
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .push(x509_cert::ext::Extension {
                extn_id: ObjectIdentifier::new_unwrap("2.5.29.15"),
                critical: true,
                extn_value: OctetString::new(key_usage.to_der().unwrap()).unwrap(),
            });

        for cert in &mut chain {
            cert.signature_algorithm = algorithm.clone();
            cert.tbs_certificate.signature = algorithm.clone();
            cert.signature = BitString::from_bytes(
                &key.sign(&cert.tbs_certificate.to_der().unwrap()).to_bytes(),
            )
            .unwrap();
        }

        Self {
            key,
            chain: chain.iter().map(|c| c.to_der().unwrap()).collect(),
        }
    }

    pub(crate) fn basic_response(&self, by_name: bool) -> BasicOcspResponse {
        use x509_cert::{
            der::{Decode as DecodeDer07, Encode as EncodeDer07},
            Certificate,
        };

        let mut basic = good_basic_response();
        let issuer = Certificate::from_der(&self.chain[1]).unwrap();
        basic.certs = None;
        basic.signature_algorithm =
            spki::AlgorithmIdentifierOwned::from_der(&issuer.signature_algorithm.to_der().unwrap())
                .unwrap();
        basic.tbs_response_data.responder_id = if by_name {
            ResponderId::ByName(
                cms::x509_cert::name::Name::from_der(
                    &issuer.tbs_certificate.subject.to_der().unwrap(),
                )
                .unwrap(),
            )
        } else {
            ResponderId::ByKey(
                OctetString::new(crate::crypto::hash::sha1(
                    issuer
                        .tbs_certificate
                        .subject_public_key_info
                        .subject_public_key
                        .raw_bytes(),
                ))
                .unwrap(),
            )
        };

        basic.tbs_response_data.responses[0].cert_id.issuer_key_hash =
            OctetString::new(crate::crypto::hash::sha1(
                issuer
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .raw_bytes(),
            ))
            .unwrap();

        basic
    }

    pub(crate) fn sign(&self, mut basic: BasicOcspResponse) -> Vec<u8> {
        use ed25519_dalek::Signer;

        basic.signature = BitString::from_bytes(
            &self
                .key
                .sign(&basic.tbs_response_data.to_der().unwrap())
                .to_bytes(),
        )
        .unwrap();

        encode_response(&basic)
    }

    pub(crate) fn delegated_response(&self, mut basic: BasicOcspResponse) -> Vec<u8> {
        use ed25519_dalek::Signer;
        use x509_cert::{
            der::{
                asn1::BitString as BitStringDer07, Decode as DecodeDer07, Encode as EncodeDer07,
            },
            Certificate,
        };

        let key = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
        let mut cert = Certificate::from_der(
            &good_basic_response()
                .certs
                .unwrap()
                .remove(0)
                .to_der()
                .unwrap(),
        )
        .unwrap();
        let algorithm = x509_cert::spki::AlgorithmIdentifierOwned::from_der(
            &basic.signature_algorithm.to_der().unwrap(),
        )
        .unwrap();
        cert.signature_algorithm = algorithm.clone();
        cert.tbs_certificate.signature = algorithm.clone();
        cert.tbs_certificate.subject_public_key_info.algorithm = algorithm;
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key =
            BitStringDer07::from_bytes(&key.verifying_key().to_bytes()).unwrap();

        cert.signature = BitStringDer07::from_bytes(
            &self
                .key
                .sign(&cert.tbs_certificate.to_der().unwrap())
                .to_bytes(),
        )
        .unwrap();

        basic.tbs_response_data.responder_id = ResponderId::ByName(
            cms::x509_cert::name::Name::from_der(&cert.tbs_certificate.subject.to_der().unwrap())
                .unwrap(),
        );

        basic.certs = Some(vec![Any::from_der(&cert.to_der().unwrap()).unwrap()]);
        basic.signature = BitString::from_bytes(
            &key.sign(&basic.tbs_response_data.to_der().unwrap())
                .to_bytes(),
        )
        .unwrap();

        encode_response(&basic)
    }
}

#[cfg(feature = "openssl")]
mod responder {
    use der::asn1::ObjectIdentifier;
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

    use super::{encode_response, Any, BasicOcspResponse, BitString, Decode, Encode, ResponderId};

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
            basic.certs = Some(vec![Any::from_der(&self.cert.to_der().unwrap()).unwrap()]);
            basic.tbs_response_data.responder_id = ResponderId::ByName(
                cms::x509_cert::name::Name::from_der(&self.cert.subject_name().to_der().unwrap())
                    .unwrap(),
            );
            // ecdsa-with-SHA256
            basic.signature_algorithm.oid = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
            basic.signature_algorithm.parameters = None;

            let mut signer = Signer::new(MessageDigest::sha256(), &self.key).unwrap();
            signer
                .update(&basic.tbs_response_data.to_der().unwrap())
                .unwrap();
            basic.signature = BitString::from_bytes(&signer.sign_to_vec().unwrap()).unwrap();

            encode_response(&basic)
        }
    }
}
