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

use std::io::Read;

use rasn::prelude::*;
use rasn_pkix::Certificate;
use x509_parser::{
    der_parser::{oid, Oid},
    extensions::ParsedExtension,
    prelude::*,
};

use crate::base64;

/// Retrieve an OCSP response if available.
///
/// Checks for an OCSP responder in the end-entity certifricate. If found, it
/// will attempt to retrieve the raw DER-encoded OCSP response.
///
/// Not available on WASM builds.
pub fn fetch_ocsp_response(certs: &[Vec<u8>]) -> Option<Vec<u8>> {
    // There must be at least one cert that isn't an end-entity cert.
    if certs.len() < 2 {
        return None;
    }

    let (_rem, cert) = X509Certificate::from_der(&certs[0]).ok()?;

    if let Some(responders) = extract_aia_responders(&cert) {
        let sha1_oid = rasn::types::Oid::new(&[1, 3, 14, 3, 2, 26])?;
        let alg = rasn::types::ObjectIdentifier::from(sha1_oid);

        let sha1_ai = rasn_pkix::AlgorithmIdentifier {
            algorithm: alg,
            parameters: Some(Any::new(rasn::der::encode(&()).ok()?)),
            // Many OCSP responders expect this to be NULL not None.
        };

        for r in responders {
            let url = url::Url::parse(&r).ok()?;
            let subject: Certificate = rasn::der::decode(&certs[0]).ok()?;
            let issuer: Certificate = rasn::der::decode(&certs[1]).ok()?;

            let issuer_name_raw = rasn::der::encode(&issuer.tbs_certificate.subject).ok()?;

            let issuer_key_raw = &issuer
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_raw_slice();

            let issuer_name_hash = OctetString::from(crate::hash::sha1(&issuer_name_raw));
            let issuer_key_hash = OctetString::from(crate::hash::sha1(issuer_key_raw));
            let serial_number = subject.tbs_certificate.serial_number;

            // Build request structures.

            let req_cert = rasn_ocsp::CertId {
                hash_algorithm: sha1_ai.clone(),
                issuer_name_hash,
                issuer_key_hash,
                serial_number,
            };

            let ocsp_req = rasn_ocsp::Request {
                req_cert,
                single_request_extensions: None,
            };

            let request_list = vec![ocsp_req];

            let tbs_request = rasn_ocsp::TbsRequest {
                version: rasn_ocsp::Version::from(0u8),
                requestor_name: None,
                request_list,
                request_extensions: None,
            };

            let ocsp_request = rasn_ocsp::OcspRequest {
                tbs_request,
                optional_signature: None,
            };

            // build query param
            let request_der = rasn::der::encode(&ocsp_request).ok()?;
            let request_str = base64::encode(&request_der);

            let req_url = url.join(&request_str).ok()?;

            // fetch OCSP response
            let request = ureq::get(req_url.as_str());
            let response = if let Some(host) = url.host() {
                request.set("Host", &host.to_string()).call().ok()? // for responders that don't support http 1.0
            } else {
                request.call().ok()?
            };

            if response.status() == 200 {
                let len = response
                    .header("Content-Length")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(10000);

                let mut ocsp_rsp: Vec<u8> = Vec::with_capacity(len);

                response
                    .into_reader()
                    .take(1000000)
                    .read_to_end(&mut ocsp_rsp)
                    .ok()?;

                return Some(ocsp_rsp);
            }
        }
    }
    None
}

fn extract_aia_responders(cert: &x509_parser::certificate::X509Certificate) -> Option<Vec<String>> {
    let em = cert.extensions_map().ok()?;

    let aia_extension = em.get(&AUTHORITY_INFO_ACCESS_OID)?;

    let ParsedExtension::AuthorityInfoAccess(aia) = aia_extension.parsed_extension() else {
        return None;
    };

    let mut output = Vec::new();

    for ad in &aia.accessdescs {
        if let x509_parser::extensions::GeneralName::URI(uri) = ad.access_location {
            if ad.access_method == AD_OCSP_OID {
                output.push(uri.to_string())
            }
        }
    }
    Some(output)
}

const AD_OCSP_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .48 .1);
const AUTHORITY_INFO_ACCESS_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .1);
