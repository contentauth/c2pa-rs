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

#[cfg(not(target_arch = "wasm32"))]
fn extract_aia_responders(cert: &x509_parser::certificate::X509Certificate) -> Option<Vec<String>> {
    use x509_parser::der_parser::{oid, Oid};

    const AD_OCSP_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .48 .1);
    const AUTHORITY_INFO_ACCESS_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .1);

    let em = cert.extensions_map().ok()?;

    let aia_extension = em.get(&AUTHORITY_INFO_ACCESS_OID)?;

    match aia_extension.parsed_extension() {
        x509_parser::extensions::ParsedExtension::AuthorityInfoAccess(aia) => {
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
        _ => None,
    }
}

/// Check the supplied cert chain for an OCSP responder in the end-entity cert.  If found it will attempt to
/// retrieve the OCSPResponse.  If successful returns OcspData containing the DER encoded OCSPResponse and
/// the DateTime for when this cached response should be refreshed, and the OCSP signer certificate chain.  
/// None otherwise.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn fetch_ocsp_response(certs: &[Vec<u8>]) -> Option<Vec<u8>> {
    use std::io::Read;

    use rasn::prelude::*;
    use rasn_pkix::Certificate;
    use x509_parser::prelude::*;

    // must have minimal chain in hierarchical order
    if certs.len() < 2 {
        return None;
    }

    let (_rem, cert) = X509Certificate::from_der(&certs[0]).ok()?;

    if let Some(responders) = extract_aia_responders(&cert) {
        let sha1_oid = rasn::types::Oid::new(&[1, 3, 14, 3, 2, 26])?; // Sha1 Oid
        let alg = rasn::types::ObjectIdentifier::from(sha1_oid);

        let sha1_ai = rasn_pkix::AlgorithmIdentifier {
            algorithm: alg,
            parameters: Some(Any::new(rasn::der::encode(&()).ok()?)), /* many OCSP responders expect this to be NULL not None */
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

            let issuer_name_hash = OctetString::from(c2pa_crypto::hash::sha1(&issuer_name_raw));
            let issuer_key_hash = OctetString::from(c2pa_crypto::hash::sha1(issuer_key_raw));
            let serial_number = subject.tbs_certificate.serial_number;

            // build request structures

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
            let request_str = c2pa_crypto::base64::encode(&request_der);

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
