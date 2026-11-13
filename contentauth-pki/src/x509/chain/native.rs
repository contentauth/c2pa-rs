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

use asn1_rs::FromDer;
use x509_parser::certificate::X509Certificate;

use super::ChainError;
use crate::x509::certificate::{
    cert_signing_alg, check_chain_order_and_ca_authorization, verify_data,
};

pub(crate) fn check_certificate_trust(
    anchor_ders: &[Vec<u8>],
    chain_der: &[Vec<u8>],
    cert_der: &[u8],
    validation_time: i64,
) -> Result<(), ChainError> {
    // Add end-entity cert to the chain if not already there.
    let full_chain = if !chain_der.is_empty() && cert_der == chain_der[0] {
        chain_der.to_vec()
    } else {
        let mut full_chain: Vec<Vec<u8>> = Vec::new();
        full_chain.push(cert_der.to_vec());
        let mut in_chain = chain_der.to_vec();
        full_chain.append(&mut in_chain);
        full_chain
    };

    // Make sure chain is in the correct order, cryptographically valid, and
    // every issuer is authorized to act as a CA.
    check_chain_order_and_ca_authorization(&full_chain)?;

    // Make sure every cert in the chain was valid at signing time - as its
    // own pass over the whole chain, independent of where a trust anchor
    // match is found below. The trust-anchor search returns as soon as it
    // finds a match, so a check placed inside that loop would only ever run
    // for the certs from the anchor match onward, silently skipping every
    // cert between that match and the leaf.
    let check_time = validation_time;
    let check_time = x509_parser::time::ASN1Time::from_timestamp(check_time)
        .map_err(|_| ChainError::NoAnchorAssociation)?;
    // The end-entity certificate's validity is reported by the certificate
    // profile check. A CA certificate outside its validity is reported as such
    // only if the chain otherwise reaches a trust anchor, as OpenSSL does;
    // otherwise the chain is simply not trusted.
    let mut ca_outside_validity = false;
    for (depth, cert) in full_chain.iter().enumerate() {
        let (_, chain_cert) =
            X509Certificate::from_der(cert).map_err(|_e| ChainError::NoAnchorAssociation)?;
        if !chain_cert.validity().is_valid_at(check_time) {
            if depth == 0 {
                return Err(ChainError::NoAnchorAssociation);
            }
            ca_outside_validity = true;
        }
    }

    // Build anchors and check against trust anchors.
    let anchors: Vec<(X509Certificate, &Vec<u8>)> = anchor_ders
        .iter()
        .filter_map(|anchor_der| {
            let (_, cert) = X509Certificate::from_der(anchor_der)
                .map_err(|_e| ChainError::NoAnchorAssociation)
                .ok()?;
            Some((cert, anchor_der))
        })
        .collect();

    // Work back from last cert in chain against the trust anchors.
    for cert in full_chain.iter().rev() {
        let (_, chain_cert) =
            X509Certificate::from_der(cert).map_err(|_e| ChainError::NoAnchorAssociation)?;

        // Check against trust anchors.
        for (anchor_cert, anchor_der) in &anchors {
            if chain_cert.issuer() == anchor_cert.subject() {
                let data = chain_cert.tbs_certificate.as_ref();
                let sig = chain_cert.signature_value.as_ref();

                let sig_alg = cert_signing_alg(&chain_cert);

                let result = verify_data(anchor_der, sig_alg, sig, data);

                match result {
                    Ok(b) => {
                        if b {
                            if ca_outside_validity {
                                return Err(ChainError::CaCertificateOutsideValidity);
                            }
                            return Ok(());
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    Err(ChainError::NoAnchorAssociation)
}
