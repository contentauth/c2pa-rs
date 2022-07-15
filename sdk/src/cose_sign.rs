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

//! Provides access to COSE signature generation.

#![deny(missing_docs)]

use ciborium::value::Value;
use coset::{iana, CoseSign1, CoseSign1Builder, HeaderBuilder, Label, TaggedCborSerializable};

use crate::{
    claim::Claim,
    cose_validator::verify_cose,
    status_tracker::OneShotStatusTracker,
    time_stamp::{cose_timestamp_countersign, make_cose_timestamp},
    Error, Result, Signer,
};

/// Generate a COSE signature for a block of bytes which must be a valid C2PA
/// claim structure.
///
/// Should only be used when the underlying signature mechanism is detached
/// from the generation of the C2PA manifest (and thus the claim embedded in it).
///
/// ## Actions taken
///
/// 1. Verifies that the data supplied is a valid C2PA claim. The function will
///    respond with [`Error::ClaimDecoding`] if not.
/// 2. Signs the data using the provided [`Signer`] instance. Will ensure that
///    the signature is padded to match `box_size`, which should be the number of
///    bytes reserved for the `c2pa.signature` JUMBF box in this claim's manifest.
///    (If `box_size` is too small for the generated signature, this function
///    will respond with an error.)
/// 3. Verifies that the signature is valid COSE. Will respond with an error
///    if unable to validate.
pub fn sign_claim(claim_bytes: &[u8], signer: &dyn Signer, box_size: usize) -> Result<Vec<u8>> {
    // must be a valid Claim
    let label = "dummy_label";
    let _claim = Claim::from_data(label, claim_bytes)?;

    // generate and verify a CoseSign1 representation of the data
    cose_sign(signer, claim_bytes, box_size).and_then(|sig| {
        // Sanity check: Ensure that this signature is valid.

        let mut cose_log = OneShotStatusTracker::new();
        match verify_cose(&sig, claim_bytes, b"", false, &mut cose_log) {
            Ok(_) => Ok(sig),
            Err(err) => Err(err),
        }
    })
}

/// Returns signed Cose_Sign1 bytes for `data`.
/// The Cose_Sign1 will be signed with the algorithm from [`Signer`].
pub(crate) fn cose_sign(signer: &dyn Signer, data: &[u8], box_size: usize) -> Result<Vec<u8>> {
    // 13.2.1. X.509 Certificates
    //
    // X.509 Certificates are stored in a header named x5chain draft-ietf-cose-x509.
    // The value is a CBOR array of byte strings, each of which contains the certificate
    // encoded as ASN.1 distinguished encoding rules (DER). This array must contain at
    // least one element. The first element of the array must be the certificate of
    // the signer, and the subjectPublicKeyInfo element of the certificate will be the
    // public key used to validate the signature. The Validity member of the TBSCertificate
    // sequence provides the time validity period of the certificate.

    /*
       This header parameter allows for a single X.509 certificate or a
       chain of X.509 certificates to be carried in the message.

       *  If a single certificate is conveyed, it is placed in a CBOR
           byte string.

       *  If multiple certificates are conveyed, a CBOR array of byte
           strings is used, with each certificate being in its own byte
           string.
    */

    let alg = signer.alg().ok_or(Error::UnsupportedType)?;

    let alg_id = match alg.as_ref() {
        "ps256" => HeaderBuilder::new()
            .algorithm(iana::Algorithm::PS256)
            .build(),
        "ps384" => HeaderBuilder::new()
            .algorithm(iana::Algorithm::PS384)
            .build(),
        "ps512" => HeaderBuilder::new()
            .algorithm(iana::Algorithm::PS512)
            .build(),
        "es256" => HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .build(),
        "es384" => HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES384)
            .build(),
        "es512" => HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES512)
            .build(),
        "ed25519" => HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .build(),
        _ => return Err(Error::UnsupportedType),
    };

    // Get the public CAs for the Signer.
    let certs = signer.certs()?;
    let sc_der_array_or_bytes = match certs.len() {
        1 => Value::Bytes(certs[0].clone()), // single cert
        _ => {
            let mut sc_der_array: Vec<Value> = Vec::new();
            for cert in certs {
                sc_der_array.push(Value::Bytes(cert));
            }
            Value::Array(sc_der_array) // provide vec of certs when required
        }
    };

    let mut unprotected = match signer.time_authority_url() {
        Some(url) => {
            let cts = cose_timestamp_countersign(data, &alg, &url)?;
            let sigtst_vec = serde_cbor::to_vec(&make_cose_timestamp(&cts))?;
            let sigtst_cbor = serde_cbor::from_slice(&sigtst_vec)?;

            HeaderBuilder::new()
                .text_value("x5chain".to_string(), sc_der_array_or_bytes)
                .text_value("sigTst".to_string(), sigtst_cbor)
        }
        None => {
            let sign_time = chrono::Utc::now().to_rfc3339(); // todo: remove when switch to cose_timestamp
            HeaderBuilder::new()
                .text_value("x5chain".to_string(), sc_der_array_or_bytes)
                .text_value("temp_signing_time".to_string(), Value::Text(sign_time))
        }
    };

    // set the ocsp responder response if available
    if let Some(ocsp) = signer.ocsp_val() {
        let mut ocsp_vec: Vec<Value> = Vec::new();
        let mut r_vals: Vec<(Value, Value)> = vec![];

        ocsp_vec.push(Value::Bytes(ocsp));
        r_vals.push((Value::Text("ocspVals".to_string()), Value::Array(ocsp_vec)));

        unprotected = unprotected.text_value("rVals".to_string(), Value::Map(r_vals));
    }

    // build complete header
    let unprotected_header = unprotected.build();

    let aad = b""; // no additional data required here

    let sign1_builder = CoseSign1Builder::new()
        .protected(alg_id)
        .unprotected(unprotected_header)
        .payload(data.to_vec())
        .try_create_signature(aad, |bytes| signer.sign(bytes))?;

    let mut sign1 = sign1_builder.build();
    sign1.payload = None; // clear the payload since it is known

    let c2pa_sig_data = pad_cose_sig(&mut sign1, box_size)?;

    // println!("sig: {}", Hexlify(&c2pa_sig_data));

    Ok(c2pa_sig_data)
}

const PAD: &str = "pad";
const PAD2: &str = "pad2";
const PAD_OFFSET: usize = 7;

// Pad the CoseSign1 structure with 0s to match the reserved box size.
// There are some values lengths that are impossible to hit with a single padding so
// when that happens a second padding is added to change the remaining needed padding.
// The default initial guess works for almost all sizes, without the need for additional loops.
fn pad_cose_sig(sign1: &mut CoseSign1, end_size: usize) -> Result<Vec<u8>> {
    let mut sign1_clone = sign1.clone();
    let cur_vec = sign1_clone
        .to_tagged_vec()
        .map_err(|_e| Error::CoseSignature)?;
    let cur_size = cur_vec.len();

    // check for box too small
    match cur_size > end_size {
        true => {
            return Err(Error::CoseSigboxTooSmall);
        }
        false if cur_size == end_size => return Ok(cur_vec),
        false => (),
    }

    let mut padding_found = false;
    let mut last_pad = 0;
    let mut target_guess = end_size - cur_size - PAD_OFFSET; // start close to desired end_size accounting for label
    loop {
        // clone to use
        sign1_clone = sign1.clone();

        // replace padding with new estimate
        for header_pair in &mut sign1_clone.unprotected.rest {
            if header_pair.0 == Label::Text("pad".to_string()) {
                if let Value::Bytes(b) = &header_pair.1 {
                    last_pad = b.len();
                }
                header_pair.1 = Value::Bytes(vec![0u8; target_guess]);
                padding_found = true;
                break;
            }
        }

        // if there was no padding add it and call again
        if !padding_found {
            sign1_clone.unprotected.rest.push((
                Label::Text(PAD.to_string()),
                Value::Bytes(vec![0u8; target_guess]),
            ));
            return pad_cose_sig(&mut sign1_clone, end_size);
        }

        // get current cbor vec to size if we reached target size
        let new_cbor = sign1_clone
            .to_tagged_vec()
            .map_err(|_e| Error::CoseSignature)?;

        match new_cbor.len() < end_size {
            true => target_guess += 1,
            false if new_cbor.len() == end_size => return Ok(new_cbor),
            false => break, // we couuld not match end_size in a single pad so break and add a second
        }
    }

    // if we reach here we need a new second padding object to hit exact size
    sign1.unprotected.rest.push((
        Label::Text(PAD2.to_string()),
        Value::Bytes(vec![0u8; last_pad - 10]),
    ));
    pad_cose_sig(sign1, end_size)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::sign_claim;

    use crate::{claim::Claim, utils::test::temp_signer};

    #[test]
    fn test_sign_claim() {
        let mut claim = Claim::new("extern_sign_test", Some("contentauth"));
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let box_size = 10000;

        let signer = temp_signer();

        let cose_sign1 = sign_claim(&claim_bytes, &signer, box_size).unwrap();

        assert_eq!(cose_sign1.len(), box_size);
    }
}
