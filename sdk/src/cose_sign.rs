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

use async_generic::async_generic;
use c2pa_crypto::{
    cose::{
        check_certificate_profile, timestamp_countersignature, timestamp_countersignature_async,
        CertificateTrustPolicy,
    },
    p1363::parse_ec_der_sig,
    SigningAlg,
};
use c2pa_status_tracker::OneShotStatusTracker;
use ciborium::value::Value;
use coset::{
    iana::{self, EnumI64},
    CoseSign1, CoseSign1Builder, Header, HeaderBuilder, Label, ProtectedHeader,
    TaggedCborSerializable,
};

use crate::{
    claim::Claim, cose_validator::verify_cose, settings::get_settings_value,
    time_stamp::make_cose_timestamp, AsyncSigner, Error, Result, Signer,
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
///    [`Error::CoseSignature`] if unable to validate.
#[async_generic(async_signature(
    claim_bytes: &[u8],
    signer: &dyn AsyncSigner,
    box_size: usize
))]
pub fn sign_claim(claim_bytes: &[u8], signer: &dyn Signer, box_size: usize) -> Result<Vec<u8>> {
    // Must be a valid claim.
    let label = "dummy_label";
    let _claim = Claim::from_data(label, claim_bytes)?;

    let signed_bytes = if _sync {
        cose_sign(signer, claim_bytes, box_size)
    } else {
        cose_sign_async(signer, claim_bytes, box_size).await
    };

    match signed_bytes {
        Ok(signed_bytes) => {
            // Sanity check: Ensure that this signature is valid.
            let mut cose_log = OneShotStatusTracker::default();
            let passthrough_cap = CertificateTrustPolicy::default();

            match verify_cose(
                &signed_bytes,
                claim_bytes,
                b"",
                true,
                &passthrough_cap,
                &mut cose_log,
            ) {
                Ok(r) => {
                    if !r.validated {
                        Err(Error::CoseSignature)
                    } else {
                        Ok(signed_bytes)
                    }
                }
                Err(err) => Err(err),
            }
        }
        Err(err) => Err(err),
    }
}

fn signing_cert_valid(signing_cert: &[u8]) -> Result<()> {
    // make sure signer certs are valid
    let mut cose_log = OneShotStatusTracker::default();
    let mut passthrough_cap = CertificateTrustPolicy::default();

    // allow user EKUs through this check if configured
    if let Ok(Some(trust_config)) = get_settings_value::<Option<String>>("trust.trust_config") {
        passthrough_cap.add_valid_ekus(trust_config.as_bytes());
    }

    Ok(check_certificate_profile(
        signing_cert,
        &passthrough_cap,
        &mut cose_log,
        None,
    )?)
}

/// Returns signed Cose_Sign1 bytes for `data`.
/// The Cose_Sign1 will be signed with the algorithm from [`Signer`].
#[async_generic(async_signature(
    signer: &dyn AsyncSigner,
    data: &[u8],
    box_size: usize
))]
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

    // make sure the signing cert is valid
    let certs = signer.certs()?;
    if let Some(signing_cert) = certs.first() {
        signing_cert_valid(signing_cert)?;
    } else {
        return Err(Error::CoseNoCerts);
    }

    let alg = signer.alg();

    // build complete header
    let (protected_header, unprotected_header) = if _sync {
        build_headers(signer, data, alg)?
    } else {
        build_headers_async(signer, data, alg).await?
    };

    let aad: &[u8; 0] = b""; // no additional data required here

    let sign1_builder = CoseSign1Builder::new()
        .protected(protected_header)
        .unprotected(unprotected_header)
        .payload(data.to_vec());

    let mut sign1 = sign1_builder.build();

    let tbs = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        sign1.protected.clone(),
        None,
        aad,
        sign1.payload.as_ref().unwrap_or(&vec![]),
    );

    let signature = if _sync {
        signer.sign(&tbs)?
    } else {
        signer.sign(tbs).await?
    };

    // fix up signatures that may be in the wrong format
    sign1.signature = match alg {
        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => {
            if parse_ec_der_sig(&signature).is_ok() {
                // fix up DER signature to be in P1363 format
                der_to_p1363(&signature, alg)?
            } else {
                signature
            }
        }
        _ => signature,
    };

    sign1.payload = None; // clear the payload since it is known

    let c2pa_sig_data = pad_cose_sig(&mut sign1, box_size)?;

    // println!("sig: {}", Hexlify(&c2pa_sig_data));

    Ok(c2pa_sig_data)
}

fn der_to_p1363(data: &[u8], alg: SigningAlg) -> Result<Vec<u8>> {
    // P1363 format: r | s

    let (_, p) = parse_ec_der_sig(data).map_err(|_err| Error::InvalidEcdsaSignature)?;

    let mut r = extfmt::Hexlify(p.r).to_string();
    let mut s = extfmt::Hexlify(p.s).to_string();

    let sig_len: usize = match alg {
        SigningAlg::Es256 => 64,
        SigningAlg::Es384 => 96,
        SigningAlg::Es512 => 132,
        _ => return Err(Error::UnsupportedType),
    };

    // pad or truncate as needed
    let rp = if r.len() > sig_len {
        // truncate
        let offset = r.len() - sig_len;
        &r[offset..r.len()]
    } else {
        // pad
        while r.len() != sig_len {
            r.insert(0, '0');
        }
        r.as_ref()
    };

    let sp = if s.len() > sig_len {
        // truncate
        let offset = s.len() - sig_len;
        &s[offset..s.len()]
    } else {
        // pad
        while s.len() != sig_len {
            s.insert(0, '0');
        }
        s.as_ref()
    };

    if rp.len() != sig_len || rp.len() != sp.len() {
        return Err(Error::InvalidEcdsaSignature);
    }

    // merge r and s strings
    let mut new_sig = rp.to_string();
    new_sig.push_str(sp);

    // convert back from hex string to byte array
    (0..new_sig.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&new_sig[i..i + 2], 16).map_err(|_err| Error::InvalidEcdsaSignature)
        })
        .collect()
}

#[async_generic(async_signature(signer: &dyn AsyncSigner, data: &[u8], alg: SigningAlg))]
fn build_headers(signer: &dyn Signer, data: &[u8], alg: SigningAlg) -> Result<(Header, Header)> {
    let mut protected_h = match alg {
        SigningAlg::Ps256 => HeaderBuilder::new().algorithm(iana::Algorithm::PS256),
        SigningAlg::Ps384 => HeaderBuilder::new().algorithm(iana::Algorithm::PS384),
        SigningAlg::Ps512 => HeaderBuilder::new().algorithm(iana::Algorithm::PS512),
        SigningAlg::Es256 => HeaderBuilder::new().algorithm(iana::Algorithm::ES256),
        SigningAlg::Es384 => HeaderBuilder::new().algorithm(iana::Algorithm::ES384),
        SigningAlg::Es512 => HeaderBuilder::new().algorithm(iana::Algorithm::ES512),
        SigningAlg::Ed25519 => HeaderBuilder::new().algorithm(iana::Algorithm::EdDSA),
    };

    let certs = signer.certs()?;

    let ocsp_val = if _sync {
        signer.ocsp_val()
    } else {
        signer.ocsp_val().await
    };

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

    // add certs to protected header (spec 1.3 now requires integer 33(X5Chain) in favor of string "x5chain" going forward)
    protected_h = protected_h.value(
        iana::HeaderParameter::X5Chain.to_i64(),
        sc_der_array_or_bytes.clone(),
    );

    let protected_header = protected_h.build();
    let ph2 = ProtectedHeader {
        original_data: None,
        header: protected_header.clone(),
    };

    let maybe_cts = if _sync {
        signer
            .time_stamp_provider()
            .and_then(|tsp| timestamp_countersignature(*tsp, data, &ph2))
    } else {
        if let Some(tsp) = signer.async_time_stamp_provider() {
            timestamp_countersignature_async(*tsp, data, &ph2).await
        } else {
            None
        }
    };

    let mut unprotected_h = if let Some(cts) = maybe_cts {
        let cts = cts?;
        let sigtst_vec = serde_cbor::to_vec(&make_cose_timestamp(&cts))?;
        let sigtst_cbor = serde_cbor::from_slice(&sigtst_vec)?;

        HeaderBuilder::new().text_value("sigTst".to_string(), sigtst_cbor)
    } else {
        HeaderBuilder::new()
    };

    // set the ocsp responder response if available
    if let Some(ocsp) = ocsp_val {
        let mut ocsp_vec: Vec<Value> = Vec::new();
        let mut r_vals: Vec<(Value, Value)> = vec![];

        ocsp_vec.push(Value::Bytes(ocsp));
        r_vals.push((Value::Text("ocspVals".to_string()), Value::Array(ocsp_vec)));

        unprotected_h = unprotected_h.text_value("rVals".to_string(), Value::Map(r_vals));
    }

    // build complete header
    let unprotected_header = unprotected_h.build();

    Ok((protected_header, unprotected_header))
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

    if cur_size == end_size {
        return Ok(cur_vec);
    }

    // check for box too small and matched size
    if cur_size + PAD_OFFSET > end_size {
        return Err(Error::CoseSigboxTooSmall);
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
            false => break, // we could not match end_size in a single pad so break and add a second
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
    use c2pa_crypto::SigningAlg;

    use super::sign_claim;
    #[cfg(not(target_arch = "wasm32"))]
    use crate::utils::test_signer::async_test_signer;
    use crate::{claim::Claim, utils::test_signer::test_signer, Result, Signer};

    #[test]
    #[cfg_attr(not(any(target_arch = "wasm32", feature = "openssl_sign")), ignore)]
    fn test_sign_claim() {
        let mut claim = Claim::new("extern_sign_test", Some("contentauth"));
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let signer = test_signer(SigningAlg::Ps256);
        let box_size = signer.reserve_size();

        let cose_sign1 = sign_claim(&claim_bytes, signer.as_ref(), box_size).unwrap();

        assert_eq!(cose_sign1.len(), box_size);
    }

    #[cfg(all(feature = "openssl_sign", feature = "file_io"))]
    #[actix::test]
    async fn test_sign_claim_async() {
        use c2pa_crypto::SigningAlg;

        use crate::{cose_sign::sign_claim_async, AsyncSigner};

        let mut claim = Claim::new("extern_sign_test", Some("contentauth"));
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let signer = async_test_signer(SigningAlg::Ps256);
        let box_size = signer.reserve_size();

        let cose_sign1 = sign_claim_async(&claim_bytes, &signer, box_size)
            .await
            .unwrap();

        assert_eq!(cose_sign1.len(), box_size);
    }

    struct BogusSigner {}

    impl BogusSigner {
        pub fn new() -> Self {
            BogusSigner {}
        }
    }

    impl Signer for BogusSigner {
        fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
            eprintln!("Canary, canary, please cause this deploy to fail!");
            Ok(b"totally bogus signature".to_vec())
        }

        fn alg(&self) -> c2pa_crypto::SigningAlg {
            c2pa_crypto::SigningAlg::Ps256
        }

        fn certs(&self) -> Result<Vec<Vec<u8>>> {
            let cert_vec: Vec<u8> = Vec::new();
            let certs = vec![cert_vec];
            Ok(certs)
        }

        fn reserve_size(&self) -> usize {
            1024
        }

        fn send_timestamp_request(&self, _message: &[u8]) -> Option<crate::error::Result<Vec<u8>>> {
            Some(Ok(Vec::new()))
        }
    }

    #[test]
    fn test_bogus_signer() {
        let mut claim = Claim::new("bogus_sign_test", Some("contentauth"));
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let box_size = 10000;

        let signer = BogusSigner::new();

        let _cose_sign1 = sign_claim(&claim_bytes, &signer, box_size);

        #[cfg(feature = "openssl")] // there is no verify on sign when openssl is disabled
        assert!(_cose_sign1.is_err());
    }
}
