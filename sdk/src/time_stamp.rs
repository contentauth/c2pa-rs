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

use std::ops::Deref;

use async_generic::async_generic;
use bcder::{
    decode::{Constructed, SliceSource},
    encode::Values,
    ConstOid, OctetString,
};
use coset::{sig_structure_data, ProtectedHeader};
use serde::{Deserialize, Serialize};
use x509_certificate::DigestAlgorithm::{self};

#[cfg(any(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    feature = "openssl"
))]
use crate::cose_validator::{
    ECDSA_WITH_SHA256_OID, ECDSA_WITH_SHA384_OID, ECDSA_WITH_SHA512_OID, EC_PUBLICKEY_OID,
    ED25519_OID, RSA_OID, SHA1_OID, SHA256_OID, SHA256_WITH_RSAENCRYPTION_OID, SHA384_OID,
    SHA384_WITH_RSAENCRYPTION_OID, SHA512_OID, SHA512_WITH_RSAENCRYPTION_OID,
};
use crate::{
    asn1::{
        rfc3161::{TimeStampResp, TstInfo, OID_CONTENT_TYPE_TST_INFO},
        rfc5652::{
            CertificateChoices::Certificate, SignedData, OID_ID_SIGNED_DATA, OID_MESSAGE_DIGEST,
            OID_SIGNING_TIME,
        },
    },
    error::{Error, Result},
    hash_utils::vec_compare,
    AsyncSigner, Signer,
};

// Generate TimeStamp signature according to https://datatracker.ietf.org/doc/html/rfc3161
// using the specified Time Authority

#[allow(dead_code)]
pub(crate) fn cose_countersign_data(data: &[u8], p_header: &ProtectedHeader) -> Vec<u8> {
    let aad: Vec<u8> = Vec::new();

    // create sig_structure_data to be signed
    sig_structure_data(
        coset::SignatureContext::CounterSignature,
        p_header.clone(),
        None,
        &aad,
        data,
    )
}

#[async_generic(
    async_signature(
        signer: &dyn AsyncSigner,
        data: &[u8],
        p_header: &ProtectedHeader,
    ))]
pub(crate) fn cose_timestamp_countersign(
    signer: &dyn Signer,
    data: &[u8],
    p_header: &ProtectedHeader,
) -> Option<Result<Vec<u8>>> {
    // create countersignature with TimeStampReq parameters
    // payload: data
    // context "CounterSigner"
    // certReq true
    // algorithm sha256

    // create sig data structure to be time stamped
    let sd = cose_countersign_data(data, p_header);

    if _sync {
        timestamp_data(signer, &sd)
    } else {
        timestamp_data_async(signer, &sd).await
    }
}

#[async_generic]
pub(crate) fn cose_sigtst_to_tstinfos(
    sigtst_cbor: &[u8],
    data: &[u8],
    p_header: &ProtectedHeader,
) -> Result<Vec<TstInfo>> {
    let tst_container: TstContainer =
        serde_cbor::from_slice(sigtst_cbor).map_err(|_err| Error::CoseTimeStampGeneration)?;

    let mut tstinfos: Vec<TstInfo> = Vec::new();

    for token in &tst_container.tst_tokens {
        let tbs = cose_countersign_data(data, p_header);
        let tst_info = if _sync {
            verify_timestamp(&token.val, &tbs)?
        } else {
            verify_timestamp_async(&token.val, &tbs).await?
        };

        tstinfos.push(tst_info);
    }

    if tstinfos.is_empty() {
        Err(Error::NotFound)
    } else {
        Ok(tstinfos)
    }
}

// internal only function to work around bug in serialization of TimeStampResponse
// so we just return the data directly
#[cfg(not(target_arch = "wasm32"))]
fn time_stamp_request_http(
    url: &str,
    headers: Option<Vec<(String, String)>>,
    request: &crate::asn1::rfc3161::TimeStampReq,
) -> Result<Vec<u8>> {
    use std::io::Read;

    const HTTP_CONTENT_TYPE_REQUEST: &str = "application/timestamp-query";
    const HTTP_CONTENT_TYPE_RESPONSE: &str = "application/timestamp-reply";

    let mut body = Vec::<u8>::new();
    request
        .encode_ref()
        .write_encoded(bcder::Mode::Der, &mut body)?;

    let mut req = ureq::post(url);

    if let Some(headers) = headers {
        for (ref name, ref value) in headers {
            req = req.set(name.as_str(), value.as_str());
        }
    }

    let response = req
        .set("Content-Type", HTTP_CONTENT_TYPE_REQUEST)
        .send_bytes(&body)
        .map_err(|_err| Error::CoseTimeStampGeneration)?;

    if response.status() == 200 && response.content_type() == HTTP_CONTENT_TYPE_RESPONSE {
        let len = response
            .header("Content-Length")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(20000);

        let mut response_bytes: Vec<u8> = Vec::with_capacity(len);

        response
            .into_reader()
            .take(1000000)
            .read_to_end(&mut response_bytes)
            .map_err(|_err| Error::CoseTimeStampGeneration)?;

        let res = TimeStampResponse(
            Constructed::decode(response_bytes.as_ref(), bcder::Mode::Der, |cons| {
                TimeStampResp::take_from(cons)
            })
            .map_err(|_err| Error::CoseTimeStampGeneration)?,
        );

        // Verify nonce was reflected, if present.
        if res.is_success() {
            if let Some(tst_info) = res
                .tst_info()
                .map_err(|_err| Error::CoseTimeStampGeneration)?
            {
                if tst_info.nonce != request.nonce {
                    return Err(Error::CoseTimeStampGeneration);
                }
            }
        }

        Ok(response_bytes)
    } else {
        Err(Error::CoseTimeStampGeneration)
    }
}

// Send a Time-Stamp request for a given message to an HTTP URL.
//
// This is a wrapper around [time_stamp_request_http] that constructs the low-level
// ASN.1 request object with reasonable defaults.

pub(crate) fn time_stamp_message_http(
    message: &[u8],
    digest_algorithm: DigestAlgorithm,
) -> Result<crate::asn1::rfc3161::TimeStampReq> {
    use rand::{thread_rng, Rng};

    let mut h = digest_algorithm.digester();
    h.update(message);
    let digest = h.finish();

    let mut random = [0u8; 8];
    thread_rng()
        .try_fill(&mut random)
        .map_err(|_| Error::CoseTimeStampGeneration)?;

    let request = crate::asn1::rfc3161::TimeStampReq {
        version: bcder::Integer::from(1_u8),
        message_imprint: crate::asn1::rfc3161::MessageImprint {
            hash_algorithm: digest_algorithm.into(),
            hashed_message: bcder::OctetString::new(bytes::Bytes::copy_from_slice(digest.as_ref())),
        },
        req_policy: None,
        nonce: Some(bcder::Integer::from(u64::from_le_bytes(random))),
        cert_req: Some(true),
        extensions: None,
    };

    Ok(request)
}

pub struct TimeStampResponse(TimeStampResp);

impl std::ops::Deref for TimeStampResponse {
    type Target = TimeStampResp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TimeStampResponse {
    // Whether the time stamp request was successful.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn is_success(&self) -> bool {
        matches!(
            self.0.status.status,
            crate::asn1::rfc3161::PkiStatus::Granted
                | crate::asn1::rfc3161::PkiStatus::GrantedWithMods
        )
    }

    fn signed_data(&self) -> Result<Option<SignedData>> {
        if let Some(token) = &self.0.time_stamp_token {
            if token.content_type == OID_ID_SIGNED_DATA {
                Ok(Some(
                    token
                        .content
                        .clone()
                        .decode(SignedData::take_from)
                        .map_err(|_err| Error::CoseTimeStampGeneration)?,
                ))
            } else {
                Err(Error::CoseTimeStampGeneration)
            }
        } else {
            Ok(None)
        }
    }

    fn tst_info(&self) -> Result<Option<TstInfo>> {
        if let Some(signed_data) = self.signed_data()? {
            if signed_data.content_info.content_type == OID_CONTENT_TYPE_TST_INFO {
                if let Some(content) = signed_data.content_info.content {
                    Ok(Some(
                        Constructed::decode(content.to_bytes(), bcder::Mode::Der, |cons| {
                            TstInfo::take_from(cons)
                        })
                        .map_err(|_err| Error::CoseTimeStampGeneration)?,
                    ))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
}

// Generate TimeStamp based on rfc3161 using "data" as MessageImprint and return raw TimeStampRsp bytes
#[async_generic(async_signature(signer: &dyn AsyncSigner, data: &[u8]))]
pub fn timestamp_data(signer: &dyn Signer, data: &[u8]) -> Option<Result<Vec<u8>>> {
    if _sync {
        signer.send_timestamp_request(data)
    } else {
        signer.send_timestamp_request(data).await
        // TO DO: Fix bug in async_generic. This .await
        // should be automatically removed.
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_generic]
pub fn default_rfc3161_request(
    url: &str,
    headers: Option<Vec<(String, String)>>,
    data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    use crate::asn1::rfc3161::TimeStampReq;
    let request = Constructed::decode(
        bcder::decode::SliceSource::new(data),
        bcder::Mode::Der,
        TimeStampReq::take_from,
    )
    .map_err(|_err| Error::CoseTimeStampGeneration)?;

    let ts = time_stamp_request_http(url, headers, &request)?;

    // sanity check
    if _sync {
        verify_timestamp(&ts, message)?;
    } else {
        verify_timestamp_async(&ts, message).await?;
    }

    Ok(ts)
}

#[allow(unused_variables)]
pub fn default_rfc3161_message(data: &[u8]) -> Result<Vec<u8>> {
    let request = time_stamp_message_http(data, x509_certificate::DigestAlgorithm::Sha256)?;

    let mut body = Vec::<u8>::new();
    request
        .encode_ref()
        .write_encoded(bcder::Mode::Der, &mut body)?;
    Ok(body)
}

pub fn gt_to_datetime(
    gt: x509_certificate::asn1time::GeneralizedTime,
) -> chrono::DateTime<chrono::Utc> {
    gt.into()
}
pub fn timestamp_to_gt(dt: i64) -> Option<x509_certificate::asn1time::GeneralizedTime> {
    use chrono::{TimeZone, Utc};
    match Utc.timestamp_opt(dt, 0) {
        chrono::offset::LocalResult::Single(time) => {
            let formatted_time = time.format("%Y%m%d%H%M%SZ").to_string();

            x509_certificate::asn1time::GeneralizedTime::parse(
                SliceSource::new(formatted_time.as_bytes()),
                false,
                x509_certificate::asn1time::GeneralizedTimeAllowedTimezone::Z,
            )
            .ok()
        }
        _ => None,
    }
}

fn time_to_datetime(t: x509_certificate::asn1time::Time) -> chrono::DateTime<chrono::Utc> {
    match t {
        x509_certificate::asn1time::Time::UtcTime(u) => *u,
        x509_certificate::asn1time::Time::GeneralTime(gt) => gt_to_datetime(gt),
    }
}

#[cfg(feature = "openssl")]
fn get_local_validator(
    sig_alg: &bcder::Oid,
    hash_alg: &bcder::Oid,
) -> Result<Box<dyn crate::validator::CoseValidator>> {
    let validator = if sig_alg.as_ref() == RSA_OID.as_bytes()
        || sig_alg.as_ref() == SHA256_WITH_RSAENCRYPTION_OID.as_bytes()
        || sig_alg.as_ref() == SHA384_WITH_RSAENCRYPTION_OID.as_bytes()
        || sig_alg.as_ref() == SHA512_WITH_RSAENCRYPTION_OID.as_bytes()
    {
        if hash_alg.as_ref() == SHA1_OID.as_bytes() {
            Box::new(crate::openssl::RsaLegacyValidator::new("sha1"))
        } else if hash_alg.as_ref() == SHA256_OID.as_bytes() {
            Box::new(crate::openssl::RsaLegacyValidator::new("rsa256"))
        } else if hash_alg.as_ref() == SHA384_OID.as_bytes() {
            Box::new(crate::openssl::RsaLegacyValidator::new("rsa384"))
        } else if hash_alg.as_ref() == SHA512_OID.as_bytes() {
            Box::new(crate::openssl::RsaLegacyValidator::new("rsa512"))
        } else {
            return Err(Error::CoseTimeStampAuthority);
        }
    } else if sig_alg.as_ref() == EC_PUBLICKEY_OID.as_bytes()
        || sig_alg.as_ref() == ECDSA_WITH_SHA256_OID.as_bytes()
        || sig_alg.as_ref() == ECDSA_WITH_SHA384_OID.as_bytes()
        || sig_alg.as_ref() == ECDSA_WITH_SHA512_OID.as_bytes()
    {
        if hash_alg.as_ref() == SHA256_OID.as_bytes() {
            crate::validator::get_validator(crate::SigningAlg::Es256)
        } else if hash_alg.as_ref() == SHA384_OID.as_bytes() {
            crate::validator::get_validator(crate::SigningAlg::Es384)
        } else if hash_alg.as_ref() == SHA512_OID.as_bytes() {
            crate::validator::get_validator(crate::SigningAlg::Es512)
        } else {
            return Err(Error::CoseTimeStampAuthority);
        }
    } else if sig_alg.as_ref() == ED25519_OID.as_bytes() {
        crate::validator::get_validator(crate::SigningAlg::Ed25519)
    } else {
        return Err(Error::CoseTimeStampAuthority);
    };

    Ok(validator)
}

#[cfg(target_arch = "wasm32")]
fn get_validator_type(sig_alg: &bcder::Oid, hash_alg: &bcder::Oid) -> Option<String> {
    if sig_alg.as_ref() == RSA_OID.as_bytes()
        || sig_alg.as_ref() == SHA256_WITH_RSAENCRYPTION_OID.as_bytes()
        || sig_alg.as_ref() == SHA384_WITH_RSAENCRYPTION_OID.as_bytes()
        || sig_alg.as_ref() == SHA512_WITH_RSAENCRYPTION_OID.as_bytes()
    {
        if hash_alg.as_ref() == SHA1_OID.as_bytes() {
            Some("sha1".to_string())
        } else if hash_alg.as_ref() == SHA256_OID.as_bytes() {
            Some("rsa256".to_string())
        } else if hash_alg.as_ref() == SHA384_OID.as_bytes() {
            Some("rsa384".to_string())
        } else if hash_alg.as_ref() == SHA512_OID.as_bytes() {
            Some("rsa512".to_string())
        } else {
            None
        }
    } else if sig_alg.as_ref() == EC_PUBLICKEY_OID.as_bytes()
        || sig_alg.as_ref() == ECDSA_WITH_SHA256_OID.as_bytes()
        || sig_alg.as_ref() == ECDSA_WITH_SHA384_OID.as_bytes()
        || sig_alg.as_ref() == ECDSA_WITH_SHA512_OID.as_bytes()
    {
        if hash_alg.as_ref() == SHA256_OID.as_bytes() {
            Some(crate::SigningAlg::Es256.to_string())
        } else if hash_alg.as_ref() == SHA384_OID.as_bytes() {
            Some(crate::SigningAlg::Es384.to_string())
        } else if hash_alg.as_ref() == SHA512_OID.as_bytes() {
            Some(crate::SigningAlg::Es512.to_string())
        } else {
            None
        }
    } else if sig_alg.as_ref() == ED25519_OID.as_bytes() {
        Some(crate::SigningAlg::Ed25519.to_string())
    } else {
        None
    }
}

// Returns TimeStamp token info if ts verifies against supplied data
#[allow(unused_variables)]
#[async_generic]
pub(crate) fn verify_timestamp(ts: &[u8], data: &[u8]) -> Result<TstInfo> {
    let mut last_err = Error::CoseInvalidTimeStamp;
    let ts_resp = get_timestamp_response(ts)?;

    // check for timestamp expiration during stamping
    if let Ok(Some(sd)) = &ts_resp.signed_data() {
        let certs = sd
            .certificates
            .clone()
            .ok_or(Error::CoseTimeStampValidity)?;

        // look for any valid signer
        for signer_info in sd.signer_infos.iter() {
            // find signer's cert
            let cert = match certs.iter().find_map(|cc| {
                let c = match cc {
                    Certificate(c) => c,
                    _ => return None,
                };

                match &signer_info.sid {
                    crate::asn1::rfc5652::SignerIdentifier::IssuerAndSerialNumber(sn) => {
                        if sn.issuer == c.tbs_certificate.issuer
                            && sn.serial_number == c.tbs_certificate.serial_number
                        {
                            Some(c)
                        } else {
                            None
                        }
                    }
                    crate::asn1::rfc5652::SignerIdentifier::SubjectKeyIdentifier(ski) => {
                        const SKI_OID: ConstOid = bcder::Oid(&[2, 5, 29, 14]);
                        if let Some(extensions) = &c.tbs_certificate.extensions {
                            if extensions.iter().any(|e| {
                                if e.id == SKI_OID {
                                    return *ski == e.value;
                                }
                                false
                            }) {
                                Some(c)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                }
            }) {
                Some(c) => c,
                None => continue,
            };

            // load unprotected TstInfo.  We will verify its contents below against signed values
            let tst_opt = ts_resp.tst_info()?;
            let mut tst = tst_opt.ok_or(Error::CoseInvalidTimeStamp)?;
            let mi = &tst.message_imprint;

            // timestamp cert expiration
            let mut signing_time = gt_to_datetime(tst.gen_time.clone()).timestamp();

            // check the signer info signed attributes
            if let Some(attributes) = &signer_info.signed_attributes {
                // if there is a signed signing time make sure it has not changed
                if let Some(Some(attrib_signing_time)) = attributes
                    .iter()
                    .find(|attr| attr.typ == OID_SIGNING_TIME)
                    .map(|attr| {
                        if attr.values.len() != 1 {
                            // per CMS spec can only contain 1 signing time value
                            return None;
                        }

                        attr.values.first().and_then(|v| {
                            v.deref()
                                .clone()
                                .decode(x509_certificate::asn1time::Time::take_from)
                                .ok()
                        })
                    })
                {
                    let signed_signing_time = match attrib_signing_time {
                        x509_certificate::asn1time::Time::UtcTime(u) => u.timestamp(),
                        x509_certificate::asn1time::Time::GeneralTime(g) => {
                            gt_to_datetime(g).timestamp()
                        }
                    };

                    // used sign date to avoid spoofing
                    // check to see if time string has been modified todo: when is this an error case
                    let _time_diff = (signing_time - signed_signing_time).abs();

                    if let Some(gt) = timestamp_to_gt(signed_signing_time) {
                        signing_time = gt_to_datetime(gt.clone()).timestamp(); // use actual signed time
                        tst.gen_time = gt;
                    };
                }

                // check the mandatory signed message digest is self consistent
                match attributes
                    .iter()
                    .find(|attr| attr.typ == OID_MESSAGE_DIGEST)
                {
                    Some(message_digest) => {
                        // message digest attribute MUST have exactly 1 value.
                        if message_digest.values.len() != 1 {
                            last_err = Error::CoseTimeStampMismatch;
                            continue;
                        }

                        // get signed message digest
                        let signed_message_digest = message_digest
                            .values
                            .first()
                            .ok_or(Error::CoseTimeStampMismatch)?
                            .deref()
                            .clone()
                            .decode(OctetString::take_from)
                            .map_err(|_| Error::CoseTimeStampMismatch)?
                            .to_bytes();

                        // get message digest hash alg
                        let digest_algorithm =
                            match DigestAlgorithm::try_from(&signer_info.digest_algorithm) {
                                Ok(d) => d,
                                Err(_) => {
                                    last_err = Error::UnsupportedType;
                                    continue;
                                }
                            };

                        let mut h = digest_algorithm.digester();
                        if let Some(content) = &sd.content_info.content {
                            h.update(&content.to_bytes());
                        }

                        let digest = h.finish();

                        if !vec_compare(&signed_message_digest, digest.as_ref()) {
                            last_err = Error::CoseTimeStampMismatch;
                            continue;
                        }
                    }
                    None => {
                        last_err = Error::CoseTimeStampMismatch;
                        continue;
                    }
                }
            }

            // build CMS structure to verify
            let tbs = match signer_info.signed_attributes_digested_content() {
                Ok(sdc) => match sdc {
                    Some(tbs) => tbs,
                    None => match &sd.content_info.content {
                        Some(d) => d.to_bytes().to_vec(),
                        None => return Err(Error::CoseTimeStampMismatch),
                    },
                },
                Err(_) => {
                    last_err = Error::CoseTimeStampMismatch;
                    continue;
                }
            };

            let hash_alg = &signer_info.digest_algorithm.algorithm;
            let sig_alg = &signer_info.signature_algorithm.algorithm;

            // grab signing certificate
            let sig_val = &signer_info.signature;
            let mut signing_key_der = Vec::<u8>::new();
            cert.tbs_certificate
                .subject_public_key_info
                .encode_ref()
                .write_encoded(bcder::Mode::Der, &mut signing_key_der)?;

            // verify signature of timestamp signature
            let validated_res: Result<bool> = if _sync {
                #[cfg(feature = "openssl")]
                {
                    let validator = get_local_validator(sig_alg, hash_alg)?;
                    validator.validate(&sig_val.to_bytes(), &tbs, &signing_key_der)
                }

                #[cfg(not(feature = "openssl"))]
                {
                    Ok(false)
                }
            } else {
                #[cfg(feature = "openssl")]
                {
                    let validator = get_local_validator(sig_alg, hash_alg)?;
                    validator.validate(&sig_val.to_bytes(), &tbs, &signing_key_der)
                }

                #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
                {
                    let mut certificate_der = Vec::<u8>::new();
                    cert.encode_ref()
                        .write_encoded(bcder::Mode::Der, &mut certificate_der)?;

                    crate::wasm::verify_data(
                        certificate_der,
                        get_validator_type(sig_alg, hash_alg),
                        sig_val.to_bytes().to_vec(),
                        tbs,
                    )
                    .await
                }

                #[cfg(all(
                    not(feature = "openssl"),
                    any(not(target_arch = "wasm32"), target_os = "wasi")
                ))]
                {
                    Ok(false)
                }
            };

            match validated_res {
                Ok(validated) => {
                    if validated {
                        // make sure this signature matches the expected data

                        // timestamp cert expiration
                        let not_before =
                            time_to_datetime(cert.tbs_certificate.validity.not_before.clone())
                                .timestamp();

                        let not_after =
                            time_to_datetime(cert.tbs_certificate.validity.not_after.clone())
                                .timestamp();

                        if !(signing_time >= not_before && signing_time <= not_after) {
                            last_err = Error::CoseTimeStampValidity;
                            continue;
                        }

                        // message imprint check
                        let digest_algorithm =
                            match DigestAlgorithm::try_from(&mi.hash_algorithm.algorithm) {
                                Ok(d) => d,
                                Err(_) => {
                                    last_err = Error::UnsupportedType;
                                    continue;
                                }
                            };

                        let mut h = digest_algorithm.digester();
                        h.update(data);
                        let digest = h.finish();

                        if !vec_compare(digest.as_ref(), &mi.hashed_message.to_bytes()) {
                            last_err = Error::CoseTimeStampMismatch;
                            continue;
                        }

                        // found a good value so return
                        return Ok(tst);
                    } else {
                        last_err = Error::CoseTimeStampMismatch;
                    }
                }
                Err(e) => last_err = e,
            }
        }
    }

    Err(last_err)
}

// Get TimeStampResponse from DER TimeStampResp bytes
pub(crate) fn get_timestamp_response(tsresp: &[u8]) -> Result<TimeStampResponse> {
    let ts = TimeStampResponse(
        Constructed::decode(tsresp, bcder::Mode::Der, |cons| {
            TimeStampResp::take_from(cons)
        })
        .map_err(|_e| Error::CoseInvalidTimeStamp)?,
    );

    Ok(ts)
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct TstToken {
    #[serde(with = "serde_bytes")]
    pub val: Vec<u8>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct TstContainer {
    #[serde(rename = "tstTokens")]
    pub tst_tokens: Vec<TstToken>,
}

impl TstContainer {
    pub fn new() -> Self {
        TstContainer {
            tst_tokens: Vec::new(),
        }
    }

    pub fn add_token(&mut self, token: TstToken) {
        self.tst_tokens.push(token);
    }
}

impl Default for TstContainer {
    fn default() -> Self {
        Self::new()
    }
}

// Wrap rfc3161 TimeStampRsp in COSE sigTst object
pub(crate) fn make_cose_timestamp(ts_data: &[u8]) -> TstContainer {
    let token = TstToken {
        val: ts_data.to_vec(),
    };

    let mut container = TstContainer::new();
    container.add_token(token);

    container
}
