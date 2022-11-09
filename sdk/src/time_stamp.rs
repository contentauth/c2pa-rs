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

use std::convert::TryFrom;

use bcder::decode::Constructed;
use coset::{iana, sig_structure_data, HeaderBuilder, ProtectedHeader};
use serde::{Deserialize, Serialize};
use x509_certificate::DigestAlgorithm::{self};

/// Generate TimeStamp signature according to https://datatracker.ietf.org/doc/html/rfc3161
/// using the specified Time Authority
use crate::error::{Error, Result};
use crate::{
    asn1::{
        rfc3161::{TimeStampResp, TstInfo, OID_CONTENT_TYPE_TST_INFO},
        rfc5652::{CertificateChoices::Certificate, SignedData, OID_ID_SIGNED_DATA},
    },
    hash_utils::vec_compare,
    SigningAlg,
};

#[allow(dead_code)]
pub(crate) fn cose_countersign_data(data: &[u8], alg: SigningAlg) -> Vec<u8> {
    let alg_id = match alg {
        SigningAlg::Ps256 => HeaderBuilder::new()
            .algorithm(iana::Algorithm::PS256)
            .build(),
        SigningAlg::Ps384 => HeaderBuilder::new()
            .algorithm(iana::Algorithm::PS384)
            .build(),
        SigningAlg::Ps512 => HeaderBuilder::new()
            .algorithm(iana::Algorithm::PS512)
            .build(),
        SigningAlg::Es256 => HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .build(),
        SigningAlg::Es384 => HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES384)
            .build(),
        SigningAlg::Es512 => HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES512)
            .build(),
        SigningAlg::Ed25519 => HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .build(),
    };

    let p_header = ProtectedHeader {
        original_data: None,
        header: alg_id,
    };
    let aad: Vec<u8> = Vec::new();

    // create sig_structure_data to be signed
    sig_structure_data(
        coset::SignatureContext::CounterSignature,
        p_header,
        None,
        &aad,
        data,
    )
}

#[allow(dead_code)]
pub(crate) fn cose_timestamp_countersign(
    data: &[u8],
    alg: SigningAlg,
    tsa_url: &str,
) -> Result<Vec<u8>> {
    // create countersignature with TimeStampReq parameters
    // payload: data
    // context "CounterSigner"
    // certReq true
    // algorithm sha256

    // create sig data structure to be time stamped
    let sd = cose_countersign_data(data, alg);

    timestamp_data(tsa_url, &sd)
}

#[allow(dead_code)]
pub(crate) fn cose_sigtst_to_tstinfos(
    sigtst_cbor: &[u8],
    data: &[u8],
    alg: SigningAlg,
) -> Result<Vec<TstInfo>> {
    let tst_container: TstContainer =
        serde_cbor::from_slice(sigtst_cbor).map_err(|_err| Error::CoseTimeStampGeneration)?;

    let mut tstinfos: Vec<TstInfo> = Vec::new();

    for token in &tst_container.tst_tokens {
        let tbs = cose_countersign_data(data, alg);
        let tst_info = verify_timestamp(&token.val, &tbs)?;
        tstinfos.push(tst_info);
    }

    if tstinfos.is_empty() {
        Err(Error::NotFound)
    } else {
        Ok(tstinfos)
    }
}

/// Get URL to Time Authority to use
#[allow(dead_code)] // in case we make use of this later
pub fn get_ta_url() -> Option<String> {
    //const TA_URL: &str = "http://timestamp.digicert.com";

    match std::env::var("CAI_TA_URL") {
        Ok(url) => Some(url),
        Err(_) => None,
    }
}

/// internal only function to work around bug in serialization of TimeStampResponse
/// so we just return the data directly
#[cfg(feature = "sign")]
fn time_stamp_request_http(
    url: &str,
    request: &crate::asn1::rfc3161::TimeStampReq,
) -> Result<Vec<u8>> {
    use std::io::Read;

    use bcder::encode::Values;

    const HTTP_CONTENT_TYPE_REQUEST: &str = "application/timestamp-query";
    const HTTP_CONTENT_TYPE_RESPONSE: &str = "application/timestamp-reply";

    let mut body = Vec::<u8>::new();
    request
        .encode_ref()
        .write_encoded(bcder::Mode::Der, &mut body)?;

    let body_reader = std::io::Cursor::new(body);

    let response = ureq::post(url)
        .set("Content-Type", HTTP_CONTENT_TYPE_REQUEST)
        .send(body_reader)
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

/// Send a Time-Stamp request for a given message to an HTTP URL.
///
/// This is a wrapper around [time_stamp_request_http] that constructs the low-level
/// ASN.1 request object with reasonable defaults.

#[cfg(feature = "sign")]
fn time_stamp_message_http(
    url: &str,
    message: &[u8],
    digest_algorithm: DigestAlgorithm,
) -> Result<Vec<u8>> {
    use ring::rand::SecureRandom;

    let mut h = digest_algorithm.digester();
    h.update(message);
    let digest = h.finish();

    let mut random = [0u8; 8];
    ring::rand::SystemRandom::new()
        .fill(&mut random)
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

    time_stamp_request_http(url, &request)
}

pub struct TimeStampResponse(TimeStampResp);

impl std::ops::Deref for TimeStampResponse {
    type Target = TimeStampResp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TimeStampResponse {
    /// Whether the time stamp request was successful.
    #[cfg(feature = "sign")]
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
                        .decode(|cons| SignedData::take_from(cons))
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
/// Generate TimeStamp based on rfc3161 using "data" as MessageImprint and return raw TimeStampRsp bytes
#[allow(unused_variables)]
pub fn timestamp_data(url: &str, data: &[u8]) -> Result<Vec<u8>> {
    #[cfg(feature = "sign")]
    {
        let ts = time_stamp_message_http(url, data, x509_certificate::DigestAlgorithm::Sha256)?;

        // sanity check
        verify_timestamp(&ts, data)?;

        Ok(ts)
    }
    #[cfg(not(feature = "sign"))]
    {
        Err(Error::WasmNoCrypto)
    }
}
pub fn gt_to_datetime(
    gt: x509_certificate::asn1time::GeneralizedTime,
) -> chrono::DateTime<chrono::Utc> {
    gt.into()
}
fn time_to_datetime(t: x509_certificate::asn1time::Time) -> chrono::DateTime<chrono::Utc> {
    match t {
        x509_certificate::asn1time::Time::UtcTime(u) => *u,
        x509_certificate::asn1time::Time::GeneralTime(gt) => gt_to_datetime(gt),
    }
}
/// Returns TimeStamp token info if ts verifies against supplied data
pub fn verify_timestamp(ts: &[u8], data: &[u8]) -> Result<TstInfo> {
    let ts_resp = get_timestamp_response(ts)?;

    // make sure this signature matches the expected data
    let tst_opt = ts_resp.tst_info()?;
    let tst = tst_opt.ok_or(Error::CoseInvalidTimeStamp)?;
    let mi = &tst.message_imprint;

    let digest_algorithm = DigestAlgorithm::try_from(&mi.hash_algorithm.algorithm)
        .map_err(|_e| Error::UnsupportedType)?;

    let mut h = digest_algorithm.digester();
    h.update(data);
    let digest = h.finish();

    if !vec_compare(digest.as_ref(), &mi.hashed_message.to_bytes()) {
        return Err(Error::CoseTimeStampMismatch);
    }

    // check for timestamp expiration during stamping
    if let Ok(Some(sd)) = ts_resp.signed_data() {
        if let Some(cs) = sd.certificates {
            if !cs.is_empty() {
                let cert = match &cs[0] {
                    Certificate(c) => c,
                    _ => return Err(Error::CoseTimeStampValidity),
                };

                let signing_time = gt_to_datetime(tst.gen_time.clone()).timestamp();
                let not_before =
                    time_to_datetime(cert.tbs_certificate.validity.not_before.clone()).timestamp();

                let not_after =
                    time_to_datetime(cert.tbs_certificate.validity.not_after.clone()).timestamp();

                if !(signing_time >= not_before && signing_time <= not_after) {
                    return Err(Error::CoseTimeStampValidity);
                }
            }
        }
    }

    Ok(tst)
}

/// Get TimeStampResponse from DER TimeStampResp bytes
pub fn get_timestamp_response(tsresp: &[u8]) -> Result<TimeStampResponse> {
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

    #[cfg(feature = "sign")]
    pub fn add_token(&mut self, token: TstToken) {
        self.tst_tokens.push(token);
    }
}

impl Default for TstContainer {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrap rfc3161 TimeStampRsp in COSE sigTst object
#[cfg(feature = "sign")]
pub fn make_cose_timestamp(ts_data: &[u8]) -> TstContainer {
    let token = TstToken {
        val: ts_data.to_vec(),
    };

    let mut container = TstContainer::new();
    container.add_token(token);

    container
}
