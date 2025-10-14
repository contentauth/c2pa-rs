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

use asn1_rs::nom::AsBytes;
use async_generic::async_generic;
use bcder::decode::Constructed;
use ciborium::value::Value;
use coset::{sig_structure_data, HeaderBuilder, Label, ProtectedHeader, SignatureContext};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    crypto::{
        asn1::rfc3161::{TimeStampResp, TstInfo},
        cose::{CertificateTrustPolicy, CoseError, TimeStampStorage},
        raw_signature::{AsyncRawSigner, RawSigner},
        time_stamp::{verify_time_stamp, verify_time_stamp_async, ContentInfo, TimeStampResponse},
    },
    status_tracker::StatusTracker,
};

/// Given a COSE signature, retrieve the `sigTst` header from it and validate
/// the information within it.
///
/// Return a [`TstInfo`] struct if available and valid.
#[async_generic]
pub(crate) fn validate_cose_tst_info(
    sign1: &coset::CoseSign1,
    data: &[u8],
    ctp: &CertificateTrustPolicy,
    validation_log: &mut StatusTracker,
) -> Result<TstInfo, CoseError> {
    let Some((sigtst, tss)) = &sign1
        .unprotected
        .rest
        .iter()
        .find_map(|x: &(Label, Value)| {
            if x.0 == Label::Text("sigTst2".to_string()) {
                Some((x.1.clone(), TimeStampStorage::V2_sigTst2_CTT))
            } else if x.0 == Label::Text("sigTst".to_string()) {
                Some((x.1.clone(), TimeStampStorage::V1_sigTst))
            } else {
                None
            }
        })
    else {
        return Err(CoseError::NoTimeStampToken);
    };

    // `maybe_sig_data` has to be declared outside the match block below so that the
    // slice we return can live long enough.
    let mut maybe_sig_data: Vec<u8> = vec![];
    let tbs = match tss {
        TimeStampStorage::V1_sigTst => data,
        TimeStampStorage::V2_sigTst2_CTT => {
            let sig_data = ByteBuf::from(sign1.signature.clone());
            ciborium::into_writer(&sig_data, &mut maybe_sig_data)
                .map_err(|e| CoseError::CborParsingError(e.to_string()))?;
            maybe_sig_data.as_slice()
        }
    };

    let mut time_cbor: Vec<u8> = vec![];
    ciborium::into_writer(sigtst, &mut time_cbor)
        .map_err(|e| CoseError::InternalError(e.to_string()))?;

    let tst_infos = if _sync {
        parse_and_validate_sigtst(&time_cbor, tbs, &sign1.protected, ctp, validation_log)?
    } else {
        parse_and_validate_sigtst_async(&time_cbor, tbs, &sign1.protected, ctp, validation_log)
            .await?
    };

    // For now, we only pay attention to the first time stamp header.
    // Technically, more are permitted, but we ignore them for now.
    let Some(tst_info) = tst_infos.into_iter().next() else {
        return Err(CoseError::NoTimeStampToken);
    };

    Ok(tst_info)
}

/// Parse the `sigTst` header from a COSE signature, which should contain one or
/// more `TstInfo` structures ([RFC 3161] time stamps).
///
/// Validate each time stamp and return them if valid.
///
/// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
#[async_generic]
pub(crate) fn parse_and_validate_sigtst(
    sigtst_cbor: &[u8],
    data: &[u8],
    p_header: &ProtectedHeader,
    ctp: &CertificateTrustPolicy,
    validation_log: &mut StatusTracker,
) -> Result<Vec<TstInfo>, CoseError> {
    let tst_container: TstContainer = ciborium::from_reader(sigtst_cbor)
        .map_err(|err| CoseError::CborParsingError(err.to_string()))?;

    let mut tstinfos: Vec<TstInfo> = vec![];

    for token in &tst_container.tst_tokens {
        let tbs = cose_countersign_data(data, p_header);

        let tst_info_res = if _sync {
            verify_time_stamp(&token.val, &tbs, ctp, validation_log)
        } else {
            verify_time_stamp_async(&token.val, &tbs, ctp, validation_log).await
        };

        if let Ok(tst_info) = tst_info_res {
            tstinfos.push(tst_info);
        }
    }

    if tstinfos.is_empty() {
        Err(CoseError::NoTimeStampToken)
    } else {
        Ok(tstinfos)
    }
}

/// Given an arbitrary message and a COSE protected header, generate the binary
/// blob to be signed as part of the COSE signature.
pub fn cose_countersign_data(data: &[u8], p_header: &ProtectedHeader) -> Vec<u8> {
    let aad: Vec<u8> = vec![];

    sig_structure_data(
        SignatureContext::CounterSignature,
        p_header.clone(),
        None,
        &aad,
        data,
    )
}

/// Raw contents of an [RFC 3161] time stamp.
///
/// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct TstToken {
    #[allow(missing_docs)]
    #[serde(with = "serde_bytes")]
    pub val: Vec<u8>,
}

#[derive(Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct TstContainer {
    #[serde(rename = "tstTokens")]
    tst_tokens: Vec<TstToken>,
}

impl TstContainer {
    pub(crate) fn add_token(&mut self, token: TstToken) {
        self.tst_tokens.push(token);
    }
}

/// Given a COSE [`ProtectedHeader`] and an arbitrary block of data, use the
/// provided [`TimeStampProvider`] or [`AsyncTimeStampProvider`] to request a
/// timestamp for that block of data.
///
/// [`TimeStampProvider`]: crate::crypto::time_stamp::TimeStampProvider
/// [`AsyncTimeStampProvider`]: crate::crypto::time_stamp::AsyncTimeStampProvider
#[async_generic(
    async_signature(
        ts_provider: &dyn AsyncRawSigner,
        data: &[u8],
        p_header: &ProtectedHeader,
        mut header_builder: HeaderBuilder,
        tss: TimeStampStorage,
    ))]
pub(crate) fn add_sigtst_header(
    ts_provider: &dyn RawSigner,
    data: &[u8],
    p_header: &ProtectedHeader,
    mut header_builder: HeaderBuilder,
    tss: TimeStampStorage,
) -> Result<HeaderBuilder, CoseError> {
    let sd = cose_countersign_data(data, p_header);

    let maybe_cts = if _sync {
        ts_provider.send_time_stamp_request(&sd)
    } else {
        ts_provider.send_time_stamp_request(&sd).await
    };

    if let Some(cts) = maybe_cts {
        let mut cts = cts?;

        if tss == TimeStampStorage::V2_sigTst2_CTT {
            // In `sigTst2`, we use only the `TimeStampToken` and not `TimeStampRsp` for
            // sigTst2
            cts = timestamptoken_from_timestamprsp(&cts).ok_or(CoseError::CborGenerationError(
                "unable to generate time stamp token".to_string(),
            ))?;
        }

        let cts = make_cose_timestamp(&cts);

        let mut sigtst_vec: Vec<u8> = vec![];
        ciborium::into_writer(&cts, &mut sigtst_vec)
            .map_err(|e| CoseError::CborGenerationError(e.to_string()))?;

        let sigtst_cbor: Value = ciborium::from_reader(sigtst_vec.as_slice())
            .map_err(|e| CoseError::CborGenerationError(e.to_string()))?;

        match tss {
            TimeStampStorage::V1_sigTst => {
                header_builder = header_builder.text_value("sigTst".to_string(), sigtst_cbor);
            }
            TimeStampStorage::V2_sigTst2_CTT => {
                header_builder = header_builder.text_value("sigTst2".to_string(), sigtst_cbor);
            }
        }
    }

    Ok(header_builder)
}

// Wrap RFC 3161 TimeStampRsp in COSE sigTst object.
fn make_cose_timestamp(ts_data: &[u8]) -> TstContainer {
    let token = TstToken {
        val: ts_data.to_vec(),
    };

    let mut container = TstContainer::default();
    container.add_token(token);

    container
}

/// Return DER encoded TimeStampToken used by sigTst2 from TimeStampResponse.
pub fn timestamptoken_from_timestamprsp(ts: &[u8]) -> Option<Vec<u8>> {
    let ts_resp = TimeStampResponse(
        Constructed::decode(ts, bcder::Mode::Der, TimeStampResp::take_from).ok()?,
    );

    let tst = ts_resp.0.time_stamp_token?;

    let a: Result<Vec<u32>, CoseError> = tst
        .content_type
        .iter()
        .map(|v| {
            v.to_u32()
                .ok_or(CoseError::InternalError("invalid component".to_string()))
        })
        .collect();

    let ci = ContentInfo {
        content_type: rasn::types::ObjectIdentifier::new(a.ok()?)?,
        content: rasn::types::Any::new(tst.content.as_bytes().to_vec()),
    };

    rasn::der::encode(&ci).ok()
}
