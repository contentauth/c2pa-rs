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
use coset::{
    cbor::value::Value, sig_structure_data, HeaderBuilder, Label, ProtectedHeader, SignatureContext,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    crypto::{
        asn1::rfc3161::{TimeStampResp, TstInfo},
        cose::{AsyncCoseSigner, CertificateTrustPolicy, CoseError, CoseSigner, TimeStampStorage},
        time_stamp::{
            verify_time_stamp, verify_time_stamp_async, ContentInfo, TimeStampError,
            TimeStampResponse,
        },
    },
    log_item,
    status_tracker::StatusTracker,
    validation_status, Result,
};

/// Given a COSE signature, retrieve the `sigTst` header from it.
///
/// Return the raw unprotected value and `sigTst` version if available.
pub(crate) fn get_cose_tst_info(sign1: &coset::CoseSign1) -> Option<(&Value, TimeStampStorage)> {
    sign1
        .unprotected
        .rest
        .iter()
        .find_map(|x: &(Label, Value)| {
            if x.0 == Label::Text("sigTst2".to_string()) {
                Some((&x.1, TimeStampStorage::V2_sigTst2_CTT))
            } else if x.0 == Label::Text("sigTst".to_string()) {
                Some((&x.1, TimeStampStorage::V1_sigTst))
            } else {
                None
            }
        })
}

/// Given a COSE Sign1, return the raw bytes of the first timestamp token in
/// sigTst/sigTst2 if present.
pub(crate) fn timestamp_token_bytes_from_sign1(sign1: &coset::CoseSign1) -> Option<Vec<u8>> {
    let (sigtst, _tss) = get_cose_tst_info(sign1)?;
    let mut time_cbor: Vec<u8> = vec![];
    coset::cbor::into_writer(sigtst, &mut time_cbor).ok()?;
    let tst_container: TstContainer = coset::cbor::from_reader(time_cbor.as_slice()).ok()?;
    let token = tst_container.tst_tokens.first()?;
    Some(token.val.clone())
}

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
    verify_trust: bool,
) -> Result<TstInfo, CoseError> {
    let Some((sigtst, tss)) = get_cose_tst_info(sign1) else {
        return Err(CoseError::NoTimeStampToken);
    };

    // `maybe_sig_data` has to be declared outside the match block below so that the
    // slice we return can live long enough.
    let mut maybe_sig_data: Vec<u8> = vec![];
    let tbs = match tss {
        TimeStampStorage::V1_sigTst => data,
        TimeStampStorage::V2_sigTst2_CTT => {
            let sig_data = ByteBuf::from(sign1.signature.clone());
            coset::cbor::into_writer(&sig_data, &mut maybe_sig_data)
                .map_err(|e| CoseError::CborParsingError(e.to_string()))?;
            maybe_sig_data.as_slice()
        }
    };

    let mut time_cbor: Vec<u8> = vec![];
    coset::cbor::into_writer(sigtst, &mut time_cbor)
        .map_err(|e| CoseError::InternalError(e.to_string()))?;

    let tst_infos = if _sync {
        parse_and_validate_sigtst(
            &time_cbor,
            tbs,
            &sign1.protected,
            ctp,
            validation_log,
            verify_trust,
        )?
    } else {
        parse_and_validate_sigtst_async(
            &time_cbor,
            tbs,
            &sign1.protected,
            ctp,
            validation_log,
            verify_trust,
        )
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
    verify_trust: bool,
) -> Result<Vec<TstInfo>, CoseError> {
    let tst_container: TstContainer = coset::cbor::from_reader(sigtst_cbor)
        .map_err(|err| CoseError::CborParsingError(err.to_string()))?;

    let mut tstinfos: Vec<TstInfo> = vec![];

    // only a single value is allowed in tstTokens
    if tst_container.tst_tokens.len() > 1 {
        log_item!(
            "",
            "only a single timestamp response is allowed in a manifest",
            "parse_and_validate_sigtst"
        )
        .validation_status(validation_status::TIMESTAMP_MALFORMED)
        .informational(validation_log);
        return Err(CoseError::NoTimeStampToken);
    }

    for token in &tst_container.tst_tokens {
        let tbs = cose_countersign_data(data, p_header);

        let tst_info_res = if _sync {
            verify_time_stamp(&token.val, &tbs, ctp, validation_log, verify_trust)
        } else {
            verify_time_stamp_async(&token.val, &tbs, ctp, validation_log, verify_trust).await
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
        ts_provider: &dyn AsyncCoseSigner,
        data: &[u8],
        p_header: &ProtectedHeader,
        mut header_builder: HeaderBuilder,
        tss: TimeStampStorage,
    ))]
pub(crate) fn add_sigtst_header(
    ts_provider: &dyn CoseSigner,
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
            cts = timestamptoken_from_timestamprsp(&cts).map_err(|err| {
                TimeStampError::DecodeError(format!(
                    "unable to parse time stamp token from timestamp response: {err:?}"
                ))
            })?;
        }

        let cts = make_cose_timestamp(&cts);

        let mut sigtst_vec: Vec<u8> = vec![];
        coset::cbor::into_writer(&cts, &mut sigtst_vec)
            .map_err(|e| CoseError::CborGenerationError(e.to_string()))?;

        let sigtst_cbor: Value = coset::cbor::from_reader(sigtst_vec.as_slice())
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
pub fn timestamptoken_from_timestamprsp(ts: &[u8]) -> Result<Vec<u8>> {
    let ts_resp = TimeStampResponse(
        Constructed::decode(ts, bcder::Mode::Der, TimeStampResp::take_from).map_err(|err| {
            CoseError::InternalError(format!("invalid timestamp response: {err:?}"))
        })?,
    );

    let tst = ts_resp
        .0
        .time_stamp_token
        .ok_or_else(|| CoseError::InternalError("invalid timestamp token".to_string()))?;

    let a = tst
        .content_type
        .iter()
        .map(|v| {
            v.to_u32()
                .ok_or(CoseError::InternalError("invalid component".to_string()))
        })
        .collect::<Result<Vec<u32>, CoseError>>()?;

    let ci = ContentInfo {
        content_type: rasn::types::ObjectIdentifier::new(a).ok_or(CoseError::InternalError(
            "invalid object identifier for timestamp response".to_string(),
        ))?,
        content: rasn::types::Any::new(tst.content.as_bytes().to_vec()),
    };

    Ok(rasn::der::encode(&ci).map_err(|err| {
        CoseError::InternalError(format!("failed to encode timestamp token: {err:?}"))
    })?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::crypto::cose::cose_signer::tests::TestSigner;

    fn timestamp_value(tokens: &[&[u8]]) -> Value {
        Value::Map(vec![(
            Value::Text("tstTokens".into()),
            Value::Array(
                tokens
                    .iter()
                    .map(|token| {
                        Value::Map(vec![(
                            Value::Text("val".into()),
                            Value::Bytes(token.to_vec()),
                        )])
                    })
                    .collect(),
            ),
        )])
    }

    #[test]
    fn timestamp_headers_preserve_legacy_version_and_first_token() {
        for (name, version) in [
            ("sigTst", TimeStampStorage::V1_sigTst),
            ("sigTst2", TimeStampStorage::V2_sigTst2_CTT),
        ] {
            let mut sign1 = coset::CoseSign1::default();
            assert!(get_cose_tst_info(&sign1).is_none());
            assert!(timestamp_token_bytes_from_sign1(&sign1).is_none());
            sign1
                .unprotected
                .rest
                .push((Label::Text("unrelated".into()), Value::Null));
            sign1.unprotected.rest.push((
                Label::Text(name.into()),
                timestamp_value(&[b"first", b"second"]),
            ));
            assert_eq!(get_cose_tst_info(&sign1).unwrap().1, version);
            assert_eq!(timestamp_token_bytes_from_sign1(&sign1).unwrap(), b"first");
            for malformed in [Value::Null, timestamp_value(&[])] {
                sign1.unprotected.rest[1].1 = malformed;
                assert!(timestamp_token_bytes_from_sign1(&sign1).is_none());
            }
        }
    }

    #[c2pa_macros::c2pa_test_async]
    async fn missing_malformed_empty_and_multiple_tokens_have_no_valid_timestamp() {
        let policy = CertificateTrustPolicy::passthrough();
        for (value, malformed) in [
            (None, false),
            (Some(Value::Null), false),
            (Some(timestamp_value(&[])), false),
            (Some(timestamp_value(&[b"bad DER"])), true),
            (Some(timestamp_value(&[b"first", b"second"])), true),
        ] {
            let mut sign1 = coset::CoseSign1::default();
            if let Some(value) = value {
                sign1
                    .unprotected
                    .rest
                    .push((Label::Text("sigTst".into()), value));
            }
            let mut log = StatusTracker::default();
            assert!(validate_cose_tst_info(&sign1, b"payload", &policy, &mut log, false).is_err());
            assert_eq!(
                log.has_status(validation_status::TIMESTAMP_MALFORMED),
                malformed
            );
            let mut log = StatusTracker::default();
            assert!(
                validate_cose_tst_info_async(&sign1, b"payload", &policy, &mut log, false)
                    .await
                    .is_err()
            );
            assert_eq!(
                log.has_status(validation_status::TIMESTAMP_MALFORMED),
                malformed
            );
        }
    }

    #[c2pa_macros::c2pa_test_async]
    async fn timestamp_provider_is_optional_and_invalid_v2_response_is_an_error() {
        let mut signer = TestSigner::new(c2pa_raw_crypto::SigningAlg::Ed25519);
        let protected = ProtectedHeader::default();
        for version in [
            TimeStampStorage::V1_sigTst,
            TimeStampStorage::V2_sigTst2_CTT,
        ] {
            let header =
                add_sigtst_header(&signer, b"data", &protected, HeaderBuilder::new(), version)
                    .unwrap()
                    .build();
            assert!(header.rest.is_empty());
            let header = add_sigtst_header_async(
                &signer,
                b"data",
                &protected,
                HeaderBuilder::new(),
                version,
            )
            .await
            .unwrap()
            .build();
            assert!(header.rest.is_empty());
        }
        signer.timestamp = Some(b"invalid DER".to_vec());
        assert!(matches!(
            add_sigtst_header(
                &signer,
                b"data",
                &protected,
                HeaderBuilder::new(),
                TimeStampStorage::V2_sigTst2_CTT
            ),
            Err(CoseError::TimeStampError(TimeStampError::DecodeError(_)))
        ));
        assert!(matches!(
            add_sigtst_header_async(
                &signer,
                b"data",
                &protected,
                HeaderBuilder::new(),
                TimeStampStorage::V2_sigTst2_CTT
            )
            .await,
            Err(CoseError::TimeStampError(TimeStampError::DecodeError(_)))
        ));
        assert!(timestamptoken_from_timestamprsp(&[0x30, 5, 0x30, 3, 2, 1, 0]).is_err());
    }

    #[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
    #[c2pa_macros::c2pa_test_async]
    async fn locally_signed_timestamps_round_trip_both_versions_and_apis() {
        use openssl::hash::MessageDigest;

        use crate::crypto::{
            cose::{signing_time_from_sign1, signing_time_from_sign1_async},
            time_stamp::verify::message_imprint_regression::{build_token, OID_SHA256},
        };

        let protected = ProtectedHeader::default();
        let policy = CertificateTrustPolicy::passthrough();
        for version in [
            TimeStampStorage::V1_sigTst,
            TimeStampStorage::V2_sigTst2_CTT,
        ] {
            let mut signer = TestSigner::new(c2pa_raw_crypto::SigningAlg::Ed25519);
            let signature = vec![7; 64];
            let mut signature_cbor = Vec::new();
            coset::cbor::into_writer(&ByteBuf::from(signature.clone()), &mut signature_cbor)
                .unwrap();
            let data = if version == TimeStampStorage::V1_sigTst {
                b"payload".as_slice()
            } else {
                signature_cbor.as_slice()
            };
            let token = build_token(
                OID_SHA256,
                MessageDigest::sha256(),
                &cose_countersign_data(data, &protected),
            );
            signer.timestamp = Some(crate::crypto::time_stamp::response_der(0, Some(&token)));
            assert_eq!(
                timestamptoken_from_timestamprsp(signer.timestamp.as_ref().unwrap()).unwrap(),
                token
            );
            let sync = add_sigtst_header(&signer, data, &protected, HeaderBuilder::new(), version)
                .unwrap()
                .build();
            let asynchronous =
                add_sigtst_header_async(&signer, data, &protected, HeaderBuilder::new(), version)
                    .await
                    .unwrap()
                    .build();
            assert_eq!(sync, asynchronous);
            let sign1 = coset::CoseSign1 {
                protected: protected.clone(),
                unprotected: sync,
                signature,
                ..Default::default()
            };
            let expected_bytes = if version == TimeStampStorage::V1_sigTst {
                signer.timestamp.as_ref().unwrap()
            } else {
                &token
            };
            assert_eq!(
                &timestamp_token_bytes_from_sign1(&sign1).unwrap(),
                expected_bytes
            );
            let sync = validate_cose_tst_info(
                &sign1,
                b"payload",
                &policy,
                &mut StatusTracker::default(),
                false,
            )
            .unwrap();
            let asynchronous = validate_cose_tst_info_async(
                &sign1,
                b"payload",
                &policy,
                &mut StatusTracker::default(),
                false,
            )
            .await
            .unwrap();
            let expected = chrono::DateTime::<chrono::Utc>::from_timestamp(1577836800, 0).unwrap();
            assert_eq!(
                chrono::DateTime::<chrono::Utc>::from(sync.gen_time),
                expected
            );
            assert_eq!(
                chrono::DateTime::<chrono::Utc>::from(asynchronous.gen_time),
                expected
            );
            assert_eq!(
                signing_time_from_sign1(&sign1, b"payload", false),
                Some(expected)
            );
            assert_eq!(
                signing_time_from_sign1_async(&sign1, b"payload", false).await,
                Some(expected)
            );
        }
    }
}
