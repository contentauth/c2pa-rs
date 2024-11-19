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

use async_generic::async_generic;
use bcder::{decode::Constructed, encode::Values};

use crate::{
    asn1::{
        rfc3161::{PkiStatus, TimeStampReq, TimeStampResp, TstInfo, OID_CONTENT_TYPE_TST_INFO},
        rfc5652::{SignedData, OID_ID_SIGNED_DATA},
    },
    time_stamp::TimeStampError,
};

#[async_generic]
pub fn default_rfc3161_request(
    url: &str,
    headers: Option<Vec<(String, String)>>,
    data: &[u8],
    _message: &[u8],
) -> Result<Vec<u8>, TimeStampError> {
    let request = Constructed::decode(
        bcder::decode::SliceSource::new(data),
        bcder::Mode::Der,
        TimeStampReq::take_from,
    )
    .map_err(|_err| TimeStampError::InternalError("failure to decode Constructed TimeStampReq"))?;

    let ts = time_stamp_request_http(url, headers, &request)?;

    // sanity check
    // TO DO BEFORE MERGE: RESTORE THIS.
    // if _sync {
    //     verify_time_stamp(&ts, message)?;
    // } else {
    //     verify_time_stamp_async(&ts, message).await?;
    // }

    Ok(ts)
}

fn time_stamp_request_http(
    url: &str,
    headers: Option<Vec<(String, String)>>,
    request: &TimeStampReq,
) -> Result<Vec<u8>, TimeStampError> {
    // This function exists to work around a bug in serialization of
    // TimeStampResp so we just return the data directly.
    use std::io::Read;

    const HTTP_CONTENT_TYPE_REQUEST: &str = "application/time_stamp-query";
    const HTTP_CONTENT_TYPE_RESPONSE: &str = "application/time_stamp-reply";

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
        .send_bytes(&body)?;

    if response.status() == 200 && response.content_type() == HTTP_CONTENT_TYPE_RESPONSE {
        let len = response
            .header("Content-Length")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(20000);

        let mut response_bytes: Vec<u8> = Vec::with_capacity(len);

        response
            .into_reader()
            .take(1000000)
            .read_to_end(&mut response_bytes)?;

        let res = TimeStampResponse(
            Constructed::decode(response_bytes.as_ref(), bcder::Mode::Der, |cons| {
                TimeStampResp::take_from(cons)
            })
            .map_err(|e| TimeStampError::DecodeError(e.to_string()))?,
        );

        // Verify nonce was reflected, if present.
        if res.is_success() {
            if let Some(tst_info) = res.tst_info()? {
                if tst_info.nonce != request.nonce {
                    return Err(TimeStampError::NonceMismatch);
                }
            }
        }

        Ok(response_bytes)
    } else {
        Err(TimeStampError::HttpErrorResponse(
            response.status(),
            response.content_type().to_string(),
        ))
    }
}

struct TimeStampResponse(TimeStampResp);

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
            PkiStatus::Granted | PkiStatus::GrantedWithMods
        )
    }

    fn signed_data(&self) -> Result<Option<SignedData>, TimeStampError> {
        if let Some(token) = &self.0.time_stamp_token {
            if token.content_type == OID_ID_SIGNED_DATA {
                Ok(Some(
                    token
                        .content
                        .clone()
                        .decode(SignedData::take_from)
                        .map_err(|e| TimeStampError::DecodeError(e.to_string()))?,
                ))
            } else {
                Err(TimeStampError::DecodeError(
                    "Invalid OID for signed data".to_string(),
                ))
            }
        } else {
            Ok(None)
        }
    }

    fn tst_info(&self) -> Result<Option<TstInfo>, TimeStampError> {
        if let Some(signed_data) = self.signed_data()? {
            if signed_data.content_info.content_type == OID_CONTENT_TYPE_TST_INFO {
                if let Some(content) = signed_data.content_info.content {
                    Ok(Some(
                        Constructed::decode(content.to_bytes(), bcder::Mode::Der, |cons| {
                            TstInfo::take_from(cons)
                        })
                        .map_err(|e| TimeStampError::DecodeError(e.to_string()))?,
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

impl From<ureq::Error> for TimeStampError {
    fn from(err: ureq::Error) -> Self {
        // The `ureq::Error` type is very large (272 bytes on aarch64), which makes
        // Clippy complain. Rather than carrying that forward, we capture the
        // description from the error in the otherwise smaller `TimeStampError` type.
        Self::HttpConnectionError(err.to_string())
    }
}
