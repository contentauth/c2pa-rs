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
use http::header;

use crate::{
    crypto::{
        asn1::rfc3161::{TimeStampReq, TimeStampResp},
        cose::CertificateTrustPolicy,
        time_stamp::{
            response::TimeStampResponse,
            verify::{verify_time_stamp, verify_time_stamp_async},
            TimeStampError,
        },
    },
    http::{
        AsyncGenericResolver, AsyncHttpResolver, HttpResolverError, SyncGenericResolver,
        SyncHttpResolver,
    },
    settings::Settings,
    status_tracker::StatusTracker,
};

/// Request an [RFC 3161] time stamp for a given piece of data from a timestamp
/// provider.
///
/// If successful, responds with the raw bytestream of the response.
///
/// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
#[async_generic]
pub fn default_rfc3161_request(
    url: &str,
    headers: Option<Vec<(String, String)>>,
    data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, TimeStampError> {
    let request = Constructed::decode(
        bcder::decode::SliceSource::new(data),
        bcder::Mode::Der,
        TimeStampReq::take_from,
    )
    .map_err(|_err| {
        TimeStampError::InternalError("failure to decode Constructed TimeStampReq".to_string())
    })?;

    let ts = if _sync {
        time_stamp_request_http(url, headers, &request)?
    } else {
        time_stamp_request_http_async(url, headers, &request).await?
    };

    let mut local_log = StatusTracker::default();
    let ctp = CertificateTrustPolicy::passthrough();

    // TODO: separate verifying time stamp and verifying time stamp trust into separate functions?
    //       do we need to pass settings here at all if `ctp` is set to pasthrough anyways?
    let mut settings = Settings::default();
    settings.verify.verify_timestamp_trust = false;

    // Make sure the time stamp is valid before we return it.
    if _sync {
        verify_time_stamp(&ts, message, &ctp, &mut local_log, &settings)?;
    } else {
        verify_time_stamp_async(&ts, message, &ctp, &mut local_log, &settings).await?;
    }

    Ok(ts)
}

#[async_generic]
fn time_stamp_request_http(
    url: &str,
    headers: Option<Vec<(String, String)>>,
    timestamp_request: &TimeStampReq,
) -> Result<Vec<u8>, TimeStampError> {
    // This function exists to work around a bug in serialization of
    // TimeStampResp so we just return the data directly.
    use std::io::Read;

    const HTTP_CONTENT_TYPE_REQUEST: &str = "application/timestamp-query";
    const HTTP_CONTENT_TYPE_RESPONSE: &str = "application/timestamp-reply";

    let mut body = Vec::<u8>::new();
    timestamp_request
        .encode_ref()
        .write_encoded(bcder::Mode::Der, &mut body)?;

    let mut request = http::Request::post(url);

    if let Some(headers) = headers {
        for (ref name, ref value) in headers {
            request = request.header(name.as_str(), value.as_str());
        }
    }

    let request = request.header(header::CONTENT_TYPE, HTTP_CONTENT_TYPE_REQUEST);

    let response = if _sync {
        SyncGenericResolver::new()
            .http_resolve(request.body(body).map_err(HttpResolverError::Http)?)?
    } else {
        AsyncGenericResolver::new()
            .http_resolve_async(request.body(body).map_err(HttpResolverError::Http)?)
            .await?
    };
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|header| header.to_str().ok());

    if response.status() == 200 && content_type == Some(HTTP_CONTENT_TYPE_RESPONSE) {
        let len = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|content_length| content_length.to_str().ok())
            .and_then(|content_length| content_length.parse().ok())
            .unwrap_or(20000);
        let mut response_bytes: Vec<u8> = Vec::with_capacity(len);

        response
            .into_body()
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
                if tst_info.nonce != timestamp_request.nonce {
                    return Err(TimeStampError::NonceMismatch);
                }
            }
        }

        Ok(response_bytes)
    } else {
        Err(TimeStampError::HttpErrorResponse(
            response.status().as_u16(),
            content_type.map(|content_type| content_type.to_owned()),
        ))
    }
}
