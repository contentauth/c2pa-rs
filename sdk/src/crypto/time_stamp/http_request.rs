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

use std::time::Duration;

use async_generic::async_generic;
use bcder::{decode::Constructed, encode::Values};
use http::header;

use crate::{
    context::Context,
    crypto::{
        asn1::rfc3161::{TimeStampReq, TimeStampResp},
        cose::CertificateTrustPolicy,
        time_stamp::{
            response::TimeStampResponse,
            verify::{verify_time_stamp, verify_time_stamp_async},
            TimeStampError,
        },
    },
    http::{HttpResolverError, RequestTimeout},
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
    context: &Context,
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
        time_stamp_request_http_with_retries(url, headers, &request, context)?
    } else {
        time_stamp_request_http_async(url, headers, &request, context).await?
    };

    let mut local_log = StatusTracker::default();
    let ctp = CertificateTrustPolicy::passthrough();

    // Make sure the time stamp is valid before we return it.
    if _sync {
        verify_time_stamp(&ts, message, &ctp, &mut local_log, false)?;
    } else {
        verify_time_stamp_async(&ts, message, &ctp, &mut local_log, false).await?;
    }

    Ok(ts)
}

/// Sends a blocking time-stamp request, and sends it again after a transient failure.
///
/// The number of attempts and the pause between them come from the context's settings
/// ([`Core::time_stamp_request_attempts`], [`Core::time_stamp_retry_delay_in_ms`]). Only the
/// blocking path retries: the async one has no runtime-independent way to pause.
///
/// [`Core::time_stamp_request_attempts`]: crate::settings::Core::time_stamp_request_attempts
/// [`Core::time_stamp_retry_delay_in_ms`]: crate::settings::Core::time_stamp_retry_delay_in_ms
fn time_stamp_request_http_with_retries(
    url: &str,
    headers: Option<Vec<(String, String)>>,
    timestamp_request: &TimeStampReq,
    context: &Context,
) -> Result<Vec<u8>, TimeStampError> {
    let core = &context.settings().core;
    let attempts = core.time_stamp_request_attempts.max(1);
    let mut delay = Duration::from_millis(core.time_stamp_retry_delay_in_ms);
    let mut attempt = 1;
    loop {
        match time_stamp_request_http(url, headers.clone(), timestamp_request, context) {
            Err(err) if attempt < attempts && is_transient(&err) => {
                std::thread::sleep(delay);
                delay = delay.saturating_mul(2);
                attempt += 1;
            }
            result => return result,
        }
    }
}

/// Whether another attempt of a time-stamp request may succeed: no answer, a timeout, or an
/// HTTP status that asks to try again later.
fn is_transient(err: &TimeStampError) -> bool {
    match err {
        TimeStampError::HttpErrorResponse(status, _) => {
            matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
        }
        TimeStampError::HttpConnectionError(_) | TimeStampError::IoError(_) => true,
        TimeStampError::HttpResolverError(
            HttpResolverError::Io(_) | HttpResolverError::Other(_),
        ) => true,
        _ => false,
    }
}

#[async_generic]
fn time_stamp_request_http(
    url: &str,
    headers: Option<Vec<(String, String)>>,
    timestamp_request: &TimeStampReq,
    context: &Context,
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

    let request = request
        .header(header::CONTENT_TYPE, HTTP_CONTENT_TYPE_REQUEST)
        .extension(RequestTimeout(Duration::from_millis(
            context.settings().core.time_stamp_request_timeout_in_ms,
        )));

    let response = if _sync {
        context
            .resolver()
            .http_resolve(request.body(body).map_err(HttpResolverError::Http)?)?
    } else {
        context
            .resolver_async()
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::{
        collections::VecDeque,
        io::{self, Cursor, Read},
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use http::{Request, Response};
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;
    use crate::{
        crypto::time_stamp::{default_rfc3161_message, response_der},
        http::{AsyncHttpResolver, SyncHttpResolver},
    };

    #[derive(Clone)]
    struct FixtureResolver {
        status: u16,
        content_type: Option<&'static str>,
        content_length: Option<&'static str>,
        body: Vec<u8>,
        fail_read: bool,
        fail_resolve: bool,
    }

    impl FixtureResolver {
        fn new(body: Vec<u8>) -> Self {
            Self {
                status: 200,
                content_type: Some("application/timestamp-reply"),
                content_length: None,
                body,
                fail_read: false,
                fail_resolve: false,
            }
        }

        fn context(self) -> Context {
            Context::new()
                .with_resolver(self.clone())
                .with_resolver_async(self)
        }
    }

    struct BrokenReader;
    impl Read for BrokenReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("test read failure"))
        }
    }

    impl SyncHttpResolver for FixtureResolver {
        fn http_resolve(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri(), "https://tsa.example/");
            assert_eq!(
                request.headers()[header::CONTENT_TYPE],
                "application/timestamp-query"
            );
            assert_eq!(request.headers()["x-test"], "characterization");
            assert!(Constructed::decode(
                request.body().as_slice(),
                bcder::Mode::Der,
                TimeStampReq::take_from
            )
            .is_ok());
            if self.fail_resolve {
                return Err(HttpResolverError::SyncHttpResolverNotImplemented);
            }

            let mut response = Response::builder().status(self.status);
            if let Some(value) = self.content_type {
                response = response.header(header::CONTENT_TYPE, value);
            }

            if let Some(value) = self.content_length {
                response = response.header(header::CONTENT_LENGTH, value);
            }

            let body: Box<dyn Read> = if self.fail_read {
                Box::new(BrokenReader)
            } else {
                Box::new(Cursor::new(self.body.clone()))
            };
            Ok(response.body(body).unwrap())
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl AsyncHttpResolver for FixtureResolver {
        async fn http_resolve_async(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            self.http_resolve(request)
        }
    }

    fn request() -> TimeStampReq {
        Constructed::decode(
            default_rfc3161_message(b"data").unwrap().as_slice(),
            bcder::Mode::Der,
            TimeStampReq::take_from,
        )
        .unwrap()
    }

    fn headers() -> Option<Vec<(String, String)>> {
        Some(vec![("x-test".into(), "characterization".into())])
    }

    #[c2pa_macros::c2pa_test_async]
    async fn status_content_type_decode_and_transport_failures_propagate() {
        let request = request();
        for (status, content_type) in [
            (503, Some("application/timestamp-reply")),
            (200, Some("application/octet-stream")),
            (200, None),
        ] {
            let mut resolver = FixtureResolver::new(Vec::new());
            resolver.status = status;
            resolver.content_type = content_type;
            let context = resolver.context();
            for result in [
                time_stamp_request_http("https://tsa.example/", headers(), &request, &context),
                time_stamp_request_http_async(
                    "https://tsa.example/",
                    headers(),
                    &request,
                    &context,
                )
                .await,
            ] {
                assert!(
                    matches!(result, Err(TimeStampError::HttpErrorResponse(s, c)) if s == status && c.as_deref() == content_type)
                );
            }
        }

        for (read, resolve) in [(false, false), (true, false), (false, true)] {
            let mut resolver = FixtureResolver::new(vec![0]);
            resolver.fail_read = read;
            resolver.fail_resolve = resolve;
            let context = resolver.context();
            for result in [
                time_stamp_request_http("https://tsa.example/", headers(), &request, &context),
                time_stamp_request_http_async(
                    "https://tsa.example/",
                    headers(),
                    &request,
                    &context,
                )
                .await,
            ] {
                assert!(match result {
                    Err(TimeStampError::IoError(_)) => read,
                    Err(TimeStampError::HttpResolverError(_)) => resolve,
                    Err(TimeStampError::DecodeError(_)) => !read && !resolve,
                    _ => false,
                });
            }
        }

        let context = FixtureResolver::new(Vec::new()).context();
        assert!(matches!(
            default_rfc3161_request(
                "https://tsa.example/",
                headers(),
                b"invalid",
                b"data",
                &context
            ),
            Err(TimeStampError::InternalError(_))
        ));
        assert!(matches!(
            default_rfc3161_request_async(
                "https://tsa.example/",
                headers(),
                b"invalid",
                b"data",
                &context
            )
            .await,
            Err(TimeStampError::InternalError(_))
        ));
    }

    /// One scripted answer of [`SequenceResolver`].
    enum Outcome {
        Status(u16),
        Unreachable,
        Disallowed,
    }

    /// Answers each request with the next scripted outcome, then with a well-formed response,
    /// and records the timeout each request carried.
    #[derive(Clone)]
    struct SequenceResolver {
        outcomes: Arc<Mutex<VecDeque<Outcome>>>,
        timeouts: Arc<Mutex<Vec<Option<RequestTimeout>>>>,
    }

    impl SequenceResolver {
        fn new(outcomes: Vec<Outcome>) -> Self {
            Self {
                outcomes: Arc::new(Mutex::new(outcomes.into())),
                timeouts: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn calls(&self) -> usize {
            self.timeouts.lock().unwrap().len()
        }
    }

    impl SyncHttpResolver for SequenceResolver {
        fn http_resolve(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            self.timeouts
                .lock()
                .unwrap()
                .push(request.extensions().get::<RequestTimeout>().copied());
            let (status, body) = match self.outcomes.lock().unwrap().pop_front() {
                Some(Outcome::Unreachable) => {
                    return Err(HttpResolverError::Io(io::Error::from(
                        io::ErrorKind::ConnectionRefused,
                    )))
                }
                Some(Outcome::Disallowed) => {
                    return Err(HttpResolverError::UriDisallowed {
                        uri: request.uri().to_string(),
                    })
                }
                Some(Outcome::Status(status)) => (status, Vec::new()),
                None => (200, response_der(2, None)),
            };
            let body: Box<dyn Read> = Box::new(Cursor::new(body));
            Ok(Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/timestamp-reply")
                .body(body)
                .unwrap())
        }
    }

    /// Sends a request through `resolver` with the given attempts, a 2 s timeout and no pause.
    fn request_with_retries(
        resolver: &SequenceResolver,
        attempts: u32,
    ) -> Result<Vec<u8>, TimeStampError> {
        let context = Context::new()
            .with_settings_value("core.time_stamp_request_attempts", attempts)
            .unwrap()
            .with_settings_value("core.time_stamp_request_timeout_in_ms", 2000u64)
            .unwrap()
            .with_settings_value("core.time_stamp_retry_delay_in_ms", 0u64)
            .unwrap()
            .with_resolver(resolver.clone());
        time_stamp_request_http_with_retries("https://tsa.example/", None, &request(), &context)
    }

    #[test]
    fn transient_failures_are_retried_with_a_timeout_on_each_attempt() {
        let resolver = SequenceResolver::new(vec![Outcome::Unreachable, Outcome::Status(503)]);
        assert_eq!(
            request_with_retries(&resolver, 3).unwrap(),
            response_der(2, None)
        );
        assert_eq!(resolver.calls(), 3);
        assert!(resolver
            .timeouts
            .lock()
            .unwrap()
            .iter()
            .all(|timeout| *timeout == Some(RequestTimeout(Duration::from_millis(2000)))));
    }

    #[test]
    fn retries_stop_after_the_last_attempt() {
        for attempts in [1, 2, 5] {
            let resolver =
                SequenceResolver::new((0..attempts + 1).map(|_| Outcome::Status(429)).collect());
            assert!(matches!(
                request_with_retries(&resolver, attempts),
                Err(TimeStampError::HttpErrorResponse(429, _))
            ));
            assert_eq!(resolver.calls(), attempts as usize);
        }
    }

    #[test]
    fn permanent_failures_are_not_retried() {
        let resolver = SequenceResolver::new(vec![Outcome::Status(400)]);
        assert!(matches!(
            request_with_retries(&resolver, 3),
            Err(TimeStampError::HttpErrorResponse(400, _))
        ));
        assert_eq!(resolver.calls(), 1);

        let resolver = SequenceResolver::new(vec![Outcome::Disallowed]);
        assert!(matches!(
            request_with_retries(&resolver, 3),
            Err(TimeStampError::HttpResolverError(
                HttpResolverError::UriDisallowed { .. }
            ))
        ));
        assert_eq!(resolver.calls(), 1);
    }

    #[c2pa_macros::c2pa_test_async]
    async fn non_granted_response_is_preserved_by_transport() {
        let response = response_der(2, None);
        let context = FixtureResolver::new(response.clone()).context();
        assert_eq!(
            time_stamp_request_http("https://tsa.example/", headers(), &request(), &context)
                .unwrap(),
            response
        );
        assert_eq!(
            time_stamp_request_http_async("https://tsa.example/", headers(), &request(), &context)
                .await
                .unwrap(),
            response
        );
    }

    #[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
    #[c2pa_macros::c2pa_test_async]
    async fn valid_response_is_verified_and_nonce_mismatch_is_rejected() {
        use openssl::hash::MessageDigest;

        use crate::crypto::time_stamp::verify::message_imprint_regression::{
            build_token, OID_SHA256,
        };

        let token = build_token(OID_SHA256, MessageDigest::sha256(), b"data");
        let response = response_der(0, Some(&token));
        let mut request = request();
        request.nonce = None;
        for content_length in [None, Some("invalid"), Some("0"), Some("4096")] {
            let mut resolver = FixtureResolver::new(response.clone());
            resolver.content_length = content_length;
            let context = resolver.context();
            let mut body = Vec::new();
            request
                .encode_ref()
                .write_encoded(bcder::Mode::Der, &mut body)
                .unwrap();
            assert_eq!(
                default_rfc3161_request(
                    "https://tsa.example/",
                    headers(),
                    &body,
                    b"data",
                    &context
                )
                .unwrap(),
                response
            );
            assert_eq!(
                default_rfc3161_request_async(
                    "https://tsa.example/",
                    headers(),
                    &body,
                    b"data",
                    &context
                )
                .await
                .unwrap(),
                response
            );
        }
        request.nonce = Some(bcder::Integer::from(1));
        let context = FixtureResolver::new(response).context();
        assert!(matches!(
            time_stamp_request_http("https://tsa.example/", headers(), &request, &context),
            Err(TimeStampError::NonceMismatch)
        ));
        assert!(matches!(
            time_stamp_request_http_async("https://tsa.example/", headers(), &request, &context)
                .await,
            Err(TimeStampError::NonceMismatch)
        ));
    }
}
