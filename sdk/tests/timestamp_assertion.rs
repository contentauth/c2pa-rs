// Copyright 2025 Adobe. All rights reserved.
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

use std::{
    io::{Cursor, Read, Seek},
    sync::{Arc, Mutex},
};

use c2pa::{
    assertions::{self, TimeStamp},
    http::{
        http::{Request, Response},
        HttpResolverError, SyncHttpResolver,
    },
    Builder, BuilderIntent, Context, Reader, Result, Signer,
};
#[cfg(not(target_arch = "wasm32"))]
use c2pa::{http::AsyncHttpResolver, AsyncSigner};

mod common;
use common::test_settings;

const TEST_IMAGE: &[u8] = include_bytes!("fixtures/no_manifest.jpg");
const FORMAT: &str = "image/jpeg";

// Basic wrapper around a Signer to include a time authority URL.
struct WrappedTsaSigner(Box<dyn Signer + Send + Sync>);

impl Signer for WrappedTsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.0.sign(data)
    }

    fn alg(&self) -> c2pa::SigningAlg {
        self.0.alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        self.0.certs()
    }

    fn reserve_size(&self) -> usize {
        self.0.reserve_size()
    }

    fn time_authority_url(&self) -> Option<String> {
        Some("http://timestamp.digicert.com".to_owned())
    }
}

const MOCK_TSA_URL: &str = "http://tsa.invalid/timestamp";
const MOCK_TSA_AUTHORIZATION: &str = "Bearer test-token";

// Wrapper around a Signer that authenticates to its time authority with a request header.
struct AuthenticatedTsaSigner(Box<dyn Signer + Send + Sync>);

impl Signer for AuthenticatedTsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.0.sign(data)
    }

    fn alg(&self) -> c2pa::SigningAlg {
        self.0.alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        self.0.certs()
    }

    fn reserve_size(&self) -> usize {
        self.0.reserve_size()
    }

    fn time_authority_url(&self) -> Option<String> {
        Some(MOCK_TSA_URL.to_owned())
    }

    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        Some(vec![(
            "Authorization".to_owned(),
            MOCK_TSA_AUTHORIZATION.to_owned(),
        )])
    }
}

// Records every request it receives and fails it, so no real time authority is contacted.
#[derive(Clone, Default)]
struct RecordingResolver {
    requests: Arc<Mutex<Vec<Request<Vec<u8>>>>>,
}

impl SyncHttpResolver for RecordingResolver {
    fn http_resolve(
        &self,
        request: Request<Vec<u8>>,
    ) -> std::result::Result<Response<Box<dyn Read>>, HttpResolverError> {
        self.requests.lock().unwrap().push(request);
        Err(HttpResolverError::Io(std::io::Error::other(
            "mock time authority is unreachable",
        )))
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl AsyncHttpResolver for RecordingResolver {
    async fn http_resolve_async(
        &self,
        request: Request<Vec<u8>>,
    ) -> std::result::Result<Response<Box<dyn Read>>, HttpResolverError> {
        self.http_resolve(request)
    }
}

// Async counterpart of `AuthenticatedTsaSigner`.
#[cfg(not(target_arch = "wasm32"))]
struct AsyncAuthenticatedTsaSigner(c2pa::CallbackSigner);

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl AsyncSigner for AsyncAuthenticatedTsaSigner {
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        AsyncSigner::sign(&self.0, data).await
    }

    fn alg(&self) -> c2pa::SigningAlg {
        AsyncSigner::alg(&self.0)
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        AsyncSigner::certs(&self.0)
    }

    fn reserve_size(&self) -> usize {
        AsyncSigner::reserve_size(&self.0)
    }

    fn time_authority_url(&self) -> Option<String> {
        Some(MOCK_TSA_URL.to_owned())
    }

    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        Some(vec![(
            "Authorization".to_owned(),
            MOCK_TSA_AUTHORIZATION.to_owned(),
        )])
    }
}

// Sign a manifest with a child ingredient and add the parent manifest
// as a timestamp assertion in the main manifest.
#[test]
fn timestamp_assertion_parent_scope() {
    let base_settings = test_settings();
    let child_context = Context::new().with_settings(base_settings).unwrap();

    let mut child_image = Cursor::new(Vec::new());

    let mut builder = Builder::from_context(child_context);
    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut Cursor::new(TEST_IMAGE),
            &mut child_image,
        )
        .unwrap();

    let mut parent_settings = test_settings();
    parent_settings
        .update_from_str(
            &toml::toml! {
                [builder.auto_timestamp_assertion]
                enabled = true
                skip_existing = false
                fetch_scope = "parent"
            }
            .to_string(),
            "toml",
        )
        .unwrap();

    child_image.rewind().unwrap();

    let mut parent_image = Cursor::new(Vec::new());

    let parent_context = Context::new().with_settings(parent_settings).unwrap();
    let mut builder = Builder::from_context(parent_context);
    builder.set_intent(BuilderIntent::Update);
    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut child_image,
            &mut parent_image,
        )
        .unwrap();

    parent_image.rewind().unwrap();

    let reader = Reader::default().with_stream(FORMAT, parent_image).unwrap();
    let timestamp_assertion: TimeStamp = reader
        .active_manifest()
        .unwrap()
        .find_assertion(assertions::labels::TIMESTAMP)
        .unwrap();

    let child_manifest_label = reader.active_manifest().unwrap().ingredients()[0]
        .active_manifest()
        .unwrap();
    assert!(timestamp_assertion
        .get_timestamp(child_manifest_label)
        .is_some());
}

// Sign a manifest with a child ingredient and add all manifests (excluding active)
// as a timestamp assertion in the main manifest.
#[test]
fn timestamp_assertion_all_scope() {
    let base_settings = test_settings();
    let child_context = Context::new().with_settings(base_settings).unwrap();

    let mut child_image = Cursor::new(Vec::new());

    let mut builder = Builder::from_context(child_context);
    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut Cursor::new(TEST_IMAGE),
            &mut child_image,
        )
        .unwrap();

    let mut parent_settings = test_settings();
    parent_settings
        .update_from_str(
            &toml::toml! {
                [builder.auto_timestamp_assertion]
                enabled = true
                skip_existing = false
                fetch_scope = "all"
            }
            .to_string(),
            "toml",
        )
        .unwrap();

    child_image.rewind().unwrap();

    let mut parent_image = Cursor::new(Vec::new());

    let parent_context = Context::new().with_settings(parent_settings).unwrap();
    let mut builder = Builder::from_context(parent_context);
    builder.set_intent(BuilderIntent::Update);
    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut child_image,
            &mut parent_image,
        )
        .unwrap();

    parent_image.rewind().unwrap();

    let reader = Reader::default().with_stream(FORMAT, parent_image).unwrap();
    let timestamp_assertion: TimeStamp = reader
        .active_manifest()
        .unwrap()
        .find_assertion(assertions::labels::TIMESTAMP)
        .unwrap();

    let child_manifest_label = reader.active_manifest().unwrap().ingredients()[0]
        .active_manifest()
        .unwrap();
    assert!(timestamp_assertion
        .get_timestamp(child_manifest_label)
        .is_some());
    // Verify the provenance claim isn't included.
    assert!(timestamp_assertion
        .get_timestamp(reader.active_label().unwrap())
        .is_none());
}

// Sign a manifest with a child ingredient and add the ingredient's active manifest label
// as a timestamp assertion in the main manifest.
#[test]
fn timestamp_assertion_explicit_builder() {
    let settings = test_settings();
    let context = Context::new().with_settings(settings).unwrap();

    let mut child_image = Cursor::new(Vec::new());

    let mut builder = Builder::from_context(context);
    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut Cursor::new(TEST_IMAGE),
            &mut child_image,
        )
        .unwrap();

    let mut parent_image = Cursor::new(Vec::new());

    let mut builder = Builder::default();
    builder.set_intent(BuilderIntent::Update);

    child_image.rewind().unwrap();
    let reader = Reader::default()
        .with_stream(FORMAT, &mut child_image)
        .unwrap();
    builder.add_timestamp(reader.active_label().unwrap());
    child_image.rewind().unwrap();

    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut child_image,
            &mut parent_image,
        )
        .unwrap();

    parent_image.rewind().unwrap();

    let reader = Reader::default().with_stream(FORMAT, parent_image).unwrap();
    let timestamp_assertion: TimeStamp = reader
        .active_manifest()
        .unwrap()
        .find_assertion(assertions::labels::TIMESTAMP)
        .unwrap();

    let child_manifest_label = reader.active_manifest().unwrap().ingredients()[0]
        .active_manifest()
        .unwrap();
    assert!(timestamp_assertion
        .get_timestamp(child_manifest_label)
        .is_some());
}

// Sign a manifest with a child ingredient using an explicit signer, then use `save_to_stream`
// (which resolves the signer from the context instead of taking one explicitly) to sign the
// parent manifest and confirm the timestamp assertion is still added.
#[test]
fn timestamp_assertion_save_to_stream() {
    let settings = test_settings();
    let context = Context::new().with_settings(settings).unwrap();

    let mut child_image = Cursor::new(Vec::new());

    let mut builder = Builder::from_context(context);
    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut Cursor::new(TEST_IMAGE),
            &mut child_image,
        )
        .unwrap();

    child_image.rewind().unwrap();
    let reader = Reader::default()
        .with_stream(FORMAT, &mut child_image)
        .unwrap();
    let child_manifest_label = reader.active_label().unwrap().to_owned();
    child_image.rewind().unwrap();

    let parent_context = Context::new()
        .with_settings(test_settings())
        .unwrap()
        .with_signer(WrappedTsaSigner(Box::new(common::test_signer())));

    let mut builder = Builder::from_context(parent_context);
    builder.set_intent(BuilderIntent::Update);
    builder.add_timestamp(child_manifest_label.as_str());

    let mut parent_image = Cursor::new(Vec::new());
    builder
        .save_to_stream(FORMAT, &mut child_image, &mut parent_image)
        .unwrap();

    parent_image.rewind().unwrap();

    let reader = Reader::default().with_stream(FORMAT, parent_image).unwrap();
    let timestamp_assertion: TimeStamp = reader
        .active_manifest()
        .unwrap()
        .find_assertion(assertions::labels::TIMESTAMP)
        .unwrap();

    assert!(timestamp_assertion
        .get_timestamp(&child_manifest_label)
        .is_some());
}

// Sign a manifest with a child ingredient and timestamp assertion it, then sign the parent manifest
// again and skip timestamping all existing timestamped manifests.
#[test]
fn timestamp_assertion_skip_existing() {
    let settings = test_settings();

    let mut child_image = Cursor::new(Vec::new());

    let mut builder =
        Builder::from_context(Context::new().with_settings(settings.clone()).unwrap());
    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut Cursor::new(TEST_IMAGE),
            &mut child_image,
        )
        .unwrap();

    child_image.rewind().unwrap();

    let mut parent_image = Cursor::new(Vec::new());

    let mut builder = Builder::default();
    builder.set_intent(BuilderIntent::Update);
    builder
        .sign(
            &common::test_signer(),
            FORMAT,
            &mut child_image,
            &mut parent_image,
        )
        .unwrap();

    let mut skip_settings = settings;
    skip_settings
        .update_from_str(
            &toml::toml! {
                [builder.auto_timestamp_assertion]
                enabled = true
                skip_existing = true
                fetch_scope = "all"
            }
            .to_string(),
            "toml",
        )
        .unwrap();

    parent_image.rewind().unwrap();

    let mut parent_parent_image = Cursor::new(Vec::new());

    // Sign it one last time to ensure the original child manifest isn't timestamped again.
    let mut builder = Builder::from_context(Context::new().with_settings(skip_settings).unwrap());
    builder.set_intent(BuilderIntent::Update);
    builder
        .sign(
            &WrappedTsaSigner(Box::new(common::test_signer())),
            FORMAT,
            &mut parent_image,
            &mut parent_parent_image,
        )
        .unwrap();

    parent_parent_image.rewind().unwrap();

    let reader = Reader::default()
        .with_stream(FORMAT, parent_parent_image)
        .unwrap();
    let timestamp_assertion: TimeStamp = reader
        .active_manifest()
        .unwrap()
        .find_assertion(assertions::labels::TIMESTAMP)
        .unwrap();
    assert_eq!(timestamp_assertion.0.len(), 1);

    let parent_manifest_label = reader.active_manifest().unwrap().ingredients()[0]
        .active_manifest()
        .unwrap();
    assert!(timestamp_assertion
        .get_timestamp(parent_manifest_label)
        .is_some());
}

// Sign a child manifest without a TSA, then return it along with an update builder for the parent
// whose context records (and fails) every HTTP request through `resolver`.
fn child_image_and_parent_builder(resolver: &RecordingResolver) -> (Cursor<Vec<u8>>, Builder) {
    let mut child_image = Cursor::new(Vec::new());

    // The child only needs a manifest to be timestamped, so it is signed without a TSA.
    let mut builder = Builder::from_context(Context::new().with_settings(test_settings()).unwrap());
    builder
        .sign(
            &common::test_signer(),
            FORMAT,
            &mut Cursor::new(TEST_IMAGE),
            &mut child_image,
        )
        .unwrap();

    let mut parent_settings = test_settings();
    parent_settings
        .update_from_str(
            &toml::toml! {
                [builder.auto_timestamp_assertion]
                enabled = true
                skip_existing = false
                fetch_scope = "parent"
            }
            .to_string(),
            "toml",
        )
        .unwrap();

    child_image.rewind().unwrap();

    let parent_context = Context::new()
        .with_settings(parent_settings)
        .unwrap()
        .with_resolver(resolver.clone());
    #[cfg(not(target_arch = "wasm32"))]
    let parent_context = parent_context.with_resolver_async(resolver.clone());

    let mut builder = Builder::from_context(parent_context);
    builder.set_intent(BuilderIntent::Update);

    (child_image, builder)
}

// Assert `resolver` saw exactly one time authority request and that it carried the signer's
// headers alongside the SDK's `Content-Type`.
fn assert_tsa_request_has_signer_headers(resolver: &RecordingResolver) {
    let requests = resolver.requests.lock().unwrap();
    let tsa_requests: Vec<_> = requests
        .iter()
        .filter(|request| request.uri() == MOCK_TSA_URL)
        .collect();
    assert_eq!(
        tsa_requests.len(),
        1,
        "expected one time authority request, got {requests:?}"
    );

    let headers = tsa_requests[0].headers();
    assert_eq!(
        headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok()),
        Some(MOCK_TSA_AUTHORIZATION)
    );
    assert_eq!(
        headers
            .get("Content-Type")
            .and_then(|value| value.to_str().ok()),
        Some("application/timestamp-query")
    );
}

// Sign a manifest with a child ingredient, then sign the parent with a signer that authenticates
// to its time authority. The request made for the ingredient's timestamp assertion must carry the
// signer's TSA headers, the same as the request for the claim signature's own timestamp.
//
// The recording resolver fails every request, so signing can't complete. The ingredient timestamp
// is requested before the claim is signed, so the request is still captured.
#[test]
fn timestamp_assertion_sends_signer_tsa_headers() {
    let resolver = RecordingResolver::default();
    let (mut child_image, mut builder) = child_image_and_parent_builder(&resolver);

    let result = builder.sign(
        &AuthenticatedTsaSigner(Box::new(common::test_signer())),
        FORMAT,
        &mut child_image,
        &mut Cursor::new(Vec::new()),
    );
    assert!(result.is_err());

    assert_tsa_request_has_signer_headers(&resolver);
}

// Same as `timestamp_assertion_sends_signer_tsa_headers`, through `Builder::sign_async`.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn timestamp_assertion_sends_signer_tsa_headers_async() {
    let resolver = RecordingResolver::default();
    let (mut child_image, mut builder) = child_image_and_parent_builder(&resolver);

    let result = builder
        .sign_async(
            &AsyncAuthenticatedTsaSigner(common::test_signer()),
            FORMAT,
            &mut child_image,
            &mut Cursor::new(Vec::new()),
        )
        .await;
    assert!(result.is_err());

    assert_tsa_request_has_signer_headers(&resolver);
}
