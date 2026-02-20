use httpmock::{HttpMockRequest, HttpMockResponse};

use crate::signer::BoxedSigner;
pub(crate) fn remote_signer_mock_server<'a>(
    server: &'a httpmock::MockServer,
    signed_bytes: &[u8],
) -> httpmock::Mock<'a> {
    server.mock(|when, then| {
        when.method(httpmock::Method::POST);
        then.status(200).body(signed_bytes);
    })
}

pub(crate) fn remote_signer_respond_with_signature(
    server: &'_ httpmock::MockServer,
    signer: BoxedSigner,
) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        when.path("/").method(httpmock::Method::POST);
        then.respond_with(move |req: &HttpMockRequest| {
            let signature = signer.sign(req.body_ref()).unwrap();
            HttpMockResponse::builder()
                .status(200)
                .header("content-type", "application/octet-stream")
                .body(signature)
                .build()
        });
    })
}
