// Copyright 2024 Adobe. All rights reserved.
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

use std::sync::Arc;

use c2pa_raw_crypto::{signer_from_private_key, RawSigner, RawSignerError, SigningAlg};
use http::Request;
use serde::{Deserialize, Serialize};

use crate::{
    create_signer,
    crypto::cert_chain_pem_to_der,
    dynamic_assertion::DynamicAssertion,
    http::{SyncGenericResolver, SyncHttpResolver},
    identity::{builder::IdentityAssertionBuilder, x509::X509CredentialHolder},
    settings::{Settings, SettingsValidate},
    signer::OwnedSignerWrapper,
    BoxedSigner, Error, Result, Signer,
};

/// Settings for configuring a local or remote [`Signer`].
///
/// A [`Signer`] can be obtained by calling the [`signer()`] function.
///
/// [`Signer`]: crate::Signer
/// [`signer()`]: crate::settings::Settings::signer
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SignerSettings {
    /// A signer configured locally.
    Local {
        /// Algorithm to use for signing.
        #[cfg_attr(feature = "json_schema", schemars(with = "crate::SigningAlgSchema"))]
        alg: SigningAlg,
        /// Certificate used for signing (PEM format).
        sign_cert: String,
        /// Private key used for signing (PEM format).
        private_key: String,
        /// Time stamp authority URL for signing.
        tsa_url: Option<String>,
        /// Referenced assertions for CAWG identity signing (optional).
        referenced_assertions: Option<Vec<String>>,
        /// Roles for CAWG identity signing (optional).
        roles: Option<Vec<String>>,
    },
    /// A signer configured remotely.
    Remote {
        /// URL that the signer will use for signing.
        /// A POST request with a byte-stream will be sent to this URL.
        url: String,
        /// Algorithm to use for signing.
        #[cfg_attr(feature = "json_schema", schemars(with = "crate::SigningAlgSchema"))]
        alg: SigningAlg,
        /// Certificate used for signing (PEM format).
        sign_cert: String,
        /// Time stamp authority URL for signing.
        tsa_url: Option<String>,
        /// Referenced assertions for CAWG identity signing (optional).
        referenced_assertions: Option<Vec<String>>,
        /// Roles for CAWG identity signing (optional).
        roles: Option<Vec<String>>,
    },
}

impl SignerSettings {
    // TODO: add async signer
    /// Returns the constructed signer from the [Settings::signer] field.
    ///
    /// If the signer settings aren't specified, this function will return [Error::MissingSignerSettings].
    pub fn signer() -> Result<BoxedSigner> {
        let signer_info = match Settings::get_thread_local_value::<Option<SignerSettings>>("signer")
        {
            Ok(Some(signer_info)) => signer_info,
            #[cfg(test)]
            _ => {
                return Ok(crate::utils::test_signer::test_signer(SigningAlg::Ps256));
            }
            #[cfg(not(test))]
            _ => {
                return Err(Error::MissingSignerSettings);
            }
        };

        let c2pa_signer = Self::c2pa_signer(signer_info)?;

        // TO DISCUSS: What if get_value returns an Err(...)?
        if let Ok(Some(cawg_x509_settings)) =
            Settings::get_thread_local_value::<Option<SignerSettings>>("cawg_x509_signer")
        {
            cawg_x509_settings.cawg_signer(c2pa_signer)
        } else {
            Ok(c2pa_signer)
        }
    }

    /// Returns a c2pa signer using the provided signer settings.
    pub fn c2pa_signer(self) -> Result<BoxedSigner> {
        match self {
            SignerSettings::Local {
                alg,
                sign_cert,
                private_key,
                tsa_url,
                referenced_assertions: _,
                roles: _,
            } => {
                create_signer::from_keys(sign_cert.as_bytes(), private_key.as_bytes(), alg, tsa_url)
            }
            SignerSettings::Remote {
                url,
                alg,
                sign_cert,
                tsa_url,
                referenced_assertions: _,
                roles: _,
            } => {
                let certs = cert_chain_pem_to_der(sign_cert.as_bytes())?;
                let reserve_size = 10000 + certs.iter().map(|c| c.len()).sum::<usize>();
                Ok(Box::new(RemoteSigner {
                    url,
                    alg,
                    reserve_size,
                    certs,
                    tsa_url,
                }))
            }
        }
    }

    /// Returns a CAWG X.509 identity signer that wraps the provided c2pa signer.
    pub fn cawg_signer(self, c2pa_signer: BoxedSigner) -> Result<BoxedSigner> {
        match self {
            SignerSettings::Local {
                alg: cawg_alg,
                sign_cert: cawg_sign_cert,
                private_key: cawg_private_key,
                tsa_url: cawg_tsa_url,
                referenced_assertions: cawg_referenced_assertions,
                roles: cawg_roles,
            } => {
                let signer = CawgX509IdentitySigner::from_settings(
                    c2pa_signer,
                    cawg_alg,
                    cawg_sign_cert.as_bytes(),
                    cawg_private_key.as_bytes(),
                    cawg_tsa_url,
                    cawg_referenced_assertions.unwrap_or_default(),
                    cawg_roles.unwrap_or_default(),
                )?;
                Ok(Box::new(signer))
            }

            SignerSettings::Remote {
                url,
                alg: cawg_alg,
                sign_cert: cawg_sign_cert,
                tsa_url: cawg_tsa_url,
                referenced_assertions: cawg_referenced_assertions,
                roles: cawg_roles,
            } => {
                // The identity (CAWG) signature is not RFC 3161 time stamped, so
                // the TSA URL is intentionally unused here (matches the Local case).
                let _ = cawg_tsa_url;

                let signer = CawgX509IdentitySigner::from_remote_settings(
                    c2pa_signer,
                    cawg_alg,
                    url,
                    cawg_sign_cert.as_bytes(),
                    cawg_referenced_assertions.unwrap_or_default(),
                    cawg_roles.unwrap_or_default(),
                )?;
                Ok(Box::new(signer))
            }
        }
    }
}

impl SettingsValidate for SignerSettings {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

/// Wraps an `Arc<dyn RawSigner>` so it can be passed as an owned `Box<dyn RawSigner>`.
struct ArcRawSigner(Arc<dyn RawSigner + Send + Sync>);

impl RawSigner for ArcRawSigner {
    fn sign(&self, data: &[u8]) -> std::result::Result<Vec<u8>, RawSignerError> {
        self.0.sign(data)
    }

    fn alg(&self) -> SigningAlg {
        self.0.alg()
    }

    fn max_signature_size(&self) -> usize {
        self.0.max_signature_size()
    }
}

pub(crate) struct CawgX509IdentitySigner {
    c2pa_signer: BoxedSigner,
    identity_signer: Arc<dyn RawSigner + Send + Sync>,
    identity_cert_chain: Vec<Vec<u8>>,
    referenced_assertions: Vec<String>,
    roles: Vec<String>,
}

impl CawgX509IdentitySigner {
    /// Creates a combined signer from cert/key bytes for the identity signer.
    pub(crate) fn from_settings(
        c2pa_signer: BoxedSigner,
        alg: SigningAlg,
        sign_cert: &[u8],
        private_key: &[u8],
        tsa_url: Option<String>,
        referenced_assertions: Vec<String>,
        roles: Vec<String>,
    ) -> Result<Self> {
        // The identity (CAWG) signature is not RFC 3161 time stamped, so the TSA
        // URL is intentionally unused here.
        let _ = tsa_url;
        let raw_signer = signer_from_private_key(private_key, alg)?;
        Ok(Self {
            c2pa_signer,
            identity_signer: Arc::from(raw_signer),
            identity_cert_chain: cert_chain_pem_to_der(sign_cert)?,
            referenced_assertions,
            roles,
        })
    }

    /// Creates a combined signer that delegates identity signing to a remote
    /// HTTP endpoint.
    pub(crate) fn from_remote_settings(
        c2pa_signer: BoxedSigner,
        alg: SigningAlg,
        url: String,
        sign_cert: &[u8],
        referenced_assertions: Vec<String>,
        roles: Vec<String>,
    ) -> Result<Self> {
        let identity_cert_chain = cert_chain_pem_to_der(sign_cert)?;
        let max_signature_size = 10_000 + identity_cert_chain.iter().map(Vec::len).sum::<usize>();

        Ok(Self {
            c2pa_signer,
            identity_signer: Arc::new(RemoteRawSigner {
                url,
                alg,
                max_signature_size,
            }),
            identity_cert_chain,
            referenced_assertions,
            roles,
        })
    }

    /// Creates a combined signer from an already-constructed identity [`Signer`].
    pub(crate) fn from_signer(
        c2pa_signer: BoxedSigner,
        identity_signer: BoxedSigner,
        referenced_assertions: &[&str],
        roles: &[&str],
    ) -> Self {
        let identity_cert_chain = identity_signer.certs().unwrap_or_default();
        Self {
            c2pa_signer,
            identity_signer: Arc::new(OwnedSignerWrapper(identity_signer)),
            identity_cert_chain,
            referenced_assertions: referenced_assertions
                .iter()
                .map(|s| s.to_string())
                .collect(),
            roles: roles.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Signer for CawgX509IdentitySigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Signer::sign(&self.c2pa_signer, data)
    }

    fn alg(&self) -> SigningAlg {
        Signer::alg(&self.c2pa_signer)
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        self.c2pa_signer.certs()
    }

    fn reserve_size(&self) -> usize {
        Signer::reserve_size(&self.c2pa_signer)
    }

    fn time_authority_url(&self) -> Option<String> {
        self.c2pa_signer.time_authority_url()
    }

    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        self.c2pa_signer.timestamp_request_headers()
    }

    fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.c2pa_signer.timestamp_request_body(message)
    }

    fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        self.c2pa_signer.send_timestamp_request(message)
    }

    fn ocsp_val(&self) -> Option<Vec<u8>> {
        self.c2pa_signer.ocsp_val()
    }

    fn direct_cose_handling(&self) -> bool {
        self.c2pa_signer.direct_cose_handling()
    }

    fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
        let identity_signer: Box<dyn RawSigner + Sync + Send + 'static> =
            Box::new(ArcRawSigner(Arc::clone(&self.identity_signer)));
        let x509_credential_holder = X509CredentialHolder::from_raw_signer(
            identity_signer,
            self.identity_cert_chain.clone(),
        );

        let mut iab = IdentityAssertionBuilder::for_credential_holder(x509_credential_holder);

        if !self.referenced_assertions.is_empty() {
            let refs: Vec<&str> = self
                .referenced_assertions
                .iter()
                .map(|s| s.as_str())
                .collect();
            iab.add_referenced_assertions(&refs);
        }

        if !self.roles.is_empty() {
            let roles: Vec<&str> = self.roles.iter().map(|s| s.as_str()).collect();
            iab.add_roles(&roles);
        }

        vec![Box::new(iab)]
    }
}

#[derive(Debug)]
pub(crate) struct RemoteSigner {
    url: String,
    alg: SigningAlg,
    certs: Vec<Vec<u8>>,
    reserve_size: usize,
    tsa_url: Option<String>,
}

impl Signer for RemoteSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        use std::io::Read;

        let request = Request::post(&self.url).body(data.to_vec())?;
        let response = SyncGenericResolver::with_redirects()
            .unwrap_or_default()
            .http_resolve(request)
            .map_err(|_| Error::FailedToRemoteSign)?;
        let mut bytes: Vec<u8> = Vec::with_capacity(self.reserve_size);
        response
            .into_body()
            .take(self.reserve_size as u64)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.certs.clone())
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }
}

/// A [`RawSigner`] that delegates identity signing to a remote HTTP endpoint.
///
/// A POST request with the raw bytes-to-be-signed as the body is sent to
/// `url`; the response body (up to `max_signature_size` bytes) is used as
/// the raw signature. This mirrors [`RemoteSigner`], but implements the
/// lower-level [`RawSigner`] trait so it can back a [`CawgX509IdentitySigner`]
/// (whose certificate chain and reserve-size accounting are handled by the
/// SDK, not the raw signer).
#[derive(Debug)]
struct RemoteRawSigner {
    url: String,
    alg: SigningAlg,
    max_signature_size: usize,
}

impl RawSigner for RemoteRawSigner {
    fn sign(&self, data: &[u8]) -> std::result::Result<Vec<u8>, RawSignerError> {
        use std::io::Read;

        let request = Request::post(&self.url)
            .body(data.to_vec())
            .map_err(|e| RawSignerError::InternalError(e.to_string()))?;
        let response = SyncGenericResolver::with_redirects()
            .unwrap_or_default()
            .http_resolve(request)
            .map_err(|e| RawSignerError::InternalError(e.to_string()))?;

        let mut bytes: Vec<u8> = Vec::with_capacity(self.max_signature_size);
        response
            .into_body()
            .take(self.max_signature_size as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| RawSignerError::InternalError(e.to_string()))?;
        Ok(bytes)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn max_signature_size(&self) -> usize {
        self.max_signature_size
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]

    #[cfg(not(target_arch = "wasm32"))]
    use crate::BoxedSigner;
    use crate::{settings::Settings, utils::test_signer, Signer, SigningAlg};

    #[cfg(not(target_arch = "wasm32"))]
    fn remote_signer_mock_server<'a>(
        server: &'a httpmock::MockServer,
        signed_bytes: &[u8],
    ) -> httpmock::Mock<'a> {
        server.mock(|when, then| {
            when.method(httpmock::Method::POST);
            then.status(200).body(signed_bytes);
        })
    }

    /// Mocks a remote signing endpoint that signs whatever bytes it receives
    /// using a local reference `signer`, simulating a real remote signing
    /// service backed by a private key it never exposes.
    #[cfg(not(target_arch = "wasm32"))]
    fn remote_signer_respond_with_signature(
        server: &httpmock::MockServer,
        signer: BoxedSigner,
    ) -> httpmock::Mock<'_> {
        server.mock(|when, then| {
            when.method(httpmock::Method::POST);
            then.respond_with(move |req: &httpmock::HttpMockRequest| {
                let signed = signer.sign(req.body_ref()).unwrap_or_default();
                http::Response::builder()
                    .status(200)
                    .body(signed)
                    .unwrap()
                    .into()
            });
        })
    }

    /// Legacy test verifying the deprecated thread-local signer API still works.
    #[test]
    #[allow(deprecated)]
    fn test_thread_local_signer() {
        assert!(Settings::signer().is_ok());
    }

    #[test]
    fn test_make_local_signer() {
        let alg = SigningAlg::Ps384;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [signer.local]
                    alg = (alg.to_string())
                    sign_cert = (String::from_utf8(sign_cert.to_vec()).unwrap())
                    private_key = (String::from_utf8(private_key.to_vec()).unwrap())
                }
                .to_string(),
            )
            .unwrap();

        // Test the settings signer path directly (context.signer() uses a custom test
        // signer in test mode, so we test SignerSettings::c2pa_signer() directly here)
        let signer_settings = settings.signer.expect("signer settings should be present");
        let signer = signer_settings.c2pa_signer().unwrap();
        assert_eq!(signer.alg(), alg);
        assert_eq!(signer.time_authority_url(), None);
        assert!(signer.sign(&[1, 2, 3]).is_ok());
    }

    #[test]
    fn test_make_cawg_local_signer_from_settings() {
        let alg = SigningAlg::Ed25519;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [signer.local]
                    alg = (alg.to_string())
                    sign_cert = (String::from_utf8(sign_cert.to_vec()).unwrap())
                    private_key = (String::from_utf8(private_key.to_vec()).unwrap())

                    [cawg_x509_signer.local]
                    alg = (alg.to_string())
                    sign_cert = (String::from_utf8(sign_cert.to_vec()).unwrap())
                    private_key = (String::from_utf8(private_key.to_vec()).unwrap())
                    referenced_assertions = ["c2pa.actions"]
                    roles = ["creator"]
                }
                .to_string(),
            )
            .unwrap();

        let c2pa_settings = settings.signer.expect("signer settings should be present");
        let c2pa_signer = c2pa_settings.c2pa_signer().unwrap();

        let cawg_settings = settings
            .cawg_x509_signer
            .expect("cawg signer settings should be present");
        let combined = cawg_settings.cawg_signer(c2pa_signer).unwrap();

        // Verify the combined signer delegates alg/certs to the underlying c2pa signer.
        assert_eq!(combined.alg(), alg);
        assert!(!combined.certs().unwrap().is_empty());
        // The combined signer produces dynamic assertions (the identity assertion builder).
        assert_eq!(combined.dynamic_assertions().len(), 1);
    }

    #[test]
    fn test_cawg_identity_signer_from_signer_path() {
        use crate::{create_signer, settings::signer::CawgX509IdentitySigner, Signer};

        let alg = SigningAlg::Ps256;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);

        let c2pa_signer = create_signer::from_keys(sign_cert, private_key, alg, None).unwrap();
        let identity_signer = create_signer::from_keys(sign_cert, private_key, alg, None).unwrap();

        let combined = CawgX509IdentitySigner::from_signer(
            c2pa_signer,
            identity_signer,
            &["c2pa.actions"],
            &["creator"],
        );

        assert_eq!(combined.alg(), alg);
        assert!(!combined.certs().unwrap().is_empty());
        assert_eq!(combined.dynamic_assertions().len(), 1);
        // Sign delegates to c2pa_signer, so it should succeed with valid data.
        assert!(combined.sign(b"test data").is_ok());
    }

    #[test]
    fn test_cawg_signer_no_referenced_assertions_or_roles() {
        use crate::{create_signer, settings::signer::CawgX509IdentitySigner};

        let alg = SigningAlg::Ps256;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);

        let c2pa_signer = create_signer::from_keys(sign_cert, private_key, alg, None).unwrap();
        let identity_signer = create_signer::from_keys(sign_cert, private_key, alg, None).unwrap();

        let combined = CawgX509IdentitySigner::from_signer(c2pa_signer, identity_signer, &[], &[]);

        // dynamic_assertions still returns one builder even with empty refs/roles.
        assert_eq!(combined.dynamic_assertions().len(), 1);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_make_remote_signer() {
        use httpmock::MockServer;

        use crate::create_signer;

        let alg = SigningAlg::Ps384;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);

        let signer = create_signer::from_keys(sign_cert, private_key, alg, None).unwrap();
        let signed_bytes = signer.sign(&[1, 2, 3]).unwrap();

        let server = MockServer::start();
        let mock = remote_signer_mock_server(&server, &signed_bytes);

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [signer.remote]
                    url = (server.base_url())
                    alg = (alg.to_string())
                    sign_cert = (String::from_utf8(sign_cert.to_vec()).unwrap())
                }
                .to_string(),
            )
            .unwrap();

        // Test the settings signer path directly (context.signer() uses a custom test
        // signer in test mode, so we test SignerSettings::c2pa_signer() directly here)
        let signer_settings = settings.signer.expect("signer settings should be present");
        let signer = signer_settings.c2pa_signer().unwrap();
        assert_eq!(signer.alg(), alg);
        assert_eq!(signer.time_authority_url(), None);
        assert_eq!(signer.sign(&[1, 2, 3]).unwrap(), signed_bytes);

        mock.assert();

        // certs() must return DER-encoded certs (not raw PEM text), matching the
        // Local variant's behavior via create_signer::from_keys.
        let der_certs = signer.certs().unwrap();
        assert!(!der_certs.is_empty());
        let pem_text = String::from_utf8(sign_cert.to_vec()).unwrap();
        let expected_der = crate::crypto::cert_chain_pem_to_der(pem_text.as_bytes()).unwrap();
        assert_eq!(der_certs, expected_der);
        for der in &der_certs {
            assert_ne!(der.as_slice(), pem_text.as_bytes());
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_make_remote_signer_json_escaped_pem() {
        use httpmock::MockServer;

        use crate::create_signer;

        let alg = SigningAlg::Ps384;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);

        let signer = create_signer::from_keys(sign_cert, private_key, alg, None).unwrap();
        let signed_bytes = signer.sign(&[1, 2, 3]).unwrap();

        let server = MockServer::start();
        let mock = remote_signer_mock_server(&server, &signed_bytes);

        // Simulate a cert chain delivered with literal "\n" escapes, as happens
        // when a PEM cert is embedded in a JSON config value.
        let pem_text = String::from_utf8(sign_cert.to_vec()).unwrap();
        let escaped_pem = pem_text.replace('\n', "\\n");

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [signer.remote]
                    url = (server.base_url())
                    alg = (alg.to_string())
                    sign_cert = (escaped_pem)
                }
                .to_string(),
            )
            .unwrap();

        let signer_settings = settings.signer.expect("signer settings should be present");
        let signer = signer_settings.c2pa_signer().unwrap();
        assert_eq!(signer.alg(), alg);
        assert_eq!(signer.sign(&[1, 2, 3]).unwrap(), signed_bytes);

        let der_certs = signer.certs().unwrap();
        assert!(!der_certs.is_empty());
        let expected_der = crate::crypto::cert_chain_pem_to_der(pem_text.as_bytes()).unwrap();
        assert_eq!(der_certs, expected_der);

        mock.assert();
    }

    #[test]
    fn test_make_remote_signer_malformed_pem_errors() {
        let alg = SigningAlg::Ps384;

        // Has BEGIN/END markers (so the parser attempts to decode a block) but
        // the body is not valid base64, so decoding must fail with an error
        // rather than silently producing an empty cert list.
        let malformed_pem =
            "-----BEGIN CERTIFICATE-----\nnot-valid-base64!!!\n-----END CERTIFICATE-----\n";

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [signer.remote]
                    url = "https://example.com/sign"
                    alg = (alg.to_string())
                    sign_cert = (malformed_pem)
                }
                .to_string(),
            )
            .unwrap();

        let signer_settings = settings.signer.expect("signer settings should be present");
        assert!(signer_settings.c2pa_signer().is_err());
    }

    #[test]
    fn test_make_remote_signer_no_pem_blocks_yields_empty_certs() {
        // No BEGIN/END markers at all: the underlying parser treats this as
        // "no blocks found" and returns an empty cert list rather than an
        // error. This documents that behavior so a future change can't
        // silently alter it without a failing test.
        let alg = SigningAlg::Ps384;

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [signer.remote]
                    url = "https://example.com/sign"
                    alg = (alg.to_string())
                    sign_cert = "not a pem cert chain at all"
                }
                .to_string(),
            )
            .unwrap();

        let signer_settings = settings.signer.expect("signer settings should be present");
        let signer = signer_settings.c2pa_signer().unwrap();
        assert_eq!(signer.certs().unwrap(), Vec::<Vec<u8>>::new());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_make_cawg_remote_signer_from_settings() {
        use httpmock::MockServer;

        use crate::create_signer;

        let c2pa_alg = SigningAlg::Ps384;
        let (c2pa_sign_cert, c2pa_private_key) =
            test_signer::cert_chain_and_private_key_for_alg(c2pa_alg);
        let c2pa_signer =
            create_signer::from_keys(c2pa_sign_cert, c2pa_private_key, c2pa_alg, None).unwrap();

        let cawg_alg = SigningAlg::Ed25519;
        let (cawg_sign_cert, cawg_private_key) =
            test_signer::cert_chain_and_private_key_for_alg(cawg_alg);
        let reference_signer =
            create_signer::from_keys(cawg_sign_cert, cawg_private_key, cawg_alg, None).unwrap();
        let signed_bytes = reference_signer.sign(&[1, 2, 3]).unwrap();

        let server = MockServer::start();
        let mock = remote_signer_mock_server(&server, &signed_bytes);

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [cawg_x509_signer.remote]
                    url = (server.base_url())
                    alg = (cawg_alg.to_string())
                    sign_cert = (String::from_utf8(cawg_sign_cert.to_vec()).unwrap())
                    referenced_assertions = ["c2pa.actions"]
                    roles = ["creator"]
                }
                .to_string(),
            )
            .unwrap();

        let cawg_settings = settings
            .cawg_x509_signer
            .expect("cawg signer settings should be present");
        let combined = cawg_settings.cawg_signer(c2pa_signer).unwrap();

        // The combined signer still delegates alg/certs/sign to the underlying
        // c2pa signer; the remote identity signer only backs dynamic_assertions().
        assert_eq!(combined.alg(), c2pa_alg);
        assert!(!combined.certs().unwrap().is_empty());
        assert_eq!(combined.dynamic_assertions().len(), 1);

        // dynamic_assertions() only builds the assertion; it doesn't invoke the
        // remote identity signer yet, so the mock is intentionally not asserted
        // here (see test_cawg_remote_signer_round_trip for the full path).
        let _ = mock;
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[c2pa_macros::c2pa_test_async]
    async fn test_cawg_remote_signer_round_trip() {
        use std::io::{Cursor, Seek};

        use httpmock::MockServer;

        use crate::{
            create_signer,
            crypto::cose::Verifier,
            identity::{
                tests::fixtures::{manifest_json, parent_json},
                x509::X509SignatureVerifier,
                IdentityAssertion,
            },
            status_tracker::StatusTracker,
            Builder, Reader,
        };

        const TEST_IMAGE: &[u8] = include_bytes!("../../tests/fixtures/CA.jpg");
        const TEST_THUMBNAIL: &[u8] = include_bytes!("../../tests/fixtures/thumbnail.jpg");

        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let c2pa_alg = SigningAlg::Ps256;
        let (c2pa_sign_cert, c2pa_private_key) =
            test_signer::cert_chain_and_private_key_for_alg(c2pa_alg);
        let c2pa_signer =
            create_signer::from_keys(c2pa_sign_cert, c2pa_private_key, c2pa_alg, None).unwrap();

        let cawg_alg = SigningAlg::Ed25519;
        let (cawg_sign_cert, cawg_private_key) =
            test_signer::cert_chain_and_private_key_for_alg(cawg_alg);
        // The "remote" endpoint is backed by a local signer holding the same
        // private key, simulating a real remote signing service.
        let reference_identity_signer =
            create_signer::from_keys(cawg_sign_cert, cawg_private_key, cawg_alg, None).unwrap();

        let server = MockServer::start();
        let mock = remote_signer_respond_with_signature(&server, reference_identity_signer);

        // decode_identity_assertions is disabled so IdentityAssertion::from_manifest
        // below can parse the raw assertion content itself (matches the pattern used
        // by other CAWG X.509 round-trip tests in sdk/src/identity/x509).
        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [cawg_x509_signer.remote]
                    url = (server.base_url())
                    alg = (cawg_alg.to_string())
                    sign_cert = (String::from_utf8(cawg_sign_cert.to_vec()).unwrap())
                    referenced_assertions = ["c2pa.actions"]
                    roles = ["creator"]
                }
                .to_string(),
            )
            .unwrap()
            .with_value("core.decode_identity_assertions", false)
            .unwrap();

        let cawg_settings = settings
            .cawg_x509_signer
            .clone()
            .expect("cawg signer settings should be present");
        let combined_signer = cawg_settings.cawg_signer(c2pa_signer).unwrap();

        let context = crate::Context::new()
            .with_settings(settings)
            .unwrap()
            .into_shared();

        let mut builder = Builder::from_shared_context(&context)
            .with_definition(manifest_json())
            .unwrap();
        builder
            .add_ingredient_from_stream(parent_json(), format, &mut source)
            .unwrap();
        builder
            .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
            .unwrap();

        builder
            .sign(&combined_signer, format, &mut source, &mut dest)
            .unwrap();

        mock.assert();

        dest.rewind().unwrap();
        let manifest_store = Reader::from_shared_context(&context)
            .with_stream(format, &mut dest)
            .unwrap();
        assert_eq!(manifest_store.validation_status(), None);

        let manifest = manifest_store.active_manifest().unwrap();
        let mut st = StatusTracker::default();
        let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

        let ia = ia_iter.next().unwrap().unwrap();
        assert!(ia_iter.next().is_none());
        drop(ia_iter);

        let x509_verifier = X509SignatureVerifier {
            cose_verifier: Verifier::IgnoreProfileAndTrustPolicy,
        };
        let sig_info = ia
            .validate(manifest, &mut st, &x509_verifier)
            .await
            .unwrap();

        assert_eq!(sig_info.cert_info.alg.unwrap(), cawg_alg);
    }
}
