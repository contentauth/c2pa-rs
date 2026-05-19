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

use http::Request;
use serde::{Deserialize, Serialize};

use crate::{
    create_signer,
    crypto::{
        raw_signature::{
            signer_from_cert_chain_and_private_key, RawSigner, RawSignerError, SigningAlg,
        },
        time_stamp::{TimeStampError, TimeStampProvider},
    },
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

    /// Returns a c2pa signer using the provided signer settings and default HTTP resolver.
    pub fn c2pa_signer(self) -> Result<BoxedSigner> {
        let resolver = Arc::new(SyncGenericResolver::with_redirects().unwrap_or_default())
            as Arc<dyn SyncHttpResolver>;
        self.c2pa_signer_with_resolver(resolver)
    }

    /// Returns a c2pa signer using the provided signer settings and a caller-supplied HTTP resolver.
    pub fn c2pa_signer_with_resolver(
        self,
        resolver: Arc<dyn SyncHttpResolver>,
    ) -> Result<BoxedSigner> {
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
            } => Ok(Box::new(RemoteSigner {
                url,
                alg,
                reserve_size: 10000 + sign_cert.len(),
                certs: vec![sign_cert.into_bytes()],
                tsa_url,
                resolver,
            })),
        }
    }

    /// Returns a CAWG X.509 identity signer using the default HTTP resolver.
    pub fn cawg_signer(self, c2pa_signer: BoxedSigner) -> Result<BoxedSigner> {
        let resolver = Arc::new(SyncGenericResolver::with_redirects().unwrap_or_default())
            as Arc<dyn SyncHttpResolver>;
        self.cawg_signer_with_resolver(c2pa_signer, resolver)
    }

    /// Returns a CAWG X.509 identity signer with a caller-supplied HTTP resolver.
    pub fn cawg_signer_with_resolver(
        self,
        c2pa_signer: BoxedSigner,
        resolver: Arc<dyn SyncHttpResolver>,
    ) -> Result<BoxedSigner> {
        match self {
            SignerSettings::Local {
                alg: cawg_alg,
                sign_cert: cawg_sign_cert,
                private_key: cawg_private_key,
                tsa_url: cawg_tsa_url,
                referenced_assertions: cawg_referenced_assertions,
                roles: cawg_roles,
            } => {
                let signer = CawgX509IdentitySigner::from_settings_with_resolver(
                    c2pa_signer,
                    cawg_alg,
                    cawg_sign_cert.as_bytes(),
                    cawg_private_key.as_bytes(),
                    cawg_tsa_url,
                    cawg_referenced_assertions.unwrap_or_default(),
                    cawg_roles.unwrap_or_default(),
                    resolver,
                )?;
                Ok(Box::new(signer))
            }

            SignerSettings::Remote {
                url: _url,
                alg: _alg,
                sign_cert: _sign_cert,
                tsa_url: _tsa_url,
                referenced_assertions: _,
                roles: _,
            } => todo!("Remote CAWG X.509 signing not yet supported"),
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

impl TimeStampProvider for ArcRawSigner {
    fn time_stamp_service_url(&self) -> Option<String> {
        self.0.time_stamp_service_url()
    }

    fn time_stamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        self.0.time_stamp_request_headers()
    }

    fn time_stamp_request_body(
        &self,
        message: &[u8],
    ) -> std::result::Result<Vec<u8>, TimeStampError> {
        self.0.time_stamp_request_body(message)
    }

    fn send_time_stamp_request(
        &self,
        message: &[u8],
    ) -> Option<std::result::Result<Vec<u8>, TimeStampError>> {
        self.0.send_time_stamp_request(message)
    }
}

impl RawSigner for ArcRawSigner {
    fn sign(&self, data: &[u8]) -> std::result::Result<Vec<u8>, RawSignerError> {
        self.0.sign(data)
    }

    fn alg(&self) -> SigningAlg {
        self.0.alg()
    }

    fn cert_chain(&self) -> std::result::Result<Vec<Vec<u8>>, RawSignerError> {
        self.0.cert_chain()
    }

    fn reserve_size(&self) -> usize {
        self.0.reserve_size()
    }

    fn ocsp_response(&self) -> Option<Vec<u8>> {
        self.0.ocsp_response()
    }
}

pub(crate) struct CawgX509IdentitySigner {
    c2pa_signer: BoxedSigner,
    identity_signer: Arc<dyn RawSigner + Send + Sync>,
    referenced_assertions: Vec<String>,
    roles: Vec<String>,
    resolver: Arc<dyn SyncHttpResolver>,
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
        let resolver = Arc::new(SyncGenericResolver::with_redirects().unwrap_or_default())
            as Arc<dyn SyncHttpResolver>;
        Self::from_settings_with_resolver(
            c2pa_signer,
            alg,
            sign_cert,
            private_key,
            tsa_url,
            referenced_assertions,
            roles,
            resolver,
        )
    }

    /// Creates a combined signer from cert/key bytes with a caller-supplied HTTP resolver.
    pub(crate) fn from_settings_with_resolver(
        c2pa_signer: BoxedSigner,
        alg: SigningAlg,
        sign_cert: &[u8],
        private_key: &[u8],
        tsa_url: Option<String>,
        referenced_assertions: Vec<String>,
        roles: Vec<String>,
        resolver: Arc<dyn SyncHttpResolver>,
    ) -> Result<Self> {
        let raw_signer =
            signer_from_cert_chain_and_private_key(sign_cert, private_key, alg, tsa_url)?;
        Ok(Self {
            c2pa_signer,
            identity_signer: Arc::from(raw_signer),
            referenced_assertions,
            roles,
            resolver,
        })
    }

    /// Creates a combined signer from an already-constructed identity [`Signer`].
    pub(crate) fn from_signer(
        c2pa_signer: BoxedSigner,
        identity_signer: BoxedSigner,
        referenced_assertions: &[&str],
        roles: &[&str],
    ) -> Self {
        let resolver = Arc::new(SyncGenericResolver::with_redirects().unwrap_or_default())
            as Arc<dyn SyncHttpResolver>;
        Self {
            c2pa_signer,
            identity_signer: Arc::new(OwnedSignerWrapper(identity_signer)),
            referenced_assertions: referenced_assertions
                .iter()
                .map(|s| s.to_string())
                .collect(),
            roles: roles.iter().map(|s| s.to_string()).collect(),
            resolver,
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
        let x509_credential_holder = X509CredentialHolder::from_raw_signer_with_resolver(
            identity_signer,
            Arc::clone(&self.resolver),
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

    fn raw_signer(&self) -> Option<Box<&dyn RawSigner>> {
        self.c2pa_signer.raw_signer()
    }
}

pub(crate) struct RemoteSigner {
    url: String,
    alg: SigningAlg,
    certs: Vec<Vec<u8>>,
    reserve_size: usize,
    tsa_url: Option<String>,
    resolver: Arc<dyn SyncHttpResolver>,
}

impl Signer for RemoteSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        use std::io::Read;

        let request = Request::post(&self.url).body(data.to_vec())?;
        let response = self
            .resolver
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

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]

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
    }
}
