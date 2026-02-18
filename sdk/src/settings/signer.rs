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

use serde::{Deserialize, Serialize};
use url::Url;

#[cfg(feature = "remote_signing")]
use crate::crypto::raw_signature::signer_from_cert_chain_and_url;
use crate::{
    create_signer,
    crypto::raw_signature::{signer_from_cert_chain_and_private_key, RawSigner},
    dynamic_assertion::DynamicAssertion,
    identity::{builder::IdentityAssertionBuilder, x509::X509CredentialHolder},
    settings::{Settings, SettingsValidate},
    BoxedSigner, Error, Result, Signer, SigningAlg,
};

/// Enum representing the CAWG X.509 signing mode: local (with private key) or remote (via URL).
///
/// This enum encapsulates the credentials needed for either local or remote CAWG X.509 identity signing.
/// It is used internally by [`CawgX509IdentitySigner`] to determine which signing path to use when
/// creating dynamic assertions.
#[derive(Clone, Debug)]
enum CawgSigningMode {
    /// Local signing mode: credentials are stored locally on the signer instance.
    Local {
        /// Signing certificate chain in PEM format.
        sign_cert: String,
        /// Private key in PEM format.
        private_key: String,
        /// Optional time stamp authority URL.
        tsa_url: Option<String>,
    },
    /// Remote signing mode: credentials are accessed via a remote signing service.
    Remote {
        /// Remote signing service URL.
        url: Url,
        /// Signing certificate chain in PEM format.
        sign_cert: String,
        /// Optional time stamp authority URL.
        tsa_url: Option<String>,
    },
}

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
            } => match Url::parse(&url) {
                Ok(url) => create_signer::from_remote_url(sign_cert.as_bytes(), url, alg, tsa_url),
                Err(e) => Err(Error::InvalidRemoteUrl(e)),
            },
        }
    }

    /// Returns a CAWG X.509 identity signer that wraps the provided c2pa signer.
    ///
    /// Supports both local signing (with private key stored locally) and remote signing
    /// (delegated to a remote signing service via URL).
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
                let signing_mode = CawgSigningMode::Local {
                    sign_cert: cawg_sign_cert,
                    private_key: cawg_private_key,
                    tsa_url: cawg_tsa_url,
                };

                let cawg_dual_signer = CawgX509IdentitySigner {
                    c2pa_signer,
                    cawg_alg,
                    signing_mode,
                    cawg_referenced_assertions: cawg_referenced_assertions.unwrap_or_default(),
                    cawg_roles: cawg_roles.unwrap_or_default(),
                };

                Ok(Box::new(cawg_dual_signer))
            }

            SignerSettings::Remote {
                url,
                alg: cawg_alg,
                sign_cert: cawg_sign_cert,
                tsa_url: cawg_tsa_url,
                referenced_assertions: cawg_referenced_assertions,
                roles: cawg_roles,
            } => {
                #[cfg(feature = "remote_signing")]
                {
                    let url = Url::parse(&url).map_err(|e| Error::InvalidRemoteUrl(e))?;
                    let signing_mode = CawgSigningMode::Remote {
                        url,
                        sign_cert: cawg_sign_cert,
                        tsa_url: cawg_tsa_url,
                    };

                    let cawg_dual_signer = CawgX509IdentitySigner {
                        c2pa_signer,
                        cawg_alg,
                        signing_mode,
                        cawg_referenced_assertions: cawg_referenced_assertions.unwrap_or_default(),
                        cawg_roles: cawg_roles.unwrap_or_default(),
                    };

                    Ok(Box::new(cawg_dual_signer))
                }
                #[cfg(not(feature = "remote_signing"))]
                {
                    Err(Error::RemoteSigningNotEnabled)
                }
            }
        }
    }
}

impl SettingsValidate for SignerSettings {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

/// Signing mode (local or remote) with all required credentials.
///
/// We store the signing mode enum here because we can't clone or transfer ownership
/// of an `X509CredentialHolder` inside the `dynamic_assertions()` callback.
/// Instead, we store the raw credentials and create the `X509CredentialHolder`
/// on-demand in `dynamic_assertions()` when needed.
struct CawgX509IdentitySigner {
    c2pa_signer: BoxedSigner,
    cawg_alg: SigningAlg,
    signing_mode: CawgSigningMode,
    cawg_referenced_assertions: Vec<String>,
    cawg_roles: Vec<String>,
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
        let raw_signer = match &self.signing_mode {
            CawgSigningMode::Local {
                sign_cert,
                private_key,
                tsa_url,
            } => signer_from_cert_chain_and_private_key(
                sign_cert.as_bytes(),
                private_key.as_bytes(),
                self.cawg_alg,
                tsa_url.clone(),
            ),
            CawgSigningMode::Remote {
                url,
                sign_cert,
                tsa_url,
            } => {
                #[cfg(feature = "remote_signing")]
                {
                    signer_from_cert_chain_and_url(
                        sign_cert.as_bytes(),
                        url.clone(),
                        self.cawg_alg,
                        tsa_url.clone(),
                    )
                }
                #[cfg(not(feature = "remote_signing"))]
                {
                    return vec![];
                }
            }
        };

        let Ok(raw_signer) = raw_signer else {
            // dynamic_assertions() API doesn't let us fail.
            // signer_from_cert_chain_and_private_key rarely fails,
            // so when it does, we do so silently.
            return vec![];
        };

        let x509_credential_holder = X509CredentialHolder::from_raw_signer(raw_signer);

        let mut iab = IdentityAssertionBuilder::for_credential_holder(x509_credential_holder);

        // Add referenced assertions if configured
        if !self.cawg_referenced_assertions.is_empty() {
            let referenced_assertions: Vec<&str> = self
                .cawg_referenced_assertions
                .iter()
                .map(|s| s.as_str())
                .collect();
            iab.add_referenced_assertions(&referenced_assertions);
        }

        // Add roles if configured
        if !self.cawg_roles.is_empty() {
            let roles: Vec<&str> = self.cawg_roles.iter().map(|s| s.as_str()).collect();
            iab.add_roles(&roles);
        }

        vec![Box::new(iab)]
    }

    fn raw_signer(&self) -> Option<Box<&dyn RawSigner>> {
        self.c2pa_signer.raw_signer()
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::{Cursor, Seek};

    use c2pa_macros::c2pa_test_async;
    use httpmock::MockServer;

    use crate::{
        create_signer,
        crypto::cose::Verifier,
        identity::{
            tests::fixtures::{manifest_json, parent_json},
            x509::X509SignatureVerifier,
            IdentityAssertion,
        },
        settings,
        settings::Settings,
        status_tracker::StatusTracker,
        utils::test_signer,
        Builder, Reader, SigningAlg,
    };

    #[test]
    fn test_make_test_signer() {
        // Makes a default test signer.
        assert!(Settings::signer().is_ok());
    }

    #[test]
    fn test_make_local_signer() {
        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        // Testing with a different alg than the default test signer.
        let alg = SigningAlg::Ps384;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);
        Settings::from_toml(
            &toml::toml! {
                [signer.local]
                alg = (alg.to_string())
                sign_cert = (String::from_utf8(sign_cert.to_vec()).unwrap())
                private_key = (String::from_utf8(private_key.to_vec()).unwrap())
            }
            .to_string(),
        )
        .unwrap();

        let signer = Settings::signer().unwrap();
        assert_eq!(signer.alg(), alg);
        assert_eq!(signer.time_authority_url(), None);
        assert!(signer.sign(&[1, 2, 3]).is_ok());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_make_remote_signer() {
        use httpmock::MockServer;

        use crate::create_signer;

        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        let alg = SigningAlg::Ps384;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);

        let signer = create_signer::from_keys(sign_cert, private_key, alg, None).unwrap();
        let signed_bytes = signer.sign(&[1, 2, 3]).unwrap();

        let server = MockServer::start();
        let mock = test_signer::remote_signer_mock_server(&server, &signed_bytes);

        Settings::from_toml(
            &toml::toml! {
                [signer.remote]
                url = (server.base_url())
                alg = (alg.to_string())
                sign_cert = (String::from_utf8(sign_cert.to_vec()).unwrap())
            }
            .to_string(),
        )
        .unwrap();

        let signer = Settings::signer().unwrap();
        assert_eq!(signer.alg(), alg);
        assert_eq!(signer.time_authority_url(), None);
        assert_eq!(signer.sign(&[1, 2, 3]).unwrap(), signed_bytes);

        mock.assert();
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_make_local_cawg_signer() {
        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        let c2pa_alg = SigningAlg::Ps384;
        let cawg_alg = SigningAlg::Es384;
        let (c2pa_sign_cert, c2pa_private_key) =
            test_signer::cert_chain_and_private_key_for_alg(c2pa_alg);
        let (cawg_cert, cawg_private_key) =
            test_signer::cert_chain_and_private_key_for_alg(cawg_alg);

        Settings::from_toml(
            &toml::toml! {
                [signer.local]
                alg = (c2pa_alg.to_string())
                sign_cert = (String::from_utf8(c2pa_sign_cert.to_vec()).unwrap())
                private_key = (String::from_utf8(c2pa_private_key.to_vec()).unwrap())

                [cawg_x509_signer.local]
                alg = (cawg_alg.to_string())
                sign_cert = (String::from_utf8(cawg_cert.to_vec()).unwrap())
                private_key = (String::from_utf8(cawg_private_key.to_vec()).unwrap())
            }
            .to_string(),
        )
        .unwrap();

        let signer = Settings::signer().unwrap();
        assert_eq!(
            signer.alg(),
            c2pa_alg,
            "Should have the same alg as the CAWG signer"
        );

        assert!(
            !signer.dynamic_assertions().is_empty(),
            "Should have dynamic assertions"
        );
        assert!(signer.sign(&[1, 2, 3]).is_ok());
    }

    #[c2pa_test_async]
    #[cfg(feature = "remote_signing")]
    async fn test_make_cawg_c2pa_remote_signers() {
        // Create mock for C2PA signer
        let c2pa_alg = SigningAlg::Ps384;
        let (c2pa_sign_cert, c2pa_private_key) =
            test_signer::cert_chain_and_private_key_for_alg(c2pa_alg);

        let local_c2pa_signer =
            create_signer::from_keys(c2pa_sign_cert, c2pa_private_key, c2pa_alg, None).unwrap();

        let c2pa_server = MockServer::start();
        let _c2pa_mock =
            test_signer::remote_signer_respond_with_signature(&c2pa_server, local_c2pa_signer);

        // Create mock for CAWG signer
        let cawg_alg = SigningAlg::Ed25519;
        let (cawg_sign_cert, cawg_private_key) =
            test_signer::cert_chain_and_private_key_for_alg(cawg_alg);
        let local_cawg_signer =
            create_signer::from_keys(&cawg_sign_cert, &cawg_private_key, cawg_alg, None).unwrap();

        let cawg_server = MockServer::start();
        let _cawg_mock =
            test_signer::remote_signer_respond_with_signature(&cawg_server, local_cawg_signer);

        let config_settings = toml::toml! {
            [signer.remote]
            url = (c2pa_server.base_url())
            alg = (c2pa_alg.to_string())
            sign_cert = (String::from_utf8(c2pa_sign_cert.to_vec()).unwrap())

            [cawg_x509_signer.remote]
            url = (cawg_server.base_url())
            alg = (cawg_alg.to_string())
            sign_cert = (String::from_utf8(cawg_sign_cert.to_vec()).unwrap())
        }
        .to_string();

        let config_settings = settings::Settings::new()
            .with_toml(config_settings.as_str())
            .expect("Error parsing config settings")
            .with_value("core.decode_identity_assertions", false)
            .expect("Error setting core.decode_identity_assertions to false");

        let context = crate::Context::new()
            .with_settings(&config_settings)
            .expect("Error creating context")
            .into_shared();

        let format = "image/jpeg";
        let mut source = Cursor::new(include_bytes!("../../tests/fixtures/CA.jpg"));
        let mut dest = Cursor::new(Vec::new());

        // Use the context when creating the Builder
        let mut builder = Builder::from_shared_context(&context)
            .with_definition(manifest_json())
            .unwrap();
        builder
            .add_ingredient_from_stream(parent_json(), format, &mut source)
            .unwrap();

        builder
            .add_resource(
                "thumbnail.jpg",
                Cursor::new(include_bytes!("../../tests/fixtures/thumbnail.jpg")),
            )
            .unwrap();

        let cawg_signer = context.signer().expect("Error getting signer from context");

        builder
            .sign(cawg_signer, format, &mut source, &mut dest)
            .unwrap();

        // Read back the Manifest that was generated using the same context
        dest.rewind().unwrap();

        let manifest_store = Reader::from_shared_context(&context)
            .with_stream(format, &mut dest)
            .unwrap();
        assert_eq!(manifest_store.validation_status(), None);

        let manifest = manifest_store.active_manifest().unwrap();
        let mut st = StatusTracker::default();
        let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

        // Should find exactly one identity assertion.
        let ia = ia_iter.next().unwrap().unwrap();
        assert!(ia_iter.next().is_none());
        drop(ia_iter);

        // And that identity assertion should be valid for this manifest.
        let x509_verifier = X509SignatureVerifier {
            cose_verifier: Verifier::IgnoreProfileAndTrustPolicy,
        };

        let sig_info = ia
            .validate(manifest, &mut st, &x509_verifier)
            .await
            .unwrap();

        let cert_info = &sig_info.cert_info;
        assert_eq!(cert_info.alg.unwrap(), SigningAlg::Ed25519);
        assert_eq!(
            cert_info.issuer_org.as_ref().unwrap(),
            "C2PA Test Signing Cert"
        );

        _c2pa_mock.assert();
        _cawg_mock.assert();
    }
}
