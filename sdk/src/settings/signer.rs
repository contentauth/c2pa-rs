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

use http::Request;
use serde::{Deserialize, Serialize};

use crate::{
    create_signer,
    crypto::raw_signature::RawSigner,
    dynamic_assertion::DynamicAssertion,
    http::{SyncGenericResolver, SyncHttpResolver},
    identity::{builder::IdentityAssertionBuilder, x509::X509CredentialHolder},
    settings::{Settings, SettingsValidate},
    Error, Result, Signer, SigningAlg,
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
        // Algorithm to use for signing.
        alg: SigningAlg,
        // Certificate used for signing (PEM format).
        sign_cert: String,
        // Private key used for signing (PEM format).
        private_key: String,
        // Time stamp authority URL for signing.
        tsa_url: Option<String>,
    },
    /// A signer configured remotely.
    Remote {
        // URL to the signer used for signing.
        //
        // A POST request with a byte stream will be sent to this URL.
        url: String,
        // Algorithm to use for signing.
        alg: SigningAlg,
        // Certificate used for signing (PEM format).
        sign_cert: String,
        // Time stamp authority URL for signing.
        tsa_url: Option<String>,
    },
}

impl SignerSettings {
    // TODO: add async signer
    /// Returns the constructed signer from the [Settings::signer] field.
    ///
    /// If the signer settings aren't specified, this function will return [Error::MissingSignerSettings].
    pub fn signer() -> Result<Box<dyn Signer>> {
        let signer_info = match Settings::get_value::<Option<SignerSettings>>("signer") {
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
            Settings::get_value::<Option<SignerSettings>>("cawg_x509_signer")
        {
            cawg_x509_settings.cawg_signer(c2pa_signer)
        } else {
            Ok(c2pa_signer)
        }
    }

    /// Returns a c2pa signer using the provided signer settings.
    pub fn c2pa_signer(self) -> Result<Box<dyn Signer>> {
        match self {
            SignerSettings::Local {
                alg,
                sign_cert,
                private_key,
                tsa_url,
            } => create_signer::from_keys(
                sign_cert.as_bytes(),
                private_key.as_bytes(),
                alg,
                tsa_url.to_owned(),
            ),
            SignerSettings::Remote {
                url,
                alg,
                sign_cert,
                tsa_url,
            } => Ok(Box::new(RemoteSigner {
                url,
                alg,
                reserve_size: 10000 + sign_cert.len(),
                certs: vec![sign_cert.into_bytes()],
                tsa_url,
            })),
        }
    }

    /// Returns a CAWG X.509 identity signer that wraps the provided c2pa signer.
    pub fn cawg_signer(self, c2pa_signer: Box<dyn Signer>) -> Result<Box<dyn Signer>> {
        match self {
            SignerSettings::Local {
                alg: cawg_alg,
                sign_cert: cawg_sign_cert,
                private_key: cawg_private_key,
                tsa_url: cawg_tsa_url,
            } => {
                let cawg_dual_signer = CawgX509IdentitySigner {
                    c2pa_signer,
                    cawg_alg,
                    cawg_sign_cert,
                    cawg_private_key,
                    cawg_tsa_url,
                };

                Ok(Box::new(cawg_dual_signer))
            }

            SignerSettings::Remote {
                url: _url,
                alg: _alg,
                sign_cert: _sign_cert,
                tsa_url: _tsa_url,
            } => todo!("Remote CAWG X.509 signing not yet supported"),
        }
    }
}

impl SettingsValidate for SignerSettings {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

struct CawgX509IdentitySigner {
    c2pa_signer: Box<dyn Signer>,
    cawg_alg: SigningAlg,
    cawg_sign_cert: String,
    cawg_private_key: String,
    cawg_tsa_url: Option<String>,
    // NOTE: The CAWG signing settings are stored here because
    // we can't clone or transfer ownership of an `X509CredentialHolder`
    // inside the dynamic_assertions callback.
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
        let Ok(raw_signer) = crate::crypto::raw_signature::signer_from_cert_chain_and_private_key(
            self.cawg_sign_cert.as_bytes(),
            self.cawg_private_key.as_bytes(),
            self.cawg_alg,
            self.cawg_tsa_url.clone(),
        ) else {
            // dynamic_assertions() API doesn't let us fail.
            // signer_from_cert_chain_and_private_key rarely fails,
            // so when it does, we do so silently.
            return vec![];
        };

        let x509_credential_holder = X509CredentialHolder::from_raw_signer(raw_signer);

        let iab = IdentityAssertionBuilder::for_credential_holder(x509_credential_holder);

        // TODO: Configure referenced assertions and role.

        vec![Box::new(iab)]
    }

    fn raw_signer(&self) -> Option<Box<&dyn RawSigner>> {
        self.c2pa_signer.raw_signer()
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
        let response = SyncGenericResolver::new()
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

    use crate::{settings::Settings, utils::test_signer, SigningAlg};

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
        let mock = remote_signer_mock_server(&server, &signed_bytes);

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
}
