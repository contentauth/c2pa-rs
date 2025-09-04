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
    resolver::http::{SyncGenericResolver, SyncHttpResolver},
    settings::Settings,
    Error, Result, Signer, SigningAlg,
};

/// Settings for configuring a local or remote [Signer][crate::Signer].
///
/// A [Signer][crate::Signer] can be obtained by calling [BuilderSettings::signer].
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SignerSettings {
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
    /// Returns the constructed signer from the [BuilderSettings::signer] field.
    ///
    /// If the signer settings aren't specified, this function will return [Error::MissingSignerSettings][crate::Error::MissingSignerSettings].
    pub fn signer() -> Result<Box<dyn Signer>> {
        let signer_info = Settings::get_value::<Option<SignerSettings>>("signer");
        match signer_info {
            Ok(Some(signer_info)) => match signer_info {
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
            },
            #[cfg(test)]
            _ => Ok(crate::utils::test_signer::test_signer(SigningAlg::Ps256)),
            #[cfg(not(test))]
            _ => Err(Error::MissingSignerSettings),
        }
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
