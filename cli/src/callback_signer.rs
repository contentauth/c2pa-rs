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

use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::{bail, Context};
use c2pa::{Error, Signer, SigningAlg};

use crate::signer::SignConfig;

/// A struct that implements [SignCallback]. This struct will call out to the client provided
/// external signer to get the signed bytes for the asset.
pub(crate) struct ExternalProcessRunner {
    config: CallbackSignerConfig,
    signer_path: PathBuf,
}

impl ExternalProcessRunner {
    pub fn new(config: CallbackSignerConfig, signer_path: PathBuf) -> Self {
        Self {
            config,
            signer_path,
        }
    }
}

impl SignCallback for ExternalProcessRunner {
    /// Runs the client-provided [Command], passing to it, via stdin, the bytes to be signed. We
    /// also pass the `reserve-size`, `sign-cert`, and `alg` as CLI arguments to the [Command].
    fn sign(&self, bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        let sign_cert = self
            .config
            .sign_cert_path
            .as_os_str()
            .to_str()
            .context("Unable to read sign_certs. Is the sign_cert path valid?")?;

        // Spawn external process provided by the `c2patool` client.
        let mut child = Command::new(&self.signer_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args(["--reserve-size", &self.config.reserve_size.to_string()])
            .args(["--alg", &format!("{}", &self.config.alg)])
            .args(["--sign-cert", sign_cert])
            .spawn()
            .context(format!("Failed to run command at {:?}", self.signer_path))?;

        // Write claim bytes to spawned processes' `stdin`.
        child
            .stdin
            .take()
            .context("Failed to access `stdin` of external process")?
            .write_all(bytes)
            .context("Failed to write data to the provided external process")?;

        let output = child
            .wait_with_output()
            .context(format!("Failed to read stdout from {:?}", self.signer_path))?;

        if !output.status.success() {
            bail!(format!(
                "User supplied signer process failed. It's stderr output was: \n{}",
                String::from_utf8(output.stderr).unwrap_or_default()
            ));
        }

        let bytes = output.stdout;
        if bytes.is_empty() {
            bail!("User supplied process succeeded, but the external process did not write signature bytes to stdout");
        }

        Ok(bytes)
    }
}

/// A config containing the required values for signing an asset with an external command.
#[derive(Clone, Debug)]
pub(crate) struct CallbackSignerConfig {
    /// Signing algorithm to use - must match the associated certs
    ///
    /// Must be one of [ ps256 | ps384 | ps51024 | es256 | es384 | es51024 | ed25519 ]
    pub alg: SigningAlg,
    /// A path to a file containing the signing cert required for signing
    pub sign_cert_path: PathBuf,
    /// Size of the claim bytes.
    pub reserve_size: usize,
    pub tsa_url: Option<String>,
}

impl CallbackSignerConfig {
    /// Constructs a new [CallbackSignerConfig] using a manifest sign config, the name of an
    /// external process, and the reserve_size.
    pub fn new(sign_config: &SignConfig, reserve_size: usize) -> anyhow::Result<Self> {
        let alg = sign_config
            .alg
            .as_deref()
            .map_or_else(|| "es256".to_string(), |alg| alg.to_lowercase())
            .parse::<SigningAlg>()
            .context("Invalid signing algorithm provided")?;

        let sign_cert_path = sign_config
            .sign_cert
            .clone()
            .context("Unable to load the provided sign_cert_path")?;

        Ok(CallbackSignerConfig {
            alg,
            sign_cert_path,
            reserve_size,
            tsa_url: sign_config.ta_url.clone(),
        })
    }
}

#[cfg_attr(test, mockall::automock)]
pub(crate) trait SignCallback {
    /// Method which will be called with the `data` to be signed. Implementors
    /// should return the signed bytes as an [anyhow::Result].
    fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// A [Signer] implementation that allows clients to provide their own function
/// to sign the manifest bytes.
pub(crate) struct CallbackSigner<'a> {
    callback: Box<dyn SignCallback + 'a>,
    config: CallbackSignerConfig,
}

impl<'a> CallbackSigner<'a> {
    pub fn new(callback: Box<impl SignCallback + 'a>, config: CallbackSignerConfig) -> Self {
        Self { callback, config }
    }
}

impl Signer for CallbackSigner<'_> {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        self.callback.sign(data).map_err(|e| {
            eprintln!("Unable to embed signature into asset. {e}");
            Error::EmbeddingError
        })
    }

    fn alg(&self) -> SigningAlg {
        self.config.alg
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        let cert_contents = std::fs::read(&self.config.sign_cert_path)
            .map_err(|_| Error::FileNotFound(format!("{:?}", self.config.sign_cert_path)))?;

        let mut pems = pem::parse_many(cert_contents).map_err(|_| Error::CoseInvalidCert)?;
        // [pem::parse_many] returns an empty vector if you supply invalid contents, like json, for example.
        // Check here if the pems vector is empty.
        if pems.is_empty() {
            return Err(Error::CoseInvalidCert);
        }

        let sign_cert = pems
            .drain(..)
            .map(|p| p.into_contents())
            .collect::<Vec<Vec<u8>>>();

        Ok(sign_cert)
    }

    fn reserve_size(&self) -> usize {
        self.config.reserve_size
    }

    fn time_authority_url(&self) -> Option<String> {
        self.config.tsa_url.clone()
    }
}

#[cfg(test)]
mod test {
    use anyhow::anyhow;

    use super::*;

    fn sign_cert_path() -> PathBuf {
        #[cfg(not(target_os = "wasi"))]
        return PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        #[cfg(target_os = "wasi")]
        return PathBuf::from("/");
    }

    #[test]
    fn test_signing_succeeds_returns_bytes() {
        let mut sign_cert_path = sign_cert_path();
        sign_cert_path.push("sample/es256_certs.pem");

        let sign_config = SignConfig {
            alg: Some(SigningAlg::Es256.to_string()),
            sign_cert: Some(sign_cert_path),
            ..Default::default()
        };

        let result = vec![1, 2, 3];
        let expected = result.clone();

        let mut mock_callback_signer = MockSignCallback::default();
        mock_callback_signer
            .expect_sign()
            .returning(move |_| Ok(result.clone()));

        let config = CallbackSignerConfig::new(&sign_config, 1024).unwrap();
        let callback = Box::new(mock_callback_signer);
        let signer = CallbackSigner::new(callback, config);

        assert_eq!(Signer::sign(&signer, &[]).unwrap(), expected);
    }

    #[test]
    fn test_signing_succeeds_returns_error_embedding() {
        let mut sign_cert_path = sign_cert_path();
        sign_cert_path.push("sample/es256_certs.pem");

        let sign_config = SignConfig {
            alg: Some(SigningAlg::Es256.to_string()),
            sign_cert: Some(sign_cert_path),
            ..Default::default()
        };

        let mut mock_callback_signer = MockSignCallback::default();
        mock_callback_signer
            .expect_sign()
            .returning(|_| Err(anyhow!("")));

        let config = CallbackSignerConfig::new(&sign_config, 1024).unwrap();
        let callback = Box::new(mock_callback_signer);
        let signer = CallbackSigner::new(callback, config);

        assert!(matches!(
            Signer::sign(&signer, &[]),
            Err(Error::EmbeddingError)
        ));
    }

    #[test]
    fn test_sign_config_to_external_sign_config_fails() {
        let sign_config = SignConfig::default();
        assert!(CallbackSignerConfig::new(&sign_config, 1024).is_err());
    }

    #[test]
    fn test_sign_config_to_external_sign_config_fails_with_invalid_signing_alg() {
        let sign_config = SignConfig {
            alg: Some("invalid_signing_alg".to_owned()),
            ..Default::default()
        };

        let result = CallbackSignerConfig::new(&sign_config, 1024);
        let error = result.err().unwrap();
        assert_eq!(format!("{error}"), "Invalid signing algorithm provided")
    }

    #[test]
    fn test_sign_config_to_external_sign_config_fails_with_missing_sign_certs() {
        let sign_config = SignConfig {
            alg: Some(SigningAlg::Es256.to_string()),
            sign_cert: None,
            ..Default::default()
        };

        let result = CallbackSignerConfig::new(&sign_config, 1024);
        let error = result.err().unwrap();
        assert_eq!(
            format!("{error}"),
            "Unable to load the provided sign_cert_path"
        )
    }

    #[test]
    fn test_try_from_succeeds_for_valid_sign_config() {
        let mut sign_cert_path = sign_cert_path();
        sign_cert_path.push("sample/es256_certs.pem");

        let expected_alg = SigningAlg::Es256;
        let sign_config = SignConfig {
            alg: Some(expected_alg.to_string()),
            sign_cert: Some(sign_cert_path),
            ..Default::default()
        };

        let expected_reserve_size = 10248;
        let esc = CallbackSignerConfig::new(&sign_config, expected_reserve_size).unwrap();
        let callback = Box::<MockSignCallback>::default();
        let signer = CallbackSigner::new(callback, esc);

        assert_eq!(Signer::alg(&signer), expected_alg);
        assert_eq!(Signer::reserve_size(&signer), expected_reserve_size);
    }

    #[test]
    fn test_callback_signer_error_file_not_found() {
        let mut sign_cert_path = sign_cert_path();
        sign_cert_path.push("sample/NOT-HERE");

        let sign_config = SignConfig {
            alg: Some(SigningAlg::Es256.to_string()),
            sign_cert: Some(sign_cert_path),
            ..Default::default()
        };

        let config = CallbackSignerConfig::new(&sign_config, 10248).unwrap();
        let callback = Box::<MockSignCallback>::default();
        let signer = CallbackSigner::new(callback, config);

        assert!(matches!(signer.certs(), Err(Error::FileNotFound(_))));
    }

    #[test]
    fn test_callback_signer_error_invalid_cert() {
        let mut sign_cert_path = sign_cert_path();
        sign_cert_path.push("sample/test.json");

        let sign_config = SignConfig {
            alg: Some(SigningAlg::Es256.to_string()),
            sign_cert: Some(sign_cert_path),
            ..Default::default()
        };

        let config = CallbackSignerConfig::new(&sign_config, 1024).unwrap();
        let callback = Box::<MockSignCallback>::default();
        let signer = CallbackSigner::new(callback, config);

        assert!(matches!(signer.certs(), Err(Error::CoseInvalidCert)));
    }

    #[test]
    fn test_callback_signer_valid_sign_certs() {
        let mut sign_cert_path = sign_cert_path();
        sign_cert_path.push("sample/es256_certs.pem");

        let sign_config = SignConfig {
            alg: Some(SigningAlg::Es256.to_string()),
            sign_cert: Some(sign_cert_path),
            ..Default::default()
        };

        let config = CallbackSignerConfig::new(&sign_config, 1024).unwrap();
        let callback = Box::<MockSignCallback>::default();
        let signer = CallbackSigner::new(callback, config);

        assert_eq!(signer.certs().unwrap().len(), 2);
    }
}
