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

use core::str;

use async_trait::async_trait;
use c2pa_crypto::{
    raw_signature::{AsyncRawSigner, RawSigner, RawSignerError, SigningAlg},
    time_stamp::{AsyncTimeStampProvider, TimeStampError, TimeStampProvider},
};
use rsa::{
    pkcs8::DecodePrivateKey,
    pss::SigningKey,
    sha2::{Sha256, Sha384, Sha512},
    signature::{RandomizedSigner, SignatureEncoding},
    RsaPrivateKey,
};

use crate::{signer::ConfigurableSigner, AsyncSigner, Error, Result, Signer};

// Implements `Signer` trait using rsa crate implementation of
// SHA256 + RSA encryption.  This implementation is only used for cross
// target compatible signer used in testing both sync and WASM async unit tests.
pub struct RsaWasmSigner {
    signcerts: Vec<Vec<u8>>,
    pkey: RsaPrivateKey,

    certs_size: usize,
    timestamp_size: usize,

    alg: SigningAlg,
    tsa_url: Option<String>,
}

impl ConfigurableSigner for RsaWasmSigner {
    fn from_signcert_and_pkey(
        signcert: &[u8],
        pkey: &[u8],
        alg: SigningAlg,
        tsa_url: Option<String>,
    ) -> Result<Self> {
        let mut signcerts = Vec::new();
        for pem in x509_parser::pem::Pem::iter_from_buffer(signcert) {
            let pem =
                pem.map_err(|_e| Error::OtherError("Reading next PEM block failed".into()))?;

            signcerts.push(pem.contents);
        }
        let pem_str = str::from_utf8(pkey)
            .map_err(|_e| Error::OtherError("Reading PKEY PEM block failed".into()))?;
        let pk = RsaPrivateKey::from_pkcs8_pem(pem_str).map_err(|e| Error::OtherError(e.into()))?;

        let signer = RsaWasmSigner {
            signcerts,
            pkey: pk,
            certs_size: signcert.len(),
            timestamp_size: 10000, /* todo: call out to TSA to get actual timestamp and use that size */
            alg,
            tsa_url,
        };

        Ok(signer)
    }
}

impl Signer for RsaWasmSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();

        match self.alg {
            SigningAlg::Ps256 => {
                let s = rsa::pss::SigningKey::<Sha256>::new(self.pkey.clone());

                let sig = s.sign_with_rng(&mut rng, data);

                Ok(sig.to_bytes().to_vec())
            }
            SigningAlg::Ps384 => {
                let s = SigningKey::<Sha384>::new(self.pkey.clone());

                let sig = s.sign_with_rng(&mut rng, data);

                Ok(sig.to_bytes().to_vec())
            }
            SigningAlg::Ps512 => {
                let s = SigningKey::<Sha512>::new(self.pkey.clone());

                let sig = s.sign_with_rng(&mut rng, data);

                Ok(sig.to_bytes().to_vec())
            }
            _ => return Err(Error::UnsupportedType),
        }
    }

    fn reserve_size(&self) -> usize {
        1024 + self.certs_size + self.timestamp_size // the Cose_Sign1 contains complete certs and timestamps so account for size
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.signcerts.clone())
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }

    fn ocsp_val(&self) -> Option<Vec<u8>> {
        None
    }

    fn raw_signer(&self) -> Box<&dyn RawSigner> {
        Box::new(self)
    }
}

impl RawSigner for RsaWasmSigner {
    fn sign(&self, data: &[u8]) -> std::result::Result<Vec<u8>, RawSignerError> {
        let mut rng = rand::thread_rng();

        match self.alg {
            SigningAlg::Ps256 => {
                let s = rsa::pss::SigningKey::<Sha256>::new(self.pkey.clone());

                let sig = s.sign_with_rng(&mut rng, data);

                Ok(sig.to_bytes().to_vec())
            }
            SigningAlg::Ps384 => {
                let s = SigningKey::<Sha384>::new(self.pkey.clone());

                let sig = s.sign_with_rng(&mut rng, data);

                Ok(sig.to_bytes().to_vec())
            }
            SigningAlg::Ps512 => {
                let s = SigningKey::<Sha512>::new(self.pkey.clone());

                let sig = s.sign_with_rng(&mut rng, data);

                Ok(sig.to_bytes().to_vec())
            }
            _ => {
                return Err(RawSignerError::InternalError(
                    "unsupported signature algorithm".to_string(),
                ))
            }
        }
    }

    fn reserve_size(&self) -> usize {
        1024 + self.certs_size + self.timestamp_size // the Cose_Sign1 contains complete certs and timestamps so account for size
    }

    fn cert_chain(&self) -> std::result::Result<Vec<Vec<u8>>, RawSignerError> {
        Ok(self.signcerts.clone())
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn ocsp_response(&self) -> Option<Vec<u8>> {
        None
    }
}

impl TimeStampProvider for RsaWasmSigner {
    fn time_stamp_service_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }
}

// If "../../tests/fixtures/certs/rs256.pub" or "../../tests/fixtures/certs/rs256.pem") change
// CHAIN_BYTES and KEY_BYTES should be updated here.
// We embed the certs here because WASM cannot read the fixtures.

const KEY_BYTES: &str = r#"-----BEGIN PRIVATE KEY-----
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
hil16PeFvT18GsZymgmmKjoKK0juBA==
-----END PRIVATE KEY-----
"#;

const CERT_BYTES: &str = r#"-----BEGIN CERTIFICATE-----
MIIGFDCCA/ygAwIBAgIUdHK+EwyPv8SBVvdfNSQOmpuOm1swDQYJKoZIhvcNAQEL
BQAwgYwxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTESMBAGA1UEBwwJU29tZXdo
ZXJlMScwJQYDVQQKDB5DMlBBIFRlc3QgSW50ZXJtZWRpYXRlIFJvb3QgQ0ExGTAX
BgNVBAsMEEZPUiBURVNUSU5HX09OTFkxGDAWBgNVBAMMD0ludGVybWVkaWF0ZSBD
QTAeFw0yNDA3MzExOTA1MDJaFw0zMjEwMTYxOTA1MDJaMIGAMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ0ExEjAQBgNVBAcMCVNvbWV3aGVyZTEfMB0GA1UECgwWQzJQ
QSBUZXN0IFNpZ25pbmcgQ2VydDEZMBcGA1UECwwQRk9SIFRFU1RJTkdfT05MWTEU
MBIGA1UEAwwLQzJQQSBTaWduZXIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQCq/rU2E/3y72c2r/RtA9G49U/n6rDNWrftt36MQIOSvY/3hmi95AgG/Uer
x5a4TUPLjzr1QV9NXSeWR7uuva0lLqy826Vz4UlUAtuZDvaqOXx2UopeU7gxEfNV
RDZLTaX7y0m+4goIVIr+ArVUm8ewe5QSFs1PqEqzlaQGe9nxG+ar1fOxGD+xPzE+
yjVDVXICDN6IcWna9d571BM4urxkK/+V4VjtxzKfLn6t39Jbm3cwDYna0jJAlqjW
D1V6K2vFA9V9AK1eOZYo/s4m4Khc5ARVPmhmJ+cpPbZMokeLzTgzE+icFGd3ID9b
2SRnZaoPnl1VGp7C9MjkQP2xcxLRYFVG7VpK4aTmhdjwa94a7hrVW3IaGMtdo1jj
J+2USEPdCqio49uriuRu/njfxUomgYOLy+Yih0dEgJykWzjeCQydXEHOwTc0YQnS
j3JNkVNrJgcAJtfxtWDAQhpyCDR7DOFwK1Yf74EuhrSS1eoFgx2mi5aEW3k1VGi4
DcnJaAlnTm+3YukKlhcQ1SbSY/v3elXqH44dkrMhI02YnqmLVaxk0QSeny3LnlUF
i/R+RHgMfg9DtFBSJy6BrDIig2kvJld1cWoofn00lOd7lhUas/tJgKZ547vOqdC2
10y4dHvliLjkXBFhbLSQIKdjveaY7hpD6SuBuB1xrTh7qZlLYQIDAQABo3gwdjAM
BgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMEMA4GA1UdDwEB/wQE
AwIGwDAdBgNVHQ4EFgQUabkweF0dTTeD61uURLw0Gy0Sk7MwHwYDVR0jBBgwFoAU
QWjNAN6ORkApBvfp1uz099iXEvMwDQYJKoZIhvcNAQELBQADggIBAGK0kfVg0Zjk
Z2L4y9Qn7RityezYVBsa7nh5B/9TJWr579DBiQPdnocPym0P2HyLZ1vGcXxLnHpW
bJYi4mRpcriXLtUB+znASLmgz1it0EJTO+MVQSqPTpfAtjr9heNcrzwIGWKAsmCC
jUt6vxRaTSSmR6bMLAZEukJeSCE3piFslA3u2k4GhGPu2RFyPtQ6mbupr+bxYTEG
QnyNgNQL5b+da1p6IPwrNtMXQ11vkR0KeOppA/LMX6ccS9jMSISceUJbBqCVdKKV
0bFKET/ayigZo9sW7SJkga+WJ8dtWhk9b9LfyK2od07ds22YiUzNgmzd8+GhOlXQ
oM7zhPuH7Xmh3laG2T7Hb4msMaBTCTO+c8Pwyqdhbyuwyi7xoYIu/wfFb6mwJ/G/
KQ0dzByfzd2ifDX1wG8uASadh+ABsi2yWqgV4kjYEdayEJdPgCyxIINSPTMgKkEi
oHxKz6+cDXaFIm0hw9qHOszj1VIp9F0MlmUoLZ4VxtNlykZKvYyFYIf3t9xca1QX
49eDoornfmUhJNavQFUDPkaH4wA7a2o48HU4AgImLnCaDMtNLEsUhFkvX6oy7cE3
1fbJel0wFUChqH0F3SxI9fHnt9orostw54E5O+8movGxmyIp8fWxqcobitz0oHMj
5+viSlzef45psTWmDXyL85G8abDsIYDS
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
"#;

pub struct RsaWasmSignerAsync {
    signer: Box<dyn Signer>,
}

impl RsaWasmSignerAsync {
    #[allow(dead_code)]
    pub fn new() -> Self {
        let cert_bytes = CERT_BYTES.as_bytes();
        let key_bytes = KEY_BYTES.as_bytes();

        Self {
            signer: Box::new(
                RsaWasmSigner::from_signcert_and_pkey(
                    cert_bytes,
                    key_bytes,
                    SigningAlg::Ps256,
                    None,
                )
                .expect("test signer configuration error"),
            ),
        }
    }
}

#[async_trait(?Send)]
impl AsyncSigner for RsaWasmSignerAsync {
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        Signer::sign(&self.signer, &data)
    }

    fn alg(&self) -> SigningAlg {
        Signer::alg(&self.signer)
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        self.signer.certs()
    }

    fn reserve_size(&self) -> usize {
        Signer::reserve_size(&self.signer)
    }

    async fn send_timestamp_request(&self, _message: &[u8]) -> Option<Result<Vec<u8>>> {
        None
    }

    fn async_raw_signer(&self) -> Box<&dyn AsyncRawSigner> {
        Box::new(self)
    }
}

#[async_trait(?Send)]
impl AsyncRawSigner for RsaWasmSignerAsync {
    async fn sign(&self, data: Vec<u8>) -> std::result::Result<Vec<u8>, RawSignerError> {
        Signer::sign(&self.signer, &data).map_err(|e| RawSignerError::InternalError(e.to_string()))
    }

    fn alg(&self) -> SigningAlg {
        Signer::alg(&self.signer)
    }

    fn cert_chain(&self) -> std::result::Result<Vec<Vec<u8>>, RawSignerError> {
        Ok(self.signer.certs()?)
    }

    fn reserve_size(&self) -> usize {
        Signer::reserve_size(&self.signer)
    }
}

#[async_trait(?Send)]
impl AsyncTimeStampProvider for RsaWasmSignerAsync {
    async fn send_time_stamp_request(
        &self,
        _message: &[u8],
    ) -> Option<std::result::Result<Vec<u8>, TimeStampError>> {
        None
    }
}

unsafe impl Sync for RsaWasmSignerAsync {}

#[allow(unused_imports)]
#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use asn1_rs::FromDer;
    use c2pa_crypto::raw_signature::SigningAlg;
    use rsa::{
        pss::{Signature, VerifyingKey},
        sha2::{Digest, Sha256},
        signature::{Keypair, Verifier},
        RsaPrivateKey,
    };

    use super::*;
    use crate::{utils::test::fixture_path, Signer};

    #[test]
    fn sign_ps256() {
        let cert_bytes = CERT_BYTES.as_bytes();
        let key_bytes = KEY_BYTES.as_bytes();

        let signer =
            RsaWasmSigner::from_signcert_and_pkey(cert_bytes, key_bytes, SigningAlg::Ps256, None)
                .unwrap();

        let data = b"some sample content to sign";

        let sig = Signer::sign(&signer, data).unwrap();
        println!("signature len = {}", sig.len());
        assert!(sig.len() <= Signer::reserve_size(&signer));

        let sk = rsa::pss::SigningKey::<Sha256>::new(signer.pkey.clone());
        let vk = sk.verifying_key();

        let signature: Signature = sig.as_slice().try_into().unwrap();
        assert!(vk.verify(data, &signature).is_ok());
    }
}
