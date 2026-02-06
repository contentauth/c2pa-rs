use http::Request;
use openssl::x509::X509;
use url::Url;

use crate::{
    crypto::{
        raw_signature::{
            openssl::{
                cert_chain::{cert_chain_to_der, check_chain_order},
                OpenSslMutex,
            },
            RawSigner, RawSignerError,
        },
        time_stamp::TimeStampProvider,
    },
    http::{SyncGenericResolver, SyncHttpResolver},
    Error, SigningAlg,
};

// ============================================================================
// Remote Raw Signer for CAWG Identity
// ============================================================================

/// A raw signer that delegates signing to a remote HTTP service.
/// Used for CAWG identity signing when configured in remote mode.
pub struct RemoteRawSigner {
    /// The URL endpoint for the signing service
    url: Url,

    /// Parsed certificate chain in DER format
    cert_chain: Vec<Vec<u8>>,

    /// Certificate chain byte size
    cert_chain_len: usize,
    /// The signing algorithm
    alg: SigningAlg,

    /// Optional TSA URL
    time_stamp_service_url: Option<String>,
    /// Timestamp size
    time_stamp_size: usize,
}

impl RemoteRawSigner {
    pub fn from_cert_chain_and_url(
        cert_chain: &[u8],
        url: Url,
        alg: SigningAlg,
        time_stamp_service_url: Option<String>,
    ) -> Result<Self, RawSignerError> {
        let _openssl = OpenSslMutex::acquire()?;

        let cert_chain = X509::stack_from_pem(cert_chain)?;

        if !check_chain_order(&cert_chain) {
            return Err(RawSignerError::InvalidSigningCredentials(
                "certificate chain in incorrect order".to_string(),
            ));
        }

        let cert_chain = cert_chain_to_der!(cert_chain)?;

        let cert_chain_len = cert_chain.iter().fold(0usize, |sum, c| sum + c.len());

        Ok(Self {
            url,
            cert_chain,
            cert_chain_len,
            alg,
            time_stamp_service_url,
            time_stamp_size: 10_000,
            // TODO: Call out to time stamp service to get actual time stamp and use that size?
        })
    }
}

impl RawSigner for RemoteRawSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        use std::io::Read;

        let request = Request::post(self.url.as_str())
            .body(data.to_vec())
            .map_err(|_| Error::FailedToRemoteSign)?;

        let response = SyncGenericResolver::new()
            .http_resolve(request)
            .map_err(|_| Error::FailedToRemoteSign)?;

        let reserve_size = self.reserve_size();
        let mut bytes: Vec<u8> = Vec::with_capacity(reserve_size);
        response
            .into_body()
            .take(reserve_size as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::FailedToRemoteSign)?;

        Ok(bytes)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError> {
        let _openssl = OpenSslMutex::acquire()?;
        Ok(self.cert_chain.clone())
    }

    fn reserve_size(&self) -> usize {
        10_000 + self.cert_chain_len + self.time_stamp_size
    }
}

impl TimeStampProvider for RemoteRawSigner {
    fn time_stamp_service_url(&self) -> Option<String> {
        self.time_stamp_service_url.clone()
    }
}
