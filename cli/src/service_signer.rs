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

use c2pa::Error::OtherError;
use std::str::FromStr;
use thiserror::Error;

use c2pa::SigningAlg;
use log::{debug, info};
use openssl::base64;
use url::Url;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub(crate) struct SignerDataResponse {
    alg: String,
    timestamp_url: Url,
    signing_url: Url,
    cert_chain: String,
}

impl SignerDataResponse {
    // base64 decode the cert_chain
    pub(crate) fn cert_chain(&self) -> Result<Vec<u8>, Error> {
        Ok(base64::decode_block(&self.cert_chain).map_err(Error::Base64Error)?)
    }
}

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),

    #[error("Base64 error: {0}")]
    Base64Error(#[from] openssl::error::ErrorStack),
}

pub(crate) trait SignerDataGetter {
    fn get_signer_data(&self) -> Result<SignerDataResponse, Error>;
}

pub(crate) struct SigningServiceImpl {
    pub(crate) root_domain: Url,
}

impl SignerDataGetter for SigningServiceImpl {
    fn get_signer_data(&self) -> Result<SignerDataResponse, Error> {
        info!("calling /signer_data at {}", self.root_domain.as_str());
        let url = self.root_domain.join("/signer_data")?;
        let response = reqwest::blocking::get(url)?;
        Ok(response.json::<SignerDataResponse>()?)
    }
}

pub(crate) struct ServiceSigner {
    signer_data: SignerDataResponse,
}

impl ServiceSigner {
    pub fn try_from(signing_service: Box<dyn SignerDataGetter>) -> Result<Self, Error> {
        let signer_data = signing_service.get_signer_data()?;
        info!(
            "signer_data.timestamp_url: {:?}",
            signer_data.timestamp_url.as_str()
        );
        info!(
            "signer_data.signer_url: {:?}",
            signer_data.signing_url.as_str()
        );
        info!("signer_data.alg: {:?}", signer_data.signing_url.as_str());
        debug!("signer_data.cert_chain: {:?}", signer_data.cert_chain);
        Ok(Self { signer_data })
    }
}

impl c2pa::Signer for ServiceSigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        info!("signing with : {:?}", self.signer_data.signing_url.as_str());

        let resp = reqwest::blocking::Client::new()
            .post(self.signer_data.signing_url.as_str())
            .query(&[("box_size", self.reserve_size())])
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(data.to_vec())
            .send()
            .map_err(|e| OtherError(Box::new(e)))?;

        info!("status: {:?}", resp.status());

        if !resp.status().is_success() {
            info!("error: {:?}", resp.text().unwrap());
            return Err(c2pa::Error::EmbeddingError)
        }

        Ok(resp.bytes().map_err(|e| OtherError(e.into()))?.to_vec())
    }

    fn alg(&self) -> SigningAlg {
        SigningAlg::from_str(&self.signer_data.alg.to_lowercase()).unwrap()
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        let cert_chain = self
            .signer_data
            .cert_chain()
            .map_err(|v| OtherError(Box::new(v)))?;
        let value = String::from_utf8(cert_chain.clone()).map_err(|v| OtherError(Box::new(v)))?;

        debug!("ServiceSigner::certs (as utf8) {:?}", value);

        let pems = pem::parse_many(self.signer_data.cert_chain().unwrap())
            .map_err(|e| OtherError(Box::new(e)))?;
        
        Ok(pems.into_iter().map(|p| p.into_contents()).collect())
    }

    fn reserve_size(&self) -> usize {
        info!("reserve_size (hardcoded): {:?}", 12488);
        12488
    }

    fn time_authority_url(&self) -> Option<String> {
        info!(
            "time_authority_url: {:?}",
            self.signer_data.timestamp_url.to_string()
        );
        Some(self.signer_data.timestamp_url.to_string())
    }
}
