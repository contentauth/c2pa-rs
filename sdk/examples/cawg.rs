// Copyright 2025 Adobe. All rights reserved.
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

//! Example App that generates a CAWG manifest for a given file
//! and validates the identity assertion.
use anyhow::{bail, Result};
use c2pa::{
    dynamic_assertion::{PartialClaim, PostValidatorAsync},
    AsyncSigner, Builder, ManifestAssertion, Reader, SigningAlg,
};
use c2pa_crypto::raw_signature;
use c2pa_status_tracker::{log_item, StatusTracker};
use cawg_identity::{
    builder::{AsyncIdentityAssertionBuilder, AsyncIdentityAssertionSigner},
    claim_aggregation::IcaSignatureVerifier,
    x509::{X509CredentialHolder, X509SignatureVerifier},
    IdentityAssertion, ToCredentialSummary,
};
use serde_json::{json, Value};

const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");

fn manifest_def() -> String {
    json!({
        "claim_generator_info": [
            {
                "name": "c2pa cawg test",
                "version": env!("CARGO_PKG_VERSION")
            }
        ],
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.opened",
                        }
                    ]
                }
            },
            {
                "label": "cawg.training-mining",
                "data": {
                "entries": {
                    "cawg.ai_inference": {
                    "use": "notAllowed"
                    },
                    "cawg.ai_generative_training": {
                    "use": "notAllowed"
                    }
                }
                }
            }
        ]
    })
    .to_string()
}

/// Creates a CAWG signer from a certificate chains and private keys.
fn async_cawg_signer() -> Result<impl AsyncSigner> {
    let c2pa_raw_signer = raw_signature::async_signer_from_cert_chain_and_private_key(
        CERTS,
        PRIVATE_KEY,
        SigningAlg::Ed25519,
        None,
    )?;

    let cawg_raw_signer = raw_signature::async_signer_from_cert_chain_and_private_key(
        CERTS,
        PRIVATE_KEY,
        SigningAlg::Ed25519,
        None,
    )?;

    let mut ia_signer = AsyncIdentityAssertionSigner::new(c2pa_raw_signer);

    let x509_holder = X509CredentialHolder::from_async_raw_signer(cawg_raw_signer);
    let iab = AsyncIdentityAssertionBuilder::for_credential_holder(x509_holder);
    ia_signer.add_identity_assertion(iab);
    Ok(ia_signer)
}

/// Validates a CAWG identity assertion.
struct CawgValidator;
impl PostValidatorAsync for CawgValidator {
    async fn validate(
        &self,
        label: &str,
        assertion: &ManifestAssertion,
        uri: &str,
        partial_claim: &PartialClaim,
        tracker: &mut StatusTracker,
    ) -> c2pa::Result<Option<Value>> {
        #[allow(clippy::single_match)]
        if label == "cawg.identity" {
            let identity_assertion: IdentityAssertion = assertion.to_assertion()?;

            let result = identity_assertion
                .validate_partial_claim(partial_claim)
                .await
                .map_err(|e| c2pa::Error::ClaimVerification(e.to_string()))?;

            // let result = serde_json::to_value(ica_validated.to_summary())
            //     .map_err(|e| c2pa::Error::ClaimVerification(e.to_string()))?;
            // TODO: pass status_tracker to the validator
            log_item!(uri.to_string(), "cawg.identity", "test cawg validator")
                .validation_status("cawg.identity.validated")
                .success(tracker);
            return Ok(Some(result));
        };
        Ok(None)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        bail!("Creates a CAWG manifest (requires source and destination file paths)");
    }
    let source: std::path::PathBuf = std::path::PathBuf::from(&args[1]);
    let dest: std::path::PathBuf = std::path::PathBuf::from(&args[2]);
    if dest.exists() {
        // delete the destination file if it exists
        std::fs::remove_file(&dest)?;
    }

    let signer = async_cawg_signer()?;
    let mut builder = Builder::from_json(&manifest_def())?;
    //builder.definition.claim_version = Some(2); // sets this to claim version 2
    builder.sign_file_async(&signer, source, &dest).await?;

    let mut reader = Reader::from_file(&dest)?;

    reader.post_validate_async(&CawgValidator {}).await?;

    println!("{reader}");
    Ok(())
}
