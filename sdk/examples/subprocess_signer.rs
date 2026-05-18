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

//! Example: subprocess signer for use with c2patool.
//!
//! This binary implements the c2patool subprocess signing protocol so it can
//! be passed to `c2patool --signer-path` or `--identity-signer-path`.
//!
//! ## Protocol
//!
//! c2patool calls the subprocess in two ways:
//!
//! **Info query** — called once before signing to discover cert and algorithm:
//! ```sh
//! subprocess_signer --signer-info
//! ```
//! The signer must write a JSON object to stdout and exit 0:
//! ```json
//! { "alg": "Ed25519", "sign_cert": "-----BEGIN CERTIFICATE-----\n..." }
//! ```
//! Fields:
//! - `alg` — signing algorithm (required)
//! - `sign_cert` — PEM certificate chain, end-entity first (required)
//! - `reserve_size` — override COSE reserve size; omit to let the SDK compute it
//!
//! **Sign** — called to produce each signature:
//! ```sh
//! subprocess_signer
//! ```
//! c2patool writes the bytes to be signed to stdin; the signer writes the raw
//! signature bytes to stdout and exits 0.
//!
//! ## Adapting for a real KMS / HSM
//!
//! Replace `ed25519_sign` with a call to your key management system.
//! The private key should never leave the signing environment.
//!
//! ## Running this example
//!
//! ```sh
//! cargo build --example subprocess_signer
//! ./target/debug/examples/subprocess_signer --signer-info
//! ```

use std::io::{self, Read, Write};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const TEST_CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const TEST_PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");

// ── Signer info ──────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct SignerInfo {
    alg: String,
    sign_cert: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reserve_size: Option<usize>,
}

// ── Operations ───────────────────────────────────────────────────────────────

fn handle_signer_info() -> Result<()> {
    let info = SignerInfo {
        alg: "Ed25519".to_string(),
        sign_cert: std::str::from_utf8(TEST_CERTS)
            .context("certs not valid UTF-8")?
            .to_string(),
        reserve_size: None,
    };
    io::stdout()
        .write_all(serde_json::to_string(&info)?.as_bytes())
        .context("writing signer info")
}

fn handle_sign() -> Result<()> {
    let mut data = Vec::new();
    io::stdin()
        .read_to_end(&mut data)
        .context("reading stdin")?;
    let sig = ed25519_sign(&data, TEST_PRIVATE_KEY)?;
    io::stdout().write_all(&sig).context("writing signature")
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--signer-info") {
        handle_signer_info()
    } else {
        handle_sign()
    }
}

// ── Ed25519 signing ──────────────────────────────────────────────────────────

fn ed25519_sign(data: &[u8], private_key_pem: &[u8]) -> Result<Vec<u8>> {
    use ed25519_dalek::{Signature, Signer, SigningKey};

    let pem = pem::parse(private_key_pem).map_err(|e| anyhow::anyhow!("{e}"))?;
    let key_bytes = pem
        .contents()
        .get(16..)
        .context("PEM too short for Ed25519 key")?;
    let key = SigningKey::try_from(key_bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
    let sig: Signature = key.sign(data);
    Ok(sig.to_bytes().to_vec())
}
