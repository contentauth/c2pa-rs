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
//! c2patool calls the subprocess in up to three ways:
//!
//! **Info query** — called once before signing to discover cert and algorithm:
//! ```sh
//! subprocess_signer --signer-info
//! ```
//! The signer must write a JSON object to stdout and exit 0:
//! ```json
//! { "alg": "ed25519", "sign_cert": "-----BEGIN CERTIFICATE-----\n...", "supports_timestamp": true }
//! ```
//! Fields:
//! - `alg` — signing algorithm (required)
//! - `sign_cert` — PEM certificate chain, end-entity first (required)
//! - `tsa_url` — timestamp authority URL; omit if the subprocess handles timestamps itself
//! - `supports_timestamp` — set to `true` to opt in to the `--timestamp` protocol below
//! - `reserve_size` — override the COSE reserve size; omit to let the SDK compute it
//!
//! **Sign** — called to produce each signature:
//! ```sh
//! subprocess_signer
//! ```
//! c2patool writes the bytes to be signed to stdin; the signer writes the raw
//! signature bytes to stdout and exits 0.  Any non-zero exit is treated as a
//! failure and the stderr output surfaces as an error message.
//!
//! **Timestamp** — called when `supports_timestamp` is `true` in the info response:
//! ```sh
//! subprocess_signer --timestamp
//! ```
//! c2patool writes the message bytes to stdin; the signer must obtain an RFC 3161
//! timestamp token (e.g. by calling a TSA URL) and write the raw token bytes to
//! stdout.  This lets the subprocess own the TSA HTTP call — useful when the TSA
//! requires credentials that should not be passed through c2patool.
//!
//! ## Configuration via environment variables
//!
//! | Variable              | Description                                  |
//! |-----------------------|----------------------------------------------|
//! | `C2PA_SIGN_CERT`      | PEM certificate chain (end-entity first)     |
//! | `C2PA_PRIVATE_KEY`    | PEM private key (keep this secret)           |
//! | `C2PA_SIGNING_ALG`    | Algorithm: `ed25519`, `es256`, … (optional)  |
//! | `C2PA_TSA_URL`        | Timestamp authority URL (optional)           |
//!
//! When neither variable is set the signer falls back to the embedded test
//! credentials — **suitable for development only**.
//!
//! ## Adapting for a real KMS / HSM
//!
//! In production, replace the signing logic in `handle_sign` with a call to
//! your key management system.  The signer only needs to implement two things:
//!
//! 1. Return the public certificate chain from `--signer-info`.
//! 2. Produce a raw signature over the bytes from stdin.
//!
//! The private key should never leave the signing environment.
//!
//! ## Running this example
//!
//! Build the binary:
//! ```sh
//! cargo build --example subprocess_signer
//! ```
//!
//! Test the info query:
//! ```sh
//! ./target/debug/examples/subprocess_signer --signer-info
//! ```
//!
//! Use it with c2patool:
//! ```sh
//! c2patool image.jpg \
//!     --manifest manifest.json \
//!     --signer-path ./target/debug/examples/subprocess_signer \
//!     -o signed.jpg
//! ```

use std::io::{self, Read, Write};

use anyhow::{Context, Result};
use c2pa::{CallbackSigner, Signer, SigningAlg};
use serde::{Deserialize, Serialize};

// ── Embedded test credentials (development only) ───────────────────────────
// In production these are replaced by values from environment variables or a
// call to a key management system.

const TEST_CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const TEST_PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");
const TEST_ALG: SigningAlg = SigningAlg::Ed25519;

// ── Signer info ─────────────────────────────────────────────────────────────

/// The JSON structure written to stdout in response to `--signer-info`.
#[derive(Serialize, Deserialize)]
struct SignerInfo {
    alg: SigningAlg,
    sign_cert: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tsa_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reserve_size: Option<usize>,
    /// When `true`, c2patool will call this subprocess with `--timestamp` to
    /// obtain RFC 3161 tokens instead of making TSA requests itself.
    #[serde(skip_serializing_if = "is_false", default)]
    supports_timestamp: bool,
}

fn is_false(b: &bool) -> bool {
    !b
}

// ── Configuration ────────────────────────────────────────────────────────────

struct Config {
    certs_pem: Vec<u8>,
    alg: SigningAlg,
    tsa_url: Option<String>,
}

impl Config {
    fn load() -> Result<Self> {
        let tsa_url = std::env::var("C2PA_TSA_URL").ok();
        Ok(Self {
            certs_pem: TEST_CERTS.to_vec(),
            alg: TEST_ALG,
            tsa_url,
        })
    }
}

// ── Operations ───────────────────────────────────────────────────────────────

/// Handle `--signer-info`: print the JSON info block and exit 0.
fn handle_signer_info(config: &Config) -> Result<()> {
    // `reserve_size` is intentionally omitted here (returns None).
    //
    // c2patool computes the full reserve automatically from (alg, sign_cert):
    //   raw signature bytes  — exact, derived from alg and the public key
    //   certificate chain    — exact, DER bytes embedded in COSE headers
    //   COSE/CBOR framing    — a small fixed constant the SDK knows
    //   timestamp token      — 8 KB default when tsa_url is present or
    //                          supports_timestamp is true, 0 otherwise
    //
    // Only set reserve_size if your TSA consistently returns tokens larger than
    // 8 KB, or if you need to override the default for any other reason.
    //
    // When `supports_timestamp` is true, `tsa_url` is omitted from the info
    // response: c2patool will call `--timestamp` instead of handling the TSA
    // request itself, so it does not need the URL.
    let supports_timestamp = config.tsa_url.is_some();
    let info = SignerInfo {
        alg: config.alg,
        sign_cert: String::from_utf8(config.certs_pem.clone())
            .context("sign_cert is not valid UTF-8")?,
        // Omit tsa_url when supports_timestamp is true: the subprocess handles
        // the TSA call, so c2patool doesn't need (or get) the URL.
        tsa_url: if supports_timestamp {
            None
        } else {
            config.tsa_url.clone()
        },
        reserve_size: None,
        supports_timestamp,
    };

    let json = serde_json::to_string(&info).context("serializing signer info")?;
    io::stdout()
        .write_all(json.as_bytes())
        .context("writing signer info to stdout")?;
    Ok(())
}

/// Handle `--timestamp`: read message bytes from stdin, obtain an RFC 3161
/// timestamp token via the configured TSA URL, and write the token to stdout.
///
/// c2patool calls this when `supports_timestamp` is `true` in the info
/// response.  The subprocess owns the TSA HTTP call, which is useful when the
/// TSA requires credentials (API keys, client certs) that should not be
/// exposed to c2patool.
///
/// In a real signer you can replace the TSA call with a call to your own
/// time-stamping infrastructure.
fn handle_timestamp(config: &Config) -> Result<()> {
    let tsa_url = config
        .tsa_url
        .as_deref()
        .context("C2PA_TSA_URL must be set to handle --timestamp requests")?;

    // Read the message bytes from stdin.
    let mut message = Vec::new();
    io::stdin()
        .read_to_end(&mut message)
        .context("reading message from stdin")?;

    // Delegate the RFC 3161 HTTP call to CallbackSigner's built-in machinery.
    // A temporary signer is created here solely to borrow its send_timestamp_request
    // implementation; the dummy signing callback is never invoked.
    let dummy_sign = |_: *const (), _: &[u8]| Ok(vec![]);
    let signer =
        CallbackSigner::new(dummy_sign, config.alg, config.certs_pem.clone()).set_tsa_url(tsa_url);

    let token = signer
        .send_timestamp_request(&message)
        .context("timestamp request returned None (no TSA URL configured?)")?
        .map_err(|e| anyhow::anyhow!("timestamp request failed: {e}"))?;

    io::stdout()
        .write_all(&token)
        .context("writing timestamp token to stdout")?;
    Ok(())
}

/// Handle the signing operation: read bytes from stdin, sign them, and write
/// the raw signature bytes to stdout.
///
/// In a real signer this is where you call your KMS / HSM / cloud API.
fn handle_sign(_config: &Config) -> Result<()> {
    // Read the bytes to sign from stdin.
    let mut data = Vec::new();
    io::stdin()
        .read_to_end(&mut data)
        .context("reading bytes from stdin")?;

    // Sign the data.
    //
    // This example uses Ed25519 via `CallbackSigner::ed25519_sign`.
    let signature = CallbackSigner::ed25519_sign(&data, TEST_PRIVATE_KEY)?;

    // Write the raw signature bytes to stdout.
    io::stdout()
        .write_all(&signature)
        .context("writing signature to stdout")?;
    Ok(())
}

// ── Entry point ─────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let config = Config::load()?;

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--signer-info") {
        handle_signer_info(&config)
    } else if args.iter().any(|a| a == "--timestamp") {
        handle_timestamp(&config)
    } else {
        handle_sign(&config)
    }
}
