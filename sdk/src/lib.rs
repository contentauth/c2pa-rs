// Copyright 2022 Adobe. All rights reserved.
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

#![deny(warnings)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg, doc_cfg_hide))]

//! This library supports reading, creating and embedding C2PA data
//! with JPEG and PNG images.
//!
//! To read with file based methods, you must add the `file_io` dependency to your Cargo.toml.
//! For example:
//!
//! ```text
//! c2pa = {version="0.11.0", features=["file_io"]}
//! ```
//!
//! # Example: Reading a ManifestStore
//!
//! ```
//! # use c2pa::Result;
//! use c2pa::{assertions::Actions, Reader};
//!
//! # fn main() -> Result<()> {
//! let manifest_store = Reader::from_file("tests/fixtures/C.jpg")?;
//! println!("{}", manifest_store.json());
//!
//! if let Some(manifest) = manifest_store.active() {
//!     let actions: Actions = manifest.find_assertion(Actions::LABEL)?;
//!     for action in actions.actions {
//!         println!("{}\n", action.action());
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Example: Adding a Manifest to a file
//!
//! ```
//! # use c2pa::Result;
//! use std::path::PathBuf;
//!
//! use c2pa::{create_signer, Builder, SigningAlg};
//! use serde::Serialize;
//! use tempfile::tempdir;
//!
//! #[derive(Serialize)]
//! struct Test {
//!     my_tag: usize,
//! }
//!
//! # fn main() -> Result<()> {
//! let mut builder = Builder::from_json(r#"{"title": "Test"}"#)?;
//! builder.add_assertion("org.contentauth.test", &Test { my_tag: 42 })?;
//!
//! // Create a ps256 signer using certs and key files
//! let signer = create_signer::from_files(
//!     "tests/fixtures/certs/ps256.pub",
//!     "tests/fixtures/certs/ps256.pem",
//!     SigningAlg::Ps256,
//!     None,
//! )?;
//!
//! // embed a manifest using the signer
//! std::fs::remove_file("../target/tmp/lib_sign.jpg"); // ensure the file does not exist
//! builder.sign_file(
//!     "tests/fixtures/C.jpg",
//!     "../target/tmp/lib_sign.jpg",
//!     &*signer,
//! )?;
//! # Ok(())
//! # }
//! ```

/// The internal name of the C2PA SDK
pub const NAME: &str = "c2pa-rs";

/// The version of this C2PA SDK
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Public modules
pub mod assertions;
#[cfg(feature = "openssl_sign")]
pub mod create_signer;
pub mod validation_status;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

// Public exports
pub use callback_signer::{create_callback_signer, SignerCallback};
pub use claim_generator_info::ClaimGeneratorInfo;
// put these behind a feature flag for the remote signer
pub use cose_sign::{sign_claim, sign_claim_async};
pub use error::{Error, Result};
pub use hash_utils::{hash_stream_by_alg, HashRange};
pub use ingredient::Ingredient;
pub use jumbf_io::{get_supported_types, load_jumbf_from_stream, save_jumbf_to_stream};
pub use manifest::Manifest;
pub use manifest_assertion::{ManifestAssertion, ManifestAssertionKind};
#[cfg(feature = "v1_api")]
pub use manifest_store::ManifestStore;
#[cfg(feature = "v1_api")]
pub use manifest_store_report::ManifestStoreReport;
pub use settings::{load_settings_from_str, reset_default_settings};
pub use signer::{AsyncSigner, RemoteSigner, Signer};
pub use signing_alg::SigningAlg;
pub use v2_api::{format_from_path, Builder, Reader};

// Internal modules
#[allow(dead_code, clippy::enum_variant_names)]
pub(crate) mod asn1;
pub(crate) mod assertion;
pub(crate) mod asset_handlers;
pub(crate) mod asset_io;
pub(crate) mod callback_signer;
pub(crate) mod claim;
pub(crate) mod claim_generator_info;
pub(crate) mod cose_sign;
pub(crate) mod cose_validator;
#[cfg(all(feature = "xmp_write", feature = "file_io"))]
pub(crate) mod embedded_xmp;
pub(crate) mod error;
pub(crate) mod hashed_uri;
pub(crate) mod ingredient;
#[allow(dead_code)]
pub(crate) mod jumbf;
pub(crate) mod jumbf_io;
pub(crate) mod manifest;
pub(crate) mod manifest_assertion;
pub(crate) mod manifest_store;
pub(crate) mod manifest_store_report;
pub(crate) mod ocsp_utils;
#[cfg(feature = "openssl")]
pub(crate) mod openssl;
pub(crate) mod resource_store;
pub(crate) mod salt;
pub(crate) mod settings;
pub(crate) mod signer;
pub(crate) mod signing_alg;
pub(crate) mod status_tracker;
pub(crate) mod store;
pub(crate) mod time_stamp;
pub(crate) mod trust_handler;
pub(crate) mod utils;
pub(crate) use utils::{cbor_types, hash_utils};
pub(crate) mod v2_api;
pub(crate) mod validator;
