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
//! To read or write a manifest file, you must add the `file_io` dependency to your Cargo.toml.
//! EXCEPTION: If you are building for WASM, do not add this dependency.
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
//! use c2pa::{assertions::Actions, ManifestStore};
//!
//! # fn main() -> Result<()> {
//! let manifest_store = ManifestStore::from_file("tests/fixtures/C.jpg")?;
//! println!("{}", manifest_store);
//!
//! if let Some(manifest) = manifest_store.get_active() {
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
//! use c2pa::{create_signer, Manifest, SigningAlg};
//! use serde::Serialize;
//! use tempfile::tempdir;
//!
//! #[derive(Serialize)]
//! struct Test {
//!     my_tag: usize,
//! }
//!
//! # fn main() -> Result<()> {
//! let mut manifest = Manifest::new("my_app".to_owned());
//! manifest.add_labeled_assertion("org.contentauth.test", &Test { my_tag: 42 })?;
//!
//! let source = PathBuf::from("tests/fixtures/C.jpg");
//! let dir = tempdir()?;
//! let dest = dir.path().join("test_file.jpg");
//!
//! // Create a ps256 signer using certs and key files
//! let signcert_path = "tests/fixtures/certs/ps256.pub";
//! let pkey_path = "tests/fixtures/certs/ps256.pem";
//! let signer = create_signer::from_files(signcert_path, pkey_path, SigningAlg::Ps256, None)?;
//!
//! // embed a manifest using the signer
//! manifest.embed(&source, &dest, &*signer)?;
//! # Ok(())
//! # }
//! ```

pub use assertion::{Assertion, AssertionBase, AssertionCbor, AssertionJson};
pub mod assertions;

mod cose_validator;

#[cfg(feature = "openssl_sign")]
pub mod create_signer;

mod error;
pub use error::{Error, Result};

mod ingredient;
pub use ingredient::Ingredient;
pub mod jumbf_io;
mod manifest;
pub use manifest::Manifest;
mod manifest_assertion;
pub use manifest_assertion::{ManifestAssertion, ManifestAssertionKind};

mod manifest_store;
pub use manifest_store::ManifestStore;

mod manifest_store_report;
pub use manifest_store_report::ManifestStoreReport;

mod resource_store;
pub use resource_store::{ResourceRef, ResourceStore};

mod signing_alg;
#[cfg(feature = "file_io")]
pub use ingredient::{DefaultOptions, IngredientOptions};
pub use signing_alg::{SigningAlg, UnknownAlgorithmError};
#[cfg(feature = "openssl_sign")]
pub(crate) mod ocsp_utils;
#[cfg(feature = "openssl_sign")]
mod openssl;

mod signer;
pub use signer::{AsyncSigner, RemoteSigner, Signer};
#[allow(dead_code, clippy::enum_variant_names)]
pub(crate) mod asn1;
pub(crate) mod assertion;
pub(crate) mod asset_handlers;
pub(crate) mod asset_io;
pub use asset_io::{CAIRead, CAIReadWrite};
/// crate private declarations
pub(crate) mod claim;

mod claim_generator_info;
pub use claim_generator_info::ClaimGeneratorInfo;

pub mod cose_sign;

#[cfg(all(feature = "xmp_write", feature = "file_io"))]
pub(crate) mod embedded_xmp;
pub(crate) mod hashed_uri;
#[allow(dead_code)]
pub(crate) mod jumbf;
pub(crate) mod salt;
pub(crate) mod status_tracker;
pub(crate) mod store;
pub(crate) mod time_stamp;
pub(crate) mod utils;
pub mod validation_status;
pub use hash_utils::HashRange;
pub(crate) use utils::{cbor_types, hash_utils};
pub use utils::{cbor_types::DateT, hash_utils::hash_stream_by_alg};
pub(crate) mod validator;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

/// The internal name of the C2PA SDK
pub const NAME: &str = "c2pa-rs";
/// The version of this C2PA SDK
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
