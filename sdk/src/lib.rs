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

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg, doc_cfg_hide))]

//! This library supports reading, creating and embedding C2PA data
//! with a variety of asset types.
//!
//! Some functionality requires you to enable specific crate features,
//! as noted in the documentation.
//!
//! The library has a new experimental Builder/Reader API that will eventually replace
//! the existing methods of reading and writing C2PA data.
//! The new API focuses on stream support and can do more with fewer methods.
//! It will be supported in all language bindings and build environments.
//! To use the new API, you must enable the `unstable_api` feature, for example:
//!
//! ```text
//! c2pa = {version="0.32.0", features=["unstable_api"]}
//! ```
//!
//! # Example: Reading a ManifestStore
//!
//! This example requires the `unstable_api` feature to be enabled.
//!
//! ```
//! # use c2pa::Result;
//! use c2pa::{assertions::Actions, Reader};
//!
//! # fn main() -> Result<()> {
//! let stream = std::fs::File::open("tests/fixtures/C.jpg")?;
//! let reader = Reader::from_stream("image/jpeg", stream)?;
//! println!("{}", reader.json());
//!
//! if let Some(manifest) = reader.active_manifest() {
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
//! This example requires the `unstable_api` feature to be enabled.
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
//!     &*signer,
//!     "tests/fixtures/C.jpg",
//!     "../target/tmp/lib_sign.jpg",
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
pub mod cose_sign;
#[cfg(feature = "openssl_sign")]
pub mod create_signer;
pub mod jumbf_io;
pub mod settings;
pub mod validation_status;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

// Public exports
pub use assertions::Relationship;
#[cfg(feature = "v1_api")]
pub use asset_io::{CAIRead, CAIReadWrite};
#[cfg(feature = "unstable_api")]
pub use builder::{Builder, ManifestDefinition};
pub use c2pa_crypto::SigningAlg;
pub use callback_signer::{CallbackFunc, CallbackSigner};
pub use claim_generator_info::ClaimGeneratorInfo;
pub use dynamic_assertion::DynamicAssertion;
pub use error::{Error, Result};
pub use external_manifest::ManifestPatchCallback;
pub use hash_utils::{hash_stream_by_alg, HashRange};
pub use ingredient::Ingredient;
#[cfg(feature = "file_io")]
pub use ingredient::{DefaultOptions, IngredientOptions};
pub use manifest::{Manifest, SignatureInfo};
pub use manifest_assertion::{ManifestAssertion, ManifestAssertionKind};
#[cfg(feature = "v1_api")]
pub use manifest_store::ManifestStore;
#[cfg(feature = "v1_api")]
pub use manifest_store_report::ManifestStoreReport;
#[cfg(feature = "unstable_api")]
pub use reader::{Reader, ValidationState};
pub use resource_store::{ResourceRef, ResourceStore};
pub use signer::{AsyncSigner, RemoteSigner, Signer};
pub use utils::mime::format_from_path;

// Internal modules
pub(crate) mod assertion;
pub(crate) mod asset_handlers;
pub(crate) mod asset_io;
#[cfg(feature = "unstable_api")]
pub(crate) mod builder;
pub(crate) mod callback_signer;
pub(crate) mod claim;
pub(crate) mod claim_generator_info;
pub(crate) mod cose_validator;
pub(crate) mod dynamic_assertion;
pub(crate) mod error;
pub(crate) mod external_manifest;
pub(crate) mod hashed_uri;
pub(crate) mod ingredient;

#[allow(dead_code)]
pub(crate) mod jumbf;

pub(crate) mod manifest;
pub(crate) mod manifest_assertion;
pub(crate) mod manifest_store;
pub(crate) mod manifest_store_report;
#[cfg(feature = "openssl")]
pub(crate) mod openssl;
#[allow(dead_code)]
// TODO: Remove this when the feature is released (used in tests only for some builds now)
pub(crate) mod reader;
pub(crate) mod resource_store;
pub(crate) mod salt;
pub(crate) mod signer;
pub(crate) mod store;
pub(crate) mod time_stamp;

pub(crate) mod utils;
pub(crate) use utils::{cbor_types, hash_utils};
