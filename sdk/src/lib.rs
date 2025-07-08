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

//! This library supports reading, creating, and embedding C2PA data
//! for a variety of asset types.
//!
//! Some functionality requires you to enable specific crate features,
//! as noted in the documentation.
//!
//! The library has a Builder/Reader API that focuses on simplicity
//! and stream support.
//!
//! ## Example: Reading a ManifestStore
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
//! ## Example: Adding a Manifest to a file
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
/// The assertions module contains the definitions for the assertions that are part of the C2PA specification.
pub mod assertions;

/// The cose_sign module contains the definitions for the COSE signing algorithms.
pub mod cose_sign;

/// The create_signer module contains the definitions for the signers that are part of the C2PA specification.
pub mod create_signer;

/// Cryptography primitives.
#[doc(hidden)]
pub mod crypto;

/// Dynamic assertions are a new feature that allows you to add assertions to a C2PA file as a part of the signing process.
#[doc(hidden)]
pub mod dynamic_assertion;

/// The `identity` module provides support for the [CAWG identity assertion](https://cawg.io/identity).
#[doc(hidden)]
pub mod identity;

/// The jumbf_io module contains the definitions for the JUMBF data in assets.
pub mod jumbf_io;

/// The settings module provides a way to configure the C2PA SDK.
pub mod settings;

/// Supports status tracking as defined in the C2PA Technical Specification.
#[doc(hidden)]
pub mod status_tracker;

/// The validation_results module contains the definitions for the validation results that are part of the C2PA specification.
pub mod validation_results;

/// The validation_status module contains the definitions for the validation status that are part of the C2PA specification.
#[doc(hidden)]
pub mod validation_status;

// Public exports
#[doc(inline)]
pub use assertions::Relationship;
#[cfg(feature = "v1_api")]
pub use asset_io::{CAIRead, CAIReadWrite};
pub use builder::{Builder, ManifestDefinition};
pub use callback_signer::{CallbackFunc, CallbackSigner};
pub use claim_generator_info::ClaimGeneratorInfo;
// pub use dynamic_assertion::{
//     AsyncDynamicAssertion, DynamicAssertion, DynamicAssertionContent, PartialClaim,
// };
pub use crypto::raw_signature::SigningAlg;
pub use error::{Error, Result};
#[doc(inline)]
pub use external_manifest::ManifestPatchCallback;
pub use hash_utils::{hash_stream_by_alg, HashRange};
pub use hashed_uri::HashedUri;
pub use ingredient::Ingredient;
#[cfg(feature = "file_io")]
pub use ingredient::{DefaultOptions, IngredientOptions};
pub use manifest::{Manifest, SignatureInfo};
pub use manifest_assertion::{ManifestAssertion, ManifestAssertionKind};
#[cfg(feature = "v1_api")]
pub use manifest_store::ManifestStore;
#[cfg(feature = "v1_api")]
pub use manifest_store_report::ManifestStoreReport;
pub use reader::Reader;
#[doc(inline)]
pub use resource_store::{ResourceRef, ResourceStore};
#[cfg(feature = "v1_api")]
pub use signer::RemoteSigner;
pub use signer::{AsyncSigner, Signer};
pub use utils::mime::format_from_path;
#[doc(inline)]
pub use validation_results::{ValidationResults, ValidationState};

// Internal modules
pub(crate) mod assertion;
pub(crate) mod asset_handlers;
pub(crate) mod asset_io;
pub(crate) mod builder;
pub(crate) mod callback_signer;
pub(crate) mod claim;
pub(crate) mod claim_generator_info;
pub(crate) mod cose_validator;
pub(crate) mod error;
pub(crate) mod external_manifest;
pub(crate) mod hashed_uri;
pub(crate) mod ingredient;

#[allow(dead_code)]
pub(crate) mod jumbf;

pub(crate) mod manifest;
pub(crate) mod manifest_assertion;
#[cfg(feature = "v1_api")]
pub(crate) mod manifest_store;
pub(crate) mod manifest_store_report;

#[allow(dead_code)]
// TODO: Remove this when the feature is released (used in tests only for some builds now)
pub(crate) mod reader;
pub(crate) mod resource_store;
pub(crate) mod salt;
pub(crate) mod signer;
pub(crate) mod store;

pub(crate) mod utils;
pub(crate) use utils::{cbor_types, hash_utils};

#[cfg(all(feature = "openssl", feature = "rust_native_crypto"))]
compile_error!("Features 'openssl' and 'rust_native_crypto' cannot be enabled at the same time.");

#[cfg(not(any(feature = "openssl", feature = "rust_native_crypto")))]
compile_error!("Either 'openssl' or 'rust_native_crypto' feature must be enabled.");

#[cfg(all(feature = "openssl", target_arch = "wasm32"))]
compile_error!("Feature 'openssl' is not available for wasm32.");
