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
#![cfg_attr(docsrs, feature(doc_cfg))]

//! This library supports reading, creating, and embedding C2PA data
//! for a variety of asset types.
//!
//! Some functionality requires you to enable specific crate features,
//! as noted in the documentation.
//!
//! The library has a Builder/Reader API that focuses on simplicity
//! and stream support.
//!
//! For more information, see [CAI open source SDK - Rust library](https://opensource.contentauthenticity.org/docs/rust-sdk/)
//!
//! # Examples
//!
//! ## Reading a manifest
//!
//! TODO: Update to use Context
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
//! ## Adding a signed manifest to a file
//!
//! TODO: Change example to be a more common case - Adding parent with intent, ingredient.
//!
//! ```
//! # use c2pa::Result;
//! use std::io::Cursor;
//!
//! use c2pa::{Builder, Context};
//! use serde::Serialize;
//! use serde_json::json;
//!
//! #[derive(Serialize)]
//! struct Test {
//!     my_tag: usize,
//! }
//!
//! # fn main() -> Result<()> {
//! // Create context with signer configuration.
//! let context =
//!     Context::new().with_settings(include_str!("../tests/fixtures/test_settings.toml"))?;
//!
//! // Build manifest.
//! let mut builder = Builder::from_context(context)
//!     .with_definition(json!({"title": "Test"}))?;
//! builder.add_assertion("org.contentauth.test", &Test { my_tag: 42 })?;
//!
//! // Save with automatic signer from context (created from settings).
//! let mut source = std::fs::File::open("tests/fixtures/C.jpg")?;
//! let mut dest = Cursor::new(Vec::new());
//! let _c2pa_data = builder.save_to_stream("image/jpeg", &mut source, &mut dest)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! The crate provides the following features:
//!
//! These features are enabled by default:
//! - **default_http**: Enables default HTTP features for sync and async HTTP resolvers (`http_req`, `http_reqwest`, `http_wasi`, and `http_std`).
//! - **openssl**: Use the vendored `openssl` implementation for cryptography.
//!
//! One of `openssl` or `rust_native_crypto` must be enabled. 
//! If both are enabled, `rust_native_crypto` is used.
//!
//! Other features:
//! - **add_thumbnails**: Adds the [`image`](https://github.com/image-rs/image) crate to enable auto-generated thumbnails, if possible and enabled in settings.
//! - **fetch_remote_manifests**: Fetches remote manifests over the network when no embedded manifest is present and that option is enabled in settings.
//! - **file_io**: Enables APIs that use filesystem I/O.
//! - **json_schema**: Adds the [`schemars`](https://github.com/GREsau/schemars) crate to derive JSON schemas for JSON-compatible structs.
//! - **pdf**: Enables basic PDF read support.
//! - **rust_native_crypto**: Use Rust native cryptography.  
//! TODO: Confirm behavior with openssl 
//!
//! ## HTTP features
//! These features toggle compilation with different HTTP libraries, depending on the one you use. 
//! Some are async-only and others are sync-only. 
//! Disabling all of them will speed up compilation and decrease build size.
//! TODO: Rationalize the HTTP features
//! - **http_ureq**: Enables `ureq` for sync HTTP requests.
//! - **http_reqwest**: Enables `reqwest` for async HTTP requests.
//! - **http_reqwest_blocking**: Enables the `blocking` feature of `reqwest` for sync HTTP requests.
//! - **http_wasi**: Enables `wasi` for sync HTTP requests on WASI.
//! - **http_wstd**: Enables `wstd` for async HTTP requests on WASI.
//!
//! ## WASM and WASI
//!
//! For WASM the only supported HTTP feature is `http_reqwest`. This means WASM
//! only supports the async API for network requests.
//!
//! For WASI the only supported HTTP features are `http_wasi`, which enables sync network requests, 
//! and `http_wstd` which enables async network requests.
//!

/// The internal name of the C2PA SDK.
pub const NAME: &str = "c2pa-rs";

/// The version of this C2PA SDK.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Public modules
/// The `assertions` module contains the definitions for the assertions that are part of the C2PA specification.
pub mod assertions;

/// The `cose_sign` module contains the definitions for the COSE signing algorithms.
pub mod cose_sign;

/// The `create_signer` module contains the definitions for the signers that are part of the C2PA specification.
pub mod create_signer;

/// Cryptography primitives.
#[doc(hidden)]
pub mod crypto;

/// Dynamic assertions are a new feature that allows you to add assertions to a C2PA file as a part of the signing process.
#[doc(hidden)]
pub mod dynamic_assertion;

// TODO: pub it when we expose in high-level API
/// The `http` module contains generic traits for configuring sync and async HTTP resolvers.
pub(crate) mod http;

/// The `identity` module provides support for the [CAWG identity assertion](https://cawg.io/identity).
#[doc(hidden)]
pub mod identity;

/// The `jumbf_io` module contains the definitions for the JUMBF data in assets.
pub mod jumbf_io;

/// The settings module provides a way to configure the C2PA SDK.
pub mod settings;

/// Supports status tracking as defined in the C2PA Technical Specification.
#[doc(hidden)]
pub mod status_tracker;

/// The `validation_results` module contains the definitions for the validation results that are part of the C2PA specification.
pub mod validation_results;

/// The `validation_status` module contains the definitions for the validation status that are part of the C2PA specification.
#[doc(hidden)]
pub mod validation_status;

// Public exports
#[doc(inline)]
pub use assertions::DigitalSourceType;
#[doc(inline)]
pub use assertions::Relationship;
pub use builder::{Builder, BuilderIntent, ManifestDefinition};
pub use callback_signer::{CallbackFunc, CallbackSigner};
pub use claim_generator_info::ClaimGeneratorInfo;
#[doc(inline)]
pub use context::Context;
pub use crypto::raw_signature::SigningAlg;
pub use error::{Error, Result};
#[doc(hidden)]
pub use external_manifest::ManifestPatchCallback;
pub use hash_utils::{hash_stream_by_alg, HashRange};
pub use hashed_uri::HashedUri;
pub use ingredient::Ingredient;
#[cfg(feature = "file_io")]
#[doc(hidden)]
pub use ingredient::{DefaultOptions, IngredientOptions};
pub use manifest::{Manifest, SignatureInfo};
pub use manifest_assertion::{ManifestAssertion, ManifestAssertionKind};
pub use reader::Reader;
#[doc(inline)]
pub use resource_store::{ResourceRef, ResourceStore};
#[doc(inline)]
pub use settings::Settings;
pub use signer::{AsyncSigner, BoxedAsyncSigner, BoxedSigner, Signer};
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
pub(crate) mod context;
pub(crate) mod cose_validator;
pub(crate) mod error;
pub(crate) mod external_manifest;
pub(crate) mod hashed_uri;
pub(crate) mod ingredient;

#[allow(dead_code)]
pub(crate) mod jumbf;

pub(crate) mod manifest;
pub(crate) mod manifest_assertion;
pub(crate) mod manifest_store_report;
/// The maybe_send_sync module contains traits for conditional Send bounds based on target architecture.
pub(crate) mod maybe_send_sync;
pub(crate) mod reader;
pub(crate) mod resource_store;
pub(crate) mod salt;
pub(crate) mod signer;
pub(crate) mod store;

pub(crate) mod utils;
pub(crate) use utils::{cbor_types, hash_utils};

#[cfg(not(any(feature = "openssl", feature = "rust_native_crypto")))]
compile_error!("Either 'openssl' or 'rust_native_crypto' feature must be enabled.");
