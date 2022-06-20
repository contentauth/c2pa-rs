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

//! This library supports reading, creating and embedding C2PA data
//! with JPEG and PNG images.
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
//! use c2pa::{
//!     assertions::User,
//!     get_signer_from_files,
//!     Manifest
//! };
//!
//! use std::path::PathBuf;
//! use tempfile::tempdir;
//!
//! # fn main() -> Result<()> {
//! let mut manifest = Manifest::new("my_app".to_owned());
//! manifest.add_assertion(&User::new("org.contentauth.mylabel", r#"{"my_tag":"Anything I want"}"#))?;
//!
//! let source = PathBuf::from("tests/fixtures/C.jpg");
//! let dir = tempdir()?;
//! let dest = dir.path().join("test_file.jpg");
//!
//! // Create a ps256 signer using certs and key files
//! let signcert_path = "tests/fixtures/certs/ps256.pub";
//! let pkey_path = "tests/fixtures/certs/ps256.pem";
//! let signer = get_signer_from_files(signcert_path, pkey_path, "ps256", None)?;
//!
//! // embed a manifest using the signer
//! manifest.embed(&source, &dest, &*signer)?;
//! # Ok(())
//! # }
//! ```

pub use assertion::{Assertion, AssertionBase, AssertionCbor, AssertionJson};
pub mod assertions;

mod cose_validator;

mod error;
pub use error::{Error, Result};

mod ingredient;
pub use ingredient::{Ingredient, IngredientOptions};
pub mod jumbf_io;
mod manifest;
pub use manifest::Manifest;
mod manifest_assertion;
pub use manifest_assertion::{ManifestAssertion, ManifestAssertionKind};

mod manifest_store;
pub use manifest_store::ManifestStore;

mod manifest_store_report;
pub use manifest_store_report::ManifestStoreReport;

#[cfg(feature = "file_io")]
pub(crate) mod ocsp_utils;
#[cfg(feature = "file_io")]
mod openssl;
#[cfg(feature = "file_io")]
pub use crate::openssl::signer::{get_signer, get_signer_from_files};

#[cfg(feature = "file_io")]
mod signer;
#[cfg(feature = "async_signer")]
pub use signer::AsyncSigner;
#[cfg(feature = "file_io")]
pub use signer::Signer;
/// crate private declarations
#[allow(dead_code, clippy::enum_variant_names)]
pub(crate) mod asn1;
pub(crate) mod assertion;
pub(crate) mod asset_handlers;
pub(crate) mod asset_io;
pub(crate) mod claim;
#[cfg(feature = "file_io")]
pub(crate) mod cose_sign;
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
pub(crate) use utils::cbor_types;
pub(crate) use utils::hash_utils;
pub(crate) use utils::xmp_inmemory_utils;
pub(crate) mod validator;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

/// The internal name of the C2PA SDK
pub const NAME: &str = "c2pa-rs";
/// The version of this C2PA SDK
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
