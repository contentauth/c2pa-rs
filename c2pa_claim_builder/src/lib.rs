// Copyright 2026 Adobe. All rights reserved.
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

//! A narrow, direct-claim-construction API over `c2pa`: [`ClaimBuilder`] (write) and
//! [`StoreReader`] (read) build/read a `Claim` directly and eagerly, without `c2pa`'s
//! JSON-staged `Builder`/`Manifest`/`Reader` layer. Everything here is a re-export of `c2pa`
//! items — see their own docs (originally in `c2pa`'s `claim_builder`/`claim_assertion`/
//! `store_reader` modules) for the model this implements.

// Assertion types (Actions, IngredientAssertion, DataHash/BmffHash/BoxHash, EmbeddedData, ...)
// and the JUMBF asset-format registry (`save_jumbf_to_stream`, `get_assetio_handler`, ...) needed
// to actually embed/extract a signed manifest.
pub use c2pa::{assertions, jumbf_io, validation_status::ValidationStatus};
pub use c2pa::{
    // URIs / hashing primitives the builder API works with
    format_from_path,
    hash_stream_by_alg,
    // Signing
    AsyncSigner,
    BoxedAsyncSigner,
    BoxedSigner,
    CallbackFunc,
    CallbackSigner,
    // Read side
    Claim,
    ClaimAssertion,
    // Write side
    ClaimAssertionBuilder,
    ClaimBuilder,
    ClaimGeneratorInfo,

    // Shared context / settings
    Context,
    EphemeralSigner,
    // Errors
    Error,
    HashRange,
    HashedUri,

    ProgressCallbackFunc,
    ProgressPhase,
    RawSignatureValidationError,
    RawSigner,
    RawSignerError,
    Result,

    Settings,

    Signer,
    SigningAlg,

    StoreReader,

    // Validation
    ValidationResults,
    ValidationState,
};
