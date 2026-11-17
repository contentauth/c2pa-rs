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

//! `cawg.vcb.*` status codes from the CAWG identity 1.3 draft, §8.3.5.

pub(crate) const INVALID_COSE_SIGN1: &str = "cawg.vcb.invalid_cose_sign1";
pub(crate) const INVALID_ALG: &str = "cawg.vcb.invalid_alg";
pub(crate) const INVALID_CONTENT_TYPE: &str = "cawg.vcb.invalid_content_type";
pub(crate) const INVALID_VERIFIABLE_CREDENTIAL: &str = "cawg.vcb.invalid_verifiable_credential";
pub(crate) const INVALID_ISSUER: &str = "cawg.vcb.invalid_issuer";
pub(crate) const DID_UNSUPPORTED_METHOD: &str = "cawg.vcb.did_unsupported_method";
pub(crate) const DID_UNAVAILABLE: &str = "cawg.vcb.did_unavailable";
pub(crate) const INVALID_DID_DOCUMENT: &str = "cawg.vcb.invalid_did_document";
pub(crate) const UNTRUSTED_ISSUER: &str = "cawg.vcb.untrusted_issuer";
pub(crate) const SIGNATURE_MISMATCH: &str = "cawg.vcb.signature_mismatch";
pub(crate) const TIME_STAMP_VALIDATED: &str = "cawg.vcb.time_stamp.validated";
pub(crate) const TIME_STAMP_INVALID: &str = "cawg.vcb.time_stamp.invalid";
pub(crate) const VALID_FROM_MISSING: &str = "cawg.vcb.valid_from.missing";
pub(crate) const VALID_FROM_INVALID: &str = "cawg.vcb.valid_from.invalid";
pub(crate) const VALID_UNTIL_INVALID: &str = "cawg.vcb.valid_until.invalid";
pub(crate) const REVOCATION_UNSUPPORTED: &str = "cawg.vcb.revocation.unsupported";
pub(crate) const SIGNER_PAYLOAD_MISMATCH: &str = "cawg.vcb.signer_payload.mismatch";
pub(crate) const BINDING_MISMATCH: &str = "cawg.vcb.binding.mismatch";
pub(crate) const VERIFIED_IDENTITIES_MISSING: &str = "cawg.vcb.verified_identities.missing";
pub(crate) const VERIFIED_IDENTITIES_INVALID: &str = "cawg.vcb.verified_identities.invalid";
pub(crate) const CREDENTIAL_VALID: &str = "cawg.vcb.credential_valid";
