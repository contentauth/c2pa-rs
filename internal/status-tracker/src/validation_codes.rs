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

//! Implements validation status for specific parts of a manifest.
//!
//! See [§15.2.1, “Standard Status Codes.”]
//!
//! [§15.2.1, “Standard Status Codes.”]: https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_standard_status_codes

use crate::log::LogKind;

// -- success codes --

/// The claim signature referenced in the ingredient's claim validated.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const CLAIM_SIGNATURE_VALIDATED: &str = "claimSignature.validated";

/// The claims signing certificate was valid at the time of signing.
///
/// Any corresponding URL should point to a C2PA claim box.
pub const CLAIM_SIGNATURE_INSIDE_VALIDITY: &str = "claimSignature.insideValidity";

/// The signing credential is listed on the validator's trust list.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const SIGNING_CREDENTIAL_TRUSTED: &str = "signingCredential.trusted";

/// The signing credential for the manifest has not been revoked:
///
/// Any corresponding URL should point to a C2PA claim
pub const SIGNING_CREDENTIAL_NOT_REVOKED: &str = "signingCredential.ocsp.notRevoked";

/// The time-stamp credential is well-formed and message imprint and validity
/// are correct.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const TIMESTAMP_VALIDATED: &str = "timeStamp.validated";

/// The time-stamp credential is listed on the validator's trust list.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const TIMESTAMP_TRUSTED: &str = "timeStamp.trusted";

/// The hash of the the referenced assertion in the ingredient's manifest
/// matches the corresponding hash in the assertion's hashed URI in the claim.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_HASHEDURI_MATCH: &str = "assertion.hashedURI.match";

/// Hash of a byte range of the asset matches the hash declared in the
/// data hash assertion.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_DATAHASH_MATCH: &str = "assertion.dataHash.match";

/// Hash of a box-based asset matches the hash declared in the BMFF
/// hash assertion.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_BMFFHASH_MATCH: &str = "assertion.bmffHash.match";

/// Hash of a box-based asset matches the hash declared in the General Box
/// Hash assertion.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_BOXHASH_MATCH: &str = "assertion.boxesHash.match";

/// Hash of all assets contained in collection match hashes declared
/// in Collection Data
/// Hash assertion.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_COLLECTIONHASH_MATCH: &str = "assertion.collectionHash.match";

/// A non-embedded (remote) assertion was accessible at the time of
/// validation.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_ACCESSIBLE: &str = "assertion.accessible";

/// Hash of the ingredient's C2PA manifest was successfully validated.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const INGREDIENT_MANIFEST_VALIDATED: &str = "ingredient.manifest.validated";

/// Hash of the ingredient’s C2PA Claim Signature box was successfully validated
///
/// Any corresponding URL should point to a C2PA assertion.
pub const INGREDIENT_CLAIM_SIGNATURE_VALIDATED: &str = "ingredient.claimSignature.validated";

// -- informational codes --

/// The validator chose not to perform an online OCSP check.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const SIGNING_CREDENTIAL_OCSP_SKIPPED: &str = "signingCredential.ocsp.skipped";

/// The validator attempted to perform an online OCSP check, but did not receive
/// a response.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const SIGNING_CREDENTIAL_OCSP_INACCESSIBLE: &str = "signingCredential.ocsp.inaccessible";

/// The time-stamp does not correspond to the contents of the claim.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const TIMESTAMP_MISMATCH: &str = "timeStamp.mismatch";

/// The time-stamp does not correspond to the contents of the claim.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const TIMESTAMP_MALFORMED: &str = "timeStamp.malformed";

/// The signed time-stamp attribute in the signature falls outside the
/// validity window of the signing certificate or the TSA's certificate.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const TIMESTAMP_OUTSIDE_VALIDITY: &str = "timeStamp.outsideValidity";

/// The time-stamp credential is not listed on the validator's trust list.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const TIMESTAMP_UNTRUSTED: &str = "timeStamp.untrusted";

/// The asset manifest cannot be interpreted by this version of the SDK.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const MANIFEST_UNKNOWN_PROVENANCE: &str = "manifest.unknownProvenance";

/// The ingredient does not contain a manifest or cannot be interpreted
/// by this version of the SDK.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const INGREDIENT_UNKNOWN_PROVENANCE: &str = "ingredient.unknownProvenance";

/// The algorithm has been deprecated.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const ALGORITHM_DEPRECATED: &str = "algorithm.deprecated";

// -- failure codes --

/// The claim cbor is invalid
///
/// Any corresponding URL should point to a C2PA claim box.
pub const CLAIM_MALFORMED: &str = "claim.malformed";

/// The referenced claim in the ingredient's manifest cannot be found.
///
/// Any corresponding URL should point to a C2PA claim box.
pub const CLAIM_MISSING: &str = "claim.missing";

/// More than one claim box is present in the manifest.
///
/// Any corresponding URL should point to a C2PA claim box.
pub const CLAIM_MULTIPLE: &str = "claim.multiple";

/// No hard bindings are present in the claim.
///
/// Any corresponding URL should point to a C2PA claim box.
pub const HARD_BINDINGS_MISSING: &str = "claim.hardBindings.missing";

// Multiple hard bindings are present in the claim.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const HARD_BINDINGS_MULTIPLE: &str = "assertion.multipleHardBindings";

/// A required field is not present in the claim.
///
/// Any corresponding URL should point to a C2PA claim box.
pub const CLAIM_REQUIRED_MISSING: &str = "claim.required.missing";

/// The cbor of the claim is not valid.
///
/// Any corresponding URL should point to a C2PA claim box.
pub const CLAIM_CBOR_INVALID: &str = "claim.cbor.invalid";

/// The hash of the the referenced ingredient claim in the manifest
/// does not match the corresponding hash in the ingredient's hashed
/// URI in the claim.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const INGREDIENT_HASHEDURI_MISMATCH: &str = "ingredient.hashedURI.mismatch";

/// The claim signature referenced in the ingredient's claim
/// cannot be found in its manifest.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const CLAIM_SIGNATURE_MISSING: &str = "claimSignature.missing";

/// The claim signature referenced in the ingredient's claim
/// failed to validate.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const CLAIM_SIGNATURE_MISMATCH: &str = "claimSignature.mismatch";

/// If a manifest was documented to exist in a remote location,
/// but is not present there, or the location is not currently available
/// (such as in an offline scenario),
/// the `manifest.inaccessible` error code shall be used to report the
/// situation.
///
/// `ValidationStatus.url()` URI reference to the C2PA Manifest that could not
/// be accessed.
pub const MANIFEST_INACCESSIBLE: &str = "manifest.inaccessible";

/// The manifest has more than one ingredient whose `relationship`
/// is `parentOf`.
///
/// Any corresponding URL should point to a C2PA claim box.
pub const MANIFEST_MULTIPLE_PARENTS: &str = "manifest.multipleParents";

/// The manifest is an update manifest, but it contains hard binding
/// or actions assertions.
///
/// Any corresponding URL should point to a C2PA claim box.
pub const MANIFEST_UPDATE_INVALID: &str = "manifest.update.invalid";

/// The manifest is an update manifest, but it contains either zero
/// or multiple `parentOf` ingredients.
///
/// Any corresponding URL should point to a C2PA claim box.
pub const MANIFEST_UPDATE_WRONG_PARENTS: &str = "manifest.update.wrongParents";

/// The signing credential is not listed on the validator's trust list.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const SIGNING_CREDENTIAL_UNTRUSTED: &str = "signingCredential.untrusted";

/// The signing credential is not valid for signing.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const SIGNING_CREDENTIAL_INVALID: &str = "signingCredential.invalid";

/// The signing credential has been revoked by the issuer.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const SIGNING_CREDENTIAL_REVOKED: &str = "signingCredential.ocsp.revoked";

/// The signing credential has expired.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const SIGNING_CREDENTIAL_EXPIRED: &str = "signingCredential.expired";

/// The hash of the the referenced assertion in the manifest does not
/// match the corresponding hash in the assertion's hashed URI in the claim.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_HASHEDURI_MISMATCH: &str = "assertion.hashedURI.mismatch";

/// An assertion listed in the ingredient's claim is missing from the
/// ingredient's manifest.
///
/// Any corresponding URL should point to a C2PA claim box.
pub const ASSERTION_MISSING: &str = "assertion.missing";

/// An assertion was found in the ingredient's manifest that was not
/// explicitly declared in the ingredient's claim.
///
/// Any corresponding URL should point to a C2PA claim box or assertion.
pub const ASSERTION_UNDECLARED: &str = "assertion.undeclared";

/// A non-embedded (remote) assertion was inaccessible at the time of
/// validation.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_INACCESSIBLE: &str = "assertion.inaccessible";

/// An assertion was declared as redacted in the ingredient's claim
/// but is still present in the ingredient's manifest.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_NOT_REDACTED: &str = "assertion.notRedacted";

/// An assertion was declared as redacted by its own claim.
///
/// Any corresponding URL should point to a C2PA claim box.
pub const ASSERTION_SELF_REDACTED: &str = "assertion.selfRedacted";

/// A required field is not present in an assertion.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_REQUIRED_MISSING: &str = "assertion.required.missing";

/// The JSON(-LD) of an assertion is not valid.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_JSON_INVALID: &str = "assertion.json.invalid";

/// The cbor of an assertion is not valid.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_CBOR_INVALID: &str = "assertion.cbor.invalid";

/// An action that requires an associated ingredient either does not have one
/// or the one specified cannot be located
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ACTION_ASSERTION_INGREDIENT_MISMATCH: &str = "assertion.action.ingredientMismatch";

/// An `action` assertion was redacted when the ingredient's
/// claim was created.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ACTION_ASSERTION_REDACTED: &str = "assertion.action.redacted";

/// The hash of a byte range of the asset does not match the
/// hash declared in the data hash assertion.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_DATAHASH_MISMATCH: &str = "assertion.dataHash.mismatch";

/// The hash of a box-based asset does not match the hash declared
/// in the BMFF hash assertion.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_BMFFHASH_MISMATCH: &str = "assertion.bmffHash.mismatch";

/// The hash of a box-based asset does not match the hash declared
/// in the General Boxes hash assertion.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_BOXHASH_MISMATCH: &str = "assertion.boxesHash.mismatch";

/// The hash of a box-based asset does not contain boxes in the expected order
/// for the General Boxes hash assertion.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_BOXHASH_UNKNOWN_BOX: &str = "assertion.boxesHash.unknownBox";

/// A hard binding assertion is in a cloud data assertion.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_CLOUD_DATA_HARD_BINDING: &str = "assertion.cloud-data.hardBinding";

/// An update manifest contains a cloud data assertion referencing
/// an actions assertion.
///
/// Any corresponding URL should point to a C2PA assertion.
pub const ASSERTION_CLOUD_DATA_ACTIONS: &str = "assertion.cloud-data.actions";

/// The value of an `alg` header, or other header that specifies an
/// algorithm used to compute the value of another field, is unknown
/// or unsupported.
///
/// Any corresponding URL should point to a C2PA claim box or C2PA assertion.
pub const ALGORITHM_UNSUPPORTED: &str = "algorithm.unsupported";

/// A value to be used when there was an error not specifically listed here.
///
/// Any corresponding URL should point to a C2PA claim box or C2PA assertion.
pub const GENERAL_ERROR: &str = "general.error";

/// The claim signature referenced in the claim was created outside the validity
/// period of the signing credential
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const CLAIM_SIGNATURE_OUTSIDE_VALIDITY: &str = "claimSignature.outsideValidity";

/// The manifest is a time-stamp manifest, but it contains a
/// disallowed (non-ingredient) assertion.
///
/// Any corresponding URL should point to a C2PA claim  box.
pub const MANIFEST_TIMESTAMP_INVALID: &str = "manifest.timestamp.invalid";

///The manifest is an time-stamp manifest, but it contains either zero or
///  multiple parentOf ingredients.
///
/// Any corresponding URL should point to a C2PA claim box.
pub const MANIFEST_TIMESTAMP_WRONG_PARENTS: &str = "manifest.timestamp.wrongParents";

/// The compressed manifest was not valid.
///
/// Any corresponding URL should point to a C2PA claim box.
pub const MANIFEST_COMPRESSED_INVALID: &str = "manifest.compressed.invalid";

/// The manifest is not referenced via an ingredient assertion.
///
/// Any corresponding URL should point to a C2PA claim box.
pub const MANIFEST_UNREFERENCED: &str = "manifest.unreferenced";

/// The OCSP response contains an unknown status for the signing credential.
///
/// Any corresponding URL should point to a C2PA claim signature box.
pub const SIGNING_CREDENTIAL_OCSP_UNKNOWN: &str = "signingCredential.ocsp.unknown";

/// An assertion listed in the claim is not in the same C2PA Manifest as
/// the claim.
///
/// Any corresponding URL should point to a C2PA claim  box.
pub const ASSERTION_OUTSIDE_MANIFEST: &str = "assertion.outsideManifest";

/// An actions assertion is malformed.
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const ASSERTION_ACTION_MALFORMED: &str = "assertion.action.malformed";

/// An action that requires an associated redaction either does not have one
///  or the one specified cannot be located
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const ASSERTION_ACTION_REDACTION_MISMATCH: &str = "assertion.action.redactionMismatch";

/// A data hash assertion is malformed.
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const ASSERTION_DATAHASH_MALFORMED: &str = "assertion.dataHash.malformed";

/// A BMFF hash assertion is malformed.
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const ASSERTION_BOXHASH_MALFORMED: &str = "assertion.bmffHash.malformed";

/// The cloud-data assertion was incomplete.
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const ASSERTION_CLOUD_DATA_MALFORMED: &str = "assertion.cloud-data.malformed";

/// A hash of an asset in the collection does not match hash declared in
/// the collection data hash assertion.
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const ASSERTION_COLLECTIONHASH_MISMATCH: &str = "assertion.collectionHash.mismatch";

/// An asset that was listed in the collection data hash assertion is
/// missing from the collection.
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const ASSERTION_COLLECTIONHASH_INCORRECT_FILE_COUNT: &str =
    "assertion.collectionHash.incorrectFileCount";

/// A URI of an asset in the collection data hash assertion contains
/// the file part '..' or '.'.
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const ASSERTION_COLLECTIONHASH_INVALID_URI: &str = "assertion.collectionHash.invalidURI";

/// The collection hash assertion was incomplete.
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const ASSERTION_COLLECTIONHASH_MALFORMED: &str = "assertion.collectionHash.malformed";

/// The ingredient assertion was incomplete.
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const ASSERTION_INGREDIENT_MALFORMED: &str = "assertion.ingredient.malformed";

/// The C2PA metadata assertion contains a field that is not
/// allowed by this specification.
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const ASSERTION_METADATA_DISALLOWED: &str = "assertion.metadata.disallowed";

/// The referenced ingredient C2PA Claim Signature was not found.
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const INGREDIENT_MANIFEST_MISSING: &str = "ingredient.manifest.missing";

/// The hash of an embedded C2PA Manifest does not match the hash declared in
/// the hashed_uri value of the activeManifest field in the ingredient
/// assertion.
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const INGREDIENT_MANIFEST_MISMATCH: &str = "ingredient.manifest.mismatch";

/// The referenced ingredient C2PA Claim Signature was not found.
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const INGREDIENT_CLAIM_SIGNATURE_MISSING: &str = "ingredient.claimSignature.missing";

/// The hash of an embedded C2PA Manifest’s C2PA Claim Signature does not match
/// the hash declared in the hashed_uri value of the claimSignature field in the
/// ingredient assertion.
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const INGREDIENT_CLAIM_SIGNATURE_MISMATCH: &str = "ingredient.claimSignature.mismatch";

/// The data pointed to by a hashed_uri cannot be located.
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const HASHED_URI_MISSING: &str = "hashedURI.missing";

/// The hash of a given hashed_uri does not match the corresponding hash
/// of the destination URI’s data
///
/// Any corresponding URL should point to a C2PA assertion box.
pub const HASHED_URI_MISMATCH: &str = "hashedURI.mismatch";

/// Returns `true` if the status code is a known C2PA success status code.
///
/// Returns `false` if the status code is a known C2PA failure status
/// code or is unknown.
///
/// ## Examples
///
/// ```
/// use c2pa_status_tracker::validation_codes::*;
///
/// assert!(is_success(CLAIM_SIGNATURE_VALIDATED));
/// assert!(!is_success(SIGNING_CREDENTIAL_REVOKED));
/// ```
pub fn is_success(status_code: &str) -> bool {
    matches!(log_kind(status_code), LogKind::Success)
}

/// Returns the [`LogKind`] for a given status code.
// TODO: This needs to be expanded to include all status codes.
pub fn log_kind(status_code: &str) -> LogKind {
    match status_code {
        CLAIM_SIGNATURE_VALIDATED
        | CLAIM_SIGNATURE_INSIDE_VALIDITY
        | SIGNING_CREDENTIAL_TRUSTED
        | SIGNING_CREDENTIAL_NOT_REVOKED
        | TIMESTAMP_TRUSTED
        | TIMESTAMP_VALIDATED
        | ASSERTION_HASHEDURI_MATCH
        | ASSERTION_DATAHASH_MATCH
        | ASSERTION_BMFFHASH_MATCH
        | ASSERTION_ACCESSIBLE
        | ASSERTION_BOXHASH_MATCH
        | ASSERTION_COLLECTIONHASH_MATCH
        | INGREDIENT_MANIFEST_VALIDATED
        | INGREDIENT_CLAIM_SIGNATURE_VALIDATED => LogKind::Success,
        SIGNING_CREDENTIAL_OCSP_SKIPPED
        | SIGNING_CREDENTIAL_OCSP_INACCESSIBLE
        | TIMESTAMP_UNTRUSTED
        | TIMESTAMP_OUTSIDE_VALIDITY
        | TIMESTAMP_MISMATCH
        | TIMESTAMP_MALFORMED
        | MANIFEST_UNKNOWN_PROVENANCE
        | INGREDIENT_UNKNOWN_PROVENANCE
        | ALGORITHM_DEPRECATED => LogKind::Informational,
        _ => LogKind::Failure,
    }
}
