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

#![deny(missing_docs)]

//! Labels for assertion types as defined in C2PA 1.0/2.x Specification.
//!
//! These constants do not include version suffixes.
//!
//! See [C2PA Standard assertions - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_c2pa_standard_assertions).
use std::sync::LazyLock;

use regex::Regex;

/// Label prefix for a claim assertion.
///
/// See [Claims- C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_claims).
pub const CLAIM: &str = "c2pa.claim";

/// Label prefix for an assertion metadata assertion.
///
/// See [Metadata about assertions - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_metadata_about_assertions).
pub const ASSERTION_METADATA: &str = "c2pa.assertion.metadata";

/// Label prefix for a data hash assertion.
///
/// See [Data hash - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_data_hash).
pub const DATA_HASH: &str = "c2pa.hash.data";

/// Label prefix for a box hash assertion.
///
/// See [General boxes hash - C2PA Technical Specification](https://c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html#_general_boxes_hash).
pub const BOX_HASH: &str = "c2pa.hash.boxes";

/// Label prefix for a BMFF-based hash assertion.
///
/// See [BMFF-based hash - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_bmff_based_hash).
pub const BMFF_HASH: &str = "c2pa.hash.bmff";

/// Label prefix for a collection hash assertion.
///
/// See [Collection data hash - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_collection_data_hash).
pub const COLLECTION_HASH: &str = "c2pa.hash.collection.data";

/// Label prefix for a soft binding assertion.
///
/// See [Soft binding - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_soft_binding_2).
pub const SOFT_BINDING: &str = "c2pa.soft-binding";

/// Label prefix for a cloud data assertion.
///
/// See [Cloud data - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_cloud_data).
pub const CLOUD_DATA: &str = "c2pa.cloud-data";

/// Label prefix for a thumbnail assertion.
///
/// See [Thumbnail - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_thumbnail).
pub const THUMBNAIL: &str = "c2pa.thumbnail";

/// Label prefix for a claim thumbnail assertion.
///
/// See [Thumbnail - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_thumbnail).
pub const CLAIM_THUMBNAIL: &str = "c2pa.thumbnail.claim";

/// Label prefix for an ingredient thumbnail assertion.
///
/// See [Thumbnail - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_thumbnail).
pub const INGREDIENT_THUMBNAIL: &str = "c2pa.thumbnail.ingredient";

/// Label prefix for a JPEG claim thumbnail assertion.
///
/// See [Thumbnail - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_thumbnail).
pub const JPEG_CLAIM_THUMBNAIL: &str = "c2pa.thumbnail.claim.jpeg";

/// Label prefix for a JPEG ingredient thumbnail assertion.
///
/// See [Thumbnail - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_thumbnail).
pub const JPEG_INGREDIENT_THUMBNAIL: &str = "c2pa.thumbnail.ingredient.jpeg";

/// Label prefix for a PNG claim thumbnail assertion.
///
/// See [Thumbnail - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_thumbnail).
pub const PNG_CLAIM_THUMBNAIL: &str = "c2pa.thumbnail.claim.png";

/// Label prefix for a PNG ingredient thumbnail assertion.
///
/// See [Thumbnail - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_thumbnail).
pub const PNG_INGREDIENT_THUMBNAIL: &str = "c2pa.thumbnail.ingredient.png";

/// Label prefix for a SVG claim thumbnail assertion.
///
/// See [Thumbnail - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_thumbnail).
pub const SVG_CLAIM_THUMBNAIL: &str = "c2pa.thumbnail.claim.svg";

/// Label prefix for a SVG ingredient thumbnail assertion.
///
/// See [Thumbnail - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_thumbnail).
pub const SVG_INGREDIENT_THUMBNAIL: &str = "c2pa.thumbnail.ingredient.svg";

/// Label prefix for an actions assertion.
///
/// See [Actions - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_actions).
pub const ACTIONS: &str = "c2pa.actions";

/// Label prefix for an ingredient assertion.
///
/// See [Ingredient - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_ingredient).
pub const INGREDIENT: &str = "c2pa.ingredient";

/// Label prefix for a depthmap assertion.
///
/// See [Depthmap - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_depthmap).
pub const DEPTHMAP: &str = "c2pa.depthmap";

/// Label prefix for a asset type assertion.
///
/// See [Asset type - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_asset_type).
pub const ASSET_TYPE: &str = "c2pa.asset-type";

/// Label prefix for a embedded data assertion.
///
/// See [Embedded data - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_embedded_data).
pub const EMBEDDED_DATA: &str = "c2pa.embedded-data";

/// Label prefix for a Icon assertion.
///
/// See [Generator info map - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_generator_info_map).
pub const ICON: &str = "c2pa.icon";

/// Label prefix for a GDepth assertion.
/// Label prefix for a GDepth depthmap assertion.
///
/// See [GDepth Depthmap - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_gdepth_depthmap).
pub const DEPTHMAP_GDEPTH: &str = "c2pa.depthmap.GDepth";

/// Label prefix for an EXIF information assertion.
/// Hidden because it's now part of standard metadata assertions.
///
/// See [EXIF information - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_exif_information).
#[doc(hidden)]
pub const EXIF: &str = "stds.exif";

/// Label prefix for an IPTC photo metadata assertion.
/// Hidden because it's now part of standard metadata assertions.
///
/// See [IPTC photo metadata - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_iptc_photo_metadata).
#[doc(hidden)]
pub const IPTC_PHOTO_METADATA: &str = "stds.iptc.photo-metadata";

/// Label prefix for any assertion based on a schema.org grammar.
/// Hidden because it's now part of standard metadata assertions.
///
/// See [Use of Schema.org - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_use_of_schema_org).
#[doc(hidden)]
pub const SCHEMA_ORG: &str = "schema.org";

/// Label prefix for a claim review assertion.
///
/// See [Claim review - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_claim_review).
pub const CLAIM_REVIEW: &str = "stds.schema-org.ClaimReview";

/// Label prefix for a creative work assertion.
///
/// See [Creative work - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_creative_work).
pub const CREATIVE_WORK: &str = "stds.schema-org.CreativeWork";

/// Label prefix for a timestamp assertion.
///
/// See [Timestamp assertion - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#timestamp_assertion).
pub const TIMESTAMP: &str = "c2pa.time-stamp";

/// Label prefix for a certificate status assertion.
///
/// See [Certificate status assertion - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#certificate_status_assertion).
pub const CERTIFICATE_STATUS: &str = "c2pa.certificate-status";

// Assertion store label
pub(crate) const ASSERTION_STORE: &str = "c2pa.assertions";

// Databoxes label
pub(crate) const DATABOX_STORE: &str = "c2pa.databoxes";

/// Label prefix for asset reference assertion.
///
/// See [Asset reference - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_asset_reference).
pub const ASSET_REFERENCE: &str = "c2pa.asset-ref";

/// extension to indicate a multipart hash
///
/// See [Multi asset hash - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_multi_asset_hash).
pub const PART: &str = ".part";

/// Label prefix for a C2PA metadata assertion.
///
/// A [metadata assertion](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_metadata)
/// can only be used for [specific metadata fields](https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#metadata_annex)
/// as described in the C2PA Technical Specification and only if those fields
/// are generated from a hardware or software source.
pub const METADATA: &str = "c2pa.metadata";

/// Label prefix for a [CAWG metadata assertion](https://cawg.io/metadata/).
///
/// The [CAWG metadata assertion](https://cawg.io/metadata/) is intended for human-generated metadata
/// and may contain metadata from any documented schema.
pub const CAWG_METADATA: &str = "cawg.metadata";

/// Array of all hash labels because they have special treatment
pub const HASH_LABELS: [&str; 4] = [DATA_HASH, BOX_HASH, BMFF_HASH, COLLECTION_HASH];

/// Array of all non-redactable labels
pub const NON_REDACTABLE_LABELS: [&str; 5] =
    [ACTIONS, DATA_HASH, BOX_HASH, BMFF_HASH, COLLECTION_HASH];

/// Must have a label that ends in '.metadata' and is preceded by an entity-specific namespace.
/// For example, a 'com.litware.metadata' assertion would be valid.
pub static METADATA_LABEL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    {
        Regex::new(r"^(?:[a-zA-Z0-9][a-zA-Z0-9_-]*)(?:\.(?:[a-zA-Z0-9][a-zA-Z0-9_-]*))*\.metadata$")
            .unwrap()
    }
});

/// Parse a label into its components
///
/// This function takes a label string and parses it into its base label,
/// version number, and instance number. The base label is the part of the
/// label without any version or instance suffixes. The version number is
/// extracted from a suffix of the form `.v{number}`, defaulting to 1 if
/// not present. The instance number is extracted from a suffix of the form
/// `__{number}`, defaulting to 0 if not present.
///
/// ABNF grammar for labels:
/// ```abnf
/// namespaced-label = qualified-namespace label [version] [instance]
/// qualified-namespace = "c2pa" / entity
/// entity = entity-component *( "." entity-component )
/// entity-component = 1( DIGIT / ALPHA ) *( DIGIT / ALPHA / "-" / "_" )
/// label = 1*( "." label-component )
/// label-component = 1( DIGIT / ALPHA ) *( DIGIT / ALPHA / "-" / "_" )
/// version = ".v" 1*DIGIT
/// instance = "__" 1*DIGIT
/// ```
pub fn parse_label(label: &str) -> (&str, usize, usize) {
    // First, extract instance if present
    let (without_instance, instance) = if let Some(pos) = label.rfind("__") {
        let instance_str = &label[pos + 2..];
        let instance = instance_str.parse::<usize>().unwrap_or(0);
        (&label[..pos], instance)
    } else {
        (label, 0)
    };

    // Then, extract version if present
    #[allow(clippy::unwrap_used)]
    static VERSION_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^v\d+$").unwrap());
    let components: Vec<&str> = without_instance.split('.').collect();
    if let Some(last) = components.last() {
        if VERSION_RE.is_match(last) {
            if let Ok(version) = last[1..].parse::<usize>() {
                let base_end = without_instance.len() - last.len() - 1;
                return (&without_instance[..base_end], version, instance);
            }
        }
    }

    (without_instance, 1, instance)
}

/// Extract the base label without version or instance suffixes
///
/// This function removes both the version suffix (`.v{number}`) and
/// instance suffix (`__{number}`) from a label, returning just the base.
///
/// # Examples
/// ```
/// use c2pa::assertions::labels;
///
/// assert_eq!(labels::base("c2pa.ingredient"), "c2pa.ingredient");
/// assert_eq!(labels::base("c2pa.ingredient.v3"), "c2pa.ingredient");
/// assert_eq!(labels::base("c2pa.ingredient__2"), "c2pa.ingredient");
/// assert_eq!(labels::base("c2pa.ingredient.v3__2"), "c2pa.ingredient");
/// assert_eq!(labels::base("c2pa.actions__1"), "c2pa.actions");
/// ```
pub fn base(label: &str) -> &str {
    parse_label(label).0
}

/// Extract version from a label
///
/// When an assertion's schema is changed in a backwards-compatible manner,
/// the label would consist of an incremented version number, for example
/// moving from `c2pa.ingredient` to `c2pa.ingredient.v2`.
///
/// Returns the version number, or 1 if no version suffix is present
/// (since version 1 is the default and never explicitly included).
///
/// See [versioning - C2PA Technical Specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_versioning).
///
/// # Examples
///
/// ```
/// use c2pa::assertions::labels;
///
/// assert_eq!(labels::version("c2pa.ingredient"), 1);
/// assert_eq!(labels::version("c2pa.ingredient.v2"), 2);
/// assert_eq!(labels::version("c2pa.ingredient.v3__2"), 3);
/// assert_eq!(labels::version("c2pa.ingredient.V2"), 1);
/// assert_eq!(labels::version("c2pa.ingredient.x2"), 1);
/// assert_eq!(labels::version("c2pa.ingredient.v-2"), 1);
/// ```
pub fn version(label: &str) -> usize {
    parse_label(label).1
}

/// Extract the instance number from a label (return 0 if none)
///
/// This function looks for a double underscore followed by a number
/// in the label and returns that number as the instance. If no such
/// pattern is found, it returns zero.
/// "__0" is default and never part of a label.
/// Invalid instances are also treated as zero.
///
/// # Examples
/// ```
/// use c2pa::assertions::labels;
///
/// assert_eq!(labels::instance("c2pa.ingredient"), 0);
/// assert_eq!(labels::instance("c2pa.actions__1"), 1);
/// assert_eq!(labels::instance("c2pa.ingredient.v3__2"), 2);
/// assert_eq!(labels::instance("c2pa.ingredient__2"), 2);
/// assert_eq!(labels::instance("c2pa.ingredient__x"), 0);
/// assert_eq!(labels::instance("c2pa.ingredient__"), 0);
/// ```
pub fn instance(label: &str) -> usize {
    parse_label(label).2
}

/// Given a thumbnail label prefix such as `CLAIM_THUMBNAIL` and a file
/// format (such as `png`), create a suitable label for an assertion.
///
/// # Examples
///
/// ```
/// use c2pa::assertions::labels;
///
/// assert_eq!(
///     labels::add_thumbnail_format(labels::CLAIM_THUMBNAIL, "image/jpeg"),
///     labels::JPEG_CLAIM_THUMBNAIL
/// );
///
/// assert_eq!(
///     labels::add_thumbnail_format(labels::INGREDIENT_THUMBNAIL, "image/png"),
///     labels::PNG_INGREDIENT_THUMBNAIL
/// );
/// ```
pub fn add_thumbnail_format(label: &str, format: &str) -> String {
    match format {
        "image/jpeg" | "jpeg" | "jpg" => format!("{label}.jpeg"),
        "image/png" | "png" => format!("{label}.png"),
        "image/svg+xml" | "svg" => format!("{label}.svg"),
        _ => {
            let p: Vec<&str> = format.split('/').collect();
            if p.len() == 2 && p[0] == "image" {
                format!("{}/{}", label, p[1]) // try to parse other image types
            } else {
                format!("{label}/{format}")
            }
        }
    }
}
