//! A set of structs to define a region of interest within an
//! [`Action`][crate::assertions::Action] or [`Metadata`].

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::Metadata;

/// An x, y coordinate used for specifying vertices in polygons.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct Coordinate {
    /// The coordinate along the x-axis.
    pub x: f64,
    /// The coordinate along the y-axis.
    pub y: f64,
}

/// The type of shape for the range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[serde(rename_all = "camelCase")]
pub enum ShapeType {
    /// A rectangle.
    Rectangle,
    /// A circle.
    Circle,
    /// A polygon.
    Polygon,
}

/// The type of unit for the range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[serde(rename_all = "camelCase")]
pub enum UnitType {
    /// Use pixels.
    Pixel,
    /// Use percentage.
    Percent,
}

/// A spatial range representing rectangle, circle, or a polygon.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct Shape {
    /// The type of shape.
    #[serde(rename = "type")]
    pub shape_type: ShapeType,
    /// The type of unit for the shape range.
    pub unit: UnitType,
    /// THe origin of the coordinate in the shape.
    pub origin: Coordinate,
    /// The width for rectangles or diameter for circles.
    ///
    /// This field can be ignored for polygons.
    pub width: Option<f64>,
    /// The height of a rectnagle.
    ///
    /// This field can be ignored for circles and polygons.
    pub height: Option<f64>,
    /// If the range is inside the shape.
    ///
    /// The default value is true.
    pub inside: Option<bool>,
    /// The vertices of the polygon.
    ///
    /// This field can be ignored for rectangles and circles.
    pub vertices: Option<Vec<Coordinate>>,
}

/// The type of time.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[serde(rename_all = "camelCase")]
pub enum TimeType {
    /// Times are described using Normal Play Time (npt) as described in RFC 2326.
    #[default]
    Npt,
}

/// A temporal range representing a starting time to an ending time.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct Time {
    /// The type of time.
    #[serde(rename = "type", default)]
    pub time_type: TimeType,
    /// The start time or the start of the asset if not present.
    pub start: Option<String>,
    /// The end time or the end of the asset if not present.
    pub end: Option<String>,
}

/// A frame range representing starting and ending frames or pages.
///
/// If both `start` and `end` are missing, the frame will span the entire asset.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct Frame {
    /// The start of the frame or the end of the asset if not present.
    ///
    /// The first frame/page starts at 0.
    pub start: Option<i32>,
    /// The end of the frame inclusive or the end of the asset if not present.
    pub end: Option<i32>,
}

/// Selects a range of text via a fragment identifier.
///
/// This is modeled after the W3C Web Annotation selector model.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct TextSelector {
    // TODO: can we provide more specific types?
    //
    /// Fragment identifier as per RFC3023 (XML) or ISO 32000-2 (PDF), Annex O.
    pub fragment: String,
    /// The start character offset or the start of the fragment if not present.
    pub start: Option<i32>,
    /// The end character offset or the end of the fragment if not present.
    pub end: Option<i32>,
}

/// One or two [`TextSelector`][TextSelector] identifiying the range to select.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct TextSelectorRange {
    /// The start (or entire) text range.
    pub selector: TextSelector,
    /// The end of the text range.
    pub end: Option<TextSelector>,
}

/// A textual range representing multiple (possibly discontinuous) ranges of text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct Text {
    /// The ranges of text to select.
    pub selectors: Vec<TextSelectorRange>,
}

/// Description of the boundaries of an identified range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct Item {
    /// The container-specific term used to identify items, such as "track_id" for MP4 or "item_ID" for HEIF.
    pub identifier: String,
    /// The value of the identifier, e.g. a value of "2" for an identifier of "track_id" would imply track 2 of the asset.
    pub value: String,
}

/// The type of range for the region of interest.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[serde(rename_all = "camelCase")]
pub enum RangeType {
    /// A spatial range, see [`Shape`] for more details.
    Spatial,
    /// A temporal range, see [`Time`] for more details.
    #[default]
    Temporal,
    /// A spatial range, see [`Frame`] for more details.
    Frame,
    /// A textual range, see [`Text`] for more details.
    Textual,
    /// A range identified by a specific identifier and value, see [`Item`] for more details.
    Identified,
}

// TODO: this can be much more idiomatic with an enum, but then it wouldn't line up with spec
//
/// A spatial, temporal, frame, or textual range describing the region of interest.
#[skip_serializing_none]
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct Range {
    /// The type of range of interest.
    #[serde(rename = "type")]
    pub range_type: RangeType,
    /// A spatial range.
    pub shape: Option<Shape>,
    /// A temporal range.
    pub time: Option<Time>,
    /// A frame range.
    pub frame: Option<Frame>,
    /// A textual range.
    pub text: Option<Text>,
    /// A item identifier.
    pub item: Option<Item>,
}

/// A role describing the region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[serde(rename_all = "camelCase")]
pub enum Role {
    /// Arbitrary area worth identifying.
    #[serde(rename = "c2pa.areaOfInterest")]
    AreaOfInterest,
    /// This area is all that is left after a crop action.
    #[serde(rename = "c2pa.cropped")]
    Cropped,
    /// This area has had edits applied to it.
    #[serde(rename = "c2pa.edited")]
    Edited,
    /// The area where an ingredient was placed/added.
    #[serde(rename = "c2pa.placed")]
    Placed,
    /// Something in this area was redacted.
    #[serde(rename = "c2pa.redacted")]
    Redacted,
    /// Area specific to a subject (human or not).
    #[serde(rename = "c2pa.subjectArea")]
    SubjectArea,
    /// A range of information was removed/deleted.
    #[serde(rename = "c2pa.deleted")]
    Deleted,
    /// Styling was applied to this area.
    #[serde(rename = "c2pa.styled")]
    Styled,
    /// Invisible watermarking was applied to this area for the purpose of soft binding.
    #[serde(rename = "c2pa.watermarked")]
    Watermarked,
}

/// A region of interest within an asset describing the change.
///
/// This struct can be used from [`Action::changes`][crate::assertions::Action::changes] or
/// [`Metadata::region_of_interest`][crate::assertions::Metadata::region_of_interest].
#[skip_serializing_none]
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct RegionOfInterest {
    /// A range describing the region of interest for the specific asset.
    pub region: Vec<Range>,
    /// A free-text string representing a human-readable name for the region which might be used in a user interface.
    pub name: Option<String>,
    /// A free-text string representing a machine-readable, unique to this assertion, identifier for the region.
    pub identifier: Option<String>,
    /// A value from a controlled vocabulary such as <https://cv.iptc.org/newscodes/imageregiontype/> or an entity-specific
    /// value (e.g., com.litware.newType) that represents the type of thing(s) depicted by a region.
    ///
    /// Note this field serializes/deserializes into the name `type`.
    #[serde(rename = "type")]
    pub region_type: Option<String>,
    /// A value from our controlled vocabulary or an entity-specific value (e.g., com.litware.coolArea) that represents
    /// the role of a region among other regions.
    pub role: Option<Role>,
    /// A free-text string.
    pub description: Option<String>,
    // If we didn't have a box, `Metadata` would recursively use `RegionOfInterest` causing an infinite size error.
    //
    /// Additional information about the asset.
    pub metadata: Option<Box<Metadata>>,
}
