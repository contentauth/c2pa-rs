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

//! HTTP range rules, as pure functions.
//!
//! [`crate::asset_transport`] is generic and takes no HTTP dependency. These helpers are
//! the one exception: they operate on values a fetch already produced, so a transport
//! does not reimplement the RFC 9110 rules that decide whether a response can be trusted
//! at the requested offset. Inputs are `u16` and `&str`, outputs are crate types, and no
//! HTTP client is pulled in.
//!
//! They are advisory. A transport that never calls them still passes the mandatory checks
//! in `fetch_versioned`, which every read goes through.

use std::num::NonZeroU64;

use crate::asset_transport::{AssetTransportError, ObjectVersion};

/// A parsed `Content-Range` header value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentRange {
    /// `bytes first-last/total` from a `206`. `total` is `None` for `*`.
    Range {
        /// First byte position served, inclusive.
        first: u64,
        /// Last byte position served, inclusive.
        last: u64,
        /// Total object length, when the origin states it.
        total: Option<u64>,
    },
    /// `bytes */total` from a `416`, stating the length the range missed.
    Unsatisfied {
        /// Total object length.
        total: u64,
    },
}

/// Whether an origin advertises range support, per its `Accept-Ranges` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AcceptRanges {
    /// `bytes` is among the accepted units.
    Bytes,
    /// `none`: the origin states it accepts no range units.
    None,
    /// Header absent, or naming units other than `bytes`.
    Unknown,
}

/// Parses a `Content-Range` header value.
///
/// Returns `None` for a value RFC 9110 14.4 makes invalid: a unit other than `bytes`,
/// `last` below `first`, or a total no greater than `last`. That section requires a
/// recipient to not recombine content from such a response, so the caller treats `None`
/// as a response it cannot place.
pub fn content_range(value: &str) -> Option<ContentRange> {
    let (unit, spec) = value.trim().split_once(' ')?;
    // RFC 9110 14.1: range units are case-insensitive.
    if !unit.eq_ignore_ascii_case("bytes") {
        return None;
    }

    let (range, total) = spec.trim().rsplit_once('/')?;
    let total = match total.trim() {
        "*" => None,
        digits => Some(digits.parse::<u64>().ok()?),
    };

    if range.trim() == "*" {
        // `bytes */total`, the 416 form. An unknown total carries no information.
        return total.map(|total| ContentRange::Unsatisfied { total });
    }

    let (first, last) = range.trim().split_once('-')?;
    let first: u64 = first.trim().parse().ok()?;
    let last: u64 = last.trim().parse().ok()?;
    if last < first {
        return None;
    }
    if total.is_some_and(|total| total <= last) {
        return None;
    }

    Some(ContentRange::Range { first, last, total })
}

/// Builds the request headers for one range read.
///
/// Emits `Range: bytes=<offset>-<offset + len - 1>`. RFC 9110 14.1.2 makes both positions
/// inclusive, so `bytes=0-1023` requests 1024 bytes and an off-by-one here shifts every
/// hash that follows. `len` is [`NonZeroU64`] because `bytes=n-(n-1)` is malformed and
/// unrepresentable rather than checked. Never emits an open-ended `bytes=n-`, which an
/// origin may answer with the whole object.
///
/// `if_range` is emitted only when the token is a quoted entity-tag. RFC 9110 13.1.5
/// forbids an HTTP-date in `If-Range` unless it is a strong validator, which needs the
/// origin's `Date` header and a one-second rule. A `Last-Modified`-derived token is
/// compared after the fact instead. An origin answering `200` to `If-Range` reports that
/// the object changed, which is the documented behavior of that header and not a fault.
///
/// Returns [`AssetTransportError::Other`] when `offset + len - 1` overflows `u64`.
pub fn headers(
    offset: u64,
    len: NonZeroU64,
    if_range: Option<&str>,
) -> Result<Vec<(&'static str, String)>, AssetTransportError> {
    let last = offset
        .checked_add(len.get() - 1)
        .ok_or_else(|| AssetTransportError::Other {
            source: format!(
                "range end overflows u64: offset {offset} plus length {len} exceeds the \
                 addressable range"
            )
            .into(),
        })?;

    let mut headers = vec![("Range", format!("bytes={offset}-{last}"))];
    if let Some(token) = if_range.map(str::trim).filter(|t| t.starts_with('"')) {
        headers.push(("If-Range", token.to_string()));
    }
    Ok(headers)
}

/// Checks a range response's status against the range contract.
///
/// - `206 Partial Content` is the success case.
/// - `200 OK` is accepted only when the whole object was requested and the whole object
///   came back: `requested` starts at 0, `total` is known, and the requested length equals
///   it. RFC 9110 14.2 lets an origin ignore `Range`, so that response is correct. Any
///   other `200` cannot be placed at the requested offset and fails.
/// - `412 Precondition Failed` answers `If-Match`, not `If-Range`, and reaches here only
///   from a transport that sends both. Reported as
///   [`AssetTransportError::VersionChanged`].
/// - `416 Range Not Satisfiable` is reported as
///   [`AssetTransportError::RangeNotSatisfiable`], carrying the total from `Content-Range`
///   when the caller supplies it. RFC 9110 15.5.17 also covers an unsupported unit or an
///   invalid range set, so a `416` whose offset lies inside a known total means the origin
///   refused a satisfiable range.
/// - Any other status means the far end did not honor `Range`.
///
/// `total` is the object length when known, from a probe or an earlier `Content-Range`.
///
/// Pure over values a fetch already produced: no I/O, no HTTP client.
pub fn validate_status(
    status: u16,
    reference: &str,
    requested: (u64, u64),
    total: Option<u64>,
    expect: Option<&ObjectVersion>,
    served: Option<&ObjectVersion>,
) -> Result<(), AssetTransportError> {
    let (offset, len) = requested;
    match status {
        206 => Ok(()),
        416 => Err(AssetTransportError::RangeNotSatisfiable {
            reference: reference.to_string(),
            offset,
            total,
        }),
        412 => Err(AssetTransportError::VersionChanged {
            expected: expect.map(ObjectVersion::to_string).unwrap_or_default(),
            got: "rejected by origin (412 Precondition Failed)".to_string(),
        }),
        200 => {
            if let (Some(expected), Some(got)) = (expect, served) {
                if expected != got {
                    return Err(AssetTransportError::VersionChanged {
                        expected: expected.to_string(),
                        got: got.to_string(),
                    });
                }
            }
            // The whole object asked for, and the whole object returned.
            if offset == 0 && total.is_some_and(|total| total == len) {
                return Ok(());
            }
            Err(AssetTransportError::Other {
                source: "expected 206 Partial Content, got 200 (server did not honor Range)".into(),
            })
        }
        other => Err(AssetTransportError::Other {
            source: format!(
                "expected 206 Partial Content, got {other} (server may not honor Range)"
            )
            .into(),
        }),
    }
}

/// Reads an `Accept-Ranges` header value.
///
/// RFC 9110 14.3: an absent header states nothing, so it maps to
/// [`AcceptRanges::Unknown`]. Only an explicit `none` is [`AcceptRanges::None`]. The
/// reliable capability test is whether a probe returns `206` or `200`, because an
/// intermediary can advertise support it does not honor.
pub fn accept_ranges(value: Option<&str>) -> AcceptRanges {
    let Some(value) = value else {
        return AcceptRanges::Unknown;
    };
    let mut units = value.split(',').map(str::trim);
    if units.clone().any(|u| u.eq_ignore_ascii_case("bytes")) {
        AcceptRanges::Bytes
    } else if units.any(|u| u.eq_ignore_ascii_case("none")) {
        AcceptRanges::None
    } else {
        AcceptRanges::Unknown
    }
}

/// Whether a `Content-Encoding` value leaves byte offsets meaningful.
///
/// RFC 9110 14.1.2 defines ranges over the encoded bytes, so offsets into a `gzip`
/// response do not address the decoded object. Accepts an absent header or `identity`.
pub fn content_encoding_ok(value: Option<&str>) -> bool {
    match value.map(str::trim) {
        None | Some("") => true,
        Some(value) => value.eq_ignore_ascii_case("identity"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn nz(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap()
    }

    #[test]
    fn content_range_parses_a_served_range() {
        assert_eq!(
            content_range("bytes 0-1023/4096"),
            Some(ContentRange::Range {
                first: 0,
                last: 1023,
                total: Some(4096)
            })
        );
        assert_eq!(
            content_range("bytes 0-1023/*"),
            Some(ContentRange::Range {
                first: 0,
                last: 1023,
                total: None
            })
        );
        assert_eq!(
            content_range("BYTES 0-0/1"),
            Some(ContentRange::Range {
                first: 0,
                last: 0,
                total: Some(1)
            })
        );
    }

    #[test]
    fn content_range_parses_the_unsatisfied_form() {
        assert_eq!(
            content_range("bytes */4096"),
            Some(ContentRange::Unsatisfied { total: 4096 })
        );
        assert_eq!(
            content_range("bytes */0"),
            Some(ContentRange::Unsatisfied { total: 0 })
        );
    }

    #[test]
    fn content_range_rejects_what_rfc_9110_14_4_makes_invalid() {
        // total <= last
        assert_eq!(content_range("bytes 0-1023/1000"), None);
        // last < first
        assert_eq!(content_range("bytes 500-100/1000"), None);
        // unit is not bytes
        assert_eq!(content_range("items 0-99/500"), None);
        assert_eq!(content_range("garbage"), None);
        assert_eq!(content_range("bytes 0-1023"), None);
    }

    #[test]
    fn headers_use_inclusive_positions() {
        assert_eq!(
            headers(0, nz(1024), None).unwrap(),
            vec![("Range", "bytes=0-1023".to_string())]
        );
        // One byte, the probe shape.
        assert_eq!(
            headers(0, nz(1), None).unwrap(),
            vec![("Range", "bytes=0-0".to_string())]
        );
        assert_eq!(
            headers(4096, nz(4096), None).unwrap(),
            vec![("Range", "bytes=4096-8191".to_string())]
        );
    }

    #[test]
    fn headers_reject_an_overflowing_range_end() {
        assert!(headers(u64::MAX, nz(2), None).is_err());
        // The last addressable byte is still fine.
        assert!(headers(u64::MAX, nz(1), None).is_ok());
    }

    #[test]
    fn headers_send_if_range_only_for_a_quoted_entity_tag() {
        let with_etag = headers(0, nz(1), Some("\"abc\"")).unwrap();
        assert_eq!(with_etag.len(), 2);
        assert_eq!(with_etag[1], ("If-Range", "\"abc\"".to_string()));

        // A date is never sent: RFC 9110 13.1.5 needs a strong-validator check this
        // helper cannot make.
        let with_date = headers(0, nz(1), Some("Wed, 01 Jan 2026 00:00:00 GMT")).unwrap();
        assert_eq!(with_date.len(), 1);

        // An unquoted token is not an entity-tag.
        let unquoted = headers(0, nz(1), Some("abc")).unwrap();
        assert_eq!(unquoted.len(), 1);
    }

    #[test]
    fn validate_status_enforces_the_range_contract() {
        let reference = "s3://bucket/key";
        assert!(validate_status(206, reference, (0, 1024), None, None, None).is_ok());

        let v1 = ObjectVersion::new("v1");
        let v2 = ObjectVersion::new("v2");
        assert!(matches!(
            validate_status(200, reference, (0, 1024), None, Some(&v1), Some(&v2)),
            Err(AssetTransportError::VersionChanged { .. })
        ));
        assert!(matches!(
            validate_status(412, reference, (0, 1024), None, Some(&v1), None),
            Err(AssetTransportError::VersionChanged { .. })
        ));
        assert!(matches!(
            validate_status(500, reference, (0, 1024), None, None, None),
            Err(AssetTransportError::Other { .. })
        ));
    }

    #[test]
    fn validate_status_accepts_a_whole_object_answered_as_200() {
        let reference = "https://example.com/a.jpg";
        // RFC 9110 14.2: the origin may ignore Range, and the whole object is what was
        // asked for.
        assert!(validate_status(200, reference, (0, 4096), Some(4096), None, None).is_ok());
        // A partial request answered with 200 cannot be placed at the offset.
        assert!(matches!(
            validate_status(200, reference, (0, 1024), Some(4096), None, None),
            Err(AssetTransportError::Other { .. })
        ));
        // Same length, but not from the start of the object.
        assert!(matches!(
            validate_status(200, reference, (512, 4096), Some(4096), None, None),
            Err(AssetTransportError::Other { .. })
        ));
        // Unknown total: nothing proves the body is the whole object.
        assert!(matches!(
            validate_status(200, reference, (0, 4096), None, None, None),
            Err(AssetTransportError::Other { .. })
        ));
    }

    #[test]
    fn validate_status_carries_the_total_from_a_416() {
        let err = validate_status(416, "https://example.com/a.jpg", (512, 1), Some(0), None, None)
            .unwrap_err();
        assert!(matches!(
            err,
            AssetTransportError::RangeNotSatisfiable {
                offset: 512,
                total: Some(0),
                ..
            }
        ));
    }

    #[test]
    fn accept_ranges_treats_absence_as_unknown() {
        assert_eq!(accept_ranges(None), AcceptRanges::Unknown);
        assert_eq!(accept_ranges(Some("bytes")), AcceptRanges::Bytes);
        assert_eq!(accept_ranges(Some("BYTES")), AcceptRanges::Bytes);
        assert_eq!(accept_ranges(Some("none")), AcceptRanges::None);
        assert_eq!(accept_ranges(Some("bytes, none")), AcceptRanges::Bytes);
        assert_eq!(accept_ranges(Some("items")), AcceptRanges::Unknown);
    }

    #[test]
    fn content_encoding_ok_accepts_only_unencoded_bytes() {
        assert!(content_encoding_ok(None));
        assert!(content_encoding_ok(Some("identity")));
        assert!(content_encoding_ok(Some("  ")));
        assert!(!content_encoding_ok(Some("gzip")));
        assert!(!content_encoding_ok(Some("br")));
    }
}
