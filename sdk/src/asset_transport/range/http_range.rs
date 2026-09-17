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

use crate::asset_transport::{range::RangeChunk, AssetTransportError, ObjectVersion};

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

/// A range response as the platform received it, before any rule is applied.
///
/// A transport fills this in with what its client handed back and calls
/// [`into_chunk`](Self::into_chunk), so the RFC 9110 rules that decide whether a
/// response is usable at the requested offset have one implementation rather than one
/// per platform.
///
/// The fields are public and exhaustive: a transport outside this crate constructs one
/// directly, which `#[non_exhaustive]` would forbid. Adding a field is therefore a
/// breaking change, which is the right trade for a type whose whole purpose is to be
/// built by its callers.
///
/// There is deliberately no `Default`: it would yield status `0`, which no origin sends
/// and which [`into_chunk`](Self::into_chunk) could only report as a server fault.
#[derive(Debug, Clone)]
pub struct RangeResponse {
    /// HTTP status code.
    pub status: u16,
    /// `Content-Range`, when the response carries one.
    pub content_range: Option<String>,
    /// `ETag`, when the response carries one.
    pub etag: Option<String>,
    /// `Last-Modified`, when the response carries one.
    pub last_modified: Option<String>,
    /// `Content-Encoding`. Across origins this needs
    /// `Access-Control-Expose-Headers`, and a response whose encoding is hidden cannot
    /// be refused by [`into_chunk`](Self::into_chunk).
    pub content_encoding: Option<String>,
    /// The body as the platform delivered it.
    pub body: Vec<u8>,
}

impl RangeResponse {
    /// The object length this response states, from `Content-Range`.
    ///
    /// A one-byte probe learns the length this way, and a `416` states it too.
    pub fn total(&self) -> Option<u64> {
        match content_range(self.content_range.as_deref()?)? {
            ContentRange::Range { total, .. } => total,
            ContentRange::Unsatisfied { total } => Some(total),
        }
    }

    /// The version this response identifies, per RFC 9110 8.8.3.
    pub fn version(&self) -> Option<ObjectVersion> {
        ObjectVersion::from_http_validators(self.etag.as_deref(), self.last_modified.as_deref())
    }

    /// Applies the range contract and yields the chunk, or the reason the response
    /// fails it.
    ///
    /// Runs the status rule, the encoding rule and the `Content-Range` rule, in that
    /// order. Status comes first because error pages are routinely compressed: checking
    /// the encoding first would report a gzipped `404` as an encoding violation instead
    /// of as the failure it is. This step establishes whether a response is a usable
    /// range response at all. The placement and length checks every transport already
    /// passes through establish afterwards whether the chunk is the one this read
    /// asked for.
    ///
    /// `total` is the object length when the caller already knows it, which lets a
    /// whole-object `200` be accepted per RFC 9110 14.2.
    pub fn into_chunk(
        self,
        reference: &str,
        requested: (u64, NonZeroU64),
        total: Option<u64>,
        expect: Option<&ObjectVersion>,
    ) -> Result<RangeChunk, AssetTransportError> {
        let (offset, len) = requested;
        let version = self.version();
        // RFC 9110 15.5.17: a `416` states the object's current length, so it corrects
        // whatever the caller believed. Every other status states nothing better than
        // what the caller already knows.
        let total = match self.status {
            416 => self.total().or(total),
            _ => total.or_else(|| self.total()),
        };
        validate_status(
            self.status,
            reference,
            (offset, len.get()),
            total,
            expect,
            version.as_ref(),
        )?;

        // RFC 9110 14.1.2 defines a range over the encoded bytes, so an encoded
        // response does not address the object the offsets refer to.
        if !content_encoding_ok(self.content_encoding.as_deref()) {
            return Err(AssetTransportError::other(std::io::Error::other(format!(
                "range response from {reference} carries a content encoding ({}), so its \
                 byte offsets do not address the object",
                self.content_encoding.as_deref().unwrap_or("unknown")
            ))));
        }

        // An origin that omits `Content-Range` leaves the requested offset, which makes
        // the caller's placement check pass without proving anything.
        let served = match self.content_range.as_deref().and_then(content_range) {
            Some(ContentRange::Range { first, .. }) => first,
            _ => offset,
        };

        let chunk = RangeChunk::new(served, self.body);
        Ok(match version {
            Some(version) => chunk.with_version(version),
            None => chunk,
        })
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

