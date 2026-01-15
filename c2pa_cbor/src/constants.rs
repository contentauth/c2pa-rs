// Copyright 2025 Adobe. All rights reserved.
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

// Internal CBOR constants shared across modules
// Not part of the public API

// CBOR major types
pub(crate) const MAJOR_UNSIGNED: u8 = 0;
pub(crate) const MAJOR_NEGATIVE: u8 = 1;
pub(crate) const MAJOR_BYTES: u8 = 2;
pub(crate) const MAJOR_TEXT: u8 = 3;
pub(crate) const MAJOR_ARRAY: u8 = 4;
pub(crate) const MAJOR_MAP: u8 = 5;
pub(crate) const MAJOR_TAG: u8 = 6;
pub(crate) const MAJOR_SIMPLE: u8 = 7;

// Standard CBOR tags (RFC 8949)
pub(crate) const TAG_DATETIME_STRING: u64 = 0; // Standard date/time string (RFC 3339)
pub(crate) const TAG_EPOCH_DATETIME: u64 = 1; // Epoch-based date/time
#[allow(dead_code)]
pub(crate) const TAG_POSITIVE_BIGNUM: u64 = 2; // Positive bignum
#[allow(dead_code)]
pub(crate) const TAG_NEGATIVE_BIGNUM: u64 = 3; // Negative bignum
#[allow(dead_code)]
pub(crate) const TAG_DECIMAL_FRACTION: u64 = 4; // Decimal fraction
#[allow(dead_code)]
pub(crate) const TAG_BIGFLOAT: u64 = 5; // Bigfloat
pub(crate) const TAG_URI: u64 = 32; // URI (RFC 3986)
pub(crate) const TAG_BASE64URL: u64 = 33; // Base64url-encoded text
pub(crate) const TAG_BASE64: u64 = 34; // Base64-encoded text
#[allow(dead_code)]
pub(crate) const TAG_MIME: u64 = 36; // MIME message

// RFC 8746 - Typed arrays encoded as byte strings
pub(crate) const TAG_UINT8_ARRAY: u64 = 64; // uint8 array
pub(crate) const TAG_UINT16BE_ARRAY: u64 = 65; // uint16 big-endian array
pub(crate) const TAG_UINT32BE_ARRAY: u64 = 66; // uint32 big-endian array
pub(crate) const TAG_UINT64BE_ARRAY: u64 = 67; // uint64 big-endian array
#[allow(dead_code)]
pub(crate) const TAG_UINT8_CLAMPED_ARRAY: u64 = 68; // uint8 clamped array
pub(crate) const TAG_UINT16LE_ARRAY: u64 = 69; // uint16 little-endian array
pub(crate) const TAG_UINT32LE_ARRAY: u64 = 70; // uint32 little-endian array
pub(crate) const TAG_UINT64LE_ARRAY: u64 = 71; // uint64 little-endian array
#[allow(dead_code)]
pub(crate) const TAG_SINT8_ARRAY: u64 = 72; // sint8 array
#[allow(dead_code)]
pub(crate) const TAG_SINT16BE_ARRAY: u64 = 73; // sint16 big-endian array
#[allow(dead_code)]
pub(crate) const TAG_SINT32BE_ARRAY: u64 = 74; // sint32 big-endian array
#[allow(dead_code)]
pub(crate) const TAG_SINT64BE_ARRAY: u64 = 75; // sint64 big-endian array
#[allow(dead_code)]
pub(crate) const TAG_SINT16LE_ARRAY: u64 = 77; // sint16 little-endian array
#[allow(dead_code)]
pub(crate) const TAG_SINT32LE_ARRAY: u64 = 78; // sint32 little-endian array
#[allow(dead_code)]
pub(crate) const TAG_SINT64LE_ARRAY: u64 = 79; // sint64 little-endian array
pub(crate) const TAG_FLOAT16BE_ARRAY: u64 = 80; // float16 big-endian array
pub(crate) const TAG_FLOAT32BE_ARRAY: u64 = 81; // float32 big-endian array
pub(crate) const TAG_FLOAT64BE_ARRAY: u64 = 82; // float64 big-endian array
#[allow(dead_code)]
pub(crate) const TAG_FLOAT128BE_ARRAY: u64 = 83; // float128 big-endian array
pub(crate) const TAG_FLOAT16LE_ARRAY: u64 = 84; // float16 little-endian array
pub(crate) const TAG_FLOAT32LE_ARRAY: u64 = 85; // float32 little-endian array
pub(crate) const TAG_FLOAT64LE_ARRAY: u64 = 86; // float64 little-endian array
#[allow(dead_code)]
pub(crate) const TAG_FLOAT128LE_ARRAY: u64 = 87; // float128 little-endian array

// Additional info values
pub(crate) const FALSE: u8 = 20;
pub(crate) const TRUE: u8 = 21;
pub(crate) const NULL: u8 = 22;
pub(crate) const UNDEFINED: u8 = 23;
#[allow(dead_code)] // These are unassigned in the IANA registry
pub(crate) const SIMPLE_VALUE: u8 = 24;
pub(crate) const FLOAT16: u8 = 25;
pub(crate) const FLOAT32: u8 = 26;
pub(crate) const FLOAT64: u8 = 27;
pub(crate) const INDEFINITE: u8 = 31;
pub(crate) const BREAK: u8 = 0xff;

// DOS protection limits
/// Default maximum allocation size (100MB) to prevent OOM attacks from malicious CBOR.
///
/// This can be overridden using `Decoder::new(reader).with_max_allocation(size)`
/// or via the `from_reader_with_limit()` convenience function.
pub const DEFAULT_MAX_ALLOCATION: usize = 100 * 1024 * 1024; // 100 MB

/// Default maximum recursion depth to prevent stack overflow from deeply nested structures.
///
/// This can be overridden using `Decoder::new(reader).with_max_depth(depth)`.
pub const DEFAULT_MAX_DEPTH: usize = 128;
