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

// Portions derived from serde_cbor (https://github.com/pyfisch/cbor)

use std::io::{BufReader, Cursor, Read};

use serde::Deserialize;

use crate::{Error, Result, constants::*};

pub struct Decoder<R: Read> {
    reader: R,
    peeked: Option<u8>,
    max_allocation: Option<usize>,
    recursion_depth: usize,
    max_recursion_depth: usize,
}

/// Safely convert u64 to usize, checking for overflow on 32-bit platforms
#[inline]
fn u64_to_usize(val: u64) -> Result<usize> {
    usize::try_from(val).map_err(|_| {
        Error::Syntax(format!(
            "Length {} exceeds maximum supported size on this platform",
            val
        ))
    })
}

impl<R: Read> Decoder<R> {
    /// Create a new CBOR decoder with default limits
    ///
    /// Default limits:
    /// - No allocation limit (relies on `try_reserve` for system-level protection)
    /// - Maximum recursion depth: 128 levels
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    ///
    /// use c2pa_cbor::Decoder;
    ///
    /// let data = vec![0xa0]; // empty map
    /// let decoder = Decoder::new(Cursor::new(&data));
    /// ```
    pub fn new(reader: R) -> Self {
        Decoder {
            reader,
            peeked: None,
            max_allocation: None,
            recursion_depth: 0,
            max_recursion_depth: DEFAULT_MAX_DEPTH,
        }
    }

    /// Set the maximum allocation size for a single CBOR value (builder pattern)
    ///
    /// This provides defense-in-depth against malicious CBOR with extremely large
    /// length fields. The limit applies to both individual allocations and cumulative
    /// sizes for indefinite-length strings. Even without this limit, `try_reserve`
    /// provides system-level protection.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    ///
    /// use c2pa_cbor::Decoder;
    ///
    /// let data = vec![0xa0];
    /// let decoder = Decoder::new(Cursor::new(&data)).with_max_allocation(1024 * 1024); // 1MB limit
    /// ```
    pub fn with_max_allocation(mut self, max_bytes: usize) -> Self {
        self.max_allocation = Some(max_bytes);
        self
    }

    /// Set the maximum recursion depth for nested structures (builder pattern)
    ///
    /// This prevents stack overflow from deeply nested CBOR structures.
    /// Default is 128 levels, which is sufficient for most use cases.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Cursor;
    ///
    /// use c2pa_cbor::Decoder;
    ///
    /// let data = vec![0xa0];
    /// let decoder = Decoder::new(Cursor::new(&data)).with_max_depth(64); // Max 64 levels of nesting
    /// ```
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_recursion_depth = max_depth;
        self
    }

    fn check_recursion_depth(&self) -> Result<()> {
        if self.recursion_depth >= self.max_recursion_depth {
            return Err(Error::Syntax(format!(
                "CBOR nesting depth {} exceeds maximum {}",
                self.recursion_depth, self.max_recursion_depth
            )));
        }
        Ok(())
    }

    /// Try to allocate a buffer of the given size
    ///
    /// This checks the configured maximum first, then uses try_reserve to
    /// respect actual system memory limits (ulimit, Docker, cgroups, etc.)
    fn try_allocate(&self, size: usize) -> Result<Vec<u8>> {
        // Check user-defined limit first (if set)
        if let Some(max) = self.max_allocation
            && size > max
        {
            return Err(Error::Syntax(format!(
                "Allocation size {} bytes exceeds maximum {} bytes",
                size, max
            )));
        }

        // Try to actually allocate - respects system limits
        let mut buf = Vec::new();
        buf.try_reserve(size).map_err(|_| {
            Error::Syntax(format!("Cannot allocate {} bytes (out of memory)", size))
        })?;
        buf.resize(size, 0);
        Ok(buf)
    }

    fn read_u8(&mut self) -> Result<u8> {
        if let Some(byte) = self.peeked.take() {
            return Ok(byte);
        }
        let mut buf = [0u8; 1];
        self.reader.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.reader.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.reader.read_exact(&mut buf)?;
        Ok(u64::from_be_bytes(buf))
    }

    fn read_length(&mut self, info: u8) -> Result<Option<u64>> {
        Ok(match info {
            0..=23 => Some(info as u64),
            24 => Some(self.read_u8()? as u64),
            25 => Some(self.read_u16()? as u64),
            26 => Some(self.read_u32()? as u64),
            27 => Some(self.read_u64()?),
            INDEFINITE => None, // Indefinite length
            _ => return Err(Error::Syntax("Invalid CBOR value".to_string())),
        })
    }

    fn peek_u8(&mut self) -> Result<u8> {
        if let Some(byte) = self.peeked {
            return Ok(byte);
        }
        let mut buf = [0u8; 1];
        self.reader.read_exact(&mut buf)?;
        self.peeked = Some(buf[0]);
        Ok(buf[0])
    }

    fn is_break(&mut self) -> Result<bool> {
        let byte = self.peek_u8()?;
        Ok(byte == BREAK)
    }

    fn read_break(&mut self) -> Result<()> {
        let byte = self.read_u8()?;
        if byte != BREAK {
            return Err(Error::Syntax("Expected break marker".to_string()));
        }
        Ok(())
    }

    /// Read a definite-length byte buffer
    #[inline]
    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut buf = self.try_allocate(len)?;
        self.reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Read a definite-length text string
    #[inline]
    fn read_text(&mut self, len: usize) -> Result<String> {
        let buf = self.read_bytes(len)?;
        String::from_utf8(buf).map_err(|_| Error::InvalidUtf8)
    }

    /// Read indefinite-length byte string by concatenating chunks
    #[inline]
    fn read_indefinite_bytes(&mut self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        loop {
            if self.is_break()? {
                self.read_break()?;
                break;
            }
            let initial = self.read_u8()?;
            let major = initial >> 5;
            let info = initial & 0x1f;
            if major != MAJOR_BYTES {
                return Err(Error::Syntax(
                    "Indefinite byte string chunks must be byte strings".to_string(),
                ));
            }
            let len = self.read_length(info)?.ok_or_else(|| {
                Error::Syntax("Indefinite byte string chunks cannot be indefinite".to_string())
            })?;
            let chunk = self.read_bytes(u64_to_usize(len)?)?;

            // Check cumulative size against max_allocation limit
            let new_size = result.len().saturating_add(chunk.len());
            if let Some(max) = self.max_allocation
                && new_size > max
            {
                return Err(Error::Syntax(format!(
                    "Indefinite byte string total size {} exceeds maximum {} bytes",
                    new_size, max
                )));
            }

            result.extend_from_slice(&chunk);
        }
        Ok(result)
    }

    /// Read indefinite-length text string by concatenating chunks
    #[inline]
    fn read_indefinite_text(&mut self) -> Result<String> {
        let mut result = String::new();
        loop {
            if self.is_break()? {
                self.read_break()?;
                break;
            }
            let initial = self.read_u8()?;
            let major = initial >> 5;
            let info = initial & 0x1f;
            if major != MAJOR_TEXT {
                return Err(Error::Syntax(
                    "Indefinite text string chunks must be text strings".to_string(),
                ));
            }
            let len = self.read_length(info)?.ok_or_else(|| {
                Error::Syntax("Indefinite text string chunks cannot be indefinite".to_string())
            })?;
            let chunk = self.read_text(u64_to_usize(len)?)?;

            // Check cumulative size against max_allocation limit
            let new_size = result.len().saturating_add(chunk.len());
            if let Some(max) = self.max_allocation
                && new_size > max
            {
                return Err(Error::Syntax(format!(
                    "Indefinite text string total size {} exceeds maximum {} bytes",
                    new_size, max
                )));
            }

            result.push_str(&chunk);
        }
        Ok(result)
    }

    pub fn read_tag(&mut self) -> Result<u64> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let info = initial & 0x1f;

        if major != MAJOR_TAG {
            return Err(Error::Syntax("Invalid CBOR value".to_string()));
        }

        match self.read_length(info)? {
            Some(tag) => Ok(tag),
            None => Err(Error::Syntax("Tag cannot be indefinite".to_string())),
        }
    }

    pub fn decode<'de, T: Deserialize<'de>>(&mut self) -> Result<T> {
        T::deserialize(&mut *self)
    }

    /// Shared core deserialization logic used by both by-value and by-reference implementations
    #[inline]
    fn deserialize_any_impl<'de, V: serde::de::Visitor<'de>>(
        &mut self,
        visitor: V,
    ) -> Result<V::Value> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let info = initial & 0x1f;

        match major {
            MAJOR_UNSIGNED => {
                let val = self.read_length(info)?.ok_or_else(|| {
                    Error::Syntax("Unsigned integer cannot be indefinite".to_string())
                })?;
                visitor.visit_u64(val)
            }
            MAJOR_NEGATIVE => {
                let val = self.read_length(info)?.ok_or_else(|| {
                    Error::Syntax("Negative integer cannot be indefinite".to_string())
                })?;
                visitor.visit_i64(-1 - val as i64)
            }
            MAJOR_BYTES => match self.read_length(info)? {
                Some(len) => {
                    let buf = self.read_bytes(u64_to_usize(len)?)?;
                    visitor.visit_byte_buf(buf)
                }
                None => visitor.visit_byte_buf(self.read_indefinite_bytes()?),
            },
            MAJOR_TEXT => match self.read_length(info)? {
                Some(len) => {
                    let s = self.read_text(u64_to_usize(len)?)?;
                    visitor.visit_string(s)
                }
                None => visitor.visit_string(self.read_indefinite_text()?),
            },
            MAJOR_ARRAY => {
                self.check_recursion_depth()?;
                self.recursion_depth += 1;
                match self.read_length(info)? {
                    Some(len) => visitor.visit_seq(SeqAccess {
                        de: self,
                        remaining: Some(u64_to_usize(len)?),
                    }),
                    None => visitor.visit_seq(SeqAccess {
                        de: self,
                        remaining: None,
                    }),
                }
                // Note: recursion_depth is decremented in SeqAccess::drop
            }
            MAJOR_MAP => {
                self.check_recursion_depth()?;
                self.recursion_depth += 1;
                match self.read_length(info)? {
                    Some(len) => visitor.visit_map(MapAccess {
                        de: self,
                        remaining: Some(u64_to_usize(len)?),
                    }),
                    None => visitor.visit_map(MapAccess {
                        de: self,
                        remaining: None,
                    }),
                }
                // Note: recursion_depth is decremented in MapAccess::drop
            }
            MAJOR_TAG => {
                // Read the tag number
                let _tag = self
                    .read_length(info)?
                    .ok_or_else(|| Error::Syntax("Tag cannot be indefinite".to_string()))?;
                // For now, just deserialize the tagged content
                // The tag information is available but we pass through to the content
                self.deserialize_any_impl(visitor)
            }
            MAJOR_SIMPLE => match info {
                FALSE => visitor.visit_bool(false),
                TRUE => visitor.visit_bool(true),
                NULL => visitor.visit_none(),
                UNDEFINED => visitor.visit_unit(),
                FLOAT16 => {
                    let mut buf = [0u8; 2];
                    self.reader.read_exact(&mut buf)?;
                    // Requires the `half` crate or wait for f16 to be stabilized
                    let f16_value = half::f16::from_be_bytes(buf);
                    visitor.visit_f32(f16_value.to_f32())
                }
                FLOAT32 => {
                    let mut buf = [0u8; 4];
                    self.reader.read_exact(&mut buf)?;
                    visitor.visit_f32(f32::from_be_bytes(buf))
                }
                FLOAT64 => {
                    let mut buf = [0u8; 8];
                    self.reader.read_exact(&mut buf)?;
                    visitor.visit_f64(f64::from_be_bytes(buf))
                }
                _ => Err(Error::Syntax("Invalid CBOR value".to_string())),
            },
            _ => Err(Error::Syntax("Invalid CBOR value".to_string())),
        }
    }

    /// Shared enum deserialization logic used by both by-value and by-reference implementations
    #[inline]
    fn deserialize_enum_impl<'de, V: serde::de::Visitor<'de>>(
        &mut self,
        visitor: V,
    ) -> Result<V::Value> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let info = initial & 0x1f;

        match major {
            MAJOR_TEXT => {
                // Unit variant encoded as string
                let len = self.read_length(info)?.ok_or_else(|| {
                    Error::Syntax("Enum variant cannot be indefinite length".to_string())
                })?;
                let s = self.read_text(u64_to_usize(len)?)?;
                visitor.visit_enum(UnitVariantAccess { variant: s })
            }
            MAJOR_MAP => {
                // Variant with data encoded as {"variant": data}
                let len = self.read_length(info)?;
                if len != Some(1) {
                    return Err(Error::Syntax(
                        "Enum variant with data must be single-entry map".to_string(),
                    ));
                }
                visitor.visit_enum(VariantAccess { de: self })
            }
            _ => Err(Error::Syntax("Invalid CBOR type for enum".to_string())),
        }
    }
}

impl<'de> Decoder<&'de [u8]> {
    /// Create a deserializer from a byte slice
    pub fn from_slice(input: &'de [u8]) -> Self {
        Decoder::new(input)
    }
}

impl<'de, R: Read> serde::Deserializer<'de> for Decoder<R> {
    type Error = crate::Error;

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
        bytes byte_buf unit unit_struct newtype_struct seq tuple
        tuple_struct map struct identifier ignored_any
    }

    fn deserialize_option<V: serde::de::Visitor<'de>>(mut self, visitor: V) -> Result<V::Value> {
        // Peek at next byte to check for null
        let initial = self.read_u8()?;
        if initial == 0xf6 {
            // CBOR null
            visitor.visit_none()
        } else {
            // Not null - process as Some(...)
            let major = initial >> 5;
            let info = initial & 0x1f;

            // Handle the value based on major type
            match major {
                MAJOR_MAP => match self.read_length(info)? {
                    Some(len) => visitor.visit_some(MapDeserializer {
                        de: &mut self,
                        remaining: Some(u64_to_usize(len)?),
                    }),
                    None => visitor.visit_some(MapDeserializer {
                        de: &mut self,
                        remaining: None,
                    }),
                },
                MAJOR_ARRAY => match self.read_length(info)? {
                    Some(len) => visitor.visit_some(ArrayDeserializer {
                        de: &mut self,
                        remaining: Some(u64_to_usize(len)?),
                    }),
                    None => visitor.visit_some(ArrayDeserializer {
                        de: &mut self,
                        remaining: None,
                    }),
                },
                _ => {
                    // For simple types, deserialize directly
                    visitor.visit_some(PrefetchedDeserializer {
                        de: &mut self,
                        major,
                        info,
                    })
                }
            }
        }
    }

    fn deserialize_any<V: serde::de::Visitor<'de>>(mut self, visitor: V) -> Result<V::Value> {
        self.deserialize_any_impl(visitor)
    }

    fn deserialize_enum<V: serde::de::Visitor<'de>>(
        mut self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_enum_impl(visitor)
    }
}

impl<'de, R: Read> serde::Deserializer<'de> for &mut Decoder<R> {
    type Error = crate::Error;

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
        bytes byte_buf unit unit_struct seq tuple
        tuple_struct map struct identifier ignored_any
    }

    fn deserialize_option<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        // Peek at next byte - check for CBOR null (0xf6)
        let initial = self.read_u8()?;
        if initial == 0xf6 {
            return visitor.visit_none();
        }

        // Not null - process as Some(...)
        // We've already read the initial byte, so handle it inline
        let major = initial >> 5;
        let info = initial & 0x1f;

        // Handle the value based on major type
        match major {
            MAJOR_MAP => match self.read_length(info)? {
                Some(len) => visitor.visit_some(MapDeserializer {
                    de: self,
                    remaining: Some(u64_to_usize(len)?),
                }),
                None => visitor.visit_some(MapDeserializer {
                    de: self,
                    remaining: None,
                }),
            },
            MAJOR_ARRAY => match self.read_length(info)? {
                Some(len) => visitor.visit_some(ArrayDeserializer {
                    de: self,
                    remaining: Some(u64_to_usize(len)?),
                }),
                None => visitor.visit_some(ArrayDeserializer {
                    de: self,
                    remaining: None,
                }),
            },
            _ => {
                // For simple types, deserialize directly
                // We need to recreate the deserialization with the byte we already read
                visitor.visit_some(PrefetchedDeserializer {
                    de: self,
                    major,
                    info,
                })
            }
        }
    }

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_any_impl(visitor)
    }

    fn deserialize_enum<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_enum_impl(visitor)
    }

    fn deserialize_newtype_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        // For backward compatibility, we need to handle both:
        // 1. NEW format: [inner_value] - 1-element array (proper tuple struct encoding)
        // 2. OLD format: inner_value - direct value (legacy transparent behavior)
        //
        // Strategy: Peek at the next byte to determine the format
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let info = initial & 0x1f;

        if major == MAJOR_ARRAY {
            // NEW format: array wrapping - deserialize as sequence
            match self.read_length(info)? {
                Some(1) => {
                    // 1-element array - extract the single element
                    visitor.visit_newtype_struct(&mut *self)
                }
                Some(len) => {
                    // Wrong array length for newtype struct
                    Err(Error::Syntax(format!(
                        "Expected 1-element array for newtype struct, got {} elements",
                        len
                    )))
                }
                None => {
                    // Indefinite-length array not supported for newtype struct
                    Err(Error::Syntax(
                        "Indefinite-length array not supported for newtype struct".to_string(),
                    ))
                }
            }
        } else {
            // OLD format: direct value (backward compatibility)
            // Put the byte back and deserialize the inner value directly
            // We need to reconstruct the deserializer state with the byte we already read
            match major {
                MAJOR_MAP => match self.read_length(info)? {
                    Some(len) => visitor.visit_newtype_struct(MapDeserializer {
                        de: self,
                        remaining: Some(u64_to_usize(len)?),
                    }),
                    None => visitor.visit_newtype_struct(MapDeserializer {
                        de: self,
                        remaining: None,
                    }),
                },
                MAJOR_TEXT => {
                    let len = self.read_length(info)?.ok_or_else(|| {
                        Error::Syntax("Text in newtype must be definite length".to_string())
                    })?;
                    let s = self.read_text(u64_to_usize(len)?)?;
                    visitor.visit_newtype_struct(StringDeserializer { value: s })
                }
                _ => {
                    // For other types, use prefetched deserializer
                    visitor.visit_newtype_struct(PrefetchedDeserializer {
                        de: self,
                        major,
                        info,
                    })
                }
            }
        }
    }
}

// Helper deserializers for Option handling
struct MapDeserializer<'a, R: Read> {
    de: &'a mut Decoder<R>,
    remaining: Option<usize>,
}

impl<'de, 'a, R: Read> serde::Deserializer<'de> for MapDeserializer<'a, R> {
    type Error = crate::Error;

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_map(MapAccess {
            de: self.de,
            remaining: self.remaining,
        })
    }
}

struct ArrayDeserializer<'a, R: Read> {
    de: &'a mut Decoder<R>,
    remaining: Option<usize>,
}

impl<'de, 'a, R: Read> serde::Deserializer<'de> for ArrayDeserializer<'a, R> {
    type Error = crate::Error;

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_seq(SeqAccess {
            de: self.de,
            remaining: self.remaining,
        })
    }
}

struct PrefetchedDeserializer<'a, R: Read> {
    de: &'a mut Decoder<R>,
    major: u8,
    info: u8,
}

impl<'de, 'a, R: Read> serde::Deserializer<'de> for PrefetchedDeserializer<'a, R> {
    type Error = crate::Error;

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.major {
            MAJOR_UNSIGNED => {
                let val = self.de.read_length(self.info)?.ok_or_else(|| {
                    Error::Syntax("Unsigned integer cannot be indefinite".to_string())
                })?;
                visitor.visit_u64(val)
            }
            MAJOR_NEGATIVE => {
                let val = self.de.read_length(self.info)?.ok_or_else(|| {
                    Error::Syntax("Negative integer cannot be indefinite".to_string())
                })?;
                visitor.visit_i64(-1 - val as i64)
            }
            MAJOR_TEXT => {
                let len = self.de.read_length(self.info)?.ok_or_else(|| {
                    Error::Syntax("Text in option must be definite length".to_string())
                })?;
                let s = self.de.read_text(u64_to_usize(len)?)?;
                visitor.visit_string(s)
            }
            MAJOR_BYTES => {
                let len = self.de.read_length(self.info)?.ok_or_else(|| {
                    Error::Syntax("Bytes in option must be definite length".to_string())
                })?;
                let buf = self.de.read_bytes(u64_to_usize(len)?)?;
                visitor.visit_byte_buf(buf)
            }
            MAJOR_SIMPLE => match self.info {
                FALSE => visitor.visit_bool(false),
                TRUE => visitor.visit_bool(true),
                _ => Err(Error::Syntax("Invalid simple type in option".to_string())),
            },
            _ => Err(Error::Syntax("Unsupported type in option".to_string())),
        }
    }
}

// String deserializer for backward compatibility in newtype structs
struct StringDeserializer {
    value: String,
}

impl<'de> serde::Deserializer<'de> for StringDeserializer {
    type Error = crate::Error;

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }

    fn deserialize_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_string(self.value)
    }
}

// Enum access for unit variants (encoded as strings)
struct UnitVariantAccess {
    variant: String,
}

impl<'de> serde::de::EnumAccess<'de> for UnitVariantAccess {
    type Error = crate::Error;
    type Variant = UnitOnly;

    fn variant_seed<V: serde::de::DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant)> {
        // Deserialize the variant name as a string
        let bytes = crate::to_vec(&self.variant)?;
        let mut decoder = Decoder::new(&bytes[..]);
        let value = seed.deserialize(&mut decoder)?;
        Ok((value, UnitOnly))
    }
}

struct UnitOnly;

impl<'de> serde::de::VariantAccess<'de> for UnitOnly {
    type Error = crate::Error;

    fn unit_variant(self) -> Result<()> {
        Ok(())
    }

    fn newtype_variant_seed<T: serde::de::DeserializeSeed<'de>>(
        self,
        _seed: T,
    ) -> Result<T::Value> {
        Err(Error::Syntax("Expected unit variant".to_string()))
    }

    fn tuple_variant<V: serde::de::Visitor<'de>>(
        self,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value> {
        Err(Error::Syntax("Expected unit variant".to_string()))
    }

    fn struct_variant<V: serde::de::Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value> {
        Err(Error::Syntax("Expected unit variant".to_string()))
    }
}

// Enum access for variants with data (encoded as {"variant": data})
struct VariantAccess<'a, R: Read> {
    de: &'a mut Decoder<R>,
}

impl<'de, 'a, R: Read> serde::de::EnumAccess<'de> for VariantAccess<'a, R> {
    type Error = crate::Error;
    type Variant = Self;

    fn variant_seed<V: serde::de::DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant)> {
        // Read the key (variant name)
        let value = seed.deserialize(&mut *self.de)?;
        Ok((value, self))
    }
}

impl<'de, 'a, R: Read> serde::de::VariantAccess<'de> for VariantAccess<'a, R> {
    type Error = crate::Error;

    fn unit_variant(self) -> Result<()> {
        Err(Error::Syntax("Expected variant with data".to_string()))
    }

    fn newtype_variant_seed<T: serde::de::DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value> {
        seed.deserialize(&mut *self.de)
    }

    fn tuple_variant<V: serde::de::Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value> {
        serde::de::Deserializer::deserialize_any(&mut *self.de, visitor)
    }

    fn struct_variant<V: serde::de::Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        serde::de::Deserializer::deserialize_any(&mut *self.de, visitor)
    }
}

struct SeqAccess<'a, R: Read> {
    de: &'a mut Decoder<R>,
    remaining: Option<usize>, // None for indefinite-length
}

impl<'a, R: Read> Drop for SeqAccess<'a, R> {
    fn drop(&mut self) {
        self.de.recursion_depth = self.de.recursion_depth.saturating_sub(1);
    }
}

impl<'de, 'a, R: Read> serde::de::SeqAccess<'de> for SeqAccess<'a, R> {
    type Error = crate::Error;

    fn next_element_seed<T: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>> {
        match self.remaining {
            Some(0) => Ok(None),
            Some(ref mut n) => {
                *n -= 1;
                seed.deserialize(&mut *self.de).map(Some)
            }
            None => {
                // Indefinite-length: check for break marker
                if self.de.is_break()? {
                    self.de.read_break()?;
                    Ok(None)
                } else {
                    seed.deserialize(&mut *self.de).map(Some)
                }
            }
        }
    }
}

struct MapAccess<'a, R: Read> {
    de: &'a mut Decoder<R>,
    remaining: Option<usize>, // None for indefinite-length
}

impl<'a, R: Read> Drop for MapAccess<'a, R> {
    fn drop(&mut self) {
        self.de.recursion_depth = self.de.recursion_depth.saturating_sub(1);
    }
}

impl<'de, 'a, R: Read> serde::de::MapAccess<'de> for MapAccess<'a, R> {
    type Error = crate::Error;

    fn next_key_seed<K: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>> {
        match self.remaining {
            Some(0) => Ok(None),
            Some(ref mut n) => {
                *n -= 1;
                seed.deserialize(&mut *self.de).map(Some)
            }
            None => {
                // Indefinite-length: check for break marker
                if self.de.is_break()? {
                    self.de.read_break()?;
                    Ok(None)
                } else {
                    seed.deserialize(&mut *self.de).map(Some)
                }
            }
        }
    }

    fn next_value_seed<V: serde::de::DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        seed.deserialize(&mut *self.de)
    }
}

/// Deserializes a value from CBOR bytes
///
/// Uses Cursor for optimized slice reading performance
pub fn from_slice<'de, T: Deserialize<'de>>(slice: &[u8]) -> Result<T> {
    if slice.is_empty() {
        return Err(Error::Syntax("empty input".to_string()));
    }

    // Use default limit to prevent OOM attacks from malicious CBOR
    // Advanced users can bypass this limit by using Decoder::new() directly
    let mut decoder = Decoder::new(Cursor::new(slice)).with_max_allocation(DEFAULT_MAX_ALLOCATION);
    let value = decoder.decode()?;

    // Check if all bytes were consumed
    let remaining = slice.len() as u64 - decoder.reader.position();
    if remaining > 0 {
        return Err(Error::Syntax(format!(
            "unexpected trailing data: {} bytes remaining",
            remaining
        )));
    }

    Ok(value)
}

/// Deserializes a value from a CBOR reader
///
/// Wraps the reader in a BufReader for optimal performance with small reads.
/// If the reader is already buffered, consider using Decoder::new() directly.
pub fn from_reader<R: Read, T: for<'de> Deserialize<'de>>(reader: R) -> Result<T> {
    // Use default limit to prevent OOM attacks from malicious CBOR
    // Advanced users can bypass this limit by using Decoder::new() directly
    let mut decoder =
        Decoder::new(BufReader::new(reader)).with_max_allocation(DEFAULT_MAX_ALLOCATION);
    decoder.decode()
}

/// Deserializes a value from a CBOR reader with a maximum allocation limit
///
/// This is useful for untrusted input to prevent DoS attacks via extremely
/// large CBOR values. Even without this limit, try_reserve provides system-level
/// protection, but this adds an application-level safety check.
pub fn from_reader_with_limit<R: Read, T: for<'de> Deserialize<'de>>(
    reader: R,
    max_bytes: usize,
) -> Result<T> {
    let mut decoder = Decoder::new(BufReader::new(reader)).with_max_allocation(max_bytes);
    decoder.decode()
}

/// Deserializes a value from CBOR bytes with a maximum allocation limit
///
/// This is useful for untrusted input to prevent DoS attacks via extremely
/// large CBOR values. Even without this limit, try_reserve provides system-level
/// protection, but this adds an application-level safety check.
pub fn from_slice_with_limit<'de, T: Deserialize<'de>>(
    slice: &[u8],
    max_bytes: usize,
) -> Result<T> {
    if slice.is_empty() {
        return Err(Error::Syntax("empty input".to_string()));
    }

    // Wrap in Cursor for better performance with small reads
    let mut decoder = Decoder::new(Cursor::new(slice)).with_max_allocation(max_bytes);
    let value = decoder.decode()?;

    // Check if all bytes were consumed
    let remaining = slice.len() as u64 - decoder.reader.position();
    if remaining > 0 {
        return Err(Error::Syntax(format!(
            "unexpected trailing data: {} bytes remaining",
            remaining
        )));
    }

    Ok(value)
}
