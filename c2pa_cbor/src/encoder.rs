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

use std::io::Write;

use serde::Serialize;

use crate::{Error, Result, constants::*};

// Encoder
pub struct Encoder<W: Write> {
    writer: W,
}

impl<W: Write> Encoder<W> {
    pub fn new(writer: W) -> Self {
        Encoder { writer }
    }

    /// Consume the encoder and return the inner writer
    pub fn into_inner(self) -> W {
        self.writer
    }

    fn write_type_value(&mut self, major: u8, value: u64) -> Result<()> {
        if value < 24 {
            self.writer.write_all(&[(major << 5) | value as u8])?;
        } else if value < 256 {
            self.writer.write_all(&[(major << 5) | 24, value as u8])?;
        } else if value < 65536 {
            self.writer.write_all(&[(major << 5) | 25])?;
            self.writer.write_all(&(value as u16).to_be_bytes())?;
        } else if value < 4294967296 {
            self.writer.write_all(&[(major << 5) | 26])?;
            self.writer.write_all(&(value as u32).to_be_bytes())?;
        } else {
            self.writer.write_all(&[(major << 5) | 27])?;
            self.writer.write_all(&value.to_be_bytes())?;
        }
        Ok(())
    }

    pub fn write_tag(&mut self, tag: u64) -> Result<()> {
        self.write_type_value(MAJOR_TAG, tag)
    }

    /// Start an indefinite-length array
    pub fn write_array_indefinite(&mut self) -> Result<()> {
        self.writer.write_all(&[(MAJOR_ARRAY << 5) | INDEFINITE])?;
        Ok(())
    }

    /// Start an indefinite-length map
    pub fn write_map_indefinite(&mut self) -> Result<()> {
        self.writer.write_all(&[(MAJOR_MAP << 5) | INDEFINITE])?;
        Ok(())
    }

    /// Write a break marker to end an indefinite-length collection
    pub fn write_break(&mut self) -> Result<()> {
        self.writer.write_all(&[BREAK])?;
        Ok(())
    }

    pub fn encode<T: Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut *self)
    }
}

/// Wrapper for serializing sequences/maps with optional buffering
///
/// When serde knows the collection length (the common case), this writes directly
/// to the encoder without buffering. When the length is unknown (e.g., due to
/// `#[serde(flatten)]` or custom iterators), it buffers entries in memory and
/// writes them as definite-length once the count is known.
///
/// This ensures compatibility with `serde_transcode` and maintains C2PA's
/// requirement for definite-length encoding while avoiding the need for
/// indefinite-length CBOR support.
pub enum SerializeVec<'a, W: Write> {
    /// Direct mode: length known, writes immediately (zero overhead)
    Direct { encoder: &'a mut Encoder<W> },
    /// Array buffering mode: length unknown, collects elements
    Array {
        encoder: &'a mut Encoder<W>,
        buffer: Vec<Vec<u8>>,
    },
    /// Map buffering mode: length unknown, collects key-value pairs
    Map {
        encoder: &'a mut Encoder<W>,
        buffer: Vec<(Vec<u8>, Vec<u8>)>,
        pending_key: Option<Vec<u8>>,
    },
}

impl<'a, W: Write> serde::Serializer for &'a mut Encoder<W> {
    type Error = crate::Error;
    type Ok = ();
    type SerializeMap = SerializeVec<'a, W>;
    type SerializeSeq = SerializeVec<'a, W>;
    type SerializeStruct = SerializeVec<'a, W>;
    type SerializeStructVariant = &'a mut Encoder<W>;
    type SerializeTuple = SerializeVec<'a, W>;
    type SerializeTupleStruct = SerializeVec<'a, W>;
    type SerializeTupleVariant = &'a mut Encoder<W>;

    fn serialize_bool(self, v: bool) -> Result<()> {
        let val = if v { TRUE } else { FALSE };
        self.writer.write_all(&[(MAJOR_SIMPLE << 5) | val])?;
        Ok(())
    }

    fn serialize_i8(self, v: i8) -> Result<()> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i16(self, v: i16) -> Result<()> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i32(self, v: i32) -> Result<()> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i64(self, v: i64) -> Result<()> {
        if v >= 0 {
            self.write_type_value(MAJOR_UNSIGNED, v as u64)
        } else {
            self.write_type_value(MAJOR_NEGATIVE, (-1 - v) as u64)
        }
    }

    fn serialize_u8(self, v: u8) -> Result<()> {
        self.serialize_u64(v as u64)
    }

    fn serialize_u16(self, v: u16) -> Result<()> {
        self.serialize_u64(v as u64)
    }

    fn serialize_u32(self, v: u32) -> Result<()> {
        self.serialize_u64(v as u64)
    }

    fn serialize_u64(self, v: u64) -> Result<()> {
        self.write_type_value(MAJOR_UNSIGNED, v)
    }

    fn serialize_f32(self, v: f32) -> Result<()> {
        // Encode as CBOR float32 (major type 7, additional info 26)
        self.writer.write_all(&[(MAJOR_SIMPLE << 5) | FLOAT32])?;
        self.writer.write_all(&v.to_be_bytes())?;
        Ok(())
    }

    fn serialize_f64(self, v: f64) -> Result<()> {
        // Encode as CBOR float64 (major type 7, additional info 27)
        self.writer.write_all(&[(MAJOR_SIMPLE << 5) | FLOAT64])?;
        self.writer.write_all(&v.to_be_bytes())?;
        Ok(())
    }

    fn serialize_char(self, v: char) -> Result<()> {
        self.serialize_str(&v.to_string())
    }

    fn serialize_str(self, v: &str) -> Result<()> {
        self.write_type_value(MAJOR_TEXT, v.len() as u64)?;
        self.writer.write_all(v.as_bytes())?;
        Ok(())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        self.write_type_value(MAJOR_BYTES, v.len() as u64)?;
        self.writer.write_all(v)?;
        Ok(())
    }

    fn serialize_none(self) -> Result<()> {
        self.writer.write_all(&[(MAJOR_SIMPLE << 5) | NULL])?;
        Ok(())
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<()> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<()> {
        self.serialize_none()
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        self.serialize_unit()
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<()> {
        self.serialize_str(variant)
    }

    fn serialize_newtype_struct<T>(self, _name: &'static str, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        // Serialize as a 1-element array to maintain tuple struct semantics
        // This allows tuple structs like `struct Wrapper(Inner)` to round-trip correctly
        // Users can override with #[serde(transparent)] if they want the inner value directly
        self.write_type_value(MAJOR_ARRAY, 1)?;
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<()> {
        self.write_type_value(MAJOR_MAP, 1)?;
        variant.serialize(&mut *self)?;
        value.serialize(self)?;
        Ok(())
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        match len {
            Some(len) => {
                // Fast path: length known, write header immediately (no buffering)
                self.write_type_value(MAJOR_ARRAY, len as u64)?;
                Ok(SerializeVec::Direct { encoder: self })
            }
            None => {
                // Slow path: length unknown (rare), buffer elements until end()
                // Only happens with custom iterators that don't implement ExactSizeIterator
                Ok(SerializeVec::Array {
                    encoder: self,
                    buffer: Vec::new(),
                })
            }
        }
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        self.write_type_value(MAJOR_MAP, 1)?;
        variant.serialize(&mut *self)?;
        self.write_type_value(MAJOR_ARRAY, len as u64)?;
        Ok(self)
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap> {
        match len {
            Some(len) => {
                // Fast path: length known, write header immediately (no buffering)
                self.write_type_value(MAJOR_MAP, len as u64)?;
                Ok(SerializeVec::Direct { encoder: self })
            }
            None => {
                // Slow path: length unknown, buffer key-value pairs until end()
                // Happens with #[serde(flatten)] or custom map-like types in serde_transcode
                Ok(SerializeVec::Map {
                    encoder: self,
                    buffer: Vec::new(),
                    pending_key: None,
                })
            }
        }
    }

    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
        // Note: len is the declared field count, but skip_serializing_if may skip some fields
        // To handle this properly, we would need to buffer. For now, we write the declared count
        // and rely on the Serialize impl to not use skip_serializing_if, or to use #[serde(transparent)]
        // The proper fix is for users to not mix skip_serializing_if with CBOR serialization,
        // or to use indefinite-length encoding via manual encoding
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        self.write_type_value(MAJOR_MAP, 1)?;
        variant.serialize(&mut *self)?;
        self.write_type_value(MAJOR_MAP, len as u64)?;
        Ok(self)
    }
}

impl<W: Write> serde::ser::SerializeSeq for &mut Encoder<W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> serde::ser::SerializeTuple for &mut Encoder<W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> serde::ser::SerializeTupleStruct for &mut Encoder<W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> serde::ser::SerializeTupleVariant for &mut Encoder<W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> serde::ser::SerializeMap for &mut Encoder<W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<()> {
        key.serialize(&mut **self)
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> serde::ser::SerializeStruct for &mut Encoder<W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        key.serialize(&mut **self)?;
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> serde::ser::SerializeStructVariant for &mut Encoder<W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        key.serialize(&mut **self)?;
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<()> {
        Ok(())
    }
}

// Implementations for SerializeVec (handles buffering for unknown-length collections)

impl<'a, W: Write> SerializeVec<'a, W> {
    /// Serialize a value to a buffer for later writing
    fn serialize_to_buffer<T>(value: &T) -> Result<Vec<u8>>
    where
        T: ?Sized + Serialize,
    {
        let mut buf = Vec::new();
        let mut encoder = Encoder::new(&mut buf);
        value.serialize(&mut encoder)?;
        Ok(buf)
    }

    /// Write buffered bytes to the encoder's writer
    fn write_buffered(encoder: &mut Encoder<W>, bytes: &[u8]) -> Result<()> {
        encoder.writer.write_all(bytes)?;
        Ok(())
    }
}

impl<'a, W: Write> serde::ser::SerializeSeq for SerializeVec<'a, W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_element<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        match self {
            SerializeVec::Direct { encoder } => value.serialize(&mut **encoder),
            SerializeVec::Array { buffer, .. } => {
                buffer.push(Self::serialize_to_buffer(value)?);
                Ok(())
            }
            SerializeVec::Map { .. } => Err(Error::Message(
                "serialize_element called on map serializer".to_string(),
            )),
        }
    }

    fn end(self) -> Result<()> {
        match self {
            SerializeVec::Direct { .. } => Ok(()),
            SerializeVec::Array { encoder, buffer } => {
                // Write definite-length array header now that we know the count
                encoder.write_type_value(MAJOR_ARRAY, buffer.len() as u64)?;
                // Write all buffered elements
                for element_bytes in buffer {
                    Self::write_buffered(encoder, &element_bytes)?;
                }
                Ok(())
            }
            SerializeVec::Map { .. } => {
                Err(Error::Message("end called on map serializer".to_string()))
            }
        }
    }
}

impl<'a, W: Write> serde::ser::SerializeTuple for SerializeVec<'a, W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        serde::ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<()> {
        serde::ser::SerializeSeq::end(self)
    }
}

impl<'a, W: Write> serde::ser::SerializeTupleStruct for SerializeVec<'a, W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        serde::ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<()> {
        serde::ser::SerializeSeq::end(self)
    }
}

impl<'a, W: Write> serde::ser::SerializeMap for SerializeVec<'a, W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_key<T>(&mut self, key: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        match self {
            SerializeVec::Direct { encoder } => key.serialize(&mut **encoder),
            SerializeVec::Map { pending_key, .. } => {
                *pending_key = Some(Self::serialize_to_buffer(key)?);
                Ok(())
            }
            SerializeVec::Array { .. } => Err(Error::Message(
                "serialize_key called on array serializer".to_string(),
            )),
        }
    }

    fn serialize_value<T>(&mut self, value: &T) -> Result<()>
    where
        T: ?Sized + Serialize,
    {
        match self {
            SerializeVec::Direct { encoder } => value.serialize(&mut **encoder),
            SerializeVec::Map {
                buffer,
                pending_key,
                ..
            } => {
                let value_bytes = Self::serialize_to_buffer(value)?;
                if let Some(key_bytes) = pending_key.take() {
                    buffer.push((key_bytes, value_bytes));
                    Ok(())
                } else {
                    Err(Error::Message(
                        "serialize_value called without serialize_key".to_string(),
                    ))
                }
            }
            SerializeVec::Array { .. } => Err(Error::Message(
                "serialize_value called on array serializer".to_string(),
            )),
        }
    }

    fn end(self) -> Result<()> {
        match self {
            SerializeVec::Direct { .. } => Ok(()),
            SerializeVec::Map {
                encoder,
                buffer,
                pending_key,
            } => {
                if pending_key.is_some() {
                    return Err(Error::Message(
                        "serialize_key called without serialize_value".to_string(),
                    ));
                }
                // Write definite-length map header now that we know the count
                encoder.write_type_value(MAJOR_MAP, buffer.len() as u64)?;
                // Write all buffered key-value pairs
                for (key_bytes, value_bytes) in buffer {
                    Self::write_buffered(encoder, &key_bytes)?;
                    Self::write_buffered(encoder, &value_bytes)?;
                }
                Ok(())
            }
            SerializeVec::Array { .. } => {
                Err(Error::Message("end called on array serializer".to_string()))
            }
        }
    }
}

impl<'a, W: Write> serde::ser::SerializeStruct for SerializeVec<'a, W> {
    type Error = crate::Error;
    type Ok = ();

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        serde::ser::SerializeMap::serialize_entry(self, key, value)
    }

    fn end(self) -> Result<()> {
        serde::ser::SerializeMap::end(self)
    }
}

// Convenience functions
/// Serializes a value to a CBOR byte vector
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    // Try direct serialization first
    let mut buf = Vec::new();
    let mut encoder = Encoder::new(&mut buf);
    match encoder.encode(value) {
        Ok(()) => Ok(buf),
        Err(Error::Message(ref msg)) if msg.contains("indefinite-length") => {
            // Fall back to value-based serialization for types that need indefinite length
            // This handles #[serde(flatten)] and other cases where size is unknown
            let value = crate::value::to_value(value)?;
            buf.clear();
            let mut encoder = Encoder::new(&mut buf);
            encoder.encode(&value)?;
            Ok(buf)
        }
        Err(e) => Err(e),
    }
}

/// Serializes a value to a CBOR writer
pub fn to_writer<W: Write, T: Serialize>(writer: W, value: &T) -> Result<()> {
    let mut encoder = Encoder::new(writer);
    encoder.encode(value)?;
    Ok(())
}
