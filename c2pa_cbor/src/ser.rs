use std::io::Write;

use serde::Serialize;

use crate::{Encoder, Error, encoder::SerializeVec};

/// Serialize to Vec (may use indefinite-length encoding for iterators without known length)
/// For deterministic/canonical encoding required by C2PA, use to_vec_packed instead.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    // Note: Currently same as to_vec_packed since Rust standard collections
    // (Vec, HashMap, etc.) always know their length. Could be extended in
    // future to support indefinite-length for streaming iterators.
    crate::to_vec(value)
}

/// Serialize to Vec with packed/canonical encoding (definite-length only)
/// This ensures deterministic output required for digital signatures.
pub fn to_vec_packed<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    crate::to_vec(value)
}

/// Write to writer (may use indefinite-length encoding)
pub fn to_writer<W: Write, T: Serialize>(writer: W, value: &T) -> Result<(), Error> {
    crate::to_writer(writer, value)
}

/// A serializer for CBOR encoding
pub struct Serializer<W: Write> {
    encoder: Encoder<W>,
}

impl<W: Write> Serializer<W> {
    /// Create a new CBOR serializer
    pub fn new(writer: W) -> Self {
        Serializer {
            encoder: Encoder::new(writer),
        }
    }

    /// Create a packed/canonical serializer (same as new for now)
    pub fn packed_format(self) -> Self {
        // For now, all encoding is packed/canonical (definite-length)
        // This method exists for API compatibility with serde_cbor
        self
    }

    /// Consume the serializer and return the writer
    pub fn into_inner(self) -> W {
        self.encoder.into_inner()
    }
}

// Implement Serializer trait directly on &mut Serializer
// This allows serde_transcode and other tools to work correctly
impl<'a, W: Write> serde::Serializer for &'a mut Serializer<W> {
    type Error = Error;
    type Ok = ();
    type SerializeMap = SerializeVec<'a, W>;
    type SerializeSeq = SerializeVec<'a, W>;
    type SerializeStruct = SerializeVec<'a, W>;
    type SerializeStructVariant = &'a mut Encoder<W>;
    type SerializeTuple = SerializeVec<'a, W>;
    type SerializeTupleStruct = SerializeVec<'a, W>;
    type SerializeTupleVariant = &'a mut Encoder<W>;

    fn serialize_bool(self, v: bool) -> Result<(), Error> {
        (&mut self.encoder).serialize_bool(v)
    }

    fn serialize_i8(self, v: i8) -> Result<(), Error> {
        (&mut self.encoder).serialize_i8(v)
    }

    fn serialize_i16(self, v: i16) -> Result<(), Error> {
        (&mut self.encoder).serialize_i16(v)
    }

    fn serialize_i32(self, v: i32) -> Result<(), Error> {
        (&mut self.encoder).serialize_i32(v)
    }

    fn serialize_i64(self, v: i64) -> Result<(), Error> {
        (&mut self.encoder).serialize_i64(v)
    }

    fn serialize_u8(self, v: u8) -> Result<(), Error> {
        (&mut self.encoder).serialize_u8(v)
    }

    fn serialize_u16(self, v: u16) -> Result<(), Error> {
        (&mut self.encoder).serialize_u16(v)
    }

    fn serialize_u32(self, v: u32) -> Result<(), Error> {
        (&mut self.encoder).serialize_u32(v)
    }

    fn serialize_u64(self, v: u64) -> Result<(), Error> {
        (&mut self.encoder).serialize_u64(v)
    }

    fn serialize_f32(self, v: f32) -> Result<(), Error> {
        (&mut self.encoder).serialize_f32(v)
    }

    fn serialize_f64(self, v: f64) -> Result<(), Error> {
        (&mut self.encoder).serialize_f64(v)
    }

    fn serialize_char(self, v: char) -> Result<(), Error> {
        (&mut self.encoder).serialize_char(v)
    }

    fn serialize_str(self, v: &str) -> Result<(), Error> {
        (&mut self.encoder).serialize_str(v)
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<(), Error> {
        (&mut self.encoder).serialize_bytes(v)
    }

    fn serialize_none(self) -> Result<(), Error> {
        (&mut self.encoder).serialize_none()
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), Error> {
        (&mut self.encoder).serialize_some(value)
    }

    fn serialize_unit(self) -> Result<(), Error> {
        (&mut self.encoder).serialize_unit()
    }

    fn serialize_unit_struct(self, name: &'static str) -> Result<(), Error> {
        (&mut self.encoder).serialize_unit_struct(name)
    }

    fn serialize_unit_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
    ) -> Result<(), Error> {
        (&mut self.encoder).serialize_unit_variant(name, variant_index, variant)
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        (&mut self.encoder).serialize_newtype_struct(name, value)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        (&mut self.encoder).serialize_newtype_variant(name, variant_index, variant, value)
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        (&mut self.encoder).serialize_seq(len)
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Error> {
        (&mut self.encoder).serialize_tuple(len)
    }

    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        (&mut self.encoder).serialize_tuple_struct(name, len)
    }

    fn serialize_tuple_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        (&mut self.encoder).serialize_tuple_variant(name, variant_index, variant, len)
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        (&mut self.encoder).serialize_map(len)
    }

    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        (&mut self.encoder).serialize_struct(name, len)
    }

    fn serialize_struct_variant(
        self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        (&mut self.encoder).serialize_struct_variant(name, variant_index, variant, len)
    }
}
