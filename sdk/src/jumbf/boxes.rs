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

//! This is a library for generating ISO BMFF/JUMBF boxes
//!
//! It is based on the work of Takeru Ohta <phjgt308@gmail.com>
//! and [mse_fmp4](https://github.com/sile/mse_fmp4) and enhanced
//! by Leonard Rosenthol <lrosenth@adobe.com>
//
//!  # References
//!
//!  - [ISO BMFF Byte Stream Format](https://w3c.github.io/media-source/isobmff-byte-stream-format.html)
//!  - [JPEG universal metadata box format](https://www.iso.org/standard/73604.html)

use std::{
    any::Any,
    convert::TryInto,
    ffi::CString,
    fmt,
    io::{Read, Result as IoResult, Seek, SeekFrom, Write},
};

use hex::FromHex;
use log::debug;
use thiserror::Error;

use crate::jumbf::{boxio, labels};

/// `JumbfParseError` enumerates errors detected while parsing JUMBF data structures.
#[derive(Debug, Error)]
pub enum JumbfParseError {
    // TODO before merging PR: Add doc comments for these.
    // Is there more to say than the description string?
    #[error("unexpected end of file")]
    UnexpectedEof,

    #[error("invalid box start")]
    InvalidBoxStart,

    #[error("invalid box header")]
    InvalidBoxHeader,

    #[error("invalid box range")]
    InvalidBoxRange,

    #[error("invalid JUMBF header")]
    InvalidJumbfHeader,

    #[error("invalid JUMB box")]
    InvalidJumbBox,

    #[error("invalid UUID label")]
    InvalidUuidValue,

    #[error("invalid JSON box")]
    InvalidJsonBox,

    #[error("invalid CBOR box")]
    InvalidCborBox,

    #[error("invalid JP2C box")]
    InvalidJp2cBox,

    #[error("invalid UUID box")]
    InvalidUuidBox,

    #[error("invalid embedded file box")]
    InvalidEmbeddedFileBox,

    #[error("invalid box of unknown type")]
    InvalidUnknownBox,

    #[error("expected JUMD")]
    ExpectedJumdError,

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error("assertion salt must be 16 bytes or greater")]
    InvalidSalt,

    #[error("invalid JUMD box")]
    InvalidDescriptionBox,
}

/// A specialized `JumbfParseResult` type for JUMBF parsing operations.
pub type JumbfParseResult<T> = std::result::Result<T, JumbfParseError>;

//-----------------
// ANCHOR ISO BMFF
//-----------------
macro_rules! write_u8 {
    ($w:expr, $n:expr) => {{
        use byteorder::WriteBytesExt;
        $w.write_u8($n)?
    }};
}
// macro_rules! write_u16 {
//     ($w:expr, $n:expr) => {{
//         use byteorder::{BigEndian, WriteBytesExt};
//         $w.write_u16::<BigEndian>($n)?;
//     }};
// }
// macro_rules! write_i16 {
//     ($w:expr, $n:expr) => {{
//         use byteorder::{BigEndian, WriteBytesExt};
//         $w.write_i16::<BigEndian>($n)?;
//     }};
// }
// macro_rules! write_u24 {
//     ($w:expr, $n:expr) => {{
//         use byteorder::{BigEndian, WriteBytesExt};
//         $w.write_uint::<BigEndian>($n as u64, 3)?;
//     }};
// }
macro_rules! write_u32 {
    ($w:expr, $n:expr) => {{
        use byteorder::{BigEndian, WriteBytesExt};
        $w.write_u32::<BigEndian>($n)?;
    }};
}
// macro_rules! write_i32 {
//     ($w:expr, $n:expr) => {{
//         use byteorder::{BigEndian, WriteBytesExt};
//         $w.write_i32::<BigEndian>($n)?;
//     }};
// }
// macro_rules! write_u64 {
//     ($w:expr, $n:expr) => {{
//         use byteorder::{BigEndian, WriteBytesExt};
//         $w.write_u64::<BigEndian>($n)?;
//     }};
// }
macro_rules! write_all {
    ($w:expr, $n:expr) => {
        $w.write_all($n)?;
    };
}
// macro_rules! write_zeroes {
//     ($w:expr, $n:expr) => {
//         $w.write_all(&[0; $n][..])?;
//     };
// }
// macro_rules! write_box {
//     ($w:expr, $b:expr) => {
//         $b.write_box(&mut $w)?;
//     };
// }
// macro_rules! write_boxes {
//     ($w:expr, $bs:expr) => {
//         for b in $bs {
//             b.write_box(&mut $w)?;
//         }
//     };
// }
macro_rules! box_size {
    ($b:expr) => {
        $b.box_size()?
    };
}
// macro_rules! optional_box_size {
//     ($b:expr) => {
//         if let Some(ref b) = $b.as_ref() {
//             b.box_size()?
//         } else {
//             0
//         }
//     };
// }
macro_rules! boxes_size {
    ($b:expr) => {{
        let mut size = 0;
        for b in $b.iter() {
            size += box_size!(b);
        }
        size
    }};
}

/// ISO BMFF box.
pub trait BMFFBox: Any {
    // "Any is the closest thing to reflection there is in Rust"
    /// Box type code.
    fn box_type(&self) -> &'static [u8; 4];

    /// Box UUID (used by JUMBF)
    fn box_uuid(&self) -> &'static str;

    /// Box size.
    fn box_size(&self) -> IoResult<u32> {
        // if it a real box...
        let mut size = if self.box_type() != b"    " { 8 } else { 0 };
        size += self.box_payload_size()?;

        Ok(size)
    }

    /// Payload size of the box.
    fn box_payload_size(&self) -> IoResult<u32>;

    /// Writes the box to the given writer.
    fn write_box(&self, writer: &mut dyn Write) -> IoResult<()> {
        if self.box_type() != b"    " {
            // it's a real box...
            write_u32!(writer, self.box_size()?);
            write_all!(writer, self.box_type());
        }

        self.write_box_payload(writer)?;
        Ok(())
    }

    /// Writes the payload of the box to the given writer.
    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()>;

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any;
}

impl fmt::Debug for dyn BMFFBox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BMFFBox")
            .field("type", self.box_type())
            .field("size", &self.box_size())
            .finish()
    }
}

//---------------
// SECTION JUMBF
//---------------
pub const JUMB_FOURCC: &str = "6A756D62";
pub const JUMD_FOURCC: &str = "6A756D64";

// ANCHOR JUMBF superbox
/// JUMBF superbox (ISO 19566-5:2019, Annex A)
#[derive(Debug)]
pub struct JUMBFSuperBox {
    desc_box: JUMBFDescriptionBox,
    data_boxes: Vec<Box<dyn BMFFBox>>,
}

impl JUMBFSuperBox {
    pub fn new(box_label: &str, a_type: Option<&str>) -> Self {
        JUMBFSuperBox {
            desc_box: JUMBFDescriptionBox::new(box_label, a_type),
            data_boxes: vec![],
        }
    }

    pub fn from(a_box: JUMBFDescriptionBox) -> Self {
        JUMBFSuperBox {
            desc_box: a_box,
            data_boxes: vec![],
        }
    }

    // add a data box *WITHOUT* taking ownership of the box
    pub fn add_data_box(&mut self, b: Box<dyn BMFFBox>) {
        self.data_boxes.push(b)
    }

    // getters
    pub fn desc_box(&self) -> &JUMBFDescriptionBox {
        &self.desc_box
    }

    pub fn data_box_count(&self) -> usize {
        self.data_boxes.len()
    }

    pub fn data_box(&self, index: usize) -> &dyn BMFFBox {
        self.data_boxes[index].as_ref()
    }

    pub fn data_box_as_superbox(&self, index: usize) -> Option<&JUMBFSuperBox> {
        let da_box = &self.data_boxes[index];
        da_box.as_ref().as_any().downcast_ref::<JUMBFSuperBox>()
    }

    pub fn data_box_as_json_box(&self, index: usize) -> Option<&JUMBFJSONContentBox> {
        let da_box = &self.data_boxes[index];
        da_box
            .as_ref()
            .as_any()
            .downcast_ref::<JUMBFJSONContentBox>()
    }

    pub fn data_box_as_cbor_box(&self, index: usize) -> Option<&JUMBFCBORContentBox> {
        let da_box = &self.data_boxes[index];
        da_box
            .as_ref()
            .as_any()
            .downcast_ref::<JUMBFCBORContentBox>()
    }

    pub fn data_box_as_jp2c_box(&self, index: usize) -> Option<&JUMBFCodestreamContentBox> {
        let da_box = &self.data_boxes[index];
        da_box
            .as_ref()
            .as_any()
            .downcast_ref::<JUMBFCodestreamContentBox>()
    }

    pub fn data_box_as_uuid_box(&self, index: usize) -> Option<&JUMBFUUIDContentBox> {
        let da_box = &self.data_boxes[index];
        da_box
            .as_ref()
            .as_any()
            .downcast_ref::<JUMBFUUIDContentBox>()
    }

    pub fn data_box_as_embedded_file_content_box(
        &self,
        index: usize,
    ) -> Option<&JUMBFEmbeddedFileContentBox> {
        let da_box = &self.data_boxes[index];
        da_box
            .as_ref()
            .as_any()
            .downcast_ref::<JUMBFEmbeddedFileContentBox>()
    }

    pub fn data_box_as_embedded_media_type_box(
        &self,
        index: usize,
    ) -> Option<&JUMBFEmbeddedFileDescriptionBox> {
        let da_box = &self.data_boxes[index];
        da_box
            .as_ref()
            .as_any()
            .downcast_ref::<JUMBFEmbeddedFileDescriptionBox>()
    }
}

impl BMFFBox for JUMBFSuperBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"jumb"
    }

    fn box_uuid(&self) -> &'static str {
        JUMB_FOURCC
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let mut size = 0;
        size += box_size!(self.desc_box);
        if !self.data_boxes.is_empty() {
            size += boxes_size!(self.data_boxes)
        }
        Ok(size)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        let res = self.desc_box.write_box(writer);
        for b in &self.data_boxes {
            b.write_box(writer)?;
        }
        res
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ANCHOR JUMBF Description box
/// JUMBF Description box (ISO 19566-5:2019, Annex A)
#[derive(Debug)]
pub struct JUMBFDescriptionBox {
    box_uuid: [u8; 16],                 // a 128-bit UUID for the type
    toggles: u8,                        // bit field for valid values
    label: CString,                     // Null terminated UTF-8 string (OPTIONAL)
    box_id: Option<u32>,                // user assigned value (OPTIONAL)
    signature: Option<[u8; 32]>,        // SHA-256 hash of the payload (OPTIONAL)
    private: Option<CAISaltContentBox>, // private salt content box
}

impl JUMBFDescriptionBox {
    /// Makes a new `JUMBFDescriptionBox` instance.
    pub fn new(box_label: &str, a_type: Option<&str>) -> Self {
        JUMBFDescriptionBox {
            box_uuid: match a_type {
                Some(ref t) => <[u8; 16]>::from_hex(t).unwrap_or([0u8; 16]),
                None => [0u8; 16], // init to all zeros
            },
            toggles: 3, // 0x11 (Requestable + Label Present)
            label: CString::new(box_label).unwrap_or_default(),
            box_id: None,
            signature: None,
            private: None,
        }
    }

    pub fn set_salt(&mut self, salt: Vec<u8>) -> JumbfParseResult<()> {
        if salt.len() < 16 {
            return Err(JumbfParseError::InvalidSalt);
        }

        self.private = Some(CAISaltContentBox::new(salt));
        self.toggles = 19; // 0x10011 (Requestable + Label Present + Private)

        Ok(())
    }

    pub fn get_salt(&self) -> Option<Vec<u8>> {
        self.private.as_ref().map(|saltbox| saltbox.salt.clone())
    }

    /// Makes a new `JUMBFDescriptionBox` instance from read in data
    pub fn from(
        uuid: &[u8; 16],
        togs: u8,
        box_label: Vec<u8>,
        bxid: Option<u32>,
        sig: Option<[u8; 32]>,
        private: Option<CAISaltContentBox>,
    ) -> Self {
        let c_string: CString;
        unsafe {
            c_string = CString::from_vec_unchecked(box_label);
        }
        JUMBFDescriptionBox {
            box_uuid: *uuid,
            toggles: togs, // will always be 0x11 (Requestable + Label Present)
            label: c_string,
            box_id: bxid,
            signature: sig,
            private,
        }
    }

    /// getters
    pub fn uuid(&self) -> String {
        hex::encode(self.box_uuid).to_uppercase()
    }

    pub fn label(&self) -> String {
        self.label.clone().into_string().unwrap_or_default()
    }
}

impl BMFFBox for JUMBFDescriptionBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"jumd"
    }

    fn box_uuid(&self) -> &'static str {
        JUMD_FOURCC
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        write_all!(writer, &self.box_uuid);
        write_u8!(writer, self.toggles);

        if self.label.to_str().unwrap_or_default().chars().count() > 0 {
            write_all!(writer, self.label.as_bytes_with_nul());
        }

        if let Some(x) = self.box_id {
            write_u32!(writer, x);
        }

        if let Some(x) = self.signature {
            write_all!(writer, &x);
        }

        if let Some(salt) = &self.private {
            salt.write_box(writer)?;
        }

        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ANCHOR JUMBF UUIDs
pub const JUMBF_CODESTREAM_UUID: &str = "6579D6FBDBA2446BB2AC1B82FEEB89D1";
pub const JUMBF_JSON_UUID: &str = "6A736F6E00110010800000AA00389B71";
pub const JUMBF_CBOR_UUID: &str = "63626F7200110010800000AA00389B71";
// pub const JUMBF_XML_UUID: &str = "786D6C2000110010800000AA00389B71";
pub const JUMBF_UUID_UUID: &str = "7575696400110010800000AA00389B71";
pub const JUMBF_EMBEDDED_FILE_UUID: &str = "40CB0C32BB8A489DA70B2AD6F47F4369";
// ANCHOR JUMBF Content box
/// JUMBF Content box (ISO 19566-5:2019, Annex B)
#[derive(Debug, Default)]
pub struct JUMBFContentBox;

impl BMFFBox for JUMBFContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"jumd"
    }

    fn box_uuid(&self) -> &'static str {
        "" // base JUMBF boxes don't have any...
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        Ok(0) // it isn't a real box, just a base class
    }

    fn write_box_payload(&self, _writer: &mut dyn Write) -> IoResult<()> {
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ANCHOR JUMB Padding Box
#[derive(Debug, Default)]
pub struct JUMBFPaddingContentBox {
    padding: Vec<u8>, // arbitrary number of zero'd bytes...
}

impl BMFFBox for JUMBFPaddingContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"free"
    }

    fn box_uuid(&self) -> &'static str {
        "" // base JUMBF boxes don't have any...
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = self.padding.len();
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        if !self.padding.is_empty() {
            write_all!(writer, &self.padding);
        }
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JUMBFPaddingContentBox {
    pub fn new_with_vec(padding: Vec<u8>) -> Self {
        JUMBFPaddingContentBox { padding }
    }

    // we do not take a vec to ensure the box contains only zeros
    pub fn new(box_size: usize) -> Self {
        JUMBFPaddingContentBox {
            padding: vec![0; box_size],
        }
    }
}

// ANCHOR JUMBF JSON Content box
/// JUMBF JSON Content box (ISO 19566-5:2019, Annex B.4)
#[derive(Debug, Default)]
pub struct JUMBFJSONContentBox {
    json: Vec<u8>, // arbitrary bunch of bytes...
}

impl BMFFBox for JUMBFJSONContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"json"
    }

    fn box_uuid(&self) -> &'static str {
        JUMBF_JSON_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = self.json.len();
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        if !self.json.is_empty() {
            write_all!(writer, &self.json);
        }
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JUMBFJSONContentBox {
    // the content box takes ownership of the data!
    pub fn new(json_in: Vec<u8>) -> Self {
        JUMBFJSONContentBox { json: json_in }
    }

    // getter
    pub fn json(&self) -> &Vec<u8> {
        &self.json
    }
}

pub struct JUMBFCBORContentBox {
    cbor: Vec<u8>, // arbitrary bunch of bytes...
}

impl BMFFBox for JUMBFCBORContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"cbor"
    }

    fn box_uuid(&self) -> &'static str {
        JUMBF_CBOR_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = self.cbor.len();
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        if !self.cbor.is_empty() {
            write_all!(writer, &self.cbor);
        }
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JUMBFCBORContentBox {
    // the content box takes ownership of the data!
    pub fn new(cbor_in: Vec<u8>) -> Self {
        JUMBFCBORContentBox { cbor: cbor_in }
    }

    // getter
    pub fn cbor(&self) -> &Vec<u8> {
        &self.cbor
    }
}

// ANCHOR JUMBF Codestream Content box
/// JUMBF Codestream Content box (ISO 19566-5:2019, Annex B.2)
#[derive(Debug, Default)]
pub struct JUMBFCodestreamContentBox {
    data: Vec<u8>, // arbitrary bunch of bytes...
}

impl BMFFBox for JUMBFCodestreamContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"jp2c"
    }

    fn box_uuid(&self) -> &'static str {
        JUMBF_CODESTREAM_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = self.data.len();
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        if !self.data.is_empty() {
            write_all!(writer, &self.data);
        }
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JUMBFCodestreamContentBox {
    // the content box takes ownership of the data!
    pub fn new(data_in: Vec<u8>) -> Self {
        JUMBFCodestreamContentBox { data: data_in }
    }

    // getter
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

// ANCHOR JUMBF UUID Content box
/// JUMBF UUID Content box (ISO 19566-5:2019, Annex B.5)
#[derive(Debug, Default)]
pub struct JUMBFUUIDContentBox {
    uuid: [u8; 16], // a 128-bit UUID for the type
    data: Vec<u8>,  // arbitrary bunch of bytes...
}

impl BMFFBox for JUMBFUUIDContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"uuid"
    }

    fn box_uuid(&self) -> &'static str {
        JUMBF_UUID_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = 16 /*UUID*/ + self.data.len();
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        if !self.data.is_empty() {
            write_all!(writer, &self.uuid);
            write_all!(writer, &self.data);
        }
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JUMBFUUIDContentBox {
    // the content box takes ownership of the data!
    pub fn new(uuid_in: &[u8; 16], data_in: Vec<u8>) -> Self {
        let mut u: [u8; 16] = Default::default();
        u.copy_from_slice(uuid_in);

        JUMBFUUIDContentBox {
            uuid: u,
            data: data_in,
        }
    }

    // getters
    pub fn uuid(&self) -> &[u8; 16] {
        &self.uuid
    }

    // getter
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

// !SECTION

//---------------
// SECTION CAI
//---------------
pub const CAI_BLOCK_UUID: &str = "6332706100110010800000AA00389B71"; // c2pa
pub const CAI_STORE_UUID: &str = "63326D6100110010800000AA00389B71"; // c2ma
pub const CAI_UPDATE_MANIFEST_UUID: &str = "6332756D00110010800000AA00389B71"; // c2um
pub const CAI_ASSERTION_STORE_UUID: &str = "6332617300110010800000AA00389B71"; // c2as
pub const CAI_INGREDIENT_STORE_UUID: &str = "6361697300110010800000AA00389B71"; //cais
pub const CAI_JSON_ASSERTION_UUID: &str = "6A736F6E00110010800000AA00389B71"; // json
pub const CAI_CBOR_ASSERTION_UUID: &str = "63626F7200110010800000AA00389B71"; // cbor
pub const CAI_CODESTREAM_ASSERTION_UUID: &str = "6579D6FBDBA2446BB2AC1B82FEEB89D1";
pub const CAI_INGREDIENT_UUID: &str = "6361696E00110010800000AA00389B71"; // cain
pub const CAI_CLAIM_UUID: &str = "6332636C00110010800000AA00389B71"; // c2cl
pub const CAI_SIGNATURE_UUID: &str = "6332637300110010800000AA00389B71"; // c2cs
pub const CAI_EMBEDDED_FILE_UUID: &str = "40CB0C32BB8A489DA70B2AD6F47F4369";
pub const CAI_EMBEDDED_FILE_DESCRIPTION_UUID: &str = "6266646200110010800000AA00389B71"; // bfdb
pub const CAI_EMBEDED_FILE_DATA_UUID: &str = "6269646200110010800000AA00389B71"; // bidb
pub const CAI_VERIFIABLE_CREDENTIALS_STORE_UUID: &str = "6332766300110010800000AA00389B71"; //c2vc
pub const CAI_UUID_ASSERTION_UUID: &str = "7575696400110010800000AA00389B71"; // uuid

// ANCHOR Salt Content Box
/// Salt Content Box
#[derive(Debug)]
pub struct CAISaltContentBox {
    salt: Vec<u8>, // salt data...
}

impl BMFFBox for CAISaltContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"c2sh"
    }

    fn box_uuid(&self) -> &'static str {
        "" // base JUMBF boxes don't have any...
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = self.salt.len();
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        write_all!(writer, &self.salt);
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAISaltContentBox {
    pub fn new(data_in: Vec<u8>) -> Self {
        CAISaltContentBox { salt: data_in }
    }
}
// ANCHOR Signature Content Box
/// Signature Content Box
#[derive(Debug)]
pub struct CAISignatureContentBox {
    uuid: [u8; 16],    // a 128-bit UUID
    sig_data: Vec<u8>, // signature data...
}

impl BMFFBox for CAISignatureContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"uuid"
    }

    fn box_uuid(&self) -> &'static str {
        "" // base JUMBF boxes don't have any...
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        write_all!(writer, &self.uuid);
        write_all!(writer, &self.sig_data);
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAISignatureContentBox {
    pub fn new(data_in: Vec<u8>) -> Self {
        CAISignatureContentBox {
            uuid: <[u8; 16]>::from_hex(CAI_SIGNATURE_UUID).unwrap_or_default(),
            sig_data: data_in,
        }
    }
}

// ANCHOR Signature Box
/// Signature Box
#[derive(Debug)]
pub struct CAISignatureBox {
    sig_box: JUMBFSuperBox,
}

impl BMFFBox for CAISignatureBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_SIGNATURE_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.sig_box.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAISignatureBox {
    pub fn new() -> Self {
        CAISignatureBox {
            sig_box: JUMBFSuperBox::new(labels::SIGNATURE, Some(CAI_SIGNATURE_UUID)),
        }
    }

    // add a signature content box *WITHOUT* taking ownership of the box
    pub fn add_signature(&mut self, b: Box<dyn BMFFBox>) {
        self.sig_box.add_data_box(b)
    }
}

impl Default for CAISignatureBox {
    fn default() -> Self {
        Self::new()
    }
}

// ANCHOR Claim Box
/// Claim Box
#[derive(Debug)]
pub struct CAIClaimBox {
    claim_box: JUMBFSuperBox,
}

impl BMFFBox for CAIClaimBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_CLAIM_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.claim_box.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAIClaimBox {
    pub fn new() -> Self {
        CAIClaimBox {
            claim_box: JUMBFSuperBox::new(labels::CLAIM, Some(CAI_CLAIM_UUID)),
        }
    }

    // add a JUMBFCBORContentBox box, with the claim's CBOR
    // *WITHOUT* taking ownership of the box
    pub fn add_claim(&mut self, b: Box<dyn BMFFBox>) {
        self.claim_box.add_data_box(b)
    }
}

impl Default for CAIClaimBox {
    fn default() -> Self {
        Self::new()
    }
}

// ANCHOR UUID Assertion Box
/// UUID Assertion Box
#[derive(Debug)]
pub struct CAIUUIDAssertionBox {
    assertion_box: JUMBFSuperBox,
}

impl BMFFBox for CAIUUIDAssertionBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_UUID_ASSERTION_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.assertion_box.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAIUUIDAssertionBox {
    pub fn new(box_label: &str) -> Self {
        CAIUUIDAssertionBox {
            assertion_box: JUMBFSuperBox::new(box_label, Some(CAI_UUID_ASSERTION_UUID)),
        }
    }

    // add a JUMBFJSONContentBox box, with the assertion's JSON
    // takes ownership of the JSON
    pub fn add_uuid(&mut self, uuid_str: &str, data: Vec<u8>) -> JumbfParseResult<()> {
        let uuid = hex::decode(uuid_str).map_err(|_e| JumbfParseError::InvalidUuidValue)?;
        if uuid.len() != 16 {
            // the uuid is defined a as 16 bytes
            return Err(JumbfParseError::InvalidUuidValue);
        }

        let mut u: [u8; 16] = Default::default();
        u.copy_from_slice(&uuid);
        let assertion_content = JUMBFUUIDContentBox::new(&u, data);
        self.assertion_box.add_data_box(Box::new(assertion_content));

        Ok(())
    }

    pub fn set_salt(&mut self, salt: Vec<u8>) -> JumbfParseResult<()> {
        self.assertion_box.desc_box.set_salt(salt)
    }

    pub fn super_box(&self) -> &dyn BMFFBox {
        &self.assertion_box
    }
}

// ANCHOR JSON Assertion Box
/// JSON Assertion Box
#[derive(Debug)]
pub struct CAIJSONAssertionBox {
    assertion_box: JUMBFSuperBox,
}

impl BMFFBox for CAIJSONAssertionBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_JSON_ASSERTION_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.assertion_box.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAIJSONAssertionBox {
    pub fn new(box_label: &str) -> Self {
        CAIJSONAssertionBox {
            assertion_box: JUMBFSuperBox::new(box_label, Some(CAI_JSON_ASSERTION_UUID)),
        }
    }

    // add a JUMBFJSONContentBox box, with the assertion's JSON
    // takes ownership of the JSON
    pub fn add_json(&mut self, json_in: Vec<u8>) {
        let assertion_content = JUMBFJSONContentBox::new(json_in);
        self.assertion_box.add_data_box(Box::new(assertion_content));
    }

    pub fn set_salt(&mut self, salt: Vec<u8>) -> JumbfParseResult<()> {
        self.assertion_box.desc_box.set_salt(salt)
    }

    pub fn super_box(&self) -> &dyn BMFFBox {
        &self.assertion_box
    }
}

pub struct CAICBORAssertionBox {
    assertion_box: JUMBFSuperBox,
}

impl BMFFBox for CAICBORAssertionBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_CBOR_ASSERTION_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.assertion_box.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAICBORAssertionBox {
    pub fn new(box_label: &str) -> Self {
        CAICBORAssertionBox {
            assertion_box: JUMBFSuperBox::new(box_label, Some(CAI_CBOR_ASSERTION_UUID)),
        }
    }

    // add a JUMBFCBORContentBox box, with the assertion's CBOR
    // takes ownership of the CBOR
    pub fn add_cbor(&mut self, cbor_in: Vec<u8>) {
        let assertion_content = JUMBFCBORContentBox::new(cbor_in);
        self.assertion_box.add_data_box(Box::new(assertion_content));
    }

    pub fn set_salt(&mut self, salt: Vec<u8>) -> JumbfParseResult<()> {
        self.assertion_box.desc_box.set_salt(salt)
    }

    pub fn super_box(&self) -> &dyn BMFFBox {
        &self.assertion_box
    }
}

// ANCHOR Ingredient Box
/// Ingedient  Box
#[derive(Debug)]
pub struct CAIIngredientBox {
    ingredient_box: JUMBFSuperBox,
}

impl BMFFBox for CAIIngredientBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_INGREDIENT_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.ingredient_box.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAIIngredientBox {
    pub fn new(box_label: &str) -> Self {
        CAIIngredientBox {
            ingredient_box: JUMBFSuperBox::new(box_label, Some(CAI_INGREDIENT_UUID)),
        }
    }

    // add a JUMBFCodestreamContentBox box, with the codestream data
    //  takes ownership of the data
    pub fn add_data(&mut self, data_in: Vec<u8>) {
        let ingredient_content = JUMBFCodestreamContentBox::new(data_in);
        self.ingredient_box
            .add_data_box(Box::new(ingredient_content));
    }
}

// ANCHOR Assertion Store
/// Assertion Store
#[derive(Debug)]
pub struct CAIAssertionStore {
    store: JUMBFSuperBox,
}

impl BMFFBox for CAIAssertionStore {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_ASSERTION_STORE_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.store.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAIAssertionStore {
    pub fn new() -> Self {
        CAIAssertionStore {
            store: JUMBFSuperBox::new(labels::ASSERTIONS, Some(CAI_ASSERTION_STORE_UUID)),
        }
    }

    pub fn from(in_box: JUMBFSuperBox) -> Self {
        CAIAssertionStore { store: in_box }
    }

    // add an assertion box (of various types) *WITHOUT* taking ownership of the box
    pub fn add_assertion(&mut self, b: Box<dyn BMFFBox>) {
        self.store.add_data_box(b)
    }
}

impl Default for CAIAssertionStore {
    fn default() -> Self {
        Self::new()
    }
}

// ANCHOR Verifiable Credential Store
/// Ingredients Store
#[derive(Debug)]
pub struct CAIVerifiableCredentialStore {
    store: JUMBFSuperBox,
}

impl BMFFBox for CAIVerifiableCredentialStore {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_VERIFIABLE_CREDENTIALS_STORE_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.store.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAIVerifiableCredentialStore {
    pub fn new() -> Self {
        CAIVerifiableCredentialStore {
            store: JUMBFSuperBox::new(
                labels::CREDENTIALS,
                Some(CAI_VERIFIABLE_CREDENTIALS_STORE_UUID),
            ),
        }
    }

    pub fn from(in_box: JUMBFSuperBox) -> Self {
        CAIVerifiableCredentialStore { store: in_box }
    }

    // add an credential box *WITHOUT* taking ownership of the box
    pub fn add_credential(&mut self, b: Box<dyn BMFFBox>) {
        self.store.add_data_box(b)
    }
}

impl Default for CAIVerifiableCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

// ANCHOR CAI Store
/// CAI Store
#[derive(Debug)]
pub struct CAIStore {
    is_update_manifest: bool,
    store: JUMBFSuperBox,
}

impl BMFFBox for CAIStore {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        if self.is_update_manifest {
            CAI_UPDATE_MANIFEST_UUID
        } else {
            CAI_STORE_UUID
        }
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.store.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl CAIStore {
    pub fn new(box_label: &str, update_manifest: bool) -> Self {
        let id = if update_manifest {
            Some(CAI_UPDATE_MANIFEST_UUID)
        } else {
            Some(CAI_STORE_UUID)
        };
        let sbox = JUMBFSuperBox::new(box_label, id);
        CAIStore {
            is_update_manifest: update_manifest,
            store: sbox,
        }
    }

    pub fn from(sbox: JUMBFSuperBox) -> Self {
        let update_manifest = sbox.box_uuid() == CAI_UPDATE_MANIFEST_UUID;

        CAIStore {
            is_update_manifest: update_manifest,
            store: sbox,
        }
    }

    /// add a box (of various types) *WITHOUT* taking ownership of the box
    pub fn add_box(&mut self, b: Box<dyn BMFFBox>) {
        self.store.add_data_box(b)
    }

    // getters
    pub fn super_box(&self) -> &JUMBFSuperBox {
        &self.store
    }

    pub fn desc_box(&self) -> &JUMBFDescriptionBox {
        &self.store.desc_box
    }

    pub fn data_box_count(&self) -> usize {
        self.store.data_boxes.len()
    }

    pub fn data_box(&self, index: usize) -> &dyn BMFFBox {
        self.store.data_boxes[index].as_ref()
    }

    pub fn assertion_store(&self) -> Option<&JUMBFSuperBox> {
        // we REALLY want to return a CAIAssertionStore but can't do to referencing...
        self.store.data_box_as_superbox(0)
    }
}

// ANCHOR CAI Block
/// CAI Block
#[derive(Debug)]
pub struct Cai {
    sbox: JUMBFSuperBox,
}

impl BMFFBox for Cai {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        CAI_BLOCK_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.sbox.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Cai {
    pub fn new() -> Self {
        Cai {
            sbox: JUMBFSuperBox::new(labels::MANIFEST_STORE, Some(CAI_BLOCK_UUID)),
        }
    }

    pub fn from(in_box: JUMBFSuperBox) -> Self {
        Cai { sbox: in_box }
    }

    /// add a box (of various types) *WITHOUT* taking ownership of the box
    pub fn add_box(&mut self, b: Box<dyn BMFFBox>) {
        self.sbox.add_data_box(b)
    }

    // getters
    pub fn super_box(&self) -> &JUMBFSuperBox {
        &self.sbox
    }

    pub fn desc_box(&self) -> &JUMBFDescriptionBox {
        &self.sbox.desc_box
    }

    pub fn data_box_count(&self) -> usize {
        self.sbox.data_boxes.len()
    }

    pub fn data_box(&self, index: usize) -> &dyn BMFFBox {
        self.sbox.data_boxes[index].as_ref()
    }

    pub fn data_box_as_superbox(&self, index: usize) -> Option<&JUMBFSuperBox> {
        let da_box = &self.sbox.data_boxes[index];
        da_box.as_ref().as_any().downcast_ref::<JUMBFSuperBox>()
    }

    pub fn store(&self) -> Option<&JUMBFSuperBox> {
        // we REALLY want to return a UpdateManifest but can't do to referencing...
        self.sbox.data_box_as_superbox(0)
    }
}

impl Default for Cai {
    fn default() -> Self {
        Self::new()
    }
}

pub struct JumbfEmbeddedFileBox {
    embedding_box: JUMBFSuperBox,
}

impl BMFFBox for JumbfEmbeddedFileBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"    "
    }

    fn box_uuid(&self) -> &'static str {
        JUMBF_EMBEDDED_FILE_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        self.embedding_box.write_box(writer)
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JumbfEmbeddedFileBox {
    pub fn new(box_label: &str) -> Self {
        JumbfEmbeddedFileBox {
            embedding_box: JUMBFSuperBox::new(box_label, Some(JUMBF_EMBEDDED_FILE_UUID)),
        }
    }

    // add a JUMBFJSONContentBox box, with the claim's JSON
    // *WITHOUT* taking ownership of the box
    pub fn add_data(&mut self, data: Vec<u8>, media_type: String, file_name: Option<String>) {
        // add media type box
        let m = JUMBFEmbeddedFileDescriptionBox::new(media_type, file_name);
        self.embedding_box.add_data_box(Box::new(m));

        // add data box
        let d = JUMBFEmbeddedFileContentBox::new(data);
        self.embedding_box.add_data_box(Box::new(d));
    }

    pub fn media_type_box(&self) -> Option<&JUMBFEmbeddedFileDescriptionBox> {
        let efd_box = &self.embedding_box.data_boxes[0];
        efd_box
            .as_ref()
            .as_any()
            .downcast_ref::<JUMBFEmbeddedFileDescriptionBox>()
    }

    pub fn data_box(&self) -> Option<&JUMBFEmbeddedFileContentBox> {
        let efc_box = &self.embedding_box.data_boxes[1];
        efc_box
            .as_ref()
            .as_any()
            .downcast_ref::<JUMBFEmbeddedFileContentBox>()
    }

    pub fn set_salt(&mut self, salt: Vec<u8>) -> JumbfParseResult<()> {
        self.embedding_box.desc_box.set_salt(salt)
    }

    pub fn get_salt(&self) -> Option<Vec<u8>> {
        self.embedding_box
            .desc_box
            .private
            .as_ref()
            .map(|saltbox| saltbox.salt.clone())
    }

    pub fn super_box(&self) -> &dyn BMFFBox {
        &self.embedding_box
    }
}

impl Default for JumbfEmbeddedFileBox {
    fn default() -> Self {
        Self::new("")
    }
}
#[derive(Debug, Default)]
pub struct JUMBFEmbeddedFileContentBox {
    data: Vec<u8>, // arbitrary bunch of bytes...
}

impl BMFFBox for JUMBFEmbeddedFileContentBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"bidb"
    }

    fn box_uuid(&self) -> &'static str {
        CAI_EMBEDED_FILE_DATA_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = self.data.len();
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        if !self.data.is_empty() {
            write_all!(writer, &self.data);
        }
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JUMBFEmbeddedFileContentBox {
    // the content box takes ownership of the data!
    pub fn new(data_in: Vec<u8>) -> Self {
        JUMBFEmbeddedFileContentBox { data: data_in }
    }

    // getter
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

#[derive(Debug)]
pub struct JUMBFEmbeddedFileDescriptionBox {
    toggles: u8,                // media togles
    media_type: CString,        // file media type
    file_name: Option<CString>, // optional file name
}

impl BMFFBox for JUMBFEmbeddedFileDescriptionBox {
    fn box_type(&self) -> &'static [u8; 4] {
        b"bfdb"
    }

    fn box_uuid(&self) -> &'static str {
        CAI_EMBEDDED_FILE_DESCRIPTION_UUID
    }

    fn box_payload_size(&self) -> IoResult<u32> {
        let size = boxio::ByteCounter::calculate(|w| self.write_box_payload(w))?;
        Ok(size as u32)
    }

    fn write_box_payload(&self, writer: &mut dyn Write) -> IoResult<()> {
        write_u8!(writer, self.toggles);
        if self.media_type.to_str().unwrap_or_default().chars().count() > 0 {
            write_all!(writer, self.media_type.as_bytes_with_nul());
        }
        /*
        if let Some(name) = &self.file_name {
            if name
                .to_str()
                .expect("Incompatible string representation")
                .chars()
                .count()
                > 0
            {
                write_all!(writer, name.as_bytes_with_nul())
            }
        }
        */
        Ok(())
    }

    // Necessary method to enable conversion between types...
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl JUMBFEmbeddedFileDescriptionBox {
    pub fn new(media_type: String, file_name: Option<String>) -> Self {
        let mut new_toggles = 0;

        let cfile_name = match file_name {
            Some(f) => {
                new_toggles = 1;
                Some(CString::new(f).unwrap_or_default())
            }
            None => None,
        };

        JUMBFEmbeddedFileDescriptionBox {
            toggles: new_toggles,
            media_type: CString::new(media_type).unwrap_or_default(),
            file_name: cfile_name,
        }
    }

    fn to_rust_str(&self, s: &CString) -> String {
        let bytes = s.clone().into_bytes();

        let nul_range_end = bytes
            .iter()
            .position(|&c| c == b'\0')
            .unwrap_or(bytes.len());

        if let Ok(r_str) = String::from_utf8(bytes[0..nul_range_end].to_vec()) {
            r_str
        } else {
            String::new()
        }
    }

    pub fn media_type(&self) -> String {
        self.to_rust_str(&self.media_type)
    }

    pub fn file_name(&self) -> Option<String> {
        self.file_name.as_ref().map(|f| self.to_rust_str(f))
    }

    /// Makes a new `JUMBFDescriptionBox` instance from read in data
    pub fn from(togs: u8, mt_bytes: Vec<u8>, fn_bytes: Option<Vec<u8>>) -> Self {
        let mt_cstring: CString = unsafe { CString::from_vec_unchecked(mt_bytes) };
        let fn_cstring = fn_bytes.map(|b| unsafe { CString::from_vec_unchecked(b) });

        JUMBFEmbeddedFileDescriptionBox {
            toggles: togs,          // media togles
            media_type: mt_cstring, // file media type
            file_name: fn_cstring,  // optional file name
        }
    }
}

// !SECTION

//---------------
// SECTION Box Reader
//---------------

const HEADER_SIZE: u64 = 8;
const TOGGLE_SIZE: u64 = 1;

/// method for getting the current position
pub fn current_pos<R: Seek>(seeker: &mut R) -> JumbfParseResult<u64> {
    Ok(seeker.seek(SeekFrom::Current(0))?)
}

/// method for seeking back to the start of the box (header)
pub fn box_start<R: Seek>(seeker: &mut R) -> JumbfParseResult<u64> {
    Ok(current_pos(seeker).map_err(|_| JumbfParseError::InvalidBoxStart)? - HEADER_SIZE)
}

/// method for skipping over `size` bytes
pub fn skip_bytes<S: Seek>(seeker: &mut S, size: u64) -> JumbfParseResult<()> {
    seeker.seek(SeekFrom::Current(size as i64))?;
    Ok(())
}

/// method for skipping to a specific position (`pos`)
pub fn skip_bytes_to<S: Seek>(seeker: &mut S, pos: u64) -> JumbfParseResult<()> {
    seeker.seek(SeekFrom::Start(pos))?;
    Ok(())
}

// method to skip over an entire box
pub fn skip_box<S: Seek>(seeker: &mut S, size: u64) -> JumbfParseResult<()> {
    let start = box_start(seeker)?;
    skip_bytes_to(seeker, start + size)?;
    Ok(())
}

/// method for skipping backwards `size` bytes
pub fn unread_bytes<S: Seek>(seeker: &mut S, size: u64) -> JumbfParseResult<()> {
    let new_loc = -(size as i64);
    seeker.seek(SeekFrom::Current(new_loc))?;
    Ok(())
}

/// macro for dealing with the type of a BMFF/JUMBF box
macro_rules! boxtype {
    ($( $name:ident => $value:expr ),*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum BoxType {
            $( $name, )*
            UnknownBox(u32),
        }

        impl From<u32> for BoxType {
            fn from(t: u32) -> BoxType {
                match t {
                    $( $value => BoxType::$name, )*
                    _ => BoxType::UnknownBox(t),
                }
            }
        }

    }
}

boxtype! {
    Empty => 0x0000_0000,
    Jumb => 0x6A75_6D62,
    Jumd => 0x6A75_6D64,
    Padding => 0x6672_6565,
    SaltHash => 0x6332_7368,
    Json => 0x6A73_6F6E,
    Uuid => 0x7575_6964,
    Jp2c => 0x6A70_3263,
    Cbor => 0x6362_6F72,
    EmbedMediaDesc => 0x6266_6462,
    EmbedContent => 0x6269_6462
}

// ANCHOR BlockHeader
/// class for storing the header of a block
pub struct BoxHeader {
    pub name: BoxType,
    pub size: u64,
}
impl BoxHeader {
    pub fn new(name: BoxType, size: u64) -> Self {
        Self { name, size }
    }
}

// ANCHOR BoxReader
/// class for reading BMFF/JUMBF boxes
pub struct BoxReader {}

impl BoxReader {
    pub fn read_header<R: Read>(reader: &mut R) -> JumbfParseResult<BoxHeader> {
        // Create and read to buf.
        let mut buf = [0u8; 8]; // 8 bytes for box header.
        let bytes_read = reader.read(&mut buf)?;

        if bytes_read == 0 {
            // end of file!
            return Ok(BoxHeader::new(BoxType::Empty, 0));
        }

        // Get size.
        let s = buf[0..4]
            .try_into()
            .map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        let size = u32::from_be_bytes(s);

        // Get box type string.
        let t = buf[4..8]
            .try_into()
            .map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        let typ = u32::from_be_bytes(t);

        // Get large size if size is 1
        if size == 1 {
            reader.read_exact(&mut buf)?;
            let s = buf; //.try_into().unwrap();
            let large_size = u64::from_be_bytes(s);

            Ok(BoxHeader {
                name: BoxType::from(typ),
                size: large_size,
            })
        } else {
            Ok(BoxHeader {
                name: BoxType::from(typ),
                size: size as u64,
            })
        }
    }

    pub fn read_desc_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFDescriptionBox> {
        let mut bytes_left = size;
        let mut uuid = [0u8; 16]; // 16 bytes for the UUID
        let bytes_read = reader.read(&mut uuid)?;
        if bytes_read == 0 {
            // end of file!
            return Ok(JUMBFDescriptionBox::new("", None));
        }
        bytes_left -= bytes_read as u64;

        let mut togs = [0u8]; // 1 byte of toggles
        reader.read_exact(&mut togs)?;
        bytes_left -= 1;

        if togs[0] & 0x03 == 0x03 {
            // must be requestable and labeled
            // read label
            let mut sbuf = Vec::with_capacity(64);
            loop {
                let mut buf = [0; 1];
                reader.read_exact(&mut buf)?;
                bytes_left -= 1;
                if buf[0] == 0x00 {
                    break;
                } else {
                    sbuf.push(buf[0]);
                }
            }

            // if there is a signature, we need to read it...
            let sig = if togs[0] & 0x08 == 0x08 {
                let mut sigbuf: [u8; 32] = [0; 32];
                reader.read_exact(&mut sigbuf)?;
                bytes_left -= 32;
                Some(sigbuf)
            } else {
                None
            };

            // read private box if necessary
            let private = if togs[0] & 0x10 == 0x10 {
                let header = BoxReader::read_header(reader)
                    .map_err(|_| JumbfParseError::InvalidBoxHeader)?;
                if header.size == 0 {
                    // bad read,
                    return Err(JumbfParseError::InvalidBoxHeader);
                } else if header.size != bytes_left - HEADER_SIZE {
                    // this means that we started w/o the header...
                    unread_bytes(reader, HEADER_SIZE)?;
                }

                if header.name == BoxType::SaltHash {
                    let data_len = header.size - HEADER_SIZE;
                    let mut buf = vec![0u8; data_len as usize];
                    reader.read_exact(&mut buf)?;

                    bytes_left -= header.size;

                    Some(CAISaltContentBox::new(buf))
                } else {
                    return Err(JumbfParseError::InvalidBoxHeader);
                }
            } else {
                None
            };

            if bytes_left != HEADER_SIZE {
                // make sure we have consumed the entire box
                return Err(JumbfParseError::InvalidBoxHeader);
            }

            return Ok(JUMBFDescriptionBox::from(
                &uuid, togs[0], sbuf, None, sig, private,
            ));
        }
        Err(JumbfParseError::InvalidDescriptionBox)
    }

    pub fn read_json_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFJSONContentBox> {
        let header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        if header.size == 0 {
            // bad read, return empty box...
            return Ok(JUMBFJSONContentBox::new(Vec::new()));
        } else if header.size != size {
            // this means that we started w/o the header...
            unread_bytes(reader, HEADER_SIZE)?;
        }

        let json_len = size - HEADER_SIZE;
        let mut buf = vec![0u8; json_len as usize];
        reader.read_exact(&mut buf)?;

        Ok(JUMBFJSONContentBox::new(buf))
    }

    pub fn read_cbor_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFCBORContentBox> {
        let header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        if header.size == 0 {
            // bad read, return empty box...
            return Ok(JUMBFCBORContentBox::new(Vec::new()));
        } else if header.size != size {
            // this means that we started w/o the header...
            unread_bytes(reader, HEADER_SIZE)?;
        }

        let cbor_len = size - HEADER_SIZE;
        let mut buf = vec![0u8; cbor_len as usize];
        reader.read_exact(&mut buf)?;

        Ok(JUMBFCBORContentBox::new(buf))
    }

    pub fn read_padding_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFPaddingContentBox> {
        let header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        if header.size == 0 {
            // bad read, return empty box...
            return Ok(JUMBFPaddingContentBox::new(0));
        } else if header.size != size {
            // this means that we started w/o the header...
            unread_bytes(reader, HEADER_SIZE)?;
        }

        let padding_len = size - HEADER_SIZE;
        let mut buf = vec![0u8; padding_len as usize];
        reader.read_exact(&mut buf)?;

        Ok(JUMBFPaddingContentBox::new_with_vec(buf))
    }

    pub fn read_jp2c_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFCodestreamContentBox> {
        let header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        if header.size == 0 {
            // bad read, return empty box...
            return Ok(JUMBFCodestreamContentBox::new(Vec::new()));
        } else if header.size != size {
            // this means that we started w/o the header...
            unread_bytes(reader, HEADER_SIZE)?;
        }

        // read the data itself...
        let data_len = size - HEADER_SIZE;
        let mut buf = vec![0u8; data_len as usize];
        reader.read_exact(&mut buf)?;

        Ok(JUMBFCodestreamContentBox::new(buf))
    }

    pub fn read_uuid_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFUUIDContentBox> {
        let header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        if header.size == 0 {
            // bad read, return empty box...
            return Ok(JUMBFUUIDContentBox::new(&[0u8; 16], Vec::new()));
        } else if header.size != size {
            // this means that we started w/o the header...
            unread_bytes(reader, HEADER_SIZE)?;
        }

        // now read the UUID
        let mut uuid = [0u8; 16]; // 16 bytes of UUID
        reader.read_exact(&mut uuid)?;

        // and finally the data itself...
        let data_len = size - HEADER_SIZE - 16 /*UUID*/;
        let mut buf = vec![0u8; data_len as usize];
        reader.read_exact(&mut buf)?;

        Ok(JUMBFUUIDContentBox::new(&uuid, buf))
    }

    pub fn read_embedded_media_desc_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFEmbeddedFileDescriptionBox> {
        let header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        if header.size == 0 {
            // bad read, return empty box...
            return Ok(JUMBFEmbeddedFileDescriptionBox::new("".to_string(), None));
        } else if header.size != size {
            // this means that we started w/o the header...
            unread_bytes(reader, HEADER_SIZE)?;
        }

        //toggles: u8,                // media togles
        //media_type: CString,        // file media type
        //file_name: Option<CString>, // optional file name

        // now read the media_type
        let mut togs = [0u8]; // 1 byte of toggles
        reader.read_exact(&mut togs)?;

        // read the data itself...
        let data_len = size - HEADER_SIZE - TOGGLE_SIZE;
        let mut buf = vec![0u8; data_len as usize];
        reader.read_exact(&mut buf)?;

        let (media_type, file_name) = match togs[0] {
            1 => {
                // there may be two c strings in this vec
                match buf.iter().position(|&x| x == 0) {
                    Some(pos) => {
                        if pos != buf.len() - 1 {
                            (buf, None)
                        } else {
                            let (first, second) = buf.split_at(pos);
                            (first.to_vec(), Some(second.to_vec()))
                        }
                    }
                    None => (buf, None),
                }
            }
            _ => (buf, None),
        };

        Ok(JUMBFEmbeddedFileDescriptionBox::from(
            togs[0], media_type, file_name,
        ))
    }

    pub fn read_embedded_content_box<R: Read + Seek>(
        reader: &mut R,
        size: u64,
    ) -> JumbfParseResult<JUMBFEmbeddedFileContentBox> {
        let header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidBoxHeader)?;
        if header.size == 0 {
            // bad read, return empty box...
            return Ok(JUMBFEmbeddedFileContentBox::new(Vec::new()));
        } else if header.size != size {
            // this means that we started w/o the header...
            unread_bytes(reader, HEADER_SIZE)?;
        }

        // read data itself...
        let data_len = size - HEADER_SIZE;
        let mut buf = vec![0u8; data_len as usize];
        reader.read_exact(&mut buf)?;

        Ok(JUMBFEmbeddedFileContentBox::new(buf))
    }

    pub fn read_super_box<R: Read + Seek>(reader: &mut R) -> JumbfParseResult<JUMBFSuperBox> {
        // find out where we're starting...
        let start_pos = current_pos(reader).map_err(|_| JumbfParseError::InvalidBoxRange)?;

        // start with the initial jumb
        let jumb_header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidJumbfHeader)?;
        if jumb_header.name == BoxType::Empty {
            return Err(JumbfParseError::UnexpectedEof);
        } else if jumb_header.name != BoxType::Jumb {
            return Err(JumbfParseError::InvalidJumbfHeader);
        }

        // figure out where this particular box ends...
        let dest_pos = start_pos + jumb_header.size;

        // now let's load the jumd
        let jumd_header =
            BoxReader::read_header(reader).map_err(|_| JumbfParseError::ExpectedJumdError)?;
        if jumb_header.name == BoxType::Empty {
            return Err(JumbfParseError::UnexpectedEof);
        } else if jumd_header.name != BoxType::Jumd {
            return Err(JumbfParseError::ExpectedJumdError);
        }

        // load the description box & create a new superbox from it
        let jdesc = BoxReader::read_desc_box(reader, jumd_header.size)
            .map_err(|_| JumbfParseError::UnexpectedEof)?;
        if jdesc.label().is_empty() {
            return Err(JumbfParseError::UnexpectedEof);
        }
        let box_label = jdesc.label();
        debug!(
            "{}",
            format!("START#Label: {:?}", box_label /*jdesc.label()*/)
        );
        let mut sbox = JUMBFSuperBox::from(jdesc);

        // read each following box and add it to the sbox
        let mut found = true;
        while found {
            let box_header =
                BoxReader::read_header(reader).map_err(|_| JumbfParseError::InvalidJumbfHeader)?;
            if box_header.name == BoxType::Empty {
                found = false;
            } else {
                unread_bytes(reader, HEADER_SIZE)?; // seek back to the beginning of the box
                let next_box: Box<dyn BMFFBox> = match box_header.name {
                    BoxType::Jumb => Box::new(
                        BoxReader::read_super_box(reader)
                            .map_err(|_| JumbfParseError::InvalidJumbBox)?,
                    ),
                    BoxType::Json => Box::new(
                        BoxReader::read_json_box(reader, box_header.size)
                            .map_err(|_| JumbfParseError::InvalidJsonBox)?,
                    ),
                    BoxType::Cbor => Box::new(
                        BoxReader::read_cbor_box(reader, box_header.size)
                            .map_err(|_| JumbfParseError::InvalidCborBox)?,
                    ),
                    BoxType::Padding => Box::new(
                        BoxReader::read_padding_box(reader, box_header.size)
                            .map_err(|_| JumbfParseError::InvalidCborBox)?,
                    ),
                    BoxType::Jp2c => Box::new(
                        BoxReader::read_jp2c_box(reader, box_header.size)
                            .map_err(|_| JumbfParseError::InvalidJp2cBox)?,
                    ),

                    BoxType::Uuid => Box::new(
                        BoxReader::read_uuid_box(reader, box_header.size)
                            .map_err(|_| JumbfParseError::InvalidUuidBox)?,
                    ),
                    BoxType::EmbedMediaDesc => Box::new(
                        BoxReader::read_embedded_media_desc_box(reader, box_header.size)
                            .map_err(|_| JumbfParseError::InvalidEmbeddedFileBox)?,
                    ),
                    BoxType::EmbedContent => Box::new(
                        BoxReader::read_embedded_content_box(reader, box_header.size)
                            .map_err(|_| JumbfParseError::InvalidEmbeddedFileBox)?,
                    ),
                    _ => {
                        debug!("{}", format!("Unknown Boxtype: {:?}", box_header.name));
                        // per the jumbf spec ignore unknown boxes so skip by if possible
                        let header = BoxReader::read_header(reader)
                            .map_err(|_| JumbfParseError::InvalidBoxHeader)?;
                        if header.size == 0 {
                            // bad read, return empty box...
                            return Err(JumbfParseError::InvalidUnknownBox);
                        } else if header.size != box_header.size {
                            // this means that we started w/o the header...
                            unread_bytes(reader, HEADER_SIZE)?;
                        }

                        // read data itself...
                        let data_len = box_header.size - HEADER_SIZE;
                        let mut buf = vec![0u8; data_len as usize];
                        reader.read_exact(&mut buf)?;
                        continue;
                    }
                };
                sbox.add_data_box(next_box);
            }

            // if our current position is past the size, bail out...
            if let Ok(p) = current_pos(reader) {
                if p >= dest_pos {
                    found = false;
                }
            }
        }

        debug!(
            "{}",
            format!("END#Label: {:?}", box_label /*jdesc.label()*/)
        );

        // return the filled out sbox
        Ok(sbox)
    }
}

// !SECTION

//---------------
// SECTION Tests
//---------------

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use extfmt::*;

    use super::*;

    // base_len = size (u32) + type (u32)
    // desc_len = base + 16 (UUID type) + 1 (TOGGLE)
    // cont_len = base
    // sig_len  = base + 16 (UUID type)
    const BOX_BASE_LEN: usize = 4 + 4;
    const DESC_BOX_BASE: usize = BOX_BASE_LEN + 16 + 1;
    const CONT_BOX_BASE: usize = BOX_BASE_LEN;
    const SIG_BOX_BASE: usize = BOX_BASE_LEN + 16;
    const EMBED_MEDIA_BASE: usize = BOX_BASE_LEN + 1;
    const EMBED_DATA_BASE: usize = BOX_BASE_LEN;

    fn compute_desc_box_size(box_label: &str) -> usize {
        DESC_BOX_BASE + box_label.len() + 1
    }

    // len is base + desc (base + len(label) + 1 (null term))
    fn compute_super_box_size(box_label: &str) -> usize {
        let mut len = BOX_BASE_LEN;
        len += compute_desc_box_size(box_label);
        len
    }

    fn compute_content_box_size(box_label: &str, data_size: usize) -> usize {
        let content_box_expected_len = CONT_BOX_BASE + data_size;
        let desc_box_expected_len = compute_desc_box_size(box_label);
        BOX_BASE_LEN + desc_box_expected_len + content_box_expected_len
    }

    fn compute_signature_box_size(sig_size: usize) -> usize {
        let content_box_expected_len = SIG_BOX_BASE + sig_size;
        let desc_box_expected_len = compute_desc_box_size(labels::SIGNATURE);
        BOX_BASE_LEN + desc_box_expected_len + content_box_expected_len
    }

    fn compute_media_type_box_size(media_type: &str, file_name: Option<&str>) -> usize {
        let mut len = EMBED_MEDIA_BASE + media_type.len() + 1;
        if let Some(f) = file_name {
            len += f.len() + 1;
        }
        len
    }

    fn compute_embedded_box_size(data_size: usize) -> usize {
        EMBED_DATA_BASE + data_size
    }

    fn compute_thumbnail_box_size(
        box_label: &str,
        data_size: usize,
        media_type: &str,
        file_name: Option<&str>,
    ) -> usize {
        let mut len = compute_super_box_size(box_label);
        len += compute_media_type_box_size(media_type, file_name);
        len += compute_embedded_box_size(data_size);
        len
    }

    // ANCHOR: DescBox
    #[test]
    fn description_box() {
        let box_label = "test.descbox";
        let jdb = JUMBFDescriptionBox::new(box_label, None);
        let mut mem_box: Vec<u8> = Vec::new();

        jdb.write_box(&mut mem_box)
            .expect("Unable to write description box");

        println!("DescriptionBox:\t{}", Hexlify(&mem_box));
        assert_eq!(
            format!("{}", Hexlify(&mem_box)),
            "000000266a756d640000000000000000000000000000000003746573742e64657363626f7800"
        );

        let expected_len = compute_desc_box_size(box_label);
        assert_eq!(mem_box.len(), expected_len); // make sure the length is correct
    }

    // ANCHOR: SuperBox
    #[test]
    fn super_box() {
        let box_label = "test.superbox";
        let jsb = JUMBFSuperBox::new(box_label, None);
        let mut mem_box: Vec<u8> = Vec::new();

        jsb.write_box(&mut mem_box)
            .expect("Unable to write superbox");

        let expected_len = compute_super_box_size(box_label);
        assert_eq!(mem_box.len(), expected_len); // make sure the length is correct

        println!("SuperBox:\t{}", Hexlify(&mem_box));
        assert_eq!(format!("{}", Hexlify(&mem_box)), "0000002f6a756d62000000276a756d640000000000000000000000000000000003746573742e7375706572626f7800");
    }

    // ANCHOR: SuperBox + Data Box
    #[test]
    fn super_box_with_one_data_box() {
        let box_label = "test.superbox_databox";
        let mut jsb = JUMBFSuperBox::new(box_label, None);

        let data_box_label = "test.databox";
        let jdb = Box::new(JUMBFSuperBox::new(data_box_label, None));
        jsb.add_data_box(jdb);

        // now write it and see what we get!!
        let mut mem_box: Vec<u8> = Vec::new();
        jsb.write_box(&mut mem_box)
            .expect("Unable to write superbox");

        let data_box_expected_len = compute_super_box_size(data_box_label);
        let expected_len = data_box_expected_len + compute_super_box_size(box_label);
        assert_eq!(mem_box.len(), expected_len); // make sure the length is correct

        println!("SuperBox + DataBox:\t{}", Hexlify(&mem_box));
        assert_eq!(format!("{}", Hexlify(&mem_box)), "000000656a756d620000002f6a756d640000000000000000000000000000000003746573742e7375706572626f785f64617461626f78000000002e6a756d62000000266a756d640000000000000000000000000000000003746573742e64617461626f7800");
    }

    // ANCHOR: Signature Box
    #[test]
    fn cai_signature_box() {
        let mut sigb = CAISignatureBox::new();

        let some_data = String::from("this would normally be binary signature data...");
        let sig_len = some_data.len();
        let sigc = CAISignatureContentBox::new(some_data.into_bytes());
        sigb.add_signature(Box::new(sigc));

        let mut mem_box: Vec<u8> = Vec::new();
        sigb.write_box(&mut mem_box)
            .expect("Unable to write CAI Signature");

        // expected_len is base + desc_box + content+box
        let expected_len = compute_signature_box_size(sig_len);
        assert_eq!(mem_box.len(), expected_len); // make sure the length is correct

        println!("CAISignatureBox:\t{}", Hexlify(&mem_box));
        assert_eq!(format!("{}", Hexlify(&mem_box)), "000000776a756d62000000286a756d646332637300110010800000aa00389b7103633270612e7369676e61747572650000000047757569646332637300110010800000aa00389b717468697320776f756c64206e6f726d616c6c792062652062696e617279207369676e617475726520646174612e2e2e");
    }

    // ANCHOR: Claim Box
    #[test]
    fn cai_claim_box() {
        let mut cb = CAIClaimBox::new();

        let claim_json = String::from(
            "{
            \"recorder\" : \"Photoshop\",
            \"parent_claim\" : \"self#jumbf=c_tpic_1/c2pa.claim?hl=6E6DD0923B57DCE\",
            \"signature\" : \"self#jumbf=s_adbe_1\",
            \"assertions\" : [
                \"self#jumbf=as_adbe_1/c2pa.identity?hl=45919681DCCAF6ABAD\",
                \"self#jumbf=as_adbe_1/c2pa.thumbnail.jpeg?hl=76142BD62363F\"
            ],
            \"redacted_assertions\" : [
                \"self#jumbf=as_tp_1/c2pa.location.precise\"
            ],
            \"asset_hashes\": []
        }",
        );

        let clen = claim_json.len();
        let cjson = JUMBFJSONContentBox::new(claim_json.into_bytes());
        cb.add_claim(Box::new(cjson));

        let mut mem_box: Vec<u8> = Vec::new();
        cb.write_box(&mut mem_box)
            .expect("Unable to write CAI Claim");

        let expected_len = compute_content_box_size(labels::CLAIM, clen);
        assert_eq!(mem_box.len(), expected_len); // make sure the length is correct

        println!("CAIClaimBox:\t{}", Hexlify(&mem_box));
        assert_eq!(format!("{}", Hexlify(&mem_box)), "0000023b6a756d62000000246a756d646332636c00110010800000aa00389b7103633270612e636c61696d000000020f6a736f6e7b0a202020202020202020202020227265636f7264657222203a202250686f746f73686f70222c0a20202020202020202020202022706172656e745f636c61696d22203a202273656c66236a756d62663d635f747069635f312f633270612e636c61696d3f686c3d364536444430393233423537444345222c0a202020202020202020202020227369676e617475726522203a202273656c66236a756d62663d735f616462655f31222c0a20202020202020202020202022617373657274696f6e7322203a205b0a202020202020202020202020202020202273656c66236a756d62663d61735f616462655f312f633270612e6964656e746974793f686c3d343539313936383144434341463641424144222c0a202020202020202020202020202020202273656c66236a756d62663d61735f616462655f312f633270612e7468756d626e61696c2e6a7065673f686c3d37363134324244363233363346220a2020202020202020202020205d2c0a2020202020202020202020202272656461637465645f617373657274696f6e7322203a205b0a202020202020202020202020202020202273656c66236a756d62663d61735f74705f312f633270612e6c6f636174696f6e2e70726563697365220a2020202020202020202020205d2c0a2020202020202020202020202261737365745f686173686573223a205b5d0a20202020202020207d");
    }

    // ANCHOR: Location assertion
    #[test]
    fn cai_location_assertion_box() {
        let box_label = "c2pa.location.broad";
        let location = String::from("{ \"location\": \"San Francisco\"}");
        let loc_len = location.len();

        let mut cb = CAIJSONAssertionBox::new(box_label);
        cb.add_json(location.into_bytes());

        let mut mem_box: Vec<u8> = Vec::new();
        cb.write_box(&mut mem_box)
            .expect("Unable to write location.broad assertion");

        let expected_len = compute_content_box_size(box_label, loc_len);
        assert_eq!(mem_box.len(), expected_len); // make sure the length is correct

        println!("CAI Broad Location:\t{}", Hexlify(&mem_box));
        assert_eq!(format!("{}", Hexlify(&mem_box)), "0000005b6a756d620000002d6a756d646a736f6e00110010800000aa00389b7103633270612e6c6f636174696f6e2e62726f616400000000266a736f6e7b20226c6f636174696f6e223a202253616e204672616e636973636f227d");
    }

    // ANCHOR: Assertion Store
    #[test]
    fn assertion_store() {
        // create the assertion store
        let mut a_store = CAIAssertionStore::new();

        // create some assertions & add to the store
        let th_box_label = "c2pa.claim.thumbnail";
        let img = String::from("<image data goes here>");
        let img_len = img.len();
        let mut tb = JumbfEmbeddedFileBox::new(th_box_label);
        tb.add_data(img.into_bytes(), "image/jpeg".to_string(), None);
        a_store.add_assertion(Box::new(tb));
        let tb_len = compute_thumbnail_box_size(th_box_label, img_len, "image/jpeg", None);

        let id_box_label = "c2pa.identity";
        let identity = String::from("{ \"uri\": \"did:adobe:lrosenth@adobe.com\"}");
        let id_len = identity.len();
        let mut ib = CAIJSONAssertionBox::new(id_box_label);
        ib.add_json(identity.into_bytes());
        a_store.add_assertion(Box::new(ib));
        let ib_len = compute_content_box_size(id_box_label, id_len);

        // write it to memory
        let mut mem_box: Vec<u8> = Vec::new();
        a_store
            .write_box(&mut mem_box)
            .expect("Unable to write assertion store");

        // and test the results
        let store_sup_len = compute_super_box_size("c2pa.assertions");
        let expected_len = store_sup_len + tb_len + ib_len;
        assert_eq!(mem_box.len(), expected_len); // make sure the length is correct

        println!("CAI Assertion Store:\t{}", Hexlify(&mem_box));
        assert_eq!(format!("{}", Hexlify(&mem_box)), "000000f86a756d62000000296a756d646332617300110010800000aa00389b7103633270612e617373657274696f6e7300000000686a756d620000002e6a756d6440cb0c32bb8a489da70b2ad6f47f436903633270612e636c61696d2e7468756d626e61696c00000000146266646200696d6167652f6a706567000000001e626964623c696d616765206461746120676f657320686572653e0000005f6a756d62000000276a756d646a736f6e00110010800000aa00389b7103633270612e6964656e7469747900000000306a736f6e7b2022757269223a20226469643a61646f62653a6c726f73656e74684061646f62652e636f6d227d");
    }

    // ANCHOR: CAI Store
    #[test]
    fn cai_store() {
        // create the CAI store
        let store_label = "cb.adobe_1";
        let mut cai_store = CAIStore::new(store_label, false);

        // create the assertion store
        let mut a_store = CAIAssertionStore::new();

        // create an assertions & add to the store
        let th_box_label = "c2pa.claim.thumbnail";
        let img = String::from("<image data goes here>");
        let img_len = img.len();
        let mut tb = JumbfEmbeddedFileBox::new(th_box_label);
        tb.add_data(img.into_bytes(), "image/jpeg".to_string(), None);
        a_store.add_assertion(Box::new(tb));

        // add the assertion store to the cai store
        cai_store.add_box(Box::new(a_store));

        // create a claim & add it to the cai store
        let mut cb = CAIClaimBox::new();
        let claim_json = String::from(
            "{
            \"recorder\" : \"Photoshop\",
            \"signature\" : \"self#jumbf=s_adobe_1\",
            \"assertions\" : [
                \"self#jumbf=as_adobe_1/c2pa.thumbnail.jpeg?hl=76142BD62363F\"
            ]
        }",
        );

        let clen = claim_json.len();
        let cjson = JUMBFJSONContentBox::new(claim_json.into_bytes());
        cb.add_claim(Box::new(cjson));
        cai_store.add_box(Box::new(cb));

        // create a signature & add to the cai store
        let mut sigb = CAISignatureBox::new();
        let some_data = String::from("this would normally be binary signature data...");
        let sig_len = some_data.len();
        let sigc = CAISignatureContentBox::new(some_data.into_bytes());
        sigb.add_signature(Box::new(sigc));
        cai_store.add_box(Box::new(sigb));

        // write it to memory
        let mut mem_box: Vec<u8> = Vec::new();
        cai_store
            .write_box(&mut mem_box)
            .expect("Unable to write CAI store");

        // and test the results
        let cai_store_sup_len = compute_super_box_size(store_label);
        let a_store_sup_len = compute_super_box_size("c2pa.assertions");
        let tb_len = compute_thumbnail_box_size(th_box_label, img_len, "image/jpeg", None);
        let claim_len = compute_content_box_size(labels::CLAIM, clen);
        let sig_box_len = compute_signature_box_size(sig_len);
        let expected_len = cai_store_sup_len + a_store_sup_len + tb_len + claim_len + sig_box_len;
        assert_eq!(mem_box.len(), expected_len); // make sure the length is correct

        println!("C2PA Store:\t{}", Hexlify(&mem_box));
        assert_eq!(format!("{}", Hexlify(&mem_box)), "0000024b6a756d62000000246a756d6463326d6100110010800000aa00389b710363622e61646f62655f3100000000996a756d62000000296a756d646332617300110010800000aa00389b7103633270612e617373657274696f6e7300000000686a756d620000002e6a756d6440cb0c32bb8a489da70b2ad6f47f436903633270612e636c61696d2e7468756d626e61696c00000000146266646200696d6167652f6a706567000000001e626964623c696d616765206461746120676f657320686572653e0000010f6a756d62000000246a756d646332636c00110010800000aa00389b7103633270612e636c61696d00000000e36a736f6e7b0a202020202020202020202020227265636f7264657222203a202250686f746f73686f70222c0a202020202020202020202020227369676e617475726522203a202273656c66236a756d62663d735f61646f62655f31222c0a20202020202020202020202022617373657274696f6e7322203a205b0a202020202020202020202020202020202273656c66236a756d62663d61735f61646f62655f312f633270612e7468756d626e61696c2e6a7065673f686c3d37363134324244363233363346220a2020202020202020202020205d0a20202020202020207d000000776a756d62000000286a756d646332637300110010800000aa00389b7103633270612e7369676e61747572650000000047757569646332637300110010800000aa00389b717468697320776f756c64206e6f726d616c6c792062652062696e617279207369676e617475726520646174612e2e2e");
    }

    // ANCHOR: CAI block
    #[test]
    fn cai_block() {
        // create the CAI block
        let mut cai_block = Cai::new();

        // create the CAI store
        let store_label = "cb.adobe_1";
        let mut cai_store = CAIStore::new(store_label, false);

        // create the assertion store
        let mut a_store = CAIAssertionStore::new();

        // create an assertions & add to the store
        let loc_box_label = "c2pa.location.broad";
        let location = String::from("{ \"location\": \"Margate City, NJ\"}");
        let loc_len = location.len();
        let mut loc_box = CAIJSONAssertionBox::new(loc_box_label);
        loc_box.add_json(location.into_bytes());
        a_store.add_assertion(Box::new(loc_box));

        // add the assertion store to the cai store
        cai_store.add_box(Box::new(a_store));

        // create a claim & add it to the cai store
        let mut cb = CAIClaimBox::new();
        let claim_json = String::from(
            "{
            \"recorder\" : \"Photoshop\",
            \"signature\" : \"self#jumbf=s_adobe_1\",
            \"assertions\" : [
                \"self#jumbf=as_adobe_1/c2pa.location.broad?hl=76142BD62363F\"
            ]
        }",
        );

        let clen = claim_json.len();
        let cjson = JUMBFJSONContentBox::new(claim_json.into_bytes());
        cb.add_claim(Box::new(cjson));
        cai_store.add_box(Box::new(cb));

        // create a signature & add to the cai store
        let mut sigb = CAISignatureBox::new();
        let some_data = String::from("this would normally be binary signature data...");
        let sig_len = some_data.len();
        let sigc = CAISignatureContentBox::new(some_data.into_bytes());
        sigb.add_signature(Box::new(sigc));
        cai_store.add_box(Box::new(sigb));

        // finally add the completed cai store into the cai block
        cai_block.add_box(Box::new(cai_store));

        // write it to memory
        let mut mem_box: Vec<u8> = Vec::new();
        cai_block
            .write_box(&mut mem_box)
            .expect("Unable to write CAI block");

        // and test the results
        let cai_block_sup_len = compute_super_box_size(labels::MANIFEST_STORE);
        let cai_store_sup_len = compute_super_box_size(store_label);
        let a_store_sup_len = compute_super_box_size("c2pa.assertions");
        let lb_len = compute_content_box_size(loc_box_label, loc_len);
        let claim_len = compute_content_box_size(labels::CLAIM, clen);
        let sig_box_len = compute_signature_box_size(sig_len);

        let expected_len = cai_block_sup_len
            + cai_store_sup_len
            + a_store_sup_len
            + lb_len
            + claim_len
            + sig_box_len;

        assert_eq!(mem_box.len(), expected_len); // make sure the length is correct

        println!("CAI Block:\t{}", Hexlify(&mem_box));
        assert_eq!(format!("{}", Hexlify(&mem_box)), "000002676a756d620000001e6a756d646332706100110010800000aa00389b71036332706100000002416a756d62000000246a756d6463326d6100110010800000aa00389b710363622e61646f62655f31000000008f6a756d62000000296a756d646332617300110010800000aa00389b7103633270612e617373657274696f6e73000000005e6a756d620000002d6a756d646a736f6e00110010800000aa00389b7103633270612e6c6f636174696f6e2e62726f616400000000296a736f6e7b20226c6f636174696f6e223a20224d61726761746520436974792c204e4a227d0000010f6a756d62000000246a756d646332636c00110010800000aa00389b7103633270612e636c61696d00000000e36a736f6e7b0a202020202020202020202020227265636f7264657222203a202250686f746f73686f70222c0a202020202020202020202020227369676e617475726522203a202273656c66236a756d62663d735f61646f62655f31222c0a20202020202020202020202022617373657274696f6e7322203a205b0a202020202020202020202020202020202273656c66236a756d62663d61735f61646f62655f312f633270612e6c6f636174696f6e2e62726f61643f686c3d37363134324244363233363346220a2020202020202020202020205d0a20202020202020207d000000776a756d62000000286a756d646332637300110010800000aa00389b7103633270612e7369676e61747572650000000047757569646332637300110010800000aa00389b717468697320776f756c64206e6f726d616c6c792062652062696e617279207369676e617475726520646174612e2e2e");
    }

    // ANCHOR: JUMB BlockReader
    #[test]
    fn jumb_box_reader() {
        const JUMB_TEST: &str = "000000026A756D62";
        let buffer = hex::decode(JUMB_TEST).expect("decode failed");
        let mut buf_reader = Cursor::new(buffer);
        let jumb_header = BoxReader::read_header(&mut buf_reader).unwrap();
        assert_eq!(jumb_header.size, 2);
        assert_eq!(jumb_header.name, BoxType::Jumb);
    }

    // ANCHOR: DescriptionBox Reader
    /*
     #[test]
     fn desc_box_reader() {
         const JUMD_DESC: &str =
             "000000256A756D62000000216A756D646332706100110010800000AA00389B7103633270612E763100";
         let buffer = hex::decode(JUMD_DESC).expect("decode failed");
         let mut buf_reader = Cursor::new(buffer);

         let jumb_header = BoxReader::read_header(&mut buf_reader).unwrap();
         assert_eq!(jumb_header.size, 0x25);
         assert_eq!(jumb_header.name, BoxType::JumbBox);

         let jumd_header = BoxReader::read_header(&mut buf_reader).unwrap();
         assert_eq!(jumd_header.size, 0x21);
         assert_eq!(jumd_header.name, BoxType::JumdBox);

         let desc_box = BoxReader::read_desc_box(&mut buf_reader, jumd_header.size).unwrap();
         assert_eq!(desc_box.label(), labels::MANIFEST_STORE);
         assert_eq!(desc_box.uuid(), "6332706100110010800000AA00389B71");
     }
    */
    // ANCHOR: JSON Content Box Reader
    #[test]
    fn json_box_reader() {
        const JSON_BOX: &str ="0000005a6a756d620000002d6a756d646a736f6e00110010800000aa00389b7103633270612e6c6f636174696f6e2e62726f616400000000266a736f6e7b20226c6f636174696f6e223a202253616e204672616e636973636f227d";

        let buffer = hex::decode(JSON_BOX).expect("decode failed");
        let mut buf_reader = Cursor::new(buffer);
        let super_box = BoxReader::read_super_box(&mut buf_reader).unwrap();

        let desc_box = super_box.desc_box();
        assert_eq!(desc_box.label(), "c2pa.location.broad");
        assert_eq!(desc_box.uuid(), CAI_JSON_ASSERTION_UUID);
        assert_eq!(super_box.data_box_count(), 1);

        let json_box = super_box.data_box_as_json_box(0).unwrap();
        assert_eq!(json_box.box_uuid(), JUMBF_JSON_UUID);
        assert_eq!(json_box.json().len(), 30);
    }

    #[allow(dead_code)]
    fn check_one_box(
        parent_box: &JUMBFSuperBox,
        index: usize,
        count: usize,
        label: &str,
        uuid: &str,
    ) {
        let superbox = parent_box.data_box_as_superbox(index).unwrap();
        assert_eq!(superbox.box_uuid(), JUMB_FOURCC);
        assert_eq!(superbox.data_box_count(), count);

        let desc_box = superbox.desc_box();
        assert_eq!(desc_box.label(), label);
        assert_eq!(desc_box.uuid(), uuid);
    }

    // ANCHOR: Full CAI Block Reader
    /*
    #[test]
    fn cai_box_reader() {
        const CAI_BOX: &str ="0000026a6a756d62000000216a756d646332706100110010800000AA00389B71036332706100000002446a756d62000000246a756d6463326D6100110010800000AA00389B710363622e61646f62655f31000000008f6a756d62000000296a756d646332617300110010800000AA00389B7103633270612e617373657274696f6e73000000005e6a756d620000002d6a756d646a736f6e00110010800000aa00389b7103633270612e6c6f636174696f6e2e62726f616400000000296a736f6e7b20226c6f636174696f6e223a20224d61726761746520436974792c204e4a227d000001126a756d62000000276a756d646332636C00110010800000AA00389B7103633270612e636c61696d2e763100000000e36a736f6e7b0a202020202020202020202020227265636f7264657222203a202250686f746f73686f70222c0a202020202020202020202020227369676e617475726522203a202273656c66236a756d62663d735f61646f62655f31222c0a20202020202020202020202022617373657274696f6e7322203a205b0a202020202020202020202020202020202273656c66236a756d62663d61735f61646f62655f312f633270612e6c6f636174696f6e2e62726f61643f686c3d37363134324244363233363346220a2020202020202020202020205d0a20202020202020207d000000776a756d62000000286a756d646332637300110010800000AA00389B7103633270612e7369676e61747572650000000047757569646332637300110010800000AA00389B717468697320776f756c64206e6f726d616c6c792062652062696e617279207369676e617475726520646174612e2e2e";

        let buffer = hex::decode(CAI_BOX).expect("decode failed");
        let mut buf_reader = Cursor::new(buffer);

        // this loads up all the boxes...
        let super_box = BoxReader::read_super_box(&mut buf_reader).unwrap();
        let cai_block = Cai::from(super_box);

        // check the CAI Block
        let desc_box = cai_block.desc_box();
        assert_eq!(desc_box.label(), labels::MANIFEST_STORE);
        assert_eq!(desc_box.uuid(), CAI_BLOCK_UUID);

        // it's children are the CAI stores
        // for this test, we only have one...
        assert_eq!(cai_block.data_box_count(), 1);

        // retrieve the CAI store & validate it
        // a standard one has 3 children (assertion store, claim & sig)
        check_one_box(&cai_block.super_box(), 0, 3, "cb.adobe_1", CAI_STORE_UUID);
        let cai_store_box = cai_block.store();

        // retrieve the assertion store & validate
        check_one_box(
            &cai_store_box,
            0,
            1,
            "c2pa.assertions",
            CAI_ASSERTION_STORE_UUID,
        );

        let assertion_store_box = cai_store_box.data_box_as_superbox(0);

        // there is only one in our test, but doing a loop on general principle
        let num_assertions = assertion_store_box.data_box_count();
        assert_eq!(num_assertions, 1);

        for idx in 0..num_assertions {
            check_one_box(
                &assertion_store_box,
                idx,
                1,
                "c2pa.location.broad",
                CAI_JSON_ASSERTION_UUID,
            );

            let assertion_box = assertion_store_box.data_box_as_superbox(idx);
            let assertion_desc_box = assertion_box.desc_box();

            if assertion_desc_box.uuid() == CAI_JSON_ASSERTION_UUID {
                let json_box = assertion_box.data_box_as_json_box(0);
                assert_eq!(json_box.box_uuid(), JUMBF_JSON_UUID);
                assert_eq!(json_box.json().len(), 33);
            } else if assertion_desc_box.uuid() == CAI_CODESTREAM_ASSERTION_UUID {
                // this is where we'd validate for a thumbnail if we had one...
            }
        }

        // retrieve the claim & validate
        check_one_box(&cai_store_box, 1, 1, "c2pa.claim.v1", CAI_CLAIM_UUID);
        let claim_superbox = cai_store_box.data_box_as_superbox(1);
        let claim_desc_box = claim_superbox.desc_box();

        if claim_desc_box.uuid() == CAI_JSON_ASSERTION_UUID {
            // better be, but just in case...
            let json_box = claim_superbox.data_box_as_json_box(0);
            assert_eq!(json_box.box_uuid(), JUMBF_JSON_UUID);
            assert_eq!(json_box.json().len(), 164);
        }

        // retrieve the signature & validate
        check_one_box(&cai_store_box, 2, 1, "c2pa.signature", CAI_SIGNATURE_UUID);
        let sig_superbox = cai_store_box.data_box_as_superbox(2);
        let sig_desc_box = sig_superbox.desc_box();
        if sig_desc_box.uuid() == CAI_SIGNATURE_UUID {
            // better be, but just in case...
            let sig_box = sig_superbox.data_box_as_uuid_box(0);
            assert_eq!(sig_box.box_uuid(), JUMBF_UUID_UUID);
            assert_eq!(sig_box.data().len(), 47);
        }
    }
    */
}

// !SECTION
