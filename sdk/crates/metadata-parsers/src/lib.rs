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

use std::io::{Read, Seek, Write};

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use thiserror::Error;

mod asset_handlers;
mod xmp;

// TODO: temp
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct BoxMap {
    pub names: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    pub hash: ByteBuf,
    pub pad: ByteBuf,

    #[serde(skip)]
    pub range_start: usize,

    #[serde(skip)]
    pub range_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashBlockObjectType {
    Cai,
    Xmp,
    Other,
}

#[derive(Debug, PartialEq)]
pub struct HashObjectPositions {
    pub offset: usize, // offset from beginning of file to the beginning of object
    pub length: usize, // length of object
    pub htype: HashBlockObjectType, // type of hash block object
}

pub trait CAIRead: Read + Seek + Send {}

impl<T> CAIRead for T where T: Read + Seek + Send {}

pub trait CAIReadWrite: CAIRead + Write {}

impl<T> CAIReadWrite for T where T: CAIRead + Write {}

/// CAIReader trait to insure CAILoader method support both Read & Seek
// Interface for in memory CAI reading
pub trait C2paReader: Sync + Send {
    // Return entire CAI block as Vec<u8>
    fn read_c2pa(&self, src: impl Read + Seek) -> Result<Vec<u8>, ParseError>;

    // Get XMP block
    fn read_xmp(&self, src: impl Read + Seek) -> Result<String, ParseError> {
        Err(ParseError::Unsupported)
    }
}

pub trait C2paWriter: Sync + Send {
    // Writes store_bytes into output_steam using input_stream as the source asset
    fn write_c2pa(
        &self,
        src: impl Read + Seek,
        dst: impl Read + Write + Seek,
        bytes: &[u8],
    ) -> Result<(), ParseError>;

    // Remove entire C2PA manifest store from asset
    fn remove_c2pa(
        &self,
        src: impl Read + Seek,
        dst: impl Read + Write + Seek,
    ) -> Result<(), ParseError>;

    fn patch_c2pa(&self, src: impl Read + Seek, bytes: &[u8]) -> Result<(), ParseError>;

    fn write_xmp(
        &self,
        src: impl Read + Seek,
        dst: impl Read + Write + Seek,
        xmp: String,
    ) -> Result<(), ParseError> {
        Err(ParseError::Unsupported)
    }
}

pub trait Hasher {
    fn data_hash(&self, src: dyn CAIRead) -> Result<Vec<HashObjectPositions>, ParseError> {
        Err(ParseError::Unsupported)
    }

    fn box_hash(&self, src: dyn CAIRead) -> Result<Vec<BoxMap>, ParseError> {
        Err(ParseError::Unsupported)
    }

    fn bmff_hash(&self, src: dyn CAIRead) -> Result<Vec<()>, ParseError> {
        Err(ParseError::Unsupported)
    }

    fn collection_hash(&self, src: dyn CAIRead) -> Result<Vec<()>, ParseError> {
        Err(ParseError::Unsupported)
    }
}

pub trait Parser {
    fn new() -> Self
    where
        Self: Sized;

    // TODO: return enum
    fn supported_types(&self) -> &[&str];

    fn infer_type(&self, src: dyn CAIRead) -> &str {
        // TODO: this function will infer the mime from the magic signature
        todo!()
    }
}

#[derive(Debug, Error)]
pub enum ParseError {
    // TODO
    #[error("TODO")]
    Unsupported,
}
