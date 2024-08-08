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

use crate::{ByteSpan, CodecError, DataHash, Decode, Encode, Hash, Span, Support};

/// Supports working with ".c2pa" files containing only manifest store data
#[derive(Debug)]
pub struct C2paCodec<R> {
    src: R,
}

impl<R> C2paCodec<R> {
    pub fn new(src: R) -> Self {
        Self { src }
    }
}

impl Support for C2paCodec<()> {
    const MAX_SIGNATURE_LEN: usize = 0;

    fn supports_signature(_signature: &[u8]) -> bool {
        false
    }

    fn supports_extension(extension: &str) -> bool {
        extension == "c2pa"
    }

    fn supports_mime(mime: &str) -> bool {
        mime == "application/c2pa" || mime == "application/x-c2pa-manifest-store"
    }
}

impl<R: Read + Seek> Decode for C2paCodec<R> {
    fn read_c2pa(&mut self) -> Result<Option<Vec<u8>>, CodecError> {
        let mut cai_data = Vec::new();
        // read the whole file
        self.src.read_to_end(&mut cai_data)?;
        Ok(Some(cai_data))
    }
}

impl<R: Read + Seek> Encode for C2paCodec<R> {
    fn write_c2pa(&mut self, mut dst: impl Write, c2pa: &[u8]) -> Result<(), CodecError> {
        // just write the store bytes and ingore the input stream
        dst.write_all(c2pa)?;
        Ok(())
    }

    fn remove_c2pa(&mut self, _dst: impl Write) -> Result<bool, CodecError> {
        // TODO: true or false?
        Ok(false)
    }

    fn patch_c2pa(&self, mut dst: impl Read + Write + Seek, c2pa: &[u8]) -> Result<(), CodecError> {
        dst.write_all(c2pa)?;
        Ok(())
    }
}

impl<R: Read + Seek> Span for C2paCodec<R> {
    fn hash(&mut self) -> Result<Hash, CodecError> {
        todo!()
    }

    fn data_hash(&mut self) -> Result<DataHash, CodecError> {
        Ok(DataHash {
            spans: vec![ByteSpan { start: 0, len: 0 }],
        })
    }
}
