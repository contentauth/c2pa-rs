// Copyright 2024 Adobe. All rights reserved.
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

use std::io::{Read, Seek, SeekFrom, Write};

use crate::{Error, Result};

// Insert data at arbitrary location in a stream.
// location is from the start of the source stream
#[allow(dead_code)]
pub(crate) fn insert_data_at<R: Read + Seek, W: Write>(
    source: &mut R,
    dest: &mut W,
    location: u64,
    data: &[u8],
) -> Result<()> {
    source.rewind()?;

    let mut before_handle = source.take(location);

    std::io::copy(&mut before_handle, dest)?;

    // write out the data
    dest.write_all(data)?;

    // write out the rest of the source
    let source = before_handle.into_inner();
    source.seek(SeekFrom::Start(location))?;
    std::io::copy(source, dest)?;

    Ok(())
}

// Returns length of the stream, stream position is preserved
#[allow(dead_code)]
pub(crate) fn stream_len<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<u64> {
    let old_pos = reader.stream_position()?;
    let len = reader.seek(SeekFrom::End(0))?;

    if old_pos != len {
        reader.seek(SeekFrom::Start(old_pos))?;
    }

    Ok(len)
}

// Returns a new Vec first making sure it can hold the desired capacity.  Fill
// with default value if provided
pub(crate) fn safe_vec<T: Clone>(item_cnt: u64, init_with: Option<T>) -> Result<Vec<T>> {
    let num_items = usize::try_from(item_cnt)?;

    // make sure we can allocate vec
    let mut output: Vec<T> = Vec::new();
    output
        .try_reserve_exact(num_items)
        .map_err(|_e| Error::InsufficientMemory)?;

    // fill if requested
    if let Some(i) = init_with {
        output.resize(num_items, i);
    }

    Ok(output)
}

pub trait ReaderUtils {
    // Reads contents from a stream making sure if can be done and will fit within available memory
    fn read_to_vec(&mut self, data_len: u64) -> Result<Vec<u8>>;

    // Return the length of the stream
    fn stream_size(&mut self) -> Result<u64>;
}

// Provide implementation for any object that support Read + Seek
impl<R: Read + Seek> ReaderUtils for R {
    fn read_to_vec(&mut self, data_len: u64) -> Result<Vec<u8>> {
        let old_pos = self.stream_position()?;
        let len = self.seek(SeekFrom::End(0))?;

        // reset seek pointer
        if old_pos != len {
            self.seek(SeekFrom::Start(old_pos))?;
        }

        if old_pos
            .checked_add(data_len)
            .ok_or(Error::BadParam("file read out of range".into()))?
            > len
        {
            return Err(Error::BadParam("read past file end".into()));
        }

        // make sure we can allocate vec
        let mut output: Vec<u8> = safe_vec(data_len, None)?;

        self.take(data_len).read_to_end(&mut output)?;

        Ok(output)
    }

    fn stream_size(&mut self) -> Result<u64> {
        stream_len(self)
    }
}
