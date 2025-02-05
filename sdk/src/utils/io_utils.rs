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

use std::{
    ffi::OsStr,
    io::{Read, Seek, SeekFrom, Write},
};

#[allow(unused)] // different code path for WASI
use tempfile::{tempdir, Builder, NamedTempFile, TempDir};

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

// Replace data at arbitrary location and len in a stream.
// start_location is where the replacement data will start
// replace_len is how many bytes from source to replaced starting a start_location
// data is the data that will be inserted at start_location
#[allow(dead_code)]
pub(crate) fn patch_stream<R: Read + Seek + ?Sized, W: Write + ?Sized>(
    source: &mut R,
    dest: &mut W,
    start_location: u64,
    replace_len: u64,
    data: &[u8],
) -> Result<()> {
    source.rewind()?;
    let source_len = stream_len(source)?;

    if start_location + replace_len > source_len {
        return Err(Error::BadParam("read past end of source stream".into()));
    }

    let mut before_handle = source.take(start_location);

    // copy data before start location
    std::io::copy(&mut before_handle, dest)?;

    // write out new data
    dest.write_all(data)?;

    // write out the rest of the source skipping the bytes we wanted to replace
    let source = before_handle.into_inner();
    source.seek(SeekFrom::Start(start_location + replace_len))?;
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
            .ok_or(Error::BadParam("source stream read out of range".into()))?
            > len
        {
            return Err(Error::BadParam("read past end of source stream".into()));
        }

        // make sure we can allocate vec
        let mut output: Vec<u8> = safe_vec(data_len, None)?;

        self.take(data_len).read_to_end(&mut output)?;

        Ok(output)
    }
}

pub(crate) fn tempfile_builder<T: AsRef<OsStr> + Sized>(prefix: T) -> Result<NamedTempFile> {
    #[cfg(all(target_os = "wasi", target_env = "p1"))]
    return Error::NotImplemented("tempfile_builder requires wasip2 or later".to_string());

    #[cfg(all(target_os = "wasi", not(target_env = "p1")))]
    return Builder::new()
        .prefix(&prefix)
        .rand_bytes(5)
        .tempfile_in("/")
        .map_err(Error::IoError);

    #[cfg(not(target_os = "wasi"))]
    return Builder::new()
        .prefix(&prefix)
        .rand_bytes(5)
        .tempfile()
        .map_err(Error::IoError);
}

#[allow(dead_code)] // used in tests
pub(crate) fn tempdirectory() -> Result<TempDir> {
    #[cfg(target_os = "wasi")]
    return TempDir::new_in("/").map_err(|e| Error::IoError(e.into()));

    #[cfg(not(target_os = "wasi"))]
    return tempdir().map_err(Error::IoError);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    //use env_logger;
    use super::*;

    #[test]
    fn test_patch_stream() {
        let source = "this is a very very good test";

        // test truncation
        let mut output = Vec::new();
        patch_stream(&mut Cursor::new(source.as_bytes()), &mut output, 10, 5, &[]).unwrap();
        assert_eq!(&output, "this is a very good test".as_bytes());

        // test truncation with new data
        let mut output = Vec::new();
        patch_stream(
            &mut Cursor::new(source.as_bytes()),
            &mut output,
            10,
            14,
            "so so".as_bytes(),
        )
        .unwrap();
        assert_eq!(&output, "this is a so so test".as_bytes());

        // test insertion, leaving existing data
        let mut output = Vec::new();
        patch_stream(
            &mut Cursor::new(source.as_bytes()),
            &mut output,
            10,
            0,
            "very ".as_bytes(),
        )
        .unwrap();
        assert_eq!(&output, "this is a very very very good test".as_bytes());

        // test replacement of data
        let mut output = Vec::new();
        patch_stream(
            &mut Cursor::new(source.as_bytes()),
            &mut output,
            0,
            29,
            "all new data".as_bytes(),
        )
        .unwrap();
        assert_eq!(&output, "all new data".as_bytes());

        // test removal of all data
        let mut output = Vec::new();
        patch_stream(&mut Cursor::new(source.as_bytes()), &mut output, 0, 29, &[]).unwrap();
        assert_eq!(&output, "".as_bytes());

        // test replacement of too much data
        let mut output = Vec::new();
        assert!(patch_stream(
            &mut Cursor::new(source.as_bytes()),
            &mut output,
            10,
            29,
            &[],
        )
        .is_err());
    }
}
