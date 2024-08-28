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

use crate::Result;

/// Insert data at arbitrary location in a stream.  
/// location is from the start of the source stream
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

/// returns length of the steam
pub(crate) fn stream_len<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<u64> {
    let old_pos = reader.stream_position()?;
    let len = reader.seek(SeekFrom::End(0))?;

    if old_pos != len {
        reader.seek(SeekFrom::Start(old_pos))?;
    }

    Ok(len)
}
