// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

//! Inline port of `sdk::utils::io_utils::ReaderUtils` — used by the JUMBF
//! box parser in `jumbf::boxes`.

use std::io::{Read, Result, Seek, SeekFrom};

pub trait ReaderUtils {
    fn read_to_vec(&mut self, data_len: u64) -> Result<Vec<u8>>;
}

impl<R: Read + Seek> ReaderUtils for R {
    fn read_to_vec(&mut self, data_len: u64) -> Result<Vec<u8>> {
        let old_pos = self.stream_position()?;
        let len = self.seek(SeekFrom::End(0))?;

        if old_pos != len {
            self.seek(SeekFrom::Start(old_pos))?;
        }

        if old_pos.saturating_add(data_len) > len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "read past end of stream",
            ));
        }

        let n = data_len as usize;
        let mut buf = Vec::new();
        buf.try_reserve_exact(n).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::OutOfMemory, "allocation failed")
        })?;
        buf.resize(n, 0);
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}
