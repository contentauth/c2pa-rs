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

//! This is a library for I/O related constituent elements
//!
//! It is based on the work of Takeru Ohta <phjgt308@gmail.com>
//! and [mse_fmp4](https://github.com/sile/mse_fmp4)

use std::io::{sink, Result as IoResult, Sink, Write};

#[derive(Debug)]
pub struct ByteCounter<T> {
    inner: T,
    count: usize,
}

impl<T> ByteCounter<T> {
    pub fn new(inner: T) -> Self {
        ByteCounter { inner, count: 0 }
    }

    pub fn count(&self) -> usize {
        self.count
    }
}

impl ByteCounter<Sink> {
    pub fn with_sink() -> Self {
        Self::new(sink())
    }

    pub fn calculate<F>(f: F) -> IoResult<u64>
    where
        F: FnOnce(&mut Self) -> IoResult<()>,
    {
        let mut writer = ByteCounter::with_sink();
        f(&mut writer)?;
        Ok(writer.count() as u64)
    }
}

impl<T: Write> Write for ByteCounter<T> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        let size = self.inner.write(buf)?;
        self.count += size;
        Ok(size)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.inner.flush()
    }
}
