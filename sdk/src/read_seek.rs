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

use std::io::{Cursor, Read, Seek, Write};

use crate::maybe_send_sync::MaybeSend;

/// Marker trait for a seekable, readable stream that can be sent across threads.
///
/// Blanket-implemented for any type that is `Read + Seek + Send` (or `Read + Seek`
/// on targets without threading). Exists so it can be used in `dyn` position
/// (`&mut dyn ReadSeek`) — Rust trait objects can only name one non-auto trait, so
/// this trait exists to bundle `Read` + `Seek` into one.
///
/// `&mut dyn ReadSeek` itself implements `Read`/`Seek` (via std's blanket impls for
/// `&mut R`), so it can be passed directly to third-party generic functions like
/// `fn read<T: Read + Seek>(reader: T)` — reborrow with `&mut *stream` (or, for
/// `fn read<T: Read + Seek>(reader: &mut T)`, `&mut stream` on a `mut` binding) to
/// avoid moving the original reference.
pub trait ReadSeek: Read + Seek + MaybeSend {}

impl<T> ReadSeek for T where T: Read + Seek + MaybeSend {}

impl From<String> for Box<dyn ReadSeek> {
    fn from(val: String) -> Self {
        Box::new(Cursor::new(val))
    }
}

/// Marker trait for a seekable, readable, writable stream that can be sent across
/// threads.
///
/// Blanket-implemented for any type that is `ReadSeek + Write`. Exists for the same
/// reason as [`ReadSeek`]: to bundle multiple traits into one for use in `dyn`
/// position (`&mut dyn ReadWriteSeek`).
pub trait ReadWriteSeek: ReadSeek + Write {}

impl<T> ReadWriteSeek for T where T: ReadSeek + Write {}
