// Copyright 2023 Adobe. All rights reserved.
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
    io::{Cursor, Read, Seek, SeekFrom, Write},
    slice,
};

use crate::Error;

#[repr(C)]
#[derive(Debug)]
/// An opaque struct to hold a context value for the stream callbacks.
pub struct StreamContext;

#[repr(C)]
#[derive(Debug)]
/// Defines the seek mode for the seek callback.
pub enum C2paSeekMode {
    /// Seeks from the start of the stream.
    Start = 0,

    /// Seeks from the current position in the stream.
    Current = 1,

    /// Seeks from the end of the stream.
    End = 2,
}

/// Defines a callback to read from a stream.
///
/// The return value is the number of bytes read, or a negative number for an error.
type ReadCallback =
    unsafe extern "C" fn(context: *mut StreamContext, data: *mut u8, len: isize) -> isize;

/// Defines a callback to seek to an offset in a stream.
///
/// The return value is the new position in the stream, or a negative number for an error.
type SeekCallback =
    unsafe extern "C" fn(context: *mut StreamContext, offset: isize, mode: C2paSeekMode) -> isize;

/// Defines a callback to write to a stream.
///
/// The return value is the number of bytes written, or a negative number for an error.
type WriteCallback =
    unsafe extern "C" fn(context: *mut StreamContext, data: *const u8, len: isize) -> isize;

/// Defines a callback to flush a stream.
///
/// The return value is 0 for success, or a negative number for an error.
type FlushCallback = unsafe extern "C" fn(context: *mut StreamContext) -> isize;

#[repr(C)]
/// A C2paStream is a Rust Read/Write/Seek stream that can be created and used in C.
#[derive(Debug)]
pub struct C2paStream {
    context: *mut StreamContext,
    reader: ReadCallback,
    seeker: SeekCallback,
    writer: WriteCallback,
    flusher: FlushCallback,
}

impl C2paStream {
    /// Creates a new C2paStream from context with callbacks.
    ///
    /// # Arguments
    /// * `context` - a pointer to a StreamContext
    /// * `read` - a ReadCallback to read from the stream
    /// * `seek` - a SeekCallback to seek in the stream
    /// * `write` - a WriteCallback to write to the stream
    /// * `flush` - a FlushCallback to flush the stream
    ///
    /// # Safety
    /// The context must remain valid for the lifetime of the C2paStream.
    ///
    /// The read, seek, and write callbacks must be valid for the lifetime of the C2paStream.
    ///
    /// The resulting C2paStream must be released by calling c2pa_release_stream.
    pub unsafe fn new(
        context: *mut StreamContext,
        reader: ReadCallback,
        seeker: SeekCallback,
        writer: WriteCallback,
        flusher: FlushCallback,
    ) -> Self {
        Self {
            context, // : unsafe { Box::from_raw(context) },
            reader,
            seeker,
            writer,
            flusher,
        }
    }

    /// Extracts the context from the C2paStream (used for testing in Rust).
    pub fn extract_context(&mut self) -> Box<StreamContext> {
        let context_ptr = std::mem::replace(&mut self.context, std::ptr::null_mut());
        unsafe { Box::from_raw(context_ptr) }
    }
}

impl Read for C2paStream {
    /// Reads bytes from the stream into the provided buffer.
    ///
    /// # Arguments
    /// * `buf` - a mutable slice where the read bytes will be stored
    ///
    /// # Returns
    /// * `Ok(usize)` - the number of bytes read
    /// * `Err(std::io::Error)` - an error occurred during reading
    ///
    /// # Errors
    /// * Returns an error if the buffer size exceeds `isize::MAX`
    /// * Returns an error if the underlying C callback returns an error too (negative value)
    /// ```
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.len() > isize::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Read buffer is too large",
            ));
        }

        let bytes_read =
            unsafe { (self.reader)(&mut (*self.context), buf.as_mut_ptr(), buf.len() as isize) };

        // Returns a negative number for errors.
        if bytes_read < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(bytes_read as usize)
    }
}

impl Seek for C2paStream {
    /// Seeks to a position in the stream.
    ///
    /// # Arguments
    /// * `from` - a seek mode and offset:
    ///   - `SeekFrom::Start(offset)` - Seeks from the beginning of the stream
    ///   - `SeekFrom::Current(offset)` - Seeks from the current position
    ///   - `SeekFrom::End(offset)` - Seeks from the end of the stream
    ///
    /// # Returns
    /// * `Ok(u64)` - the new position in the stream
    /// * `Err(std::io::Error)` - an error occurred during the seek operation
    ///
    /// # Errors
    /// * Returns an error if the underlying C callback returns an error too (negative value)
    /// ```
    fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
        let (pos, mode) = match from {
            std::io::SeekFrom::Current(pos) => (pos, C2paSeekMode::Current),
            std::io::SeekFrom::Start(pos) => (pos as i64, C2paSeekMode::Start),
            std::io::SeekFrom::End(pos) => (pos, C2paSeekMode::End),
        };

        let new_pos = unsafe { (self.seeker)(&mut (*self.context), pos as isize, mode) };
        if new_pos < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(new_pos as u64)
    }
}

impl Write for C2paStream {
    /// Writes bytes from the provided buffer to the stream.
    ///
    /// # Arguments
    /// * `buf` - a slice containing the bytes to write to the stream
    ///
    /// # Returns
    /// * `Ok(usize)` - the number of bytes written, which may be less than the buffer size
    /// * `Err(std::io::Error)` - an error occurred during the write operation
    ///
    /// # Errors
    /// * Returns an error if the buffer size exceeds `isize::MAX`
    /// * Returns an error if the underlying C callback returns an error too (negative value)
    /// ```
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > isize::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Write buffer is too large",
            ));
        }
        let bytes_written =
            unsafe { (self.writer)(&mut (*self.context), buf.as_ptr(), buf.len() as isize) };
        if bytes_written < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(bytes_written as usize)
    }

    /// Flushes the stream, ensuring buffered data is written.
    ///
    /// # Returns
    /// * `Ok(())` - the flush operation completed successfully
    /// * `Err(std::io::Error)` - an error occurred during the flush operation
    ///
    /// # Errors
    /// * Returns an error if the underlying C callback returns an error too (negative value)
    /// ```
    fn flush(&mut self) -> std::io::Result<()> {
        let err = unsafe { (self.flusher)(&mut (*self.context)) };
        if err < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

unsafe impl Send for C2paStream {}
unsafe impl Sync for C2paStream {}

/// Creates a new C2paStream from context with callbacks.
///
/// This allows implementing streams in other languages.
///
/// # Arguments
/// * `context` - a pointer to a StreamContext
/// * `read` - a ReadCallback to read from the stream
/// * `seek` - a SeekCallback to seek in the stream
/// * `write` - a WriteCallback to write to the stream
///
/// # Safety
/// The context must remain valid for the lifetime of the C2paStream.
///
/// The resulting C2paStream must be released by calling c2pa_release_stream.
#[no_mangle]
pub unsafe extern "C" fn c2pa_create_stream(
    context: *mut StreamContext,
    reader: ReadCallback,
    seeker: SeekCallback,
    writer: WriteCallback,
    flusher: FlushCallback,
) -> *mut C2paStream {
    Box::into_raw(Box::new(C2paStream::new(
        context, reader, seeker, writer, flusher,
    )))
}

/// Releases a C2paStream allocated by Rust.
///
/// # Safety
/// Can only be released once and is invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_release_stream(stream: *mut C2paStream) {
    if !stream.is_null() {
        drop(Box::from_raw(stream));
    }
}

/// This struct is used to test the C2paStream implementation.
///
/// It is a wrapper around a `Cursor<Vec<u8>>`.
///
/// It is exported in Rust so that it may be used externally.
pub struct TestC2paStream {
    cursor: Cursor<Vec<u8>>,
}

impl TestC2paStream {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            cursor: Cursor::new(data),
        }
    }

    unsafe extern "C" fn reader(context: *mut StreamContext, data: *mut u8, len: isize) -> isize {
        let stream: &mut TestC2paStream = &mut *(context as *mut TestC2paStream);
        let data: &mut [u8] = slice::from_raw_parts_mut(data, len as usize);
        match stream.cursor.read(data) {
            Ok(bytes) => bytes as isize,
            Err(e) => {
                crate::Error::set_last(Error::Io(e.to_string()));
                -1
            }
        }
    }

    unsafe extern "C" fn seeker(
        context: *mut StreamContext,
        offset: isize,
        mode: C2paSeekMode,
    ) -> isize {
        let stream: &mut TestC2paStream = &mut *(context as *mut TestC2paStream);

        match mode {
            C2paSeekMode::Start => {
                if offset < 0 {
                    crate::Error::set_last(Error::Io("Offset out of bounds".to_string()));
                    return -1;
                }
                stream.cursor.set_position(offset as u64);
            }

            C2paSeekMode::Current => match stream.cursor.seek(SeekFrom::Current(offset as i64)) {
                Ok(_) => {}
                Err(e) => {
                    crate::Error::set_last(Error::Io(e.to_string()));
                    return -1;
                }
            },

            C2paSeekMode::End => match stream.cursor.seek(SeekFrom::End(offset as i64)) {
                Ok(_) => {}
                Err(e) => {
                    crate::Error::set_last(Error::Io(e.to_string()));
                    return -1;
                }
            },
        }

        stream.cursor.position() as isize
    }

    unsafe extern "C" fn flusher(_context: *mut StreamContext) -> isize {
        0
    }

    unsafe extern "C" fn writer(context: *mut StreamContext, data: *const u8, len: isize) -> isize {
        let stream: &mut TestC2paStream = &mut *(context as *mut TestC2paStream);
        let data: &[u8] = slice::from_raw_parts(data, len as usize);
        match stream.cursor.write(data) {
            Ok(bytes) => bytes as isize,
            Err(e) => {
                crate::Error::set_last(Error::Io(e.to_string()));
                -1
            }
        }
    }

    pub fn into_c_stream(self) -> C2paStream {
        unsafe {
            C2paStream::new(
                Box::into_raw(Box::new(self)) as *mut StreamContext,
                Self::reader,
                Self::seeker,
                Self::writer,
                Self::flusher,
            )
        }
    }

    pub fn from_bytes(data: Vec<u8>) -> C2paStream {
        let test_stream = Self::new(data);
        test_stream.into_c_stream()
    }

    pub fn from_c_stream(mut c_stream: C2paStream) -> Self {
        let original_context = c_stream.extract_context();
        unsafe { *Box::from_raw(Box::into_raw(original_context) as *mut TestC2paStream) }
    }

    pub fn drop_c_stream(c_stream: C2paStream) {
        drop(Self::from_c_stream(c_stream));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cstream_read() {
        let data = vec![1, 2, 3, 4, 5];
        let mut c_stream = TestC2paStream::from_bytes(data);

        let mut buf = [0u8; 3];
        assert_eq!(c_stream.read(&mut buf).unwrap(), 3);
        assert_eq!(buf, [1, 2, 3]);

        let mut buf = [0u8; 3];
        assert_eq!(c_stream.read(&mut buf).unwrap(), 2);
        assert_eq!(buf, [4, 5, 0]);

        let _test_stream = TestC2paStream::from_c_stream(c_stream);
    }

    #[test]
    fn test_cstream_seek() {
        let data = vec![1, 2, 3, 4, 5];
        let mut c_stream = TestC2paStream::from_bytes(data);

        c_stream.seek(SeekFrom::Start(2)).unwrap();
        let mut buf = [0u8; 3];
        assert_eq!(c_stream.read(&mut buf).unwrap(), 3);
        assert_eq!(buf, [3, 4, 5]);

        c_stream.seek(SeekFrom::End(-2)).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(c_stream.read(&mut buf).unwrap(), 2);
        assert_eq!(buf, [4, 5]);

        c_stream.seek(SeekFrom::Current(-4)).unwrap();
        let mut buf = [0u8; 3];
        assert_eq!(c_stream.read(&mut buf).unwrap(), 3);
        assert_eq!(buf, [2, 3, 4]);

        TestC2paStream::drop_c_stream(c_stream);
    }

    #[test]
    fn test_cstream_write() {
        let data = vec![1, 2, 3, 4, 5];
        let mut c_stream = TestC2paStream::from_bytes(data);
        c_stream.seek(SeekFrom::End(0)).unwrap();
        let buf = [6, 7, 8];
        let bytes_written = c_stream.write(&buf).unwrap();
        assert_eq!(bytes_written, 3);
        assert_eq!(c_stream.seek(SeekFrom::End(0)).unwrap(), 8);
        TestC2paStream::drop_c_stream(c_stream);
    }

    #[test]
    fn test_cstream_read_empty() {
        let data = vec![];
        let mut c_stream = TestC2paStream::from_bytes(data);

        let mut buf = [0u8; 3];
        assert_eq!(c_stream.read(&mut buf).unwrap(), 0);
        assert_eq!(buf, [0, 0, 0]);

        TestC2paStream::drop_c_stream(c_stream);
    }

    #[test]
    fn test_cstream_seek_out_of_bounds() {
        let data = vec![1, 2, 3, 4, 5];
        let mut c_stream = TestC2paStream::from_bytes(data);

        // Seek before the start of the stream
        assert!(c_stream.seek(SeekFrom::Start(10)).is_ok());

        // Seek to a negative position
        assert!(c_stream.seek(SeekFrom::Current(-20)).is_err());

        TestC2paStream::drop_c_stream(c_stream);
    }

    #[test]
    fn test_cstream_write_overwrite() {
        let data = vec![1, 2, 3, 4, 5];
        let mut c_stream = TestC2paStream::from_bytes(data);

        c_stream.seek(SeekFrom::Start(2)).unwrap();
        let buf = [9, 9];
        let bytes_written = c_stream.write(&buf).unwrap();
        assert_eq!(bytes_written, 2);

        c_stream.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = [0u8; 5];
        assert_eq!(c_stream.read(&mut buf).unwrap(), 5);
        assert_eq!(buf, [1, 2, 9, 9, 5]);

        TestC2paStream::drop_c_stream(c_stream);
    }

    #[test]
    fn test_cstream_flush() {
        let data = vec![1, 2, 3, 4, 5];
        let mut c_stream = TestC2paStream::from_bytes(data);

        // Flush should succeed without errors
        assert!(c_stream.flush().is_ok());

        TestC2paStream::drop_c_stream(c_stream);
    }

    #[test]
    fn test_cstream_large_read() {
        let data = vec![1, 2, 3, 4, 5];
        let mut c_stream = TestC2paStream::from_bytes(data);

        let mut buf = [0u8; 10];
        assert_eq!(c_stream.read(&mut buf).unwrap(), 5);
        assert_eq!(buf[..5], [1, 2, 3, 4, 5]);
        assert_eq!(buf[5..], [0, 0, 0, 0, 0]);

        TestC2paStream::drop_c_stream(c_stream);
    }

    #[test]
    fn test_cstream_large_write() {
        let data = vec![1, 2, 3];
        let mut c_stream = TestC2paStream::from_bytes(data);

        c_stream.seek(SeekFrom::End(0)).unwrap();
        let buf = [6, 7, 8, 9, 10];
        let bytes_written = c_stream.write(&buf).unwrap();
        assert_eq!(bytes_written, 5);

        c_stream.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(c_stream.read(&mut buf).unwrap(), 8);
        assert_eq!(buf, [1, 2, 3, 6, 7, 8, 9, 10]);

        TestC2paStream::drop_c_stream(c_stream);
    }

    #[test]
    fn test_cstream_seek_to_end() {
        let data = vec![1, 2, 3, 4, 5];
        let mut c_stream = TestC2paStream::from_bytes(data);

        let end_pos = c_stream.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(end_pos, 5);

        let mut buf = [0u8; 1];
        assert_eq!(c_stream.read(&mut buf).unwrap(), 0); // No data to read at the end

        TestC2paStream::drop_c_stream(c_stream);
    }

    #[test]
    fn test_create_stream() {
        let test_stream = TestC2paStream::new(vec![1, 2, 3, 4, 5]);
        let context = Box::into_raw(Box::new(test_stream));
        let context_ptr = context as *mut StreamContext;

        let c2pa_stream = unsafe {
            c2pa_create_stream(
                context_ptr,
                TestC2paStream::reader,
                TestC2paStream::seeker,
                TestC2paStream::writer,
                TestC2paStream::flusher,
            )
        };

        let c2pa_stream = unsafe { &mut *c2pa_stream };
        let mut buf = [0u8; 3];

        let result = c2pa_stream.read(&mut buf);

        result.expect("Failed to read from C2paStream");
        assert_eq!(buf, [1, 2, 3]);

        unsafe { c2pa_release_stream(c2pa_stream) };
    }
}
