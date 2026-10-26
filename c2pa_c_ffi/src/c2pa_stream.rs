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
    fs::File,
    io::{Cursor, Read, Seek, SeekFrom, Write},
    os::raw::{c_int, c_uchar},
    slice,
};

use cimpl::{
    box_tracked, bytes_or_return_null, cimpl_free, deref_mut_or_return_int, deref_or_return_int,
    out_bytes_or_return_int, untrack_owned, Error as CimplError,
};
#[cfg(test)]
use cimpl::{deref_mut_option, TypedExclusive};

use crate::{
    error::C2paError,
    macros::{ok_or_return_int, ok_or_return_null},
};
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

/// A C2paStream is a Rust Read/Write/Seek stream that can be created and used in C.
///
/// It is backed by callbacks implemented in the calling language ([`c2pa_create_stream`]),
/// or natively, without callbacks, by an open file ([`c2pa_create_stream_from_fd`]) or by a
/// buffer the stream owns ([`c2pa_create_stream_from_bytes`]).
///
/// Not `#[repr(C)]`, so cbindgen writes an opaque forward declaration: the C FFI
/// now handles opaque ids, and we shouldn't dereference anything directly anymore.
#[derive(Debug)]
pub struct C2paStream(StreamBacking);

#[derive(Debug)]
enum StreamBacking {
    Callbacks(CallbackStream),
    File(File),
    Memory(Cursor<Vec<u8>>),
}

/// A stream whose reads, seeks, writes and flushes call back into the calling language.
#[derive(Debug)]
struct CallbackStream {
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
        Self(StreamBacking::Callbacks(CallbackStream {
            context, // : unsafe { Box::from_raw(context) },
            reader,
            seeker,
            writer,
            flusher,
        }))
    }

    /// Creates a new C2paStream that reads and writes `file` natively.
    pub fn from_file(file: File) -> Self {
        Self(StreamBacking::File(file))
    }

    /// Creates a new C2paStream that reads and writes `bytes` in memory, starting at offset 0.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(StreamBacking::Memory(Cursor::new(bytes)))
    }

    /// The contents of a memory stream, or None for any other stream.
    pub fn memory_contents(&self) -> Option<&[u8]> {
        match &self.0 {
            StreamBacking::Memory(cursor) => Some(cursor.get_ref()),
            _ => None,
        }
    }
}

impl Read for C2paStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.0 {
            StreamBacking::Callbacks(stream) => stream.read(buf),
            StreamBacking::File(file) => file.read(buf),
            StreamBacking::Memory(cursor) => cursor.read(buf),
        }
    }
}

impl Seek for C2paStream {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        match &mut self.0 {
            StreamBacking::Callbacks(stream) => stream.seek(from),
            StreamBacking::File(file) => file.seek(from),
            StreamBacking::Memory(cursor) => cursor.seek(from),
        }
    }
}

impl Write for C2paStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.0 {
            StreamBacking::Callbacks(stream) => stream.write(buf),
            StreamBacking::File(file) => file.write(buf),
            StreamBacking::Memory(cursor) => cursor.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.0 {
            StreamBacking::Callbacks(stream) => stream.flush(),
            StreamBacking::File(file) => file.flush(),
            StreamBacking::Memory(cursor) => cursor.flush(),
        }
    }
}

impl Read for CallbackStream {
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
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.len() > isize::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Read buffer is too large",
            ));
        }

        let bytes_read =
            unsafe { (self.reader)(self.context, buf.as_mut_ptr(), buf.len() as isize) };

        // Returns a negative number for errors.
        if bytes_read < 0 {
            return Err(CimplError::last_message()
                .map(|msg| {
                    let _ = CimplError::take_last(); // Clear ONLY on error path
                    std::io::Error::other(msg)
                })
                .unwrap_or_else(std::io::Error::last_os_error));
        }

        Ok(bytes_read as usize)
    }
}

impl Seek for CallbackStream {
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
    fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
        let out_of_range = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek callback: stream offset out of range",
            )
        };
        let (pos, mode) = match from {
            std::io::SeekFrom::Current(pos) => (pos, C2paSeekMode::Current),
            std::io::SeekFrom::Start(pos) => (
                i64::try_from(pos).map_err(|_| out_of_range())?,
                C2paSeekMode::Start,
            ),
            std::io::SeekFrom::End(pos) => (pos, C2paSeekMode::End),
        };
        let pos = isize::try_from(pos).map_err(|_| out_of_range())?;

        let new_pos = unsafe { (self.seeker)(self.context, pos, mode) };
        if new_pos < 0 {
            return Err(CimplError::last_message()
                .map(|msg| {
                    let _ = CimplError::take_last(); // Clear ONLY on error path
                    std::io::Error::other(msg)
                })
                .unwrap_or_else(std::io::Error::last_os_error));
        }
        Ok(new_pos as u64)
    }
}

impl Write for CallbackStream {
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
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > isize::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Write buffer is too large",
            ));
        }
        let bytes_written =
            unsafe { (self.writer)(self.context, buf.as_ptr(), buf.len() as isize) };
        if bytes_written < 0 {
            return Err(CimplError::last_message()
                .map(|msg| {
                    let _ = CimplError::take_last(); // Clear ONLY on error path
                    std::io::Error::other(msg)
                })
                .unwrap_or_else(std::io::Error::last_os_error));
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
    fn flush(&mut self) -> std::io::Result<()> {
        let err = unsafe { (self.flusher)(self.context) };
        if err < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

// SAFETY: CallbackStream = 4 C function pointers + 1 context pointer.
// The callbacks and context should be safe to call from any thread.
unsafe impl Send for CallbackStream {}
unsafe impl Sync for CallbackStream {}

#[cfg(test)]
/// Test-only wrapper around a tracked C2paStream for cleaner test code.
///
/// This wrapper:
/// - Manages the tracked pointer lifecycle
/// - Provides convenient mutable access
/// - Automatically cleans up on drop
pub struct TestStream(*mut C2paStream);

#[cfg(test)]
impl TestStream {
    /// Creates a new TestStream from a Vec<u8>
    pub fn new(data: Vec<u8>) -> Self {
        Self(TestC2paStream::new(data).into_c_stream())
    }

    /// Borrow the C2paStream, with the guard keeping it alive as long as needed.
    /// Used through `Deref`/`DerefMut`.
    pub fn stream_mut(&mut self) -> TypedExclusive<C2paStream> {
        deref_mut_option!(self.0, C2paStream).expect("TestStream always wraps a tracked C2paStream")
    }

    /// Gets the raw pointer (for passing to C API functions)
    pub fn as_ptr(&mut self) -> *mut C2paStream {
        self.0
    }
}

#[cfg(test)]
impl Drop for TestStream {
    fn drop(&mut self) {
        unsafe {
            TestC2paStream::drop_c_stream(self.0);
        }
    }
}

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
/// # Callback contract
///
/// A callback must not block forever:
/// the handles it borrowed stay borrowed (during the run).
/// Not returning from the callback means handles can't be freed anymore.
///
/// Apply a timeout inside the callback, to avoid spinning forever.
/// Return -1 to propagate an error on failure.
///
/// # Safety
/// The context must remain valid for the lifetime of the C2paStream.
///
/// The callbacks and the context must be safe to invoke from any thread.
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
    box_tracked!(C2paStream::new(context, reader, seeker, writer, flusher,))
}

/// Creates a new C2paStream that reads and writes an open file natively, without callbacks.
///
/// Every read, seek and write happens in native code. Bindings whose stream callbacks must
/// re-enter their runtime (for instance retake Python's GIL, once per callback) can hand
/// regular files to this instead of [`c2pa_create_stream`]: an asset needs tens of thousands
/// of stream operations.
///
/// The stream owns a duplicate of `fd`: the caller keeps owning `fd` and may close it at any
/// time. Both share the file position, so the stream starts at the descriptor's current offset
/// and leaves it wherever the stream stopped. On Windows, `fd` is a C runtime file descriptor
/// (as returned by `_open` or `_fileno`).
///
/// # Errors
/// Returns NULL if `fd` is not an open descriptor or cannot be duplicated, and on platforms
/// without file descriptors. The error can be retrieved with `c2pa_error`.
///
/// # Safety
/// `fd` must be an open file descriptor for the duration of this call.
///
/// The resulting C2paStream must be released by calling c2pa_release_stream.
#[no_mangle]
pub unsafe extern "C" fn c2pa_create_stream_from_fd(fd: c_int) -> *mut C2paStream {
    let file = ok_or_return_null!(duplicate_fd(fd));
    box_tracked!(C2paStream::from_file(file))
}

/// Creates a new C2paStream that reads and writes a copy of `data` in memory, without callbacks.
///
/// Every read, seek and write happens in native code, like [`c2pa_create_stream_from_fd`], for
/// assets the caller holds in memory. The stream owns a copy of the `len` bytes at `data` and
/// starts at offset 0. Writes past the end grow it. Pass `data` = NULL and `len` = 0 for an
/// empty stream to sign into, then read the result with [`c2pa_stream_get_bytes`].
///
/// # Errors
/// Returns NULL if `data` is NULL with a non-zero `len`. The error can be retrieved with
/// `c2pa_error`.
///
/// # Safety
/// `data` must point to `len` readable bytes for the duration of this call.
///
/// The resulting C2paStream must be released by calling c2pa_release_stream.
#[no_mangle]
pub unsafe extern "C" fn c2pa_create_stream_from_bytes(
    data: *const c_uchar,
    len: usize,
) -> *mut C2paStream {
    let bytes = if data.is_null() && len == 0 {
        Vec::new()
    } else {
        bytes_or_return_null!(data, len, "data").to_vec()
    };
    box_tracked!(C2paStream::from_bytes(bytes))
}

/// Copies the whole contents of a stream made by [`c2pa_create_stream_from_bytes`].
///
/// The contents are returned whatever the stream's position, and the position is unchanged.
///
/// # Parameters
/// * stream: a stream made by [`c2pa_create_stream_from_bytes`].
/// * bytes_ptr: pointer to a pointer to a c_uchar to return the contents (optional, can be
///   NULL to only get their size). Set to NULL for an empty stream.
///
/// # Errors
/// Returns -1 if `stream` is not a memory stream. The error can be retrieved with `c2pa_error`.
///
/// # Safety
/// If `bytes_ptr` is not NULL, the returned bytes must be released by calling c2pa_free.
#[no_mangle]
pub unsafe extern "C" fn c2pa_stream_get_bytes(
    stream: *mut C2paStream,
    bytes_ptr: *mut *const c_uchar,
) -> i64 {
    let stream = deref_or_return_int!(stream, C2paStream);
    let bytes: &[u8] =
        ok_or_return_int!(stream.memory_contents().ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a stream made by c2pa_create_stream_from_bytes",
        )));
    out_bytes_or_return_int!(bytes.to_vec(), bytes_ptr)
}

/// Opens an owned duplicate of an open file descriptor.
#[cfg(unix)]
unsafe fn duplicate_fd(fd: c_int) -> std::io::Result<File> {
    use std::os::fd::BorrowedFd;

    if fd < 0 {
        return Err(invalid_fd());
    }
    // SAFETY: the caller guarantees `fd` is open for the duration of this call.
    let owned = unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()?;
    Ok(File::from(owned))
}

/// Opens an owned duplicate of the handle behind a C runtime file descriptor.
#[cfg(windows)]
unsafe fn duplicate_fd(fd: c_int) -> std::io::Result<File> {
    use std::os::windows::io::{BorrowedHandle, RawHandle};

    let handle = unsafe { libc::get_osfhandle(fd) };
    if handle == -1 {
        return Err(invalid_fd());
    }
    // SAFETY: the C runtime owns `handle` while `fd` is open, for the duration of this call.
    let owned = unsafe { BorrowedHandle::borrow_raw(handle as RawHandle) }.try_clone_to_owned()?;
    Ok(File::from(owned))
}

#[cfg(not(any(unix, windows)))]
unsafe fn duplicate_fd(_fd: c_int) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "file descriptor streams are not supported on this platform",
    ))
}

#[cfg(any(unix, windows))]
fn invalid_fd() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "not an open file descriptor",
    )
}

/// Releases a C2paStream allocated by Rust.
///
/// # Safety
/// Can only be released once and is invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_release_stream(stream: *mut C2paStream) {
    cimpl_free(stream as *mut std::ffi::c_void);
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
        let mut stream = deref_mut_or_return_int!(context as *mut TestC2paStream, TestC2paStream);
        let data: &mut [u8] = slice::from_raw_parts_mut(data, len as usize);
        ok_or_return_int!(stream.cursor.read(data)) as isize
    }

    unsafe extern "C" fn seeker(
        context: *mut StreamContext,
        offset: isize,
        mode: C2paSeekMode,
    ) -> isize {
        let mut stream = deref_mut_or_return_int!(context as *mut TestC2paStream, TestC2paStream);

        match mode {
            C2paSeekMode::Start => {
                if offset < 0 {
                    CimplError::set_last(CimplError::from(C2paError::Other(
                        "Offset out of bounds".to_string(),
                    )));
                    return -1;
                }
                stream.cursor.set_position(offset as u64);
            }

            C2paSeekMode::Current => match stream.cursor.seek(SeekFrom::Current(offset as i64)) {
                Ok(_) => {}
                Err(e) => {
                    CimplError::set_last(CimplError::from(C2paError::Io(e.to_string())));
                    return -1;
                }
            },

            C2paSeekMode::End => match stream.cursor.seek(SeekFrom::End(offset as i64)) {
                Ok(_) => {}
                Err(e) => {
                    CimplError::set_last(CimplError::from(C2paError::Io(e.to_string())));
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
        let mut stream = deref_mut_or_return_int!(context as *mut TestC2paStream, TestC2paStream);
        let data: &[u8] = slice::from_raw_parts(data, len as usize);
        match stream.cursor.write(data) {
            Ok(bytes) => bytes as isize,
            Err(e) => {
                CimplError::set_last(CimplError::from(C2paError::Io(e.to_string())));
                -1
            }
        }
    }

    /// Creates a tracked C2paStream pointer (for use with C API functions)
    pub fn into_c_stream(self) -> *mut C2paStream {
        unsafe {
            box_tracked!(C2paStream::new(
                box_tracked!(self) as *mut StreamContext,
                Self::reader,
                Self::seeker,
                Self::writer,
                Self::flusher,
            ))
        }
    }

    pub fn from_bytes(data: Vec<u8>) -> *mut C2paStream {
        let test_stream = Self::new(data);
        test_stream.into_c_stream()
    }

    /// # Safety
    ///
    /// - `c_stream` must be a pointer allocated via `box_tracked!`.
    /// - If non-null, `c_stream.context` must also be a tracked pointer allocated via `box_tracked!`.
    /// - Must not be called more than once for the same pointer.
    pub unsafe fn drop_c_stream(c_stream: *mut C2paStream) {
        let Ok(real_stream) = untrack_owned::<C2paStream>(c_stream) else {
            return;
        };
        if let StreamBacking::Callbacks(callbacks) = real_stream.0 {
            cimpl_free(callbacks.context as *mut std::ffi::c_void);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Opens `path` with the C runtime, as a binding would before handing the descriptor over.
    #[cfg(any(unix, windows))]
    pub(crate) fn open_fd(path: &std::path::Path, flags: c_int) -> c_int {
        #[cfg(windows)]
        let flags = flags | libc::O_BINARY;
        let path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), flags, 0o600) };
        assert!(fd >= 0, "open failed: {}", std::io::Error::last_os_error());
        fd
    }

    #[cfg(any(unix, windows))]
    fn fd_stream(fd: c_int) -> TypedExclusive<C2paStream> {
        let stream = unsafe { c2pa_create_stream_from_fd(fd) };
        assert!(!stream.is_null(), "{:?}", CimplError::last_message());
        deref_mut_option!(stream, C2paStream).unwrap()
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn test_fd_stream_reads_seeks_and_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.bin");
        std::fs::write(&path, b"0123456789").unwrap();
        let fd = open_fd(&path, libc::O_RDWR);

        let stream = unsafe { c2pa_create_stream_from_fd(fd) };
        assert!(!stream.is_null(), "{:?}", CimplError::last_message());
        {
            let mut s = deref_mut_option!(stream, C2paStream).unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"0123");
            assert_eq!(s.seek(SeekFrom::End(-2)).unwrap(), 8);
            let mut tail = Vec::new();
            s.read_to_end(&mut tail).unwrap();
            assert_eq!(tail, b"89");
            s.seek(SeekFrom::Start(2)).unwrap();
            s.write_all(b"ab").unwrap();
            s.flush().unwrap();
        }
        unsafe {
            c2pa_release_stream(stream);
            libc::close(fd);
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"01ab456789");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn test_fd_stream_shares_the_descriptor_offset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.bin");
        std::fs::write(&path, b"0123456789").unwrap();
        let fd = open_fd(&path, libc::O_RDONLY);
        assert_eq!(unsafe { libc::lseek(fd, 3, libc::SEEK_SET) }, 3);

        let stream = unsafe { c2pa_create_stream_from_fd(fd) };
        {
            let mut s = deref_mut_option!(stream, C2paStream).unwrap();
            let mut buf = [0u8; 2];
            s.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"34");
        }
        unsafe { c2pa_release_stream(stream) };
        assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) }, 5);
        unsafe { libc::close(fd) };
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn test_fd_stream_outlives_the_callers_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.bin");
        std::fs::write(&path, b"0123456789").unwrap();
        let fd = open_fd(&path, libc::O_RDONLY);
        let mut s = fd_stream(fd);
        unsafe { libc::close(fd) };

        let mut all = Vec::new();
        s.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"0123456789");
    }

    #[test]
    fn test_memory_stream_reads_seeks_writes_and_grows() {
        let data = b"0123456789";
        let stream = unsafe { c2pa_create_stream_from_bytes(data.as_ptr(), data.len()) };
        assert!(!stream.is_null(), "{:?}", CimplError::last_message());
        {
            let mut s = deref_mut_option!(stream, C2paStream).unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"0123");
            assert_eq!(s.seek(SeekFrom::End(-2)).unwrap(), 8);
            s.write_all(b"abcd").unwrap();
            s.seek(SeekFrom::Start(1)).unwrap();
        }
        let mut out = std::ptr::null();
        let len = unsafe { c2pa_stream_get_bytes(stream, &mut out) };
        assert_eq!(len, 12);
        let contents = unsafe { slice::from_raw_parts(out, len as usize) }.to_vec();
        assert_eq!(contents, b"01234567abcd");
        {
            // Reading the contents leaves the position alone.
            let mut s = deref_mut_option!(stream, C2paStream).unwrap();
            assert_eq!(s.stream_position().unwrap(), 1);
        }
        unsafe {
            assert_eq!(crate::c2pa_free(out as *const std::ffi::c_void), 0);
            c2pa_release_stream(stream);
        }
    }

    #[test]
    fn test_memory_stream_starts_empty_without_data() {
        let stream = unsafe { c2pa_create_stream_from_bytes(std::ptr::null(), 0) };
        assert!(!stream.is_null(), "{:?}", CimplError::last_message());
        let mut out = std::ptr::null();
        assert_eq!(unsafe { c2pa_stream_get_bytes(stream, &mut out) }, 0);
        assert!(out.is_null());
        {
            let mut s = deref_mut_option!(stream, C2paStream).unwrap();
            s.write_all(b"signed").unwrap();
        }
        assert_eq!(
            unsafe { c2pa_stream_get_bytes(stream, std::ptr::null_mut()) },
            6
        );
        unsafe { c2pa_release_stream(stream) };
    }

    #[test]
    fn test_memory_stream_rejects_null_data_with_a_length() {
        assert!(unsafe { c2pa_create_stream_from_bytes(std::ptr::null(), 4) }.is_null());
        assert!(CimplError::last_message().is_some());
    }

    #[test]
    fn test_get_bytes_rejects_a_callback_stream() {
        let mut stream = TestStream::new(b"0123".to_vec());
        let mut out = std::ptr::null();
        assert_eq!(
            unsafe { c2pa_stream_get_bytes(stream.as_ptr(), &mut out) },
            -1
        );
        assert!(out.is_null());
        assert!(CimplError::last_message().is_some());
    }

    #[test]
    fn test_fd_stream_rejects_an_invalid_descriptor() {
        assert!(unsafe { c2pa_create_stream_from_fd(-1) }.is_null());
        assert!(CimplError::last_message().is_some());
    }

    #[test]
    fn test_cstream_read() {
        let data = vec![1, 2, 3, 4, 5];
        let mut stream = TestStream::new(data);

        let mut buf = [0u8; 3];
        assert_eq!(stream.stream_mut().read(&mut buf).unwrap(), 3);
        assert_eq!(buf, [1, 2, 3]);

        let mut buf = [0u8; 3];
        assert_eq!(stream.stream_mut().read(&mut buf).unwrap(), 2);
        assert_eq!(buf, [4, 5, 0]);
    }

    #[test]
    fn test_cstream_seek() {
        let data = vec![1, 2, 3, 4, 5];
        let mut stream = TestStream::new(data);

        stream.stream_mut().seek(SeekFrom::Start(2)).unwrap();
        let mut buf = [0u8; 3];
        assert_eq!(stream.stream_mut().read(&mut buf).unwrap(), 3);
        assert_eq!(buf, [3, 4, 5]);

        stream.stream_mut().seek(SeekFrom::End(-2)).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.stream_mut().read(&mut buf).unwrap(), 2);
        assert_eq!(buf, [4, 5]);

        stream.stream_mut().seek(SeekFrom::Current(-4)).unwrap();
        let mut buf = [0u8; 3];
        assert_eq!(stream.stream_mut().read(&mut buf).unwrap(), 3);
        assert_eq!(buf, [2, 3, 4]);
    }

    #[test]
    fn test_cstream_write() {
        let data = vec![1, 2, 3, 4, 5];
        let mut stream = TestStream::new(data);
        stream.stream_mut().seek(SeekFrom::End(0)).unwrap();
        let buf = [6, 7, 8];
        let bytes_written = stream.stream_mut().write(&buf).unwrap();
        assert_eq!(bytes_written, 3);
        assert_eq!(stream.stream_mut().seek(SeekFrom::End(0)).unwrap(), 8);
    }

    #[test]
    fn test_cstream_read_empty() {
        let data = vec![];
        let mut stream = TestStream::new(data);

        let mut buf = [0u8; 3];
        assert_eq!(stream.stream_mut().read(&mut buf).unwrap(), 0);
        assert_eq!(buf, [0, 0, 0]);
    }

    #[test]
    fn test_seek_rejects_offsets_beyond_i64() {
        // Past i64::MAX, the old `as i64` conversion wrapped this u64 negative,
        // handing the C callback a nonsense offset; the checked conversion refuses.
        let data = vec![1, 2, 3, 4, 5];
        let mut stream = TestStream::new(data);

        let err = stream
            .stream_mut()
            .seek(SeekFrom::Start(u64::MAX))
            .expect_err("an offset beyond i64::MAX must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

        // The stream stays usable after the refusal.
        assert_eq!(stream.stream_mut().seek(SeekFrom::Start(2)).unwrap(), 2);
    }

    #[test]
    fn test_cstream_seek_out_of_bounds() {
        let data = vec![1, 2, 3, 4, 5];
        let mut stream = TestStream::new(data);

        // Seek before the start of the stream
        assert!(stream.stream_mut().seek(SeekFrom::Start(10)).is_ok());

        // Seek to a negative position
        assert!(stream.stream_mut().seek(SeekFrom::Current(-20)).is_err());
    }

    #[test]
    fn test_cstream_write_overwrite() {
        let data = vec![1, 2, 3, 4, 5];
        let mut stream = TestStream::new(data);

        stream.stream_mut().seek(SeekFrom::Start(2)).unwrap();
        let buf = [9, 9];
        let bytes_written = stream.stream_mut().write(&buf).unwrap();
        assert_eq!(bytes_written, 2);

        stream.stream_mut().seek(SeekFrom::Start(0)).unwrap();
        let mut buf = [0u8; 5];
        assert_eq!(stream.stream_mut().read(&mut buf).unwrap(), 5);
        assert_eq!(buf, [1, 2, 9, 9, 5]);
    }

    #[test]
    fn test_cstream_flush() {
        let data = vec![1, 2, 3, 4, 5];
        let mut stream = TestStream::new(data);

        // Flush should succeed without errors
        assert!(stream.stream_mut().flush().is_ok());
    }

    #[test]
    fn test_cstream_large_read() {
        let data = vec![1, 2, 3, 4, 5];
        let mut stream = TestStream::new(data);

        let mut buf = [0u8; 10];
        assert_eq!(stream.stream_mut().read(&mut buf).unwrap(), 5);
        assert_eq!(buf[..5], [1, 2, 3, 4, 5]);
        assert_eq!(buf[5..], [0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_cstream_large_write() {
        let data = vec![1, 2, 3];
        let mut stream = TestStream::new(data);

        stream.stream_mut().seek(SeekFrom::End(0)).unwrap();
        let buf = [6, 7, 8, 9, 10];
        let bytes_written = stream.stream_mut().write(&buf).unwrap();
        assert_eq!(bytes_written, 5);

        stream.stream_mut().seek(SeekFrom::Start(0)).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(stream.stream_mut().read(&mut buf).unwrap(), 8);
        assert_eq!(buf, [1, 2, 3, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_cstream_seek_to_end() {
        let data = vec![1, 2, 3, 4, 5];
        let mut stream = TestStream::new(data);

        let end_pos = stream.stream_mut().seek(SeekFrom::End(0)).unwrap();
        assert_eq!(end_pos, 5);

        let mut buf = [0u8; 1];
        assert_eq!(stream.stream_mut().read(&mut buf).unwrap(), 0); // No data to read at the end
    }

    #[test]
    fn test_create_stream() {
        let test_stream = TestC2paStream::new(vec![1, 2, 3, 4, 5]);
        let context = box_tracked!(test_stream) as *mut StreamContext;

        let c2pa_stream_ptr = unsafe {
            c2pa_create_stream(
                context,
                TestC2paStream::reader,
                TestC2paStream::seeker,
                TestC2paStream::writer,
                TestC2paStream::flusher,
            )
        };

        let mut c2pa_stream = deref_mut_option!(c2pa_stream_ptr, C2paStream).expect("just created");
        let mut buf = [0u8; 3];

        let result = c2pa_stream.read(&mut buf);

        result.expect("Failed to read from C2paStream");
        assert_eq!(buf, [1, 2, 3]);

        unsafe { c2pa_release_stream(c2pa_stream_ptr) };
        cimpl_free(context as *mut std::ffi::c_void);
    }
}
