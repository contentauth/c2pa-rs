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
    ffi::{c_uchar, CString},
    os::raw::{c_char, c_int, c_void},
    ptr,
};

/// Validates that a buffer size is within safe bounds and doesn't cause integer overflow
/// when used with pointer arithmetic.
///
/// # Arguments
/// * `size` - Size to validate
/// * `ptr` - Pointer to validate against (for address space checks)
///
/// # Returns
/// * `true` if the size is safe to use
/// * `false` if the size would cause integer overflow
unsafe fn is_safe_buffer_size(size: usize, ptr: *const c_uchar) -> bool {
    // Combined checks for early return - improves branch prediction
    if size == 0 || size > isize::MAX as usize {
        return false;
    }

    // Check if the buffer would extend beyond address space to fail fast
    if !ptr.is_null() {
        let end_ptr = ptr.add(size);
        if end_ptr < ptr {
            return false; // Wrapped around
        }
    }

    true
}

/// Creates a safe slice from raw parts with bounds validation
///
/// # Arguments
/// * `ptr` - Pointer to the data
/// * `len` - Length of the data
/// * `param_name` - Name of the parameter for error reporting
///
/// # Returns
/// * `Ok(slice)` if the slice is safe to create
/// * `Err(Error)` if bounds validation fails
unsafe fn safe_slice_from_raw_parts(
    ptr: *const c_uchar,
    len: usize,
    param_name: &str,
) -> Result<&[u8], Error> {
    if ptr.is_null() {
        return Err(Error::NullParameter(param_name.to_string()));
    }

    if !is_safe_buffer_size(len, ptr) {
        return Err(Error::Other(format!(
            "Buffer size {len} is invalid for parameter '{param_name}'",
        )));
    }

    Ok(std::slice::from_raw_parts(ptr, len))
}

// C has no namespace so we prefix things with C2PA to make them unique
#[cfg(feature = "file_io")]
use c2pa::Ingredient;
use c2pa::{
    assertions::{
        labels::{parse_label, BMFF_HASH},
        BmffHash, DataHash,
    },
    identity::validator::CawgValidator,
    Builder as C2paBuilder, CallbackSigner, Hasher as C2paHasher, Reader as C2paReader, Settings,
    SigningAlg,
};
use scopeguard::guard;
use tokio::runtime::Runtime; // cawg validator requires async

#[cfg(feature = "file_io")]
use crate::json_api::{read_file, sign_file};
use crate::{c2pa_stream::C2paStream, error::Error, signer_info::SignerInfo};

// Work around limitations in cbindgen.
mod cbindgen_fix {
    #[repr(C)]
    #[allow(dead_code)]
    pub struct C2paBuilder;

    #[repr(C)]
    #[allow(dead_code)]
    pub struct C2paReader;

    #[repr(C)]
    #[allow(dead_code)]
    pub struct C2paHasher;
}

/// List of supported signing algorithms.
#[repr(C)]
pub enum C2paSigningAlg {
    Es256,
    Es384,
    Es512,
    Ps256,
    Ps384,
    Ps512,
    Ed25519,
}

impl From<C2paSigningAlg> for SigningAlg {
    fn from(alg: C2paSigningAlg) -> Self {
        match alg {
            C2paSigningAlg::Es256 => SigningAlg::Es256,
            C2paSigningAlg::Es384 => SigningAlg::Es384,
            C2paSigningAlg::Es512 => SigningAlg::Es512,
            C2paSigningAlg::Ps256 => SigningAlg::Ps256,
            C2paSigningAlg::Ps384 => SigningAlg::Ps384,
            C2paSigningAlg::Ps512 => SigningAlg::Ps512,
            C2paSigningAlg::Ed25519 => SigningAlg::Ed25519,
        }
    }
}

/// List of possible digital source types.
#[repr(C)]
pub enum C2paDigitalSourceType {
    Empty,
    TrainedAlgorithmicData,
    DigitalCapture,
    ComputationalCapture,
    NegativeFilm,
    PositiveFilm,
    Print,
    HumanEdits,
    CompositeWithTrainedAlgorithmicMedia,
    AlgorithmicallyEnhanced,
    DigitalCreation,
    DataDrivenMedia,
    TrainedAlgorithmicMedia,
    AlgorithmicMedia,
    ScreenCapture,
    VirtualRecording,
    Composite,
    CompositeCapture,
    CompositeSynthetic,
}

impl From<C2paDigitalSourceType> for c2pa::DigitalSourceType {
    fn from(source_type: C2paDigitalSourceType) -> Self {
        match source_type {
            C2paDigitalSourceType::Empty => c2pa::DigitalSourceType::Empty,
            C2paDigitalSourceType::TrainedAlgorithmicData => {
                c2pa::DigitalSourceType::TrainedAlgorithmicData
            }
            C2paDigitalSourceType::DigitalCapture => c2pa::DigitalSourceType::DigitalCapture,
            C2paDigitalSourceType::ComputationalCapture => {
                c2pa::DigitalSourceType::ComputationalCapture
            }
            C2paDigitalSourceType::NegativeFilm => c2pa::DigitalSourceType::NegativeFilm,
            C2paDigitalSourceType::PositiveFilm => c2pa::DigitalSourceType::PositiveFilm,
            C2paDigitalSourceType::Print => c2pa::DigitalSourceType::Print,
            C2paDigitalSourceType::HumanEdits => c2pa::DigitalSourceType::HumanEdits,
            C2paDigitalSourceType::CompositeWithTrainedAlgorithmicMedia => {
                c2pa::DigitalSourceType::CompositeWithTrainedAlgorithmicMedia
            }
            C2paDigitalSourceType::AlgorithmicallyEnhanced => {
                c2pa::DigitalSourceType::AlgorithmicallyEnhanced
            }
            C2paDigitalSourceType::DigitalCreation => c2pa::DigitalSourceType::DigitalCreation,
            C2paDigitalSourceType::DataDrivenMedia => c2pa::DigitalSourceType::DataDrivenMedia,
            C2paDigitalSourceType::TrainedAlgorithmicMedia => {
                c2pa::DigitalSourceType::TrainedAlgorithmicMedia
            }
            C2paDigitalSourceType::AlgorithmicMedia => c2pa::DigitalSourceType::AlgorithmicMedia,
            C2paDigitalSourceType::ScreenCapture => c2pa::DigitalSourceType::ScreenCapture,
            C2paDigitalSourceType::VirtualRecording => c2pa::DigitalSourceType::VirtualRecording,
            C2paDigitalSourceType::Composite => c2pa::DigitalSourceType::Composite,
            C2paDigitalSourceType::CompositeCapture => c2pa::DigitalSourceType::CompositeCapture,
            C2paDigitalSourceType::CompositeSynthetic => {
                c2pa::DigitalSourceType::CompositeSynthetic
            }
        }
    }
}

/// Builder intent enumeration.
/// This specifies what kind of manifest to create.
#[repr(C)]
pub enum C2paBuilderIntent {
    /// This is a new digital creation with the specified digital source type.
    /// The Manifest must not have a parent ingredient.
    /// A `c2pa.created` action will be added if not provided.
    Create,
    /// This is an edit of a pre-existing parent asset.
    /// The Manifest must have a parent ingredient.
    /// A parent ingredient will be generated from the source stream if not otherwise provided.
    /// A `c2pa.opened` action will be tied to the parent ingredient.
    Edit,
    /// A restricted version of Edit for non-editorial changes.
    /// There must be only one ingredient, as a parent.
    /// No changes can be made to the hashed content of the parent.
    Update,
}

#[repr(C)]
pub struct C2paSigner {
    pub signer: Box<dyn c2pa::Signer>,
}

// Null check macro for C pointers.
#[macro_export]
macro_rules! null_check {
    (($ptr:expr), $transform:expr, $default:expr) => {
        if $ptr.is_null() {
            Error::set_last(Error::NullParameter(stringify!($ptr).to_string()));
            return $default;
        } else {
            $transform($ptr)
        }
    };
}

/// If the expression is null, set the last error and return null.
#[macro_export]
macro_rules! check_or_return_null {
    ($ptr : expr) => {
        null_check!(($ptr), |ptr| ptr, std::ptr::null_mut())
    };
}

/// If the expression is null, set the last error and return -1.
#[macro_export]
macro_rules! check_or_return_int {
    ($ptr : expr) => {
        null_check!(($ptr), |ptr| ptr, -1)
    };
}

/// If the expression is null, set the last error and return std::ptr::null_mut().
#[macro_export]
macro_rules! from_cstr_or_return_null {
    ($ptr : expr) => {
        null_check!(
            ($ptr),
            |ptr| { std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned() },
            std::ptr::null_mut()
        )
    };
}

// Internal routine to convert a *const c_char to a rust String or return a -1 int error.
#[macro_export]
macro_rules! from_cstr_or_return_int {
    ($ptr : expr) => {
        null_check!(
            ($ptr),
            |ptr| { std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned() },
            -1
        )
    };
}

// Internal routine to convert a *const c_char to Option<String>.
#[macro_export]
macro_rules! from_cstr_option {
    ($ptr : expr) => {
        if $ptr.is_null() {
            None
        } else {
            Some(
                std::ffi::CStr::from_ptr($ptr)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    };
}

// Internal routine to handle Result types, set errors on Err, and return default values
#[macro_export]
macro_rules! result_check {
    ($result:expr, $transform:expr, $default:expr) => {
        match $result {
            Ok(value) => $transform(value),
            Err(err) => {
                Error::from_c2pa_error(err).set_last();
                return $default;
            }
        }
    };
}

#[macro_export]
macro_rules! ok_or_return_null {
    ($result:expr, $transform:expr) => {
        result_check!($result, $transform, std::ptr::null_mut())
    };
}

#[macro_export]
macro_rules! ok_or_return_int {
    ($result:expr, $transform:expr) => {
        result_check!($result, $transform, -1)
    };
}

#[macro_export]
macro_rules! return_boxed {
    ($result:expr) => {
        ok_or_return_null!($result, |value| Box::into_raw(Box::new(value)))
    };
}

#[macro_export]
macro_rules! guard_boxed {
    ($ptr:expr) => {
        guard(Box::from_raw($ptr), |value| {
            let _ = Box::into_raw(value);
        })
    };
}

#[macro_export]
macro_rules! guard_boxed_int {
    ($ptr:expr) => {
        null_check!(
            ($ptr),
            |ptr| {
                guard(Box::from_raw(ptr), |value| {
                    let _ = Box::into_raw(value);
                })
            },
            -1
        )
    };
}

/// Defines a callback to read from a stream.
///
/// # Parameters
/// * context: A generic context value to used by the C code, often a file or stream reference.
pub type SignerCallback = unsafe extern "C" fn(
    context: *const (),
    data: *const c_uchar,
    len: usize,
    signed_bytes: *mut c_uchar,
    signed_len: usize,
) -> isize;

// Internal routine to return a rust String reference to C as *mut c_char.
// The returned value MUST be released by calling release_string
// and it is no longer valid after that call.
unsafe fn to_c_string(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Returns a version string for logging.
///
/// # Safety
/// The returned value MUST be released by calling release_string
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_version() -> *mut c_char {
    let version = format!(
        "{}/{} {}/{}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        c2pa::NAME,
        c2pa::VERSION
    );
    to_c_string(version)
}

/// Returns the last error message.
///
/// # Safety
/// The returned value MUST be released by calling release_string
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_error() -> *mut c_char {
    to_c_string(Error::last_message().unwrap_or_default())
}

/// Sets the last error message.
/// This is used by callbacks so they can set a return error message.
/// THe error should be in the form of "ErrorType: ErrorMessage".
/// If ErrorType is missing or invalid, it will be set to "Other".
/// and the message will include the original error string.
/// Can return -1 if the error string is NULL.
///
/// # Safety
/// Reads from NULL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn c2pa_error_set_last(error_str: *const c_char) -> c_int {
    let error_str = from_cstr_or_return_int!(error_str);
    Error::set_last(Error::from(error_str));
    0
}

/// Load Settings from a string.
/// Sets thread-local settings.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns 0.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn c2pa_load_settings(
    settings: *const c_char,
    format: *const c_char,
) -> c_int {
    let settings = from_cstr_or_return_int!(settings);
    let format = from_cstr_or_return_int!(format);
    // we use the legacy from_string function to set thread-local settings for backward compatibility
    let result = Settings::from_string(&settings, &format);
    ok_or_return_int!(result, |_| 0) // returns 0 on success
}

/// Returns a ManifestStore JSON string from a file path.
///
/// Any thumbnails or other binary resources will be written to data_dir if provided.
///
/// # Errors
/// Returns NULL if there were errors, otherwise returns a JSON string.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The returned value MUST be released by calling release_string
/// and it is no longer valid after that call.
#[cfg(feature = "file_io")]
#[no_mangle]
pub unsafe extern "C" fn c2pa_read_file(
    path: *const c_char,
    data_dir: *const c_char,
) -> *mut c_char {
    let path = from_cstr_or_return_null!(path);
    let data_dir = from_cstr_option!(data_dir);

    let result = read_file(&path, data_dir);
    match result {
        Ok(json) => to_c_string(json),
        Err(err) => {
            err.set_last();
            std::ptr::null_mut()
        }
    }
}

/// Returns an Ingredient JSON string from a file path.
///
/// Any thumbnail or C2PA data will be written to data_dir if provided.
///
/// # Errors
/// Returns NULL if there were errors, otherwise returns a JSON string
/// containing the Ingredient.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The returned value MUST be released by calling release_string
/// and it is no longer valid after that call.
#[cfg(feature = "file_io")]
#[no_mangle]
pub unsafe extern "C" fn c2pa_read_ingredient_file(
    path: *const c_char,
    data_dir: *const c_char,
) -> *mut c_char {
    let path = from_cstr_or_return_null!(path);
    let data_dir = from_cstr_or_return_null!(data_dir);
    let result = Ingredient::from_file_with_folder(path, data_dir).map_err(Error::from_c2pa_error);

    match result {
        Ok(ingredient) => to_c_string(ingredient.to_string()),
        Err(err) => {
            err.set_last();
            std::ptr::null_mut()
        }
    }
}

#[repr(C)]
/// Defines the configuration for a Signer.
///
/// The signer is created from the sign_cert and private_key fields.
/// an optional url to an RFC 3161 compliant time server will ensure the signature is timestamped.
pub struct C2paSignerInfo {
    /// The signing algorithm.
    pub alg: *const c_char,
    /// The public certificate chain in PEM format.
    pub sign_cert: *const c_char,
    /// The private key in PEM format.
    pub private_key: *const c_char,
    /// The timestamp authority URL or NULL.
    pub ta_url: *const c_char,
}

/// Add a signed manifest to the file at path with the given signer information.
///
/// # Errors
/// Returns an error field if there were errors.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The returned value MUST be released by calling release_string
/// and it is no longer valid after that call.
#[cfg(feature = "file_io")]
#[no_mangle]
pub unsafe extern "C" fn c2pa_sign_file(
    source_path: *const c_char,
    dest_path: *const c_char,
    manifest: *const c_char,
    signer_info: &C2paSignerInfo,
    data_dir: *const c_char,
) -> *mut c_char {
    // Convert C pointers into Rust.
    let source_path = from_cstr_or_return_null!(source_path);
    let dest_path = from_cstr_or_return_null!(dest_path);
    let manifest = from_cstr_or_return_null!(manifest);
    let data_dir = from_cstr_option!(data_dir);

    let signer_info = SignerInfo {
        alg: from_cstr_or_return_null!(signer_info.alg),
        sign_cert: from_cstr_or_return_null!(signer_info.sign_cert).into_bytes(),
        private_key: from_cstr_or_return_null!(signer_info.private_key).into_bytes(),
        ta_url: from_cstr_option!(signer_info.ta_url),
    };
    // Read manifest from JSON and then sign and write it.
    let result = sign_file(&source_path, &dest_path, &manifest, &signer_info, data_dir);
    match result {
        Ok(_c2pa_data) => to_c_string("".to_string()),
        Err(err) => {
            err.set_last();
            std::ptr::null_mut()
        }
    }
}

/// Frees a string allocated by Rust.
///
/// Deprecated: for backward api compatibility only.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The string must not have been modified in C.
/// The string can only be freed once and is invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_release_string(s: *mut c_char) {
    c2pa_string_free(s)
}

/// Frees a string allocated by Rust.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The string must not have been modified in C.
/// The string can only be freed once and is invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Frees an array of char* pointers created by Rust.
///
/// # Parameters
/// * ptr: pointer to the array of char* pointers.
/// * count: number of elements in the array.
///
/// # Safety
/// * The ptr passed into this function must point to memory that was allocated
///   by our library.
/// * The array and its strings must not have been modified in C.
/// * The array and its contents can only be freed once and is invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_free_string_array(ptr: *const *const c_char, count: usize) {
    if ptr.is_null() {
        return;
    }

    let mut_ptr = ptr as *mut *mut c_char;
    // Free each string directly using the pointer.
    for i in 0..count {
        c2pa_string_free(*mut_ptr.add(i));
    }

    // Free the array.
    Vec::from_raw_parts(mut_ptr, count, count);
}

// Run CAWG post-validation - this is async and requires a runtime.
fn post_validate(result: Result<C2paReader, c2pa::Error>) -> Result<C2paReader, c2pa::Error> {
    match result {
        Ok(mut reader) => {
            let runtime = match Runtime::new() {
                Ok(runtime) => runtime,
                Err(err) => return Err(c2pa::Error::OtherError(Box::new(err))),
            };
            match runtime.block_on(reader.post_validate_async(&CawgValidator {})) {
                Ok(_) => Ok(reader),
                Err(err) => Err(err),
            }
        }
        Err(err) => Err(err),
    }
}
/// Creates and verifies a C2paReader from an asset stream with the given format.
///
/// #Parameters
/// * format: pointer to a C string with the mime type or extension.
/// * stream: pointer to a C2paStream.
///
/// # Errors
/// Returns NULL if there were errors, otherwise returns a pointer to a ManifestStore.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The returned value MUST be released by calling c2pa_reader_free
/// and it is no longer valid after that call.
///
/// # Example
/// ```c
/// auto result = c2pa_reader_from_stream("image/jpeg", stream);
/// if (result == NULL) {
///     let error = c2pa_error();
///     printf("Error: %s\n", error);
///     c2pa_string_free(error);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_from_stream(
    format: *const c_char,
    stream: *mut C2paStream,
) -> *mut C2paReader {
    let format = from_cstr_or_return_null!(format);

    let result = C2paReader::from_stream(&format, &mut (*stream));

    return_boxed!(post_validate(result))
}

/// Get a C2paHasher for the specified algorithm
///
/// #Parameters
/// * alg: pointer to a C string specifying the supported algorithm {"sha256, "sha284", "sha512"}.
///
/// # Errors
/// Returns NULL if there were errors, otherwise returns a pointer to a C2pHasher.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// The returned value MUST be released by calling c2pa_reader_free or c2pa_hasher_finalize
/// and it is no longer valid after that call.
///
/// # Example
/// ```c
/// auto result = c2pa_hasher_from_alg("sha256");
/// if (result == NULL) {
///     let error = c2pa_error();
///     printf("Error: %s\n", error);
///     c2pa_hasher_free(result);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_hasher_from_alg(alg: *const c_char) -> *mut C2paHasher {
    let alg = from_cstr_or_return_null!(alg);
    return_boxed!(C2paHasher::new(&alg))
}

/// Update the hasher with supplied data
///
/// #Parameters
/// * hasher_ptr: point to C2paHasher from c2pa_hasher_from_alg.
/// * data_ptr: pointer to data to hash.
/// * data_len: length of data to hash.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns 0.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// hasher_ptr and data_ptr must not be NULL..
///
/// # Example
/// ```c
/// auto hasher = c2pa_hasher_from_alg("sha256");
/// if (hasher == NULL) {
///     let error = c2pa_error();
///     printf("Error: %s\n", error);
///
///     auto data = std::vector<std::uint8_t> buffer(1024);
///
///     c2pa_hasher_update(hasher, (const uint8_t*)data.data(), 1024);
///
///     c2pa_string_free(error);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_hasher_update(
    hasher_ptr: *mut C2paHasher,
    data_ptr: *const c_uchar,
    data_len: usize,
) -> i64 {
    if hasher_ptr.is_null() || data_ptr.is_null() {
        Error::set_last(Error::NullParameter(
            "hasher_ptr or data_ptr is NULL".to_string(),
        ));
        return -1;
    }

    let hash_bytes = match safe_slice_from_raw_parts(data_ptr, data_len, "hash_data") {
        Ok(bytes) => bytes,
        Err(err) => {
            err.set_last();
            return -1;
        }
    };

    let mut hasher = guard_boxed!(hasher_ptr);

    hasher.update(hash_bytes);

    0
}
/// Finalize the hasher and return the hash bytes
///
/// #Parameters
/// * hasher_ptr: point to C2paHasher from c2pa_hasher_from_alg.
/// * hash_bytes_ptr: pointer to receive the hash bytes pointer.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns the length of the hash bytes.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// hasher_ptr and hash_bytes_ptr must not be NULL.
/// The returned hash_bytes_ptr must be freed by calling c2pa_hashed_bytes_free.
///
/// # Example
/// ```c
/// auto hasher = c2pa_hasher_from_alg("sha256");
/// if (hasher == NULL) {
///     let error = c2pa_error();
///     printf("Error: %s\n", error);
///
///     auto data = std::vector<std::uint8_t> buffer(1024);
///
///     c2pa_hasher_update(hasher, (const uint8_t*)data.data(), 1024);
///
///    const uint8_t* hash_bytes = NULL;    
///    auto hash_len = c2pa_hasher_finalize(hasher, &hash_bytes);
///
///    c2pa_string_free(error);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_hasher_finalize(
    hasher_ptr: *mut C2paHasher,
    hash_bytes_ptr: *mut *const c_uchar,
) -> i64 {
    if hasher_ptr.is_null() || hash_bytes_ptr.is_null() {
        Error::set_last(Error::NullParameter(
            "hasher_ptr or data_ptr is NULL".to_string(),
        ));
        return -1;
    }

    let mut hasher = guard_boxed!(hasher_ptr);

    let hash_bytes = hasher.finalize_reset();

    if !hash_bytes_ptr.is_null() {
        let len = hash_bytes.len() as i64;
        *hash_bytes_ptr = Box::into_raw(hash_bytes.into_boxed_slice()) as *const c_uchar;
        len
    } else {
        -1
    }
}
/// Hash a u64 offset value into the hasher per C2PA BMFF hashing rules
///
/// #Parameters
/// * hasher_ptr: point to C2paHasher from c2pa_hasher_from_alg.
/// * hash_offset: u64 offset value to hash.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns 0.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// hasher_ptr must not be NULL..
///
/// # Example
/// ```c
/// auto hasher = c2pa_hasher_from_alg("sha256");
/// if (hasher == NULL) {
///     let error = c2pa_error();
///     printf("Error: %s\n", error);
///
///     auto offset = 12345678u64;
///     c2pa_hasher_hash_offset(hasher, offset);
///
///     c2pa_string_free(error);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_hasher_hash_offset(
    hasher_ptr: *mut C2paHasher,
    hash_offset: u64,
) -> i64 {
    if hasher_ptr.is_null() {
        Error::set_last(Error::NullParameter("hasher_ptr is NULL".to_string()));
        return -1;
    }

    let offset_be = hash_offset.to_be_bytes();

    let mut hasher = guard_boxed!(hasher_ptr);
    hasher.update(&offset_be);

    0
}

/// Frees a C2paHasher allocated by Rust.
///
/// # Safety
/// The C2paHasher can only be freed once and is invalid after this call.
/// /// # Safety
/// hasher_ptr must not be NULL..
///
/// # Example
/// ```c
/// auto hasher = c2pa_hasher_from_alg("sha256");
/// if (hasher == NULL) {
///     c2pa_string_free(error);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_hasher_free(hasher_ptr: *mut C2paHasher) {
    if !hasher_ptr.is_null() {
        drop(Box::from_raw(hasher_ptr));
    }
}

/// Frees hash bytes pointer returned by c2pa_hasher_finalize allocated by Rust.
///
/// # Safety
/// The hashed_bytes_ptr can only be freed once and is invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_hashed_bytes_free(hashed_bytes_ptr: *mut *const c_uchar) {
    if !hashed_bytes_ptr.is_null() {
        drop(Box::from_raw(hashed_bytes_ptr));
    }
}

/// Creates and verifies a C2paReader from a file path.
/// This allows a client to use Rust's file I/O to read the file
/// Parameters
/// * path: pointer to a C string with the file path in UTF-8.
///
/// # Errors
/// Returns NULL if there were errors, otherwise returns a pointer to a ManifestStore.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The returned value MUST be released by calling c2pa_reader_free
/// and it is no longer valid after that call.
///
/// # Example
/// ```c
/// auto result = c2pa_reader_from_file("path/to/file.jpg");
/// if (result == NULL) {
///    let error = c2pa_error();
///   printf("Error: %s\n", error);
///   c2pa_string_free(error);
/// }
/// }
/// ```
#[cfg(feature = "file_io")]
#[no_mangle]
pub unsafe fn c2pa_reader_from_file(path: *const c_char) -> *mut C2paReader {
    let path = from_cstr_or_return_null!(path);
    let result = C2paReader::from_file(&path);
    return_boxed!(post_validate(result))
}

/// Creates and verifies a C2paReader from an asset stream with the given format and manifest data.
///
/// Parameters
/// * format: pointer to a C string with the mime type or extension.
/// * stream: pointer to a C2paStream.
/// * manifest_data: pointer to the manifest data bytes.
/// * manifest_size: size of the manifest data bytes.
///
/// # Errors
/// Returns NULL if there were errors, otherwise returns a pointer to a ManifestStore.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The returned value MUST be released by calling c2pa_reader_free
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_from_manifest_data_and_stream(
    format: *const c_char,
    stream: *mut C2paStream,
    manifest_data: *const c_uchar,
    manifest_size: usize,
) -> *mut C2paReader {
    check_or_return_null!(manifest_data);
    let format = from_cstr_or_return_null!(format);

    // Safe bounds validation for manifest data
    let manifest_bytes =
        match safe_slice_from_raw_parts(manifest_data, manifest_size, "manifest_data") {
            Ok(bytes) => bytes,
            Err(err) => {
                err.set_last();
                return std::ptr::null_mut();
            }
        };

    let result = C2paReader::from_manifest_data_and_stream(manifest_bytes, &format, &mut (*stream));
    return_boxed!(post_validate(result))
}

/// Frees a C2paReader allocated by Rust.
///
/// # Safety
/// The C2paReader can only be freed once and is invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_free(reader_ptr: *mut C2paReader) {
    if !reader_ptr.is_null() {
        drop(Box::from_raw(reader_ptr));
    }
}

/// Returns a JSON string generated from a C2paReader.
///
/// # Safety
/// The returned value MUST be released by calling c2pa_string_free
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_json(reader_ptr: *mut C2paReader) -> *mut c_char {
    check_or_return_null!(reader_ptr);
    let c2pa_reader = guard_boxed!(reader_ptr);

    to_c_string(c2pa_reader.json())
}

/// Returns a detailed JSON string generated from a C2paReader.
///
/// # Safety
/// The returned value MUST be released by calling c2pa_string_free
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_detailed_json(reader_ptr: *mut C2paReader) -> *mut c_char {
    check_or_return_null!(reader_ptr);
    let c2pa_reader = guard_boxed!(reader_ptr);

    to_c_string(c2pa_reader.detailed_json())
}

/// Returns the remote url of the manifest if it was obtained remotely.
///
/// # Parameters
/// * reader_ptr: pointer to a C2paReader.
///
/// # Safety
/// reader_ptr must be a valid pointer to a C2paReader.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_remote_url(reader_ptr: *mut C2paReader) -> *const c_char {
    check_or_return_null!(reader_ptr);
    let c2pa_reader = guard_boxed!(reader_ptr);

    match c2pa_reader.remote_url() {
        Some(url) => to_c_string(url.to_string()),
        None => ptr::null(),
    }
}

/// Returns if the reader was created from an embedded manifest.
///
/// # Parameters
/// * reader_ptr: pointer to a C2paReader.
///
/// # Safety
/// reader_ptr must be a valid pointer to a C2paReader.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_is_embedded(reader_ptr: *mut C2paReader) -> bool {
    null_check!((reader_ptr), |ptr| ptr, false);
    let c2pa_reader = guard_boxed!(reader_ptr);

    c2pa_reader.is_embedded()
}

/// Writes a C2paReader resource to a stream given a URI.
///
/// The resource uri should match an identifier in the the manifest store.
///
/// # Parameters
/// * reader_ptr: pointer to a Reader.
/// * uri: pointer to a C string with the URI to identify the resource.
/// * stream: pointer to a writable C2paStream.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns size of stream written.
///
/// # Safety
/// Reads from NULL-terminated C strings.
///
/// # Example
/// ```c
/// auto result = c2pa_reader_resource_to_stream(store, "uri", stream);
/// if (result < 0) {
///     auto error = c2pa_error();
///     printf("Error: %s\n", error);
///     c2pa_string_free(error);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_resource_to_stream(
    reader_ptr: *mut C2paReader,
    uri: *const c_char,
    stream: *mut C2paStream,
) -> i64 {
    let uri = from_cstr_or_return_int!(uri);
    let reader = guard_boxed_int!(reader_ptr);
    let result = reader.resource_to_stream(&uri, &mut (*stream));
    ok_or_return_int!(result, |len| len as i64)
}

/// Returns an array of char* pointers to c2pa::Reader's supported mime types.
/// The caller is responsible for freeing the array.
///
/// # Parameters
/// * count: pointer to a usize to return the number of mime types.
///
/// # Safety
/// The returned value MUST be released by calling [c2pa_free_string_array].
/// The array and its contents are no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_supported_mime_types(
    count: *mut usize,
) -> *const *const c_char {
    c2pa_mime_types_to_c_array(C2paReader::supported_mime_types(), count)
}

/// Creates a C2paBuilder from a JSON manifest definition string.
///
/// # Errors
/// Returns NULL if there were errors, otherwise returns a pointer to a Builder.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The returned value MUST be released by calling c2pa_builder_free
/// and it is no longer valid after that call.
///
/// # Example
/// ```c
/// auto result = c2pa_builder_from_json(manifest_json);
/// if (result == NULL) {
///     auto error = c2pa_error();
///     printf("Error: %s\n", error);
///     c2pa_string_free(error);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_from_json(manifest_json: *const c_char) -> *mut C2paBuilder {
    let manifest_json = from_cstr_or_return_null!(manifest_json);
    let result = C2paBuilder::from_json(&manifest_json);
    return_boxed!(result)
}

/// Create a C2paBuilder from an archive stream.
///
/// # Errors
/// Returns NULL if there were errors, otherwise returns a pointer to a Builder.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The returned value MUST be released by calling c2pa_builder_free
/// and it is no longer valid after that call.
///
/// # Example
/// ```c
/// auto result = c2pa_builder_from_archive(stream);
/// if (result == NULL) {
///     auto error = c2pa_error();
///     printf("Error: %s\n", error);
///     c2pa_string_free(error);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_from_archive(stream: *mut C2paStream) -> *mut C2paBuilder {
    return_boxed!(C2paBuilder::from_archive(&mut (*stream)))
}

/// Returns an array of char* pointers to the supported mime types.
/// The caller is responsible for freeing the array.
///
/// # Parameters
/// * count: pointer to a usize to return the number of mime types.
///
/// # Safety
/// The returned value MUST be released by calling [c2pa_free_string_array].
/// The array and its contents are no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_supported_mime_types(
    count: *mut usize,
) -> *const *const c_char {
    c2pa_mime_types_to_c_array(C2paBuilder::supported_mime_types(), count)
}

/// Frees a C2paBuilder allocated by Rust.
///
/// # Safety
/// The C2paBuilder can only be freed once and is invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_free(builder_ptr: *mut C2paBuilder) {
    if !builder_ptr.is_null() {
        drop(Box::from_raw(builder_ptr));
    }
}

/// Sets the builder intent on the Builder.
///
/// An intent lets the API know what kind of manifest to create.
/// Intents are `Create`, `Edit`, or `Update`.
///
/// Create requires a `DigitalSourceType`. It is used for assets without a parent ingredient.
/// Edit requires a parent ingredient and is used for most assets that are being edited.
/// Update is a special case with many restrictions but is more compact than Edit.
///
/// For the `Create` intent, a valid `digital_source_type` must be provided.
/// For `Edit` and `Update` intents, `digital_source_type` will be ignored (any value is allowed).
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * intent: the builder intent (Create, Edit, or Update).
/// * digital_source_type: the digital source type (required for Create intent).
///
/// # Errors
/// Returns -1 if there were errors (null pointer for builder_ptr), otherwise returns 0.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// builder_ptr must be a valid pointer to a Builder.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_set_intent(
    builder_ptr: *mut C2paBuilder,
    intent: C2paBuilderIntent,
    digital_source_type: C2paDigitalSourceType,
) -> c_int {
    let mut builder = guard_boxed_int!(builder_ptr);

    let builder_intent = match intent {
        C2paBuilderIntent::Create => c2pa::BuilderIntent::Create(digital_source_type.into()),
        C2paBuilderIntent::Edit => c2pa::BuilderIntent::Edit,
        C2paBuilderIntent::Update => c2pa::BuilderIntent::Update,
    };

    builder.set_intent(builder_intent);
    0 as c_int
}

/// Sets the no-embed flag on the Builder.
/// When set, the builder will not embed a C2PA manifest store into the asset when signing.
/// This is useful when creating cloud or sidecar manifests.
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// # Safety
/// builder_ptr must be a valid pointer to a Builder.
#[no_mangle]
#[allow(clippy::unused_unit)] // clippy doesn't like the () return type for null_check
pub unsafe extern "C" fn c2pa_builder_set_no_embed(builder_ptr: *mut C2paBuilder) {
    null_check!((builder_ptr), |ptr| ptr, ());
    let mut builder = guard_boxed!(builder_ptr);
    builder.set_no_embed(true);
}

/// Sets the remote URL on the Builder.
/// When set, the builder will embed a remote URL into the asset when signing.
/// This is useful when creating cloud based Manifests.
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * remote_url: pointer to a C string with the remote URL.
/// # Errors
/// Returns -1 if there were errors, otherwise returns 0.
/// The error string can be retrieved by calling c2pa_error.
/// # Safety
/// Reads from NULL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_set_remote_url(
    builder_ptr: *mut C2paBuilder,
    remote_url: *const c_char,
) -> c_int {
    let mut builder = guard_boxed_int!(builder_ptr);
    let remote_url = from_cstr_or_return_int!(remote_url);
    builder.set_remote_url(&remote_url);
    0 as c_int
}

/// ⚠️ **Deprecated Soon**
/// This method is planned to be deprecated in a future release.
/// Usage should be limited and temporary.
///
/// Sets the resource directory on the Builder.
/// When set, resources that are not found in memory will be searched for in the given directory.
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * base_path: pointer to a C string with the resource directory.
/// # Errors
/// Returns -1 if there were errors, otherwise returns 0.
/// The error string can be retrieved by calling c2pa_error.
/// # Safety
/// Reads from NULL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_set_base_path(
    builder_ptr: *mut C2paBuilder,
    base_path: *const c_char,
) -> c_int {
    let mut builder = guard_boxed_int!(builder_ptr);
    let base_path = from_cstr_or_return_int!(base_path);
    builder.set_base_path(&base_path);
    0 as c_int
}

/// Adds a resource to the C2paBuilder.
///
/// The resource uri should match an identifier in the manifest definition.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * uri: pointer to a C string with the URI to identify the resource.
/// * stream: pointer to a C2paStream.
/// # Errors
/// Returns -1 if there were errors, otherwise returns 0.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_add_resource(
    builder_ptr: *mut C2paBuilder,
    uri: *const c_char,
    stream: *mut C2paStream,
) -> c_int {
    let mut builder = guard_boxed_int!(builder_ptr);
    let uri = from_cstr_or_return_int!(uri);
    let result = builder.add_resource(&uri, &mut (*stream));
    ok_or_return_int!(result, |_| 0) // returns 0 on success
}

/// Adds an ingredient to the C2paBuilder.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * ingredient_json: pointer to a C string with the JSON ingredient definition.
/// * format: pointer to a C string with the mime type or extension.
/// * source: pointer to a C2paStream.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns 0.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_add_ingredient_from_stream(
    builder_ptr: *mut C2paBuilder,
    ingredient_json: *const c_char,
    format: *const c_char,
    source: *mut C2paStream,
) -> c_int {
    check_or_return_int!(builder_ptr);
    check_or_return_int!(source);
    let mut builder = guard_boxed!(builder_ptr);
    let ingredient_json = from_cstr_or_return_int!(ingredient_json);
    let format = from_cstr_or_return_int!(format);
    let result = builder.add_ingredient_from_stream(&ingredient_json, &format, &mut (*source));
    ok_or_return_int!(result, |_| 0) // returns 0 on success
}

/// Adds an action to the manifest the Builder is constructing.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * action_json: JSON string containing the action data.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns 0.
/// The error string can be retrieved by calling [c2pa_error].
///
/// # Safety
/// Reads from NULL-terminated C strings.
///
/// # Example
/// ```C
/// const char* manifest_def = "{}";
/// C2paBuilder* builder = c2pa_builder_from_json(manifest_def);
///
/// const char* action_json = "{\n"
///     "    \"action\": \"com.example.test-action\",\n"
///     "    \"parameters\": {\n"
///     "        \"key1\": \"value1\",\n"
///     "        \"key2\": \"value2\"\n"
///     "    }\n"
/// "}";
///
/// int result = c2pa_builder_add_action(builder, action_json);
/// ```
///
/// This creates a manifest with an actions assertion
/// containing the added action (excerpt of the full manifest):
/// ```json
/// "assertions": [
///   {
///     "label": "c2pa.actions.v2",
///     "data": {
///       "actions": [
///         {
///           "action": "c2pa.created",
///           "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty"
///         },
///         {
///           "action": "com.example.test-action",
///           "parameters": {
///             "key2": "value2",
///             "key1": "value1"
///           }
///         }
///       ],
///     }
///   }
/// ]
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_add_action(
    builder_ptr: *mut C2paBuilder,
    action_json: *const c_char,
) -> c_int {
    let mut builder = guard_boxed_int!(builder_ptr);
    let action_json = from_cstr_or_return_int!(action_json);

    // Parse the JSON into a serde Value to use with the Builder
    let action_value: serde_json::Value = match serde_json::from_str(&action_json) {
        Ok(value) => value,
        Err(err) => {
            Error::from_c2pa_error(c2pa::Error::JsonError(err)).set_last();
            return -1;
        }
    };

    match builder.add_action(action_value) {
        Ok(_) => 0, // returns 0 on success
        Err(err) => {
            Error::from_c2pa_error(err).set_last();
            -1
        }
    }
}

/// Writes an Archive of the Builder to the destination stream.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * stream: pointer to a writable C2paStream.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns 0.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
///
/// # Example
/// ```c
/// auto result = c2pa_builder_to_archive(builder, stream);
/// if (result < 0) {
///     auto error = c2pa_error();
///     printf("Error: %s\n", error);
///     c2pa_string_free(error);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_to_archive(
    builder_ptr: *mut C2paBuilder,
    stream: *mut C2paStream,
) -> c_int {
    check_or_return_int!(builder_ptr);
    check_or_return_int!(stream);
    let mut builder = guard_boxed_int!(builder_ptr);
    let result = builder.to_archive(&mut (*stream));
    ok_or_return_int!(result, |_| 0) // returns 0 on success
}

/// Creates and writes signed manifest from the C2paBuilder to the destination stream.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * format: pointer to a C string with the mime type or extension.
/// * source: pointer to a C2paStream.
/// * dest: pointer to a writable C2paStream.
/// * signer: pointer to a C2paSigner.
/// * c2pa_bytes_ptr: pointer to a pointer to a c_uchar to return manifest_bytes (optional, can be NULL).
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns the size of the c2pa data.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings
/// If manifest_bytes_ptr is not NULL, the returned value MUST be released by calling c2pa_manifest_bytes_free
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_sign(
    builder_ptr: *mut C2paBuilder,
    format: *const c_char,
    source: *mut C2paStream,
    dest: *mut C2paStream,
    signer_ptr: *mut C2paSigner,
    manifest_bytes_ptr: *mut *const c_uchar,
) -> i64 {
    check_or_return_int!(builder_ptr);
    let format = from_cstr_or_return_int!(format);
    check_or_return_int!(source);
    check_or_return_int!(dest);
    check_or_return_int!(signer_ptr);
    check_or_return_int!(manifest_bytes_ptr);

    let mut builder = guard_boxed!(builder_ptr);
    let c2pa_signer = guard_boxed!(signer_ptr);

    let result = builder.sign(
        c2pa_signer.signer.as_ref(),
        &format,
        &mut *source,
        &mut *dest,
    );
    ok_or_return_int!(result, |manifest_bytes: Vec<u8>| {
        let len = manifest_bytes.len() as i64;
        if !manifest_bytes_ptr.is_null() {
            *manifest_bytes_ptr =
                Box::into_raw(manifest_bytes.into_boxed_slice()) as *const c_uchar;
        };
        len
    })
}

/// Frees a C2PA manifest returned by c2pa_builder_sign.
///
/// # Safety
/// The bytes can only be freed once and are invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_manifest_bytes_free(manifest_bytes_ptr: *const c_uchar) {
    if !manifest_bytes_ptr.is_null() {
        drop(Box::from_raw(manifest_bytes_ptr as *mut c_uchar));
    }
}

/// Creates a hashed placeholder from a Builder.
/// The placeholder is used to reserve size in an asset for later signing.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * reserved_size: the size required for a signature from the intended signer.
/// * exclusion_map_json: is an optional pointer to use add BMFF exclusions
/// * manifest_bytes_ptr: pointer to a pointer to a c_uchar to return manifest_bytes.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns the size of the manifest_bytes.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// If manifest_bytes_ptr is not NULL, the returned value MUST be released by calling c2pa_manifest_bytes_free
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_bmff_hashed_placeholder(
    builder_ptr: *mut C2paBuilder,
    reserved_size: usize,
    exclusion_map_json: *const c_char,
    manifest_bytes_ptr: *mut *const c_uchar,
) -> i64 {
    check_or_return_int!(builder_ptr);
    check_or_return_int!(manifest_bytes_ptr);
    let exclusion_map_str = from_cstr_option!(exclusion_map_json);

    let mut builder = guard_boxed!(builder_ptr);
    let result =
        builder.get_bmff_hashed_manifest_placeholder(reserved_size, exclusion_map_str.as_deref());

    ok_or_return_int!(result, |manifest_bytes: Vec<u8>| {
        let len = manifest_bytes.len() as i64;
        if !manifest_bytes_ptr.is_null() {
            *manifest_bytes_ptr =
                Box::into_raw(manifest_bytes.into_boxed_slice()) as *const c_uchar;
        };
        len
    })
}

/// Sign a Builder using the specified signer and bmff hash.
/// The hasher_ptr contains a C2paHasher that was used to accumulate the hash the file was written.
/// This is a low-level method for advanced use cases where the caller handles embedding the manifest in BMFF assets.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * signer: pointer to a C2paSigner.
/// * hasher_ptr: pointer to C2paHasher.  Can be null if you pass in asset.
/// * asset: pointer to C2paStream.  If present it will used in lieu of the value passed in hasher_ptr.
/// * manifest_bytes_ptr: pointer to a pointer to a c_uchar to return manifest_bytes (optional, can be NULL).
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns the size of the manifest_bytes.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// If manifest_bytes_ptr is not NULL, the returned value MUST be released by calling c2pa_manifest_bytes_free
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_sign_bmff_hashed_embeddable(
    builder_ptr: *mut C2paBuilder,
    signer_ptr: *mut C2paSigner,
    hasher_ptr: *mut C2paHasher,
    asset_stream_ptr: *mut C2paStream,
    manifest_bytes_ptr: *mut *const c_uchar,
) -> i64 {
    check_or_return_int!(builder_ptr);
    check_or_return_int!(signer_ptr);
    check_or_return_int!(manifest_bytes_ptr);

    let mut builder = guard_boxed!(builder_ptr);
    let c2pa_signer = guard_boxed!(signer_ptr);

    let hash = if !asset_stream_ptr.is_null() {
        let mut asset_stream = guard_boxed!(asset_stream_ptr);
        // generate the hash from the asset
        if let Some((mut bmff_hash, label)) = builder.find_assertion_by_label::<BmffHash>(BMFF_HASH)
        {
            let (_label, version, _instance) = parse_label(&label);

            bmff_hash.set_bmff_version(version);

            match bmff_hash.gen_hash_from_stream(&mut *asset_stream) {
                Ok(_) => bmff_hash.hash().map_or(Vec::new(), |v| v.clone()),
                Err(err) => {
                    println!("Error generating hash from stream: {err}");
                    Error::from_c2pa_error(err).set_last();
                    return -1;
                }
            }
        } else {
            Error::from_c2pa_error(c2pa::Error::BadParam(
                "BmffHash assertion not found in manifest".to_string(),
            ))
            .set_last();
            return -1;
        }
    } else if !hasher_ptr.is_null() {
        // grab the value from the user generated hash
        let mut hasher = guard_boxed!(hasher_ptr);
        hasher.finalize_reset()
    } else {
        Error::from_c2pa_error(c2pa::Error::BadParam(
            "must have C2paHasher or C2paStream".to_string(),
        ))
        .set_last();
        return -1;
    };

    let result = builder.sign_bmff_hashed_embeddable(c2pa_signer.signer.as_ref(), &hash);

    ok_or_return_int!(result, |manifest_bytes: Vec<u8>| {
        let len = manifest_bytes.len() as i64;
        if !manifest_bytes_ptr.is_null() {
            *manifest_bytes_ptr =
                Box::into_raw(manifest_bytes.into_boxed_slice()) as *const c_uchar;
        };
        len
    })
}

/// Creates a hashed placeholder from a Builder.
/// The placeholder is used to reserve size in an asset for later signing.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * reserved_size: the size required for a signature from the intended signer.
/// * format: pointer to a C string with the mime type or extension.
/// * manifest_bytes_ptr: pointer to a pointer to a c_uchar to return manifest_bytes.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns the size of the manifest_bytes.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// If manifest_bytes_ptr is not NULL, the returned value MUST be released by calling c2pa_manifest_bytes_free
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_data_hashed_placeholder(
    builder_ptr: *mut C2paBuilder,
    reserved_size: usize,
    format: *const c_char,
    manifest_bytes_ptr: *mut *const c_uchar,
) -> i64 {
    check_or_return_int!(builder_ptr);
    check_or_return_int!(manifest_bytes_ptr);
    let mut builder = guard_boxed!(builder_ptr);
    let format = from_cstr_or_return_int!(format);
    let result = builder.data_hashed_placeholder(reserved_size, &format);
    ok_or_return_int!(result, |manifest_bytes: Vec<u8>| {
        let len = manifest_bytes.len() as i64;
        if !manifest_bytes_ptr.is_null() {
            *manifest_bytes_ptr =
                Box::into_raw(manifest_bytes.into_boxed_slice()) as *const c_uchar;
        };
        len
    })
}

/// Sign a Builder using the specified signer and data hash.
/// The data hash is a JSON string containing DataHash information for the asset.
/// This is a low-level method for advanced use cases where the caller handles embedding the manifest.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * signer: pointer to a C2paSigner.
/// * data_hash: pointer to a C string with the JSON data hash.
/// * format: pointer to a C string with the mime type or extension.
/// * asset: pointer to a C2paStream (may be NULL to use pre calculated hashes).
/// * manifest_bytes_ptr: pointer to a pointer to a c_uchar to return manifest_bytes (optional, can be NULL).
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns the size of the manifest_bytes.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// If manifest_bytes_ptr is not NULL, the returned value MUST be released by calling c2pa_manifest_bytes_free
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_sign_data_hashed_embeddable(
    builder_ptr: *mut C2paBuilder,
    signer_ptr: *mut C2paSigner,
    data_hash: *const c_char,
    format: *const c_char,
    asset: *mut C2paStream,
    manifest_bytes_ptr: *mut *const c_uchar,
) -> i64 {
    check_or_return_int!(builder_ptr);
    check_or_return_int!(signer_ptr);
    let data_hash_json = from_cstr_or_return_int!(data_hash);
    let format = from_cstr_or_return_int!(format);
    check_or_return_int!(manifest_bytes_ptr);

    let mut data_hash: DataHash = match serde_json::from_str(&data_hash_json) {
        Ok(data_hash) => data_hash,
        Err(err) => {
            Error::from_c2pa_error(c2pa::Error::JsonError(err)).set_last();
            return -1;
        }
    };
    if !asset.is_null() {
        // calc hashes from the asset stream
        match data_hash.gen_hash_from_stream(&mut *asset) {
            Ok(_) => {}
            Err(err) => {
                Error::from_c2pa_error(err).set_last();
                return -1;
            }
        }
    }

    let mut builder = guard_boxed!(builder_ptr);
    let c2pa_signer = guard_boxed!(signer_ptr);

    let result =
        builder.sign_data_hashed_embeddable(c2pa_signer.signer.as_ref(), &data_hash, &format);

    ok_or_return_int!(result, |manifest_bytes: Vec<u8>| {
        let len = manifest_bytes.len() as i64;
        if !manifest_bytes_ptr.is_null() {
            *manifest_bytes_ptr =
                Box::into_raw(manifest_bytes.into_boxed_slice()) as *const c_uchar;
        };
        len
    })
}

/// Convert a binary c2pa manifest into an embeddable version for the given format.
/// A raw manifest (in application/c2pa format) can be uploaded to the cloud but
/// it cannot be embedded directly into an asset without extra processing.
/// This method converts the raw manifest into an embeddable version that can be
/// embedded into an asset.
///
/// # Parameters
/// * format: pointer to a C string with the mime type or extension.
/// * manifest_bytes_ptr: pointer to a c_uchar with the raw manifest bytes.
/// * manifest_bytes_size: the size of the manifest_bytes.
/// * result_bytes_ptr: pointer to a pointer to a c_uchar to return the embeddable manifest bytes.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns the size of the result_bytes.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The returned value MUST be released by calling c2pa_manifest_bytes_free
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_format_embeddable(
    format: *const c_char,
    manifest_bytes_ptr: *const c_uchar,
    manifest_bytes_size: usize,
    result_bytes_ptr: *mut *const c_uchar,
) -> i64 {
    let format = from_cstr_or_return_int!(format);
    check_or_return_int!(manifest_bytes_ptr);
    check_or_return_int!(result_bytes_ptr);

    // Safe bounds validation for manifest bytes
    let bytes = match safe_slice_from_raw_parts(
        manifest_bytes_ptr,
        manifest_bytes_size,
        "manifest_bytes_ptr",
    ) {
        Ok(bytes) => bytes,
        Err(err) => {
            err.set_last();
            return -1;
        }
    };

    let result = c2pa::Builder::composed_manifest(bytes, &format);
    ok_or_return_int!(result, |result_bytes: Vec<u8>| {
        let len = result_bytes.len() as i64;
        if !result_bytes_ptr.is_null() {
            *result_bytes_ptr = Box::into_raw(result_bytes.into_boxed_slice()) as *const c_uchar;
        };
        len
    })
}

/// Creates a C2paSigner from a callback and configuration.
///
/// # Parameters
/// * callback: a callback function to sign data.
/// * alg: the signing algorithm.
/// * certs: a pointer to a NULL-terminated string containing the certificate chain in PEM format.
/// * tsa_url: a pointer to a NULL-terminated string containing the RFC 3161 compliant timestamp authority URL.
///
/// # Errors
/// Returns NULL if there were errors, otherwise returns a pointer to a C2paSigner.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The returned value MUST be released by calling c2pa_signer_free
/// and it is no longer valid after that call.
/// When binding through the C API to other languages, the callback must live long
/// enough, possibly being re-used and called multiple times. The callback is logically
/// owned by the host/caller.
///
/// # Example
/// ```c
/// auto result = c2pa_signer_create(callback, alg, certs, tsa_url);
/// if (result == NULL) {
///     auto error = c2pa_error();
///     printf("Error: %s\n", error);
///     c2pa_string_free(error);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_signer_create(
    context: *const c_void,
    callback: SignerCallback,
    alg: C2paSigningAlg,
    certs: *const c_char,
    tsa_url: *const c_char,
) -> *mut C2paSigner {
    let certs = from_cstr_or_return_null!(certs);
    let tsa_url = from_cstr_option!(tsa_url);
    let context = context as *const ();

    // Create a callback that uses the provided C callback function
    // The callback ignores its context parameter and will use
    // the context set on the CallbackSigner closure
    let c_callback = move |context: *const (), data: &[u8]| {
        // we need to guess at a max signed size, the callback must verify this is big enough or fail.
        let signed_len_max = data.len() * 2;
        let mut signed_bytes: Vec<u8> = vec![0; signed_len_max];
        let signed_size = unsafe {
            (callback)(
                context,
                data.as_ptr(),
                data.len(),
                signed_bytes.as_mut_ptr(),
                signed_len_max,
            )
        };
        if signed_size < 0 {
            return Err(c2pa::Error::CoseSignature); // todo:: return errors from callback
        }
        signed_bytes.set_len(signed_size as usize);
        Ok(signed_bytes)
    };

    let mut signer = CallbackSigner::new(c_callback, alg.into(), certs).set_context(context);
    if let Some(tsa_url) = tsa_url.as_ref() {
        signer = signer.set_tsa_url(tsa_url);
    }
    Box::into_raw(Box::new(C2paSigner {
        signer: Box::new(signer),
    }))
}

/// Creates a C2paSigner from a SignerInfo.
/// The signer is created from the sign_cert and private_key fields.
/// an optional url to an RFC 3161 compliant time server will ensure the signature is timestamped.
///
/// # Parameters
/// * signer_info: pointer to a C2paSignerInfo.
/// # Errors
/// Returns NULL if there were errors, otherwise returns a pointer to a C2paSigner.
/// The error string can be retrieved by calling c2pa_error.
/// # Safety
/// Reads from NULL-terminated C strings.
/// The returned value MUST be released by calling c2pa_signer_free
/// and it is no longer valid after that call.
/// # Example
/// ```c
/// auto result = c2pa_signer_from_info(signer_info);
/// if (result == NULL) {
///     auto error = c2pa_error();
///     printf("Error: %s\n", error);
///     c2pa_string_free(error);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_signer_from_info(signer_info: &C2paSignerInfo) -> *mut C2paSigner {
    let signer_info = SignerInfo {
        alg: from_cstr_or_return_null!(signer_info.alg),
        sign_cert: from_cstr_or_return_null!(signer_info.sign_cert).into_bytes(),
        private_key: from_cstr_or_return_null!(signer_info.private_key).into_bytes(),
        ta_url: from_cstr_option!(signer_info.ta_url),
    };

    let signer = signer_info.signer();
    match signer {
        Ok(signer) => Box::into_raw(Box::new(C2paSigner {
            signer: Box::new(signer),
        })),
        Err(err) => {
            err.set_last();
            std::ptr::null_mut()
        }
    }
}

/// Creates a C2paSigner from the settings.
/// The signer is created from the settings defined in the c2pa_settings.json file.
///
/// # Errors
/// Returns NULL if there were errors, otherwise returns a pointer to a C2paSigner.
/// The error string can be retrieved by calling c2pa_error.
/// # Safety
/// The returned value MUST be released by calling c2pa_signer_free
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_signer_from_settings() -> *mut C2paSigner {
    let signer = Settings::signer();
    ok_or_return_null!(signer, |signer| {
        Box::into_raw(Box::new(C2paSigner {
            signer: Box::new(signer),
        }))
    })
}

/// Returns the size to reserve for the signature for this signer.
///
/// # Parameters
/// * signer_ptr: pointer to a C2paSigner.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns the size to reserve.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// The signer_ptr must be a valid pointer to a C2paSigner.
#[no_mangle]
pub unsafe extern "C" fn c2pa_signer_reserve_size(signer_ptr: *mut C2paSigner) -> i64 {
    check_or_return_int!(signer_ptr);
    let c2pa_signer = guard_boxed!(signer_ptr);
    c2pa_signer.signer.reserve_size() as i64
}

/// Frees a C2paSigner allocated by Rust.
///
/// # Safety
/// The C2paSigner can only be freed once and is invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_signer_free(signer_ptr: *const C2paSigner) {
    if !signer_ptr.is_null() {
        drop(Box::from_raw(signer_ptr as *mut C2paSigner));
    }
}

#[no_mangle]
/// Signs a byte array using the Ed25519 algorithm.
/// # Safety
/// The returned value MUST be freed by calling c2pa_signature_free
/// and it is no longer valid after that call.
pub unsafe extern "C" fn c2pa_ed25519_sign(
    bytes: *const c_uchar,
    len: usize,
    private_key: *const c_char,
) -> *const c_uchar {
    check_or_return_null!(bytes);
    let private_key = from_cstr_or_return_null!(private_key);

    // Safe bounds validation for input bytes
    let bytes = match safe_slice_from_raw_parts(bytes, len, "bytes") {
        Ok(bytes) => bytes,
        Err(err) => {
            err.set_last();
            return std::ptr::null();
        }
    };

    let result = CallbackSigner::ed25519_sign(bytes, private_key.as_bytes());
    match result {
        Ok(signed_bytes) => {
            let signed_bytes = signed_bytes.into_boxed_slice();
            let ptr = signed_bytes.as_ptr();
            std::mem::forget(signed_bytes);
            ptr
        }
        Err(_) => std::ptr::null(),
    }
}

#[no_mangle]
/// Frees a signature allocated by Rust.
/// # Safety
/// The signature can only be freed once and is invalid after this call.
pub unsafe extern "C" fn c2pa_signature_free(signature_ptr: *const u8) {
    if !signature_ptr.is_null() {
        drop(Box::from_raw(signature_ptr as *mut u8));
    }
}

/// Returns a [*const *const c_char] with the contents of of the provided [Vec<String>].
///
/// # Parameters
/// - `strs`: The vector of Rust strings to convert into [CString]s
/// - `count`: Will be set to the number of strings in the array.
///
/// # Safety
/// - The caller is responsible for eventually freeing each C string and the array itself to
///   avoid memory leaks [c2pa_free_string_array].
/// - The function uses `std::mem::forget` to intentionally leak the vector, transferring
///   ownership of the memory to the caller.
///
/// # Returns
/// - A pointer to the first element of an array of pointers to C strings (`*const *const c_char`).
///
/// # Note
/// This should be used internally. We don't want to support this as a public API.
unsafe fn c2pa_mime_types_to_c_array(strs: Vec<String>, count: *mut usize) -> *const *const c_char {
    // Even if the array is exposed as a `*const *const c_char` for read-only access,
    // the underlying memory must be allocated as `*mut *mut c_char` because freeing
    // or deallocating memory requires a mutable pointer. This ensures the caller can
    // safely release ownership of both the array and its strings.
    let mut mime_ptrs: Vec<*mut c_char> = strs.into_iter().map(|s| to_c_string(s)).collect();
    mime_ptrs.shrink_to_fit();

    // verify that the length and capacity of the vector are identitical, as we rely on this later
    // when de-allocating the memory associated to this vector.
    debug_assert_eq!(mime_ptrs.len(), mime_ptrs.capacity());

    *count = mime_ptrs.len();

    let ptr = mime_ptrs.as_ptr();
    std::mem::forget(mime_ptrs);

    ptr as *const *const c_char
}

#[cfg(test)]
mod tests {
    use std::{ffi::CString, panic::catch_unwind};

    use super::*;
    use crate::TestC2paStream;

    macro_rules! fixture_path {
        ($path:expr) => {
            concat!("../../sdk/tests/fixtures/", $path)
        };
    }

    /// Helper to create a signer and builder for testing
    /// Returns (signer, builder)
    fn setup_signer_and_builder_for_signing_tests() -> (*mut C2paSigner, *mut C2paBuilder) {
        let certs = include_str!(fixture_path!("certs/ed25519.pub"));
        let private_key = include_bytes!(fixture_path!("certs/ed25519.pem"));
        let alg = CString::new("Ed25519").unwrap();
        let sign_cert = CString::new(certs).unwrap();
        let private_key = CString::new(private_key).unwrap();
        let signer_info = C2paSignerInfo {
            alg: alg.as_ptr(),
            sign_cert: sign_cert.as_ptr(),
            private_key: private_key.as_ptr(),
            ta_url: std::ptr::null(),
        };
        let signer = unsafe { c2pa_signer_from_info(&signer_info) };
        assert!(!signer.is_null());

        let manifest_def = CString::new("{}").unwrap();
        let builder = unsafe { c2pa_builder_from_json(manifest_def.as_ptr()) };
        assert!(!builder.is_null());

        (signer, builder)
    }

    #[test]
    fn test_ed25519_sign() {
        let bytes = b"test";
        let private_key = include_bytes!(fixture_path!("certs/ed25519.pem"));
        let private_key = CString::new(private_key).unwrap();
        let signature =
            unsafe { c2pa_ed25519_sign(bytes.as_ptr(), bytes.len(), private_key.as_ptr()) };
        assert!(!signature.is_null());
        unsafe { c2pa_signature_free(signature) };
    }

    #[test]
    fn test_c2pa_signer_from_info() {
        let certs = include_str!(fixture_path!("certs/ed25519.pub"));
        let private_key = include_bytes!(fixture_path!("certs/ed25519.pem"));
        let alg = CString::new("Ed25519").unwrap();
        let sign_cert = CString::new(certs).unwrap();
        let private_key = CString::new(private_key).unwrap();
        let signer_info = C2paSignerInfo {
            alg: alg.as_ptr(),
            sign_cert: sign_cert.as_ptr(),
            private_key: private_key.as_ptr(),
            ta_url: std::ptr::null(),
        };
        let signer = unsafe { c2pa_signer_from_info(&signer_info) };
        assert!(!signer.is_null());
        unsafe { c2pa_signer_free(signer) };
    }

    #[test]
    fn test_signer_from_info_bad_alg() {
        let alg = CString::new("BadAlg").unwrap();
        let sign_cert = CString::new("certs").unwrap();
        let private_key = CString::new("private_key").unwrap();
        let signer_info = C2paSignerInfo {
            alg: alg.as_ptr(),
            sign_cert: sign_cert.as_ptr(),
            private_key: private_key.as_ptr(),
            ta_url: std::ptr::null(),
        };
        let signer = unsafe { c2pa_signer_from_info(&signer_info) };
        assert!(signer.is_null());
        let error = unsafe { c2pa_error() };
        let error = unsafe { CString::from_raw(error) };
        assert_eq!(error.to_str().unwrap(), "Other: Invalid signing algorithm");
    }

    #[test]
    fn test_sign_with_info() {
        let source_image = include_bytes!(fixture_path!("IMG_0003.jpg"));
        let mut source_stream = TestC2paStream::from_bytes(source_image.to_vec());
        let dest_vec = Vec::new();
        let mut dest_stream = TestC2paStream::new(dest_vec).into_c_stream();

        let (signer, builder) = setup_signer_and_builder_for_signing_tests();

        let format = CString::new("image/jpeg").unwrap();
        let mut manifest_bytes_ptr = std::ptr::null();
        let _ = unsafe {
            c2pa_builder_sign(
                builder,
                format.as_ptr(),
                &mut source_stream,
                &mut dest_stream,
                signer,
                &mut manifest_bytes_ptr,
            )
        };
        // let error = unsafe { c2pa_error() };
        // let error = unsafe { CString::from_raw(error) };
        // assert_eq!(error.to_str().unwrap(), "Other Invalid signing algorithm");
        // assert_eq!(result, 65485);
        TestC2paStream::drop_c_stream(source_stream);
        TestC2paStream::drop_c_stream(dest_stream);
        unsafe {
            c2pa_manifest_bytes_free(manifest_bytes_ptr);
        }
        unsafe { c2pa_builder_free(builder) };
        unsafe { c2pa_signer_free(signer) };
    }

    #[test]
    fn builder_add_actions_and_sign() {
        let source_image = include_bytes!(fixture_path!("IMG_0003.jpg"));
        let mut source_stream = TestC2paStream::from_bytes(source_image.to_vec());
        let dest_vec = Vec::new();
        let mut dest_stream = TestC2paStream::new(dest_vec).into_c_stream();

        let (signer, builder) = setup_signer_and_builder_for_signing_tests();

        let action_json = CString::new(
            r#"{
            "action": "com.example.test-action",
            "parameters": {
                "key1": "value1",
                "key2": "value2"
            }
        }"#,
        )
        .unwrap();

        // multiple calls add multiple actions
        let result = unsafe { c2pa_builder_add_action(builder, action_json.as_ptr()) };
        assert_eq!(result, 0);

        let format = CString::new("image/jpeg").unwrap();
        let mut manifest_bytes_ptr = std::ptr::null();
        let _ = unsafe {
            c2pa_builder_sign(
                builder,
                format.as_ptr(),
                &mut source_stream,
                &mut dest_stream,
                signer,
                &mut manifest_bytes_ptr,
            )
        };

        // Verify we can read the signed data back
        let dest_test_stream = TestC2paStream::from_c_stream(dest_stream);
        let mut read_stream = dest_test_stream.into_c_stream();
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), &mut read_stream) };
        assert!(!reader.is_null());

        let json = unsafe { c2pa_reader_json(reader) };
        assert!(!json.is_null());
        let json_str = unsafe { CString::from_raw(json) };
        let json_content = json_str.to_str().unwrap();

        assert!(json_content.contains("manifest"));
        assert!(json_content.contains("com.example.test-action"));

        TestC2paStream::drop_c_stream(source_stream);
        TestC2paStream::drop_c_stream(read_stream);
        unsafe {
            c2pa_manifest_bytes_free(manifest_bytes_ptr);
            c2pa_builder_free(builder);
            c2pa_signer_free(signer);
            c2pa_reader_free(reader);
        }
    }

    #[test]
    fn builder_create_intent_digital_creation_and_sign() {
        let source_image = include_bytes!(fixture_path!("IMG_0003.jpg"));
        let mut source_stream = TestC2paStream::from_bytes(source_image.to_vec());
        let dest_vec = Vec::new();
        let mut dest_stream = TestC2paStream::new(dest_vec).into_c_stream();

        let (signer, builder) = setup_signer_and_builder_for_signing_tests();

        // The create intent requires needs a digital source type
        let result = unsafe {
            c2pa_builder_set_intent(
                builder,
                C2paBuilderIntent::Create,
                C2paDigitalSourceType::DigitalCreation,
            )
        };
        assert_eq!(result, 0);

        let format = CString::new("image/jpeg").unwrap();
        let mut manifest_bytes_ptr = std::ptr::null();
        let _ = unsafe {
            c2pa_builder_sign(
                builder,
                format.as_ptr(),
                &mut source_stream,
                &mut dest_stream,
                signer,
                &mut manifest_bytes_ptr,
            )
        };

        // Verify we can read the signed data back
        let dest_test_stream = TestC2paStream::from_c_stream(dest_stream);
        let mut read_stream = dest_test_stream.into_c_stream();
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), &mut read_stream) };
        assert!(!reader.is_null());

        let json = unsafe { c2pa_reader_json(reader) };
        assert!(!json.is_null());

        let json_str = unsafe { CString::from_raw(json) };
        let json_content = json_str.to_str().unwrap();

        assert!(json_content.contains("c2pa.created"));
        // Verify the digital source type was used
        assert!(json_content.contains("digitalSourceType"));
        assert!(json_content.contains("digitalCreation"));
        // Verify there is only one c2pa.created action
        assert_eq!(
            json_content.matches("\"action\": \"c2pa.created\"").count(),
            1
        );

        TestC2paStream::drop_c_stream(source_stream);
        TestC2paStream::drop_c_stream(read_stream);
        unsafe {
            c2pa_manifest_bytes_free(manifest_bytes_ptr);
            c2pa_builder_free(builder);
            c2pa_signer_free(signer);
            c2pa_reader_free(reader);
        }
    }

    #[test]
    fn builder_create_intent_empty_and_sign() {
        let source_image = include_bytes!(fixture_path!("IMG_0003.jpg"));
        let mut source_stream = TestC2paStream::from_bytes(source_image.to_vec());
        let dest_vec = Vec::new();
        let mut dest_stream = TestC2paStream::new(dest_vec).into_c_stream();

        let (signer, builder) = setup_signer_and_builder_for_signing_tests();

        // The create intent requires needs a digital source type
        let result = unsafe {
            c2pa_builder_set_intent(
                builder,
                C2paBuilderIntent::Create,
                C2paDigitalSourceType::Empty,
            )
        };
        assert_eq!(result, 0);

        let format = CString::new("image/jpeg").unwrap();
        let mut manifest_bytes_ptr = std::ptr::null();
        let _ = unsafe {
            c2pa_builder_sign(
                builder,
                format.as_ptr(),
                &mut source_stream,
                &mut dest_stream,
                signer,
                &mut manifest_bytes_ptr,
            )
        };

        // Verify we can read the signed data back
        let dest_test_stream = TestC2paStream::from_c_stream(dest_stream);
        let mut read_stream = dest_test_stream.into_c_stream();
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), &mut read_stream) };
        assert!(!reader.is_null());

        let json = unsafe { c2pa_reader_json(reader) };
        assert!(!json.is_null());

        let json_str = unsafe { CString::from_raw(json) };
        let json_content = json_str.to_str().unwrap();

        assert!(json_content.contains("c2pa.created"));
        // Verify the digital source type we picked was used
        assert!(json_content.contains("digitalsourcetype/empty"));

        TestC2paStream::drop_c_stream(source_stream);
        TestC2paStream::drop_c_stream(read_stream);
        unsafe {
            c2pa_manifest_bytes_free(manifest_bytes_ptr);
            c2pa_builder_free(builder);
            c2pa_signer_free(signer);
            c2pa_reader_free(reader);
        }
    }

    #[test]
    fn builder_edit_intent_and_sign() {
        // Use an already-signed image as the source for editing
        let signed_source_image = include_bytes!(fixture_path!("C.jpg"));
        let mut source_stream = TestC2paStream::from_bytes(signed_source_image.to_vec());
        let dest_vec = Vec::new();
        let mut dest_stream = TestC2paStream::new(dest_vec).into_c_stream();

        let (signer, builder) = setup_signer_and_builder_for_signing_tests();

        // Edit intent will extract the parent ingredient from source
        // (Digital source type is ignored in the case of the edit intent)
        let result = unsafe {
            c2pa_builder_set_intent(
                builder,
                C2paBuilderIntent::Edit,
                C2paDigitalSourceType::Empty,
            )
        };
        assert_eq!(result, 0);

        // Verify we can read the signed data back
        let format = CString::new("image/jpeg").unwrap();
        let mut manifest_bytes_ptr = std::ptr::null();
        let _ = unsafe {
            c2pa_builder_sign(
                builder,
                format.as_ptr(),
                &mut source_stream,
                &mut dest_stream,
                signer,
                &mut manifest_bytes_ptr,
            )
        };

        let dest_test_stream = TestC2paStream::from_c_stream(dest_stream);
        let mut read_stream = dest_test_stream.into_c_stream();
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), &mut read_stream) };
        assert!(!reader.is_null());

        let json = unsafe { c2pa_reader_json(reader) };
        assert!(!json.is_null());
        let json_str = unsafe { CString::from_raw(json) };
        let json_content = json_str.to_str().unwrap();

        assert!(json_content.contains("c2pa.opened"));
        // Verify the digital source type parameter was ignored for Edit intent
        // and no "empty" source type appears in the JSON
        assert!(!json_content.contains("digitalsourcetype/empty"));

        TestC2paStream::drop_c_stream(source_stream);
        TestC2paStream::drop_c_stream(read_stream);
        unsafe {
            c2pa_manifest_bytes_free(manifest_bytes_ptr);
            c2pa_builder_free(builder);
            c2pa_signer_free(signer);
            c2pa_reader_free(reader);
        }
    }

    #[test]
    fn test_c2pa_builder_no_embed_null() {
        let builder: *mut c2pa::Builder = std::ptr::null_mut();
        unsafe { c2pa_builder_set_no_embed(builder) };
    }

    #[test]
    fn test_c2pa_builder_set_remote_url_null() {
        let builder: *mut c2pa::Builder = std::ptr::null_mut();
        let remote_url = CString::new("https://example.com").unwrap();
        let result = unsafe { c2pa_builder_set_remote_url(builder, remote_url.as_ptr()) };
        assert_eq!(result, -1);
        let error = unsafe { c2pa_error() };
        let error = unsafe { CString::from_raw(error) };
        assert_eq!(error.to_str().unwrap(), "NullParameter: builder_ptr");
    }

    #[test]
    fn test_c2pa_builder_no_embed() {
        let manifest_def = CString::new("{}").unwrap();
        let builder = unsafe { c2pa_builder_from_json(manifest_def.as_ptr()) };
        assert!(!builder.is_null());
        unsafe { c2pa_builder_set_no_embed(builder) };
        unsafe { c2pa_builder_free(builder) };
    }

    #[test]
    fn test_c2pa_version() {
        let version = unsafe { c2pa_version() };
        assert!(!version.is_null());
        let version_str = unsafe { CString::from_raw(version) };
        assert!(!version_str.to_str().unwrap().is_empty());
    }

    #[test]
    fn test_c2pa_error_no_error() {
        let error = unsafe { c2pa_error() };
        assert!(!error.is_null());
        let error_str = unsafe { CString::from_raw(error) };
        assert_eq!(error_str.to_str().unwrap(), "");
    }

    #[test]
    fn test_c2pa_load_settings() {
        let settings = CString::new("{}").unwrap();
        let format = CString::new("json").unwrap();
        let result = unsafe { c2pa_load_settings(settings.as_ptr(), format.as_ptr()) };
        assert_eq!(result, 0);
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_c2pa_read_file_null_path() {
        let data_dir = CString::new("/tmp").unwrap();
        let result = unsafe { c2pa_read_file(std::ptr::null(), data_dir.as_ptr()) };
        assert!(result.is_null());
        let error = unsafe { c2pa_error() };
        let error_str = unsafe { CString::from_raw(error) };
        assert_eq!(error_str.to_str().unwrap(), "NullParameter: path");
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_c2pa_read_ingredient_file_null_path() {
        let data_dir = CString::new("/tmp").unwrap();
        let result = unsafe { c2pa_read_ingredient_file(std::ptr::null(), data_dir.as_ptr()) };
        assert!(result.is_null());
        let error = unsafe { c2pa_error() };
        let error_str = unsafe { CString::from_raw(error) };
        assert_eq!(error_str.to_str().unwrap(), "NullParameter: path");
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_c2pa_sign_file_null_source_path() {
        let dest_path = CString::new("/tmp/output.jpg").unwrap();
        let manifest = CString::new("{}").unwrap();
        let signer_info = C2paSignerInfo {
            alg: std::ptr::null(),
            sign_cert: std::ptr::null(),
            private_key: std::ptr::null(),
            ta_url: std::ptr::null(),
        };
        let result = unsafe {
            c2pa_sign_file(
                std::ptr::null(),
                dest_path.as_ptr(),
                manifest.as_ptr(),
                &signer_info,
                std::ptr::null(),
            )
        };
        assert!(result.is_null());
        let error = unsafe { c2pa_error() };
        let error_str = unsafe { CString::from_raw(error) };
        assert_eq!(error_str.to_str().unwrap(), "NullParameter: source_path");
    }

    #[test]
    fn test_c2pa_reader_remote_url() {
        let mut stream = TestC2paStream::new(include_bytes!(fixture_path!("cloud.jpg")).to_vec())
            .into_c_stream();

        let format = CString::new("image/jpeg").unwrap();
        let result = unsafe { c2pa_reader_from_stream(format.as_ptr(), &mut stream) };
        assert!(!result.is_null());
        let remote_url = unsafe { c2pa_reader_remote_url(result) };
        assert!(!remote_url.is_null());
        let remote_url = unsafe { std::ffi::CStr::from_ptr(remote_url) };
        assert_eq!(remote_url, c"https://cai-manifests.adobe.com/manifests/adobe-urn-uuid-5f37e182-3687-462e-a7fb-573462780391");
        TestC2paStream::drop_c_stream(stream);
    }

    // cargo test test_reader_file_with_wrong_label -- --nocapture
    #[test]
    fn test_reader_file_with_wrong_label() {
        let mut stream = TestC2paStream::new(
            include_bytes!(fixture_path!("adobe-20220124-E-clm-CAICAI.jpg")).to_vec(),
        )
        .into_c_stream();

        let format = CString::new("image/jpeg").unwrap();
        let result: *mut C2paReader =
            unsafe { c2pa_reader_from_stream(format.as_ptr(), &mut stream) };
        assert!(!result.is_null());
        TestC2paStream::drop_c_stream(stream);
    }

    #[test]
    fn test_c2pa_reader_from_stream_null_format() {
        let mut stream = TestC2paStream::new(Vec::new()).into_c_stream();

        let result = unsafe { c2pa_reader_from_stream(std::ptr::null(), &mut stream) };
        assert!(result.is_null());
        let error = unsafe { c2pa_error() };
        let error_str = unsafe { CString::from_raw(error) };
        assert_eq!(error_str.to_str().unwrap(), "NullParameter: format");
        TestC2paStream::drop_c_stream(stream);
    }

    #[test]
    fn test_c2pa_reader_from_stream_cawg() {
        let source_image = include_bytes!(
            "../../sdk/src/identity/tests/fixtures/claim_aggregation/ica_validation/success.jpg"
        );
        let mut stream = TestC2paStream::from_bytes(source_image.to_vec());
        let format = CString::new("image/jpeg").unwrap();
        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), &mut stream) };
        assert!(!reader.is_null());
        let json = unsafe { c2pa_reader_json(reader) };
        assert!(!json.is_null());
        let json_str = unsafe { CString::from_raw(json) };
        assert!(json_str.to_str().unwrap().contains("Silly Cats 929"));
        assert!(json_str
            .to_str()
            .unwrap()
            .contains("cawg.ica.credential_valid"));
        TestC2paStream::drop_c_stream(stream);
    }

    #[test]
    fn test_c2pa_reader_json_null_reader() {
        let result = unsafe { c2pa_reader_json(std::ptr::null_mut()) };
        assert!(result.is_null());
        let error = unsafe { c2pa_error() };
        let error_str = unsafe { CString::from_raw(error) };
        assert_eq!(error_str.to_str().unwrap(), "NullParameter: reader_ptr");
    }

    #[test]
    fn test_c2pa_builder_add_resource_null_uri() {
        let manifest_def = CString::new("{}").unwrap();
        let builder = unsafe { c2pa_builder_from_json(manifest_def.as_ptr()) };
        assert!(!builder.is_null());
        let mut stream = TestC2paStream::new(Vec::new()).into_c_stream();
        let result = unsafe { c2pa_builder_add_resource(builder, std::ptr::null(), &mut stream) };
        assert_eq!(result, -1);
        let error = unsafe { c2pa_error() };
        let error_str = unsafe { CString::from_raw(error) };
        assert_eq!(error_str.to_str().unwrap(), "NullParameter: uri");
        TestC2paStream::drop_c_stream(stream);
        unsafe { c2pa_builder_free(builder) };
    }

    #[test]
    fn test_c2pa_builder_to_archive_null_stream() {
        let manifest_def = CString::new("{}").unwrap();
        let builder = unsafe { c2pa_builder_from_json(manifest_def.as_ptr()) };
        assert!(!builder.is_null());
        let result = unsafe { c2pa_builder_to_archive(builder, std::ptr::null_mut()) };
        assert_eq!(result, -1);
        let error = unsafe { c2pa_error() };
        let error_str = unsafe { CString::from_raw(error) };
        assert_eq!(error_str.to_str().unwrap(), "NullParameter: stream");
        unsafe { c2pa_builder_free(builder) };
    }

    #[test]
    fn test_c2pa_builder_read_supported_mime_types() {
        let mut count = 0;
        let mime_types = unsafe { c2pa_builder_supported_mime_types(&mut count) };
        assert!(!mime_types.is_null());
        assert_eq!(count, C2paBuilder::supported_mime_types().len());
        unsafe { c2pa_free_string_array(mime_types, count) };
    }

    #[test]
    fn test_c2pa_reader_read_supported_mime_types() {
        let mut count = 0;
        let mime_types = unsafe { c2pa_reader_supported_mime_types(&mut count) };
        assert!(!mime_types.is_null());
        assert_eq!(count, C2paReader::supported_mime_types().len());
        unsafe { c2pa_free_string_array(mime_types, count) };
    }

    #[test]
    fn test_c2pa_free_string_array_with_nullptr() {
        assert!(catch_unwind(|| {
            unsafe {
                c2pa_free_string_array(std::ptr::null_mut(), 0);
            }
        })
        .is_ok());
    }

    #[test]
    fn test_c2pa_free_string_array_with_count_1() {
        let strings = vec![CString::new("image/jpeg").unwrap()];
        let ptrs: Vec<*mut c_char> = strings.into_iter().map(|s| s.into_raw()).collect();
        let ptr = ptrs.as_ptr() as *const *const c_char;
        let count = ptrs.len();
        std::mem::forget(ptrs);

        // Assert the function doesn't panic
        assert!(catch_unwind(|| {
            unsafe {
                c2pa_free_string_array(ptr, count);
            }
        })
        .is_ok());
    }

    #[test]
    fn test_create_callback_signer() {
        extern "C" fn test_callback(
            _context: *const (),
            _data: *const c_uchar,
            _len: usize,
            _signed_bytes: *mut c_uchar,
            _signed_len: usize,
        ) -> isize {
            // Placeholder signer
            1
        }

        let certs = include_str!(fixture_path!("certs/ed25519.pub"));
        let certs_cstr = CString::new(certs).unwrap();

        let signer = unsafe {
            c2pa_signer_create(
                std::ptr::null(),
                test_callback,
                C2paSigningAlg::Ed25519,
                certs_cstr.as_ptr(),
                std::ptr::null(),
            )
        };

        // verify signer is not null (aka could be created)
        assert!(!signer.is_null());

        unsafe { c2pa_signer_free(signer) };
    }

    #[test]
    fn test_sign_with_callback_signer() {
        // Create an example callback that uses the Ed25519 signing function,
        // since we have it around. It is important a "real" callback returns -1 on error.
        extern "C" fn test_callback(
            _context: *const (),
            data: *const c_uchar,
            len: usize,
            signed_bytes: *mut c_uchar,
            signed_len: usize,
        ) -> isize {
            let private_key = include_bytes!(fixture_path!("certs/ed25519.pem"));
            let private_key_cstr = match CString::new(private_key) {
                Ok(s) => s,
                Err(_) => return -1,
            };

            let signature = unsafe { c2pa_ed25519_sign(data, len, private_key_cstr.as_ptr()) };

            // This should not happen, but in a real callback implementation we should check
            if signature.is_null() {
                return -1;
            }

            let signature_len = 64;
            if signed_len < signature_len {
                // This should not happen either, but in a real callback implementation we should check
                unsafe { c2pa_signature_free(signature) };
                return -1;
            }

            // Safe bounds validation for test callback
            let signature_slice =
                match unsafe { safe_slice_from_raw_parts(signature, signature_len, "signature") } {
                    Ok(slice) => slice,
                    Err(_) => {
                        unsafe { c2pa_signature_free(signature) };
                        return -1;
                    }
                };

            // Validate signed_bytes bounds
            if !unsafe { is_safe_buffer_size(signed_len, signed_bytes) } {
                unsafe { c2pa_signature_free(signature) };
                return -1;
            }

            let signed_slice = unsafe { std::slice::from_raw_parts_mut(signed_bytes, signed_len) };

            if signature_len <= signed_slice.len() {
                signed_slice[..signature_len].copy_from_slice(signature_slice);
            } else {
                unsafe { c2pa_signature_free(signature) };
                return -1;
            }

            unsafe { c2pa_signature_free(signature) };
            signature_len as isize
        }

        let source_image = include_bytes!(fixture_path!("IMG_0003.jpg"));
        let mut source_stream = TestC2paStream::from_bytes(source_image.to_vec());
        let dest_vec = Vec::new();
        let mut dest_stream = TestC2paStream::new(dest_vec).into_c_stream();

        let certs = include_str!(fixture_path!("certs/ed25519.pub"));
        let certs_cstr = CString::new(certs).unwrap();

        // Callback signer with a "real" callback that signs data
        let signer = unsafe {
            c2pa_signer_create(
                std::ptr::null(), // context
                test_callback,
                C2paSigningAlg::Ed25519,
                certs_cstr.as_ptr(),
                std::ptr::null(), // tsa_url
            )
        };

        assert!(!signer.is_null());

        let manifest_def = CString::new("{}").unwrap();
        let builder = unsafe { c2pa_builder_from_json(manifest_def.as_ptr()) };
        assert!(!builder.is_null());

        let result = unsafe {
            c2pa_builder_set_intent(
                builder,
                C2paBuilderIntent::Create,
                C2paDigitalSourceType::Empty,
            )
        };
        assert_eq!(result, 0);

        let format = CString::new("image/jpeg").unwrap();
        let mut manifest_bytes_ptr = std::ptr::null();

        // Data gets signed here using the callback
        let result = unsafe {
            c2pa_builder_sign(
                builder,
                format.as_ptr(),
                &mut source_stream,
                &mut dest_stream,
                signer,
                &mut manifest_bytes_ptr,
            )
        };
        assert!(result > 0);

        // Verify we can read the signed data back
        let dest_test_stream = TestC2paStream::from_c_stream(dest_stream);
        let mut read_stream = dest_test_stream.into_c_stream();
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), &mut read_stream) };
        assert!(!reader.is_null());

        let json = unsafe { c2pa_reader_json(reader) };
        assert!(!json.is_null());
        let json_str = unsafe { CString::from_raw(json) };
        let json_content = json_str.to_str().unwrap();

        assert!(json_content.contains("manifest"));

        TestC2paStream::drop_c_stream(source_stream);
        TestC2paStream::drop_c_stream(read_stream);
        unsafe {
            c2pa_manifest_bytes_free(manifest_bytes_ptr);
            c2pa_reader_free(reader);
        }
        unsafe { c2pa_builder_free(builder) };
        unsafe { c2pa_signer_free(signer) };
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_reader_from_file_cawg_identity() {
        let settings = CString::new(include_bytes!(
            "../../cli/tests/fixtures/trust/cawg_test_settings.toml"
        ))
        .unwrap();
        let format = CString::new("toml").unwrap();
        let result = unsafe { c2pa_load_settings(settings.as_ptr(), format.as_ptr()) };
        assert_eq!(result, 0);

        let base = env!("CARGO_MANIFEST_DIR");
        let path =
            CString::new(format!("{base}/../sdk/tests/fixtures/C_with_CAWG_data.jpg")).unwrap();
        let reader = unsafe { c2pa_reader_from_file(path.as_ptr()) };
        if reader.is_null() {
            let error = unsafe { c2pa_error() };
            let error_str = unsafe { CString::from_raw(error) };
            panic!("Failed to create reader: {}", error_str.to_str().unwrap());
        }
        assert!(!reader.is_null());
        let json = unsafe { c2pa_reader_json(reader) };
        assert!(!json.is_null());
        let json_str = unsafe { CString::from_raw(json) };
        println!("JSON Report: {}", json_str.to_str().unwrap());
        let json_report = json_str.to_str().unwrap();
        assert!(json_report.contains("cawg.identity"));
        assert!(json_report.contains("cawg.identity.well-formed"));
    }

    #[test]
    fn test_c2pa_signer_from_settings() {
        const SETTINGS: &str = include_str!("../../sdk/tests/fixtures/test_settings.json");
        let settings = CString::new(SETTINGS).unwrap();
        let format = CString::new("json").unwrap();
        let result = unsafe { c2pa_load_settings(settings.as_ptr(), format.as_ptr()) };
        assert_eq!(result, 0);
        let signer = unsafe { c2pa_signer_from_settings() };
        assert!(!signer.is_null());
        unsafe { c2pa_signer_free(signer) };
    }
    #[test]
    fn test_bmff_embeddable() {
        let manifest_def = r#"{
        "title": "Video Test",
        "format": "video/mp4",
        "claim_generator_info": [
            {
                "name": "ffmpeg_sample_app",
                "version": "1.0.0"
            }
        ],
        "metadata": [
            {
                "dateTime": "1985-04-12T23:20:50.52Z",
                "my_custom_metadata": "my custom metatdata value"
            }
        ],
        "ingredients": [
            {
                "title": "Some Source Video",
                "format": "video/mp4",
                "instance_id": "12345",
                "relationship": "inputTo",
                "metadata": {
                    "dateTime": "1985-04-12T23:20:50.52Z",
                    "my_custom_metadata": "my custom metatdata value"
                }
            }
        ],
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.created",
                            "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
                            "softwareAgent": {
                                "name": "ffmpeg_sample_app",
                                "version": "1.0.0"
                            },
                            "description": "This video was created by ffmpeg_sample_app",
                            "when": "2025-04-22T17:25:28Z",
                            "parameters": {
                                "description": "This image was edited by Adobe Firefly"
                            },
                            "softwareAgentIndex": 0
                        }
                    ]
                }
            },
            {
                "label": "c2pa.metadata",
                "data": {
                    "@context" : {
                        "exif": "http://ns.adobe.com/exif/1.0/",
                        "exifEX": "http://cipa.jp/exif/1.0/",
                        "tiff": "http://ns.adobe.com/tiff/1.0/",
                        "Iptc4xmpExt": "http://iptc.org/std/Iptc4xmpExt/2008-02-29/",
                        "photoshop" : "http://ns.adobe.com/photoshop/1.0/"
                    },
                    "photoshop:DateCreated": "Aug 31, 2022",
                    "Iptc4xmpExt:DigitalSourceType": "https://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",
                    "exif:GPSVersionID": "2.2.0.0",
                    "exif:GPSLatitude": "39,21.102N",
                    "exif:GPSLongitude": "74,26.5737W",
                    "exif:GPSAltitudeRef": 0,
                    "exif:GPSAltitude": "100963/29890",
                    "exifEX:LensSpecification": { "@list": [ 1.55, 4.2, 1.6, 2.4 ] }
                },
                "kind": "Json"
            }
        ]
    }"#;

        let signer_def = r#"{
        "signer": {
            "local": {
              "alg": "ps256",
              "sign_cert": "-----BEGIN CERTIFICATE-----\\n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\\n-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----\\n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\\nwvq03sA=\\n-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----\\n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\\n-----END CERTIFICATE-----",
              "private_key": "-----BEGIN PRIVATE KEY-----\\n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\\nG/dZR0Qj3j0T5F9GX719XpmzYbVFKIKPTsKF\\n-----END PRIVATE KEY-----\\n"
            }
          }
        }"#;

        let manifest_def = CString::new(manifest_def.as_bytes()).unwrap();
        let signer_def = CString::new(signer_def.as_bytes()).unwrap();
        let format = CString::new("json").unwrap();

        let data = "Some data to hash";
        let alg = CString::new("sha256").unwrap();

        let source_image = include_bytes!(fixture_path!("sample1.heic"));
        let mut source_stream = TestC2paStream::from_bytes(source_image.to_vec());

        // set up full write simulate sequence
        unsafe {
            let hasher = c2pa_hasher_from_alg(alg.as_ptr());
            let _setting = c2pa_load_settings(signer_def.as_ptr(), format.as_ptr());
            let builder = c2pa_builder_from_json(manifest_def.as_ptr());
            let signer = c2pa_signer_from_settings();
            let reserve_size = c2pa_signer_reserve_size(signer);

            assert!(!hasher.is_null());
            assert!(!builder.is_null());
            assert!(!signer.is_null());

            // get embedded placeholder
            let mut placeholder_bytes = std::ptr::null();
            let placeholder_len = c2pa_builder_bmff_hashed_placeholder(
                builder,
                reserve_size as usize,
                std::ptr::null(),
                &mut placeholder_bytes,
            );

            // gen some hash values
            let c = c2pa_hasher_update(hasher, data.as_ptr(), data.len());
            assert!(c == 0);

            // gen final manifest
            let mut manifest_bytes = std::ptr::null();

            let manifest_len = c2pa_builder_sign_bmff_hashed_embeddable(
                builder,
                signer,
                hasher,
                &mut source_stream,
                &mut manifest_bytes,
            );
            assert_ne!(manifest_len, -1);
            assert_eq!(placeholder_len, manifest_len);

            c2pa_builder_free(builder);
            c2pa_signer_free(signer);
            c2pa_manifest_bytes_free(placeholder_bytes);
            c2pa_manifest_bytes_free(manifest_bytes);
            c2pa_hasher_free(hasher)
        }
    }
}
