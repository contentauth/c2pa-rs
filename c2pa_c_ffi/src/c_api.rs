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
    ffi::CString,
    os::raw::{c_char, c_int, c_uchar, c_void},
};

#[cfg(feature = "file_io")]
use c2pa::Ingredient;
// C has no namespace so we prefix things with C2PA to make them unique
use c2pa::{
    assertions::DataHash, identity::validator::CawgValidator, settings::load_settings_from_str,
    Builder as C2paBuilder, CallbackSigner, Reader as C2paReader, SigningAlg,
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
    let result = load_settings_from_str(&settings, &format);
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
    let manifest_bytes = std::slice::from_raw_parts(manifest_data, manifest_size);

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
    let bytes = std::slice::from_raw_parts(manifest_bytes_ptr, manifest_bytes_size);

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
    let bytes = std::slice::from_raw_parts(bytes, len);
    let private_key = from_cstr_or_return_null!(private_key);

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
        println!("json: {}", json_str.to_str().unwrap());
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
        let strings = vec![CString::new("image/jpg").unwrap()];
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

            let signature_slice = unsafe { std::slice::from_raw_parts(signature, signature_len) };
            let signed_slice = unsafe { std::slice::from_raw_parts_mut(signed_bytes, signed_len) };
            signed_slice[..signature_len].copy_from_slice(signature_slice);

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
        let json_report = json_str.to_str().unwrap();
        assert!(json_report.contains("cawg.identity"));
        assert!(json_report.contains("cawg.ica.credential_valid"));
    }
}
