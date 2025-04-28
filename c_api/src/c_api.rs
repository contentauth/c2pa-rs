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
    ffi::CString,
    os::raw::{c_char, c_int, c_uchar, c_void},
};

// C has no namespace so we prefix things with C2PA to make them unique
use c2pa::{
    assertions::DataHash, settings::load_settings_from_str, Builder as C2paBuilder, CallbackSigner,
    Reader as C2paReader, SigningAlg,
};
use cawg_identity::validator::CawgValidator;
use tokio::runtime::Runtime;

use crate::{
    c2pa_stream::C2paStream,
    error::Error,
    json_api::{read_file, read_ingredient_file, sign_file},
    signer_info::SignerInfo,
};

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

// Internal routine to test for null and return null error
#[macro_export]
macro_rules! null_check {
    ($ptr : expr) => {
        if $ptr.is_null() {
            Error::set_last(Error::NullParameter(stringify!($ptr).to_string()));
            return std::ptr::null_mut();
        }
    };
}

// Internal test for null and return -1 error
#[macro_export]
macro_rules! null_check_int {
    ($ptr : expr) => {
        if $ptr.is_null() {
            Error::set_last(Error::NullParameter(stringify!($ptr).to_string()));
            return -1;
        }
    };
}

// Internal routine to convert a *const c_char to a rust String or return a NULL error.
#[macro_export]
macro_rules! from_cstr_null_check {
    ($ptr : expr) => {
        if $ptr.is_null() {
            Error::set_last(Error::NullParameter(stringify!($ptr).to_string()));
            return std::ptr::null_mut();
        } else {
            std::ffi::CStr::from_ptr($ptr)
                .to_string_lossy()
                .into_owned()
        }
    };
}

// Internal routine to convert a *const c_char to a rust String or return a -1 int error.
#[macro_export]
macro_rules! from_cstr_null_check_int {
    ($ptr : expr) => {
        if $ptr.is_null() {
            Error::set_last(Error::NullParameter(stringify!($ptr).to_string()));
            return -1;
        } else {
            std::ffi::CStr::from_ptr($ptr)
                .to_string_lossy()
                .into_owned()
        }
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
    let settings = from_cstr_null_check_int!(settings);
    let format = from_cstr_null_check_int!(format);
    let result = load_settings_from_str(&settings, &format);
    match result {
        Ok(_) => 0,
        Err(err) => {
            Error::from_c2pa_error(err).set_last();
            -1
        }
    }
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
#[no_mangle]
pub unsafe extern "C" fn c2pa_read_file(
    path: *const c_char,
    data_dir: *const c_char,
) -> *mut c_char {
    let path = from_cstr_null_check!(path);
    let data_dir = from_cstr_option!(data_dir);

    let result = read_file(&path, data_dir);

    match result {
        Ok(json) => to_c_string(json),
        Err(e) => {
            e.set_last();
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
#[no_mangle]
pub unsafe extern "C" fn c2pa_read_ingredient_file(
    path: *const c_char,
    data_dir: *const c_char,
) -> *mut c_char {
    let path = from_cstr_null_check!(path);
    let data_dir = from_cstr_null_check!(data_dir);

    let result = read_ingredient_file(&path, &data_dir);

    match result {
        Ok(json) => to_c_string(json),
        Err(e) => {
            e.set_last();
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
#[no_mangle]
pub unsafe extern "C" fn c2pa_sign_file(
    source_path: *const c_char,
    dest_path: *const c_char,
    manifest: *const c_char,
    signer_info: &C2paSignerInfo,
    data_dir: *const c_char,
) -> *mut c_char {
    // Convert C pointers into Rust.
    let source_path = from_cstr_null_check!(source_path);
    let dest_path = from_cstr_null_check!(dest_path);
    let manifest = from_cstr_null_check!(manifest);
    let data_dir = from_cstr_option!(data_dir);

    let signer_info = SignerInfo {
        alg: from_cstr_null_check!(signer_info.alg),
        sign_cert: from_cstr_null_check!(signer_info.sign_cert).into_bytes(),
        private_key: from_cstr_null_check!(signer_info.private_key).into_bytes(),
        ta_url: from_cstr_option!(signer_info.ta_url),
    };
    // Read manifest from JSON and then sign and write it.
    let result = sign_file(&source_path, &dest_path, &manifest, &signer_info, data_dir);

    match result {
        Ok(_c2pa_data) => to_c_string("".to_string()),
        Err(e) => {
            e.set_last();
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

/// Creates and verifies a C2paReader from an asset stream with the given format.
///
/// Parameters
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
    let format = from_cstr_null_check!(format);

    let result = C2paReader::from_stream(&format, &mut *stream);
    match result {
        Ok(mut reader) => {
            let runtime = match Runtime::new() {
                Ok(runtime) => runtime,
                Err(err) => {
                    Error::Other(err.to_string()).set_last();
                    return std::ptr::null_mut();
                }
            };
            let result = runtime.block_on(reader.post_validate_async(&CawgValidator {}));
            match result {
                Ok(_) => (),
                Err(err) => {
                    Error::from_c2pa_error(err).set_last();
                    return std::ptr::null_mut();
                }
            }
            Box::into_raw(Box::new(reader))
        }
        Err(err) => {
            Error::from_c2pa_error(err).set_last();
            std::ptr::null_mut()
        }
    }
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
    let c2pa_reader: Box<C2paReader> = Box::from_raw(reader_ptr);
    let json = c2pa_reader.json();
    let _ = Box::into_raw(c2pa_reader);
    to_c_string(json)
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
    let reader: Box<C2paReader> = Box::from_raw(reader_ptr);
    let uri = from_cstr_null_check_int!(uri);
    let result = reader.resource_to_stream(&uri, &mut (*stream));
    let _ = Box::into_raw(reader);
    match result {
        Ok(len) => len as i64,
        Err(err) => {
            Error::from_c2pa_error(err).set_last();
            -1
        }
    }
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
    let manifest_json = from_cstr_null_check!(manifest_json);
    let result = C2paBuilder::from_json(&manifest_json);
    match result {
        Ok(builder) => Box::into_raw(Box::new(builder)),
        Err(err) => {
            Error::from_c2pa_error(err).set_last();
            std::ptr::null_mut()
        }
    }
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
    let result = C2paBuilder::from_archive(&mut (*stream));
    match result {
        Ok(builder) => Box::into_raw(Box::new(builder)),
        Err(err) => {
            Error::from_c2pa_error(err).set_last();
            std::ptr::null_mut()
        }
    }
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
pub unsafe extern "C" fn c2pa_builder_set_no_embed(builder_ptr: *mut C2paBuilder) {
    let mut builder: Box<C2paBuilder> = Box::from_raw(builder_ptr);
    builder.set_no_embed(true);
    let _ = Box::into_raw(builder);
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
    let mut builder: Box<C2paBuilder> = Box::from_raw(builder_ptr);
    let remote_url = from_cstr_null_check_int!(remote_url);
    builder.set_remote_url(&remote_url);
    let _ = Box::into_raw(builder);
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
    let mut builder: Box<C2paBuilder> = Box::from_raw(builder_ptr);
    let uri = from_cstr_null_check_int!(uri);
    let result = builder.add_resource(&uri, &mut (*stream));
    match result {
        Ok(_builder) => {
            let _ = Box::into_raw(builder);
            0 as c_int
        }
        Err(err) => {
            Error::from_c2pa_error(err).set_last();
            -1
        }
    }
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
    let mut builder: Box<C2paBuilder> = Box::from_raw(builder_ptr);
    let ingredient_json = from_cstr_null_check_int!(ingredient_json);
    let format = from_cstr_null_check_int!(format);
    let result = builder.add_ingredient_from_stream(&ingredient_json, &format, &mut (*source));
    match result {
        Ok(_builder) => {
            let _ = Box::into_raw(builder);
            0 as c_int
        }
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
    let mut builder: Box<C2paBuilder> = Box::from_raw(builder_ptr);
    let result = builder.to_archive(&mut (*stream));
    match result {
        Ok(_builder) => {
            let _ = Box::into_raw(builder);
            0 as c_int
        }
        Err(err) => {
            Error::from_c2pa_error(err).set_last();
            -1
        }
    }
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
    signer: *mut C2paSigner,
    manifest_bytes_ptr: *mut *const c_uchar,
) -> i64 {
    let mut builder: Box<C2paBuilder> = Box::from_raw(builder_ptr);
    let format = from_cstr_null_check_int!(format);

    let c2pa_signer = Box::from_raw(signer);

    let result = builder.sign(
        c2pa_signer.signer.as_ref(),
        &format,
        &mut *source,
        &mut *dest,
    );
    let _ = Box::into_raw(c2pa_signer);
    let _ = Box::into_raw(builder);
    match result {
        Ok(manifest_bytes) => {
            let len = manifest_bytes.len() as i64;
            if !manifest_bytes_ptr.is_null() {
                *manifest_bytes_ptr =
                    Box::into_raw(manifest_bytes.into_boxed_slice()) as *const c_uchar;
            };
            len
        }
        Err(err) => {
            Error::from_c2pa_error(err).set_last();
            -1
        }
    }
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
    null_check_int!(builder_ptr);
    null_check_int!(manifest_bytes_ptr);
    let mut builder: Box<C2paBuilder> = Box::from_raw(builder_ptr);
    let format = from_cstr_null_check_int!(format);
    let result = builder.data_hashed_placeholder(reserved_size, &format);
    let _ = Box::into_raw(builder);
    match result {
        Ok(manifest_bytes) => {
            let len = manifest_bytes.len() as i64;
            *manifest_bytes_ptr =
                Box::into_raw(manifest_bytes.into_boxed_slice()) as *const c_uchar;
            len
        }
        Err(err) => {
            Error::from_c2pa_error(err).set_last();
            -1
        }
    }
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
    signer: *mut C2paSigner,
    data_hash: *const c_char,
    format: *const c_char,
    asset: *mut C2paStream,
    manifest_bytes_ptr: *mut *const c_uchar,
) -> i64 {
    null_check_int!(builder_ptr);
    null_check_int!(manifest_bytes_ptr);

    let data_hash_json = from_cstr_null_check_int!(data_hash);
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
    let format = from_cstr_null_check_int!(format);

    let mut builder: Box<C2paBuilder> = Box::from_raw(builder_ptr);
    let c2pa_signer = Box::from_raw(signer);

    let result =
        builder.sign_data_hashed_embeddable(c2pa_signer.signer.as_ref(), &data_hash, &format);

    let _ = Box::into_raw(c2pa_signer);
    let _ = Box::into_raw(builder);

    match result {
        Ok(manifest_bytes) => {
            let len = manifest_bytes.len() as i64;
            *manifest_bytes_ptr =
                Box::into_raw(manifest_bytes.into_boxed_slice()) as *const c_uchar;
            len
        }
        Err(err) => {
            Error::from_c2pa_error(err).set_last();
            -1
        }
    }
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
    null_check_int!(manifest_bytes_ptr);
    null_check_int!(result_bytes_ptr);
    let format = from_cstr_null_check_int!(format);
    let bytes = std::slice::from_raw_parts(manifest_bytes_ptr, manifest_bytes_size);

    // todo: Add a way to do this without using the v1_api Manifest
    let result = c2pa::Manifest::composed_manifest(bytes, &format);
    match result {
        Ok(result_bytes) => {
            let len = result_bytes.len() as i64;
            *result_bytes_ptr = Box::into_raw(result_bytes.into_boxed_slice()) as *const c_uchar;
            len
        }
        Err(err) => {
            Error::from_c2pa_error(err).set_last();
            -1
        }
    }
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
/// Reads from NULL-terminated C strings
/// The returned value MUST be released by calling c2pa_signer_free
/// and it is no longer valid after that call.
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
    let certs = from_cstr_null_check!(certs);
    let tsa_url = from_cstr_option!(tsa_url);
    let context = context as *const ();

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
        //println!("signed_size: {}", signed_size);
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
        alg: from_cstr_null_check!(signer_info.alg),
        sign_cert: from_cstr_null_check!(signer_info.sign_cert).into_bytes(),
        private_key: from_cstr_null_check!(signer_info.private_key).into_bytes(),
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
    null_check_int!(signer_ptr);
    let c2pa_signer: Box<C2paSigner> = Box::from_raw(signer_ptr);
    let size = c2pa_signer.signer.reserve_size() as i64;
    let _ = Box::into_raw(c2pa_signer);
    size
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
    let private_key = from_cstr_null_check!(private_key);

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

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;
    use crate::TestC2paStream;

    const TEST_CERTS: &str = include_str!("../../sdk/tests/fixtures/certs/ed25519.pub");
    const TEST_PRIVATE_KEY: &[u8] = include_bytes!("../../sdk/tests/fixtures/certs/ed25519.pem");
    const TEST_ALG: &str = "Ed25519";
    const TEST_ASSET: &[u8] = include_bytes!("../../sdk/tests/fixtures/IMG_0003.jpg");

    #[test]
    fn test_ed25519_sign() {
        let bytes = b"test";
        let private_key = CString::new(TEST_PRIVATE_KEY).unwrap();
        let signature =
            unsafe { c2pa_ed25519_sign(bytes.as_ptr(), bytes.len(), private_key.as_ptr()) };
        assert!(!signature.is_null());
        unsafe { c2pa_signature_free(signature) };
    }

    #[test]
    fn test_c2pa_signer_from_info() {
        let alg = CString::new(TEST_ALG).unwrap();
        let sign_cert = CString::new(TEST_CERTS).unwrap();
        let private_key = CString::new(TEST_PRIVATE_KEY).unwrap();
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
        assert_eq!(error.to_str().unwrap(), "Other Invalid signing algorithm");
    }

    #[test]
    fn test_sign_with_info() {
        let mut source_stream = TestC2paStream::from_bytes(TEST_ASSET.to_vec());
        let dest_vec = Vec::new();
        let mut dest_stream = TestC2paStream::new(dest_vec).into_c_stream();
        let alg = CString::new(TEST_ALG).unwrap();
        let sign_cert = CString::new(TEST_CERTS).unwrap();
        let private_key = CString::new(TEST_PRIVATE_KEY).unwrap();
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
        //let error = unsafe { c2pa_error() };
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
}
