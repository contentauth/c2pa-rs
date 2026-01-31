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
    os::raw::{c_char, c_int, c_uchar, c_void},
    sync::Arc,
};

// C has no namespace so we prefix things with C2PA to make them unique
#[cfg(feature = "file_io")]
use c2pa::Ingredient;
use c2pa::{
    assertions::DataHash, identity::validator::CawgValidator, Builder as C2paBuilder,
    CallbackSigner, Context, Reader as C2paReader, Settings as C2paSettings, SigningAlg,
};
use tokio::runtime::Runtime; // cawg validator requires async

#[cfg(feature = "file_io")]
use crate::json_api::{read_file, sign_file};
// Import macros and utilities from cimpl
use crate::{
    box_tracked, c2pa_stream::C2paStream, cimpl_free, cstr_or_return_int, cstr_or_return_neg,
    cstr_or_return_null, deref_mut_or_return, deref_mut_or_return_neg, deref_mut_or_return_null,
    deref_or_return_null, error::Error, from_cstr_option, guard_boxed_int, ok_or_return_int,
    ok_or_return_null, option_to_c_string, ptr_or_return_int, ptr_or_return_null,
    safe_slice_from_raw_parts, signer_info::SignerInfo, to_c_string, CimplError,
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
#[allow(dead_code)]
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
    pub struct C2paContextBuilder;

    #[repr(C)]
    #[allow(dead_code)]
    pub struct C2paContext;

    #[repr(C)]
    #[allow(dead_code)]
    pub struct C2paSettings;
}

type C2paContextBuilder = Context;
type C2paContext = Arc<Context>;

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

// // Internal routine to return a rust String reference to C as *mut c_char.
// // The returned value MUST be released by calling release_string
// // and it is no longer valid after that call.
// unsafe fn to_c_string(s: String) -> *mut c_char {
//     match CString::new(s) {
//         Ok(c_str) => c_str.into_raw(),
//         Err(_) => std::ptr::null_mut(),
//     }
// }

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
    to_c_string(Error::last_message())
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
    let error_str = cstr_or_return_neg!(error_str);
    CimplError::from(Error::from(error_str)).set_last();
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
    let settings = cstr_or_return_neg!(settings);
    let format = cstr_or_return_neg!(format);
    // we use the legacy from_string function to set thread-local settings for backward compatibility
    let result = C2paSettings::from_string(&settings, &format);
    ok_or_return_zero!(result);
    0 // returns 0 on success
}

/// Creates a new C2PA settings object with default values.
///
/// # Safety
///
/// This function is safe to call. The returned pointer must be freed
/// by calling `c2pa_settings_free()`.
///
/// # Returns
///
/// A pointer to a newly allocated C2paSettings object, or NULL on allocation failure.
#[no_mangle]
pub unsafe extern "C" fn c2pa_settings_new() -> *mut C2paSettings {
    box_tracked!(C2paSettings::new())
}

/// Updates settings from a JSON or TOML string.
///
/// # Safety
///
/// * `settings` must be a valid pointer to a C2paSettings object previously
///   created by `c2pa_settings_new()` and not yet freed.
/// * `settings_str` must be a valid pointer to a null-terminated UTF-8 string.
/// * `format` must be a valid pointer to a null-terminated string containing
///   either "json" or "toml".
/// * The pointers must remain valid for the duration of this call.
/// * This function is not thread-safe - do not call concurrently on the same `settings`.
///
/// # Returns
///
/// 0 on success, negative value on error.
#[no_mangle]
pub unsafe extern "C" fn c2pa_settings_update_from_string(
    settings: *mut C2paSettings,
    settings_str: *const c_char,
    format: *const c_char,
) -> c_int {
    let settings = deref_mut_or_return_neg!(settings, C2paSettings);
    let settings_str = cstr_or_return_neg!(settings_str);
    let format = cstr_or_return_neg!(format);
    let result = settings.update_from_str(&settings_str, &format);
    ok_or_return_int!(result);
    0
}

/// Sets a specific configuration value in the settings using dot notation.
///
/// # Safety
///
/// * `settings` must be a valid pointer to a C2paSettings object previously
///   created by `c2pa_settings_new()` and not yet freed.
/// * `path` must be a valid pointer to a null-terminated UTF-8 string containing
///   a dot-separated path (e.g., "verify.verify_after_sign").
/// * `value` must be a valid pointer to a null-terminated UTF-8 string containing
///   a JSON value (e.g., "true", "\"ps256\"", "42").
/// * The pointers must remain valid for the duration of this call.
/// * This function is not thread-safe - do not call concurrently on the same `settings`.
///
/// # Returns
///
/// 0 on success, negative value on error.
#[no_mangle]
pub unsafe extern "C" fn c2pa_settings_set_value(
    settings: *mut C2paSettings,
    path: *const c_char,
    value: *const c_char,
) -> c_int {
    let settings = deref_mut_or_return_neg!(settings, C2paSettings);
    let path = cstr_or_return_neg!(path);
    let value_str = cstr_or_return_neg!(value);

    // Parse the JSON value to determine the type
    let parsed_value: serde_json::Value = match serde_json::from_str(&value_str) {
        Ok(v) => v,
        Err(e) => {
            CimplError::from(c2pa::Error::BadParam(format!("Invalid JSON value: {e}"))).set_last();
            return -1;
        }
    };

    // Convert JSON value to config::Value and set it
    let result = match parsed_value {
        serde_json::Value::Bool(b) => settings.set_value(&path, b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                settings.set_value(&path, i)
            } else if let Some(f) = n.as_f64() {
                settings.set_value(&path, f)
            } else {
                Err(c2pa::Error::BadParam("Invalid number format".to_string()))
            }
        }
        serde_json::Value::String(s) => settings.set_value(&path, s),
        serde_json::Value::Array(arr) => {
            // Convert array to Vec<String> for common use case
            let string_vec: c2pa::Result<Vec<String>> = arr
                .iter()
                .map(|v| {
                    if let serde_json::Value::String(s) = v {
                        Ok(s.clone())
                    } else {
                        Err(c2pa::Error::BadParam(
                            "Array values must be strings".to_string(),
                        ))
                    }
                })
                .collect();
            match string_vec {
                Ok(vec) => settings.set_value(&path, vec),
                Err(e) => Err(e),
            }
        }
        serde_json::Value::Null => Err(c2pa::Error::BadParam("Cannot set null values".to_string())),
        serde_json::Value::Object(_) => Err(c2pa::Error::BadParam(
            "Cannot set object values directly, use update_from_string instead".to_string(),
        )),
    };

    ok_or_return_int!(result);
    0
}

/// Creates a new context builder with default settings.
///
/// Use this to construct a context with custom configuration. After setting up
/// the builder, call `c2pa_context_builder_build()` to create an immutable context.
///
/// # Safety
///
/// This function is safe to call. The returned pointer must be freed by calling
/// `c2pa_free()` or converted to a context with `c2pa_context_builder_build()`.
///
/// # Returns
///
/// A pointer to a newly allocated C2paContextBuilder object, or NULL on allocation failure.
///
/// # Example
///
/// ```c
/// // Create and configure a builder
/// C2paContextBuilder* builder = c2pa_context_builder_new();
/// C2paSettings* settings = c2pa_settings_new();
/// c2pa_settings_set_value(settings, "verify.verify_after_sign", "true");
/// c2pa_context_builder_set_settings(builder, settings);
/// c2pa_free(settings);
///
/// // Build immutable context
/// C2paContext* ctx = c2pa_context_builder_build(builder);
/// // builder is now invalid, ctx can be shared
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_context_builder_new() -> *mut C2paContextBuilder {
    box_tracked!(Context::new())
}

/// Updates the builder with settings.
///
/// This configures the builder with the provided settings. The settings are cloned
/// internally, so the caller retains ownership. If this call fails, the builder
/// remains in its previous valid state.
///
/// # Safety
///
/// * `builder` must be a valid pointer to a C2paContextBuilder object previously
///   created by `c2pa_context_builder_new()` and not yet built.
/// * `settings` must be a valid pointer to a C2paSettings object.
/// * The pointers must remain valid for the duration of this call.
/// * This function is not thread-safe - do not call concurrently on the same `builder`.
///
/// # Returns
///
/// 0 on success, negative value on error.
#[no_mangle]
pub unsafe extern "C" fn c2pa_context_builder_set_settings(
    builder: *mut C2paContextBuilder,
    settings: *mut C2paSettings,
) -> c_int {
    let builder = deref_mut_or_return_neg!(builder, C2paContextBuilder);
    let settings = deref_or_return_neg!(settings, C2paSettings);
    let result = builder.set_settings(settings);
    ok_or_return_int!(result);
    0
}

/// Builds an immutable, shareable context from the builder.
///
/// The builder is consumed by this operation and becomes invalid.
/// The returned context is immutable and can be shared between multiple
/// Reader and Builder instances.
///
/// # Safety
///
/// * `builder` must be a valid pointer to a C2paContextBuilder.
/// * After calling this function, the builder pointer is INVALID and must not be used again.
/// * The returned context must be freed with `c2pa_free()`.
///
/// # Returns
///
/// A pointer to an immutable C2paContext that can be shared, or NULL on error.
#[no_mangle]
pub unsafe extern "C" fn c2pa_context_builder_build(
    builder: *mut C2paContextBuilder,
) -> *mut C2paContext {
    let context = Box::from_raw(builder);
    box_tracked!((*context).into_shared())
}

/// Creates a new immutable context with default settings.
///
/// This is a convenience function equivalent to:
/// ```c
/// builder = c2pa_context_builder_new();
/// ctx = c2pa_context_builder_build(builder);
/// ```
///
/// Use `c2pa_context_builder_new()` if you need to configure the context
/// before building it.
///
/// # Safety
///
/// This function is safe to call. The returned pointer must be freed with `c2pa_free()`.
///
/// # Returns
///
/// A pointer to a newly allocated immutable C2paContext object, or NULL on allocation failure.
#[no_mangle]
pub unsafe extern "C" fn c2pa_context_new() -> *mut C2paContext {
    box_tracked!(Context::new().into_shared())
}

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
    let path = cstr_or_return_null!(path);
    let data_dir = from_cstr_option!(data_dir);

    let result = read_file(&path, data_dir);
    let json = ok_or_return_null!(result);
    to_c_string(json)
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
    let path = cstr_or_return_null!(path);
    let data_dir = cstr_or_return_null!(data_dir);
    let result = Ingredient::from_file_with_folder(path, data_dir).map_err(Error::from_c2pa_error);
    let ingredient = ok_or_return_null!(result);
    let json = serde_json::to_string(&ingredient).unwrap_or_default();
    to_c_string(json)
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
    let source_path = cstr_or_return_null!(source_path);
    let dest_path = cstr_or_return_null!(dest_path);
    let manifest = cstr_or_return_null!(manifest);
    let data_dir = cstr_option!(data_dir);

    let signer_info = SignerInfo {
        alg: cstr_or_return_null!(signer_info.alg),
        sign_cert: cstr_or_return_null!(signer_info.sign_cert).into_bytes(),
        private_key: cstr_or_return_null!(signer_info.private_key).into_bytes(),
        ta_url: cstr_option!(signer_info.ta_url),
    };
    // Read manifest from JSON and then sign and write it.
    let result = sign_file(&source_path, &dest_path, &manifest, &signer_info, data_dir);
    let bytes = ok_or_return_null!(result);
    let json = String::from_utf8_lossy(&bytes).to_string();
    to_c_string(json)
}

/// Frees any pointer allocated by this library.
///
/// This is a generic free function that works for all C2PA objects including:
/// - C2paContext
/// - C2paSettings
/// - C2paBuilder
/// - C2paReader
/// - C2paSigner
/// - strings (c_char*)
/// - and any other objects created by this library
///
/// # Safety
///
/// * The pointer must have been allocated by this library (e.g., from c2pa_context_new(),
///   c2pa_settings_new(), c2pa_builder_from_json(), etc.)
/// * The pointer must not have been modified in C.
/// * The pointer can only be freed once and is invalid after this call.
/// * Do not use type-specific free functions (like c2pa_string_free) if you use this.
///
/// # Returns
///
/// 0 on success, -1 on error (e.g., if the pointer was not allocated by this library).
#[no_mangle]
pub unsafe extern "C" fn c2pa_free(ptr: *mut c_void) -> c_int {
    cimpl_free!(ptr)
}

/// Frees a string allocated by Rust.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The string must not have been modified in C.
/// The string can only be freed once and is invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_string_free(s: *mut c_char) {
    cimpl_free!(s);
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

/// # Safety
/// This function is safe to call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_new() -> *mut C2paReader {
    box_tracked!(C2paReader::from_context(Context::default()))
}

/// Creates a new C2paReader from a shared context.
///
/// The context can be reused to create multiple readers and builders.
///
/// # Safety
///
/// * `context` must be a valid pointer to a C2paContext object.
/// * The context pointer remains valid after this call and can be reused.
///
/// # Returns
///
/// A pointer to a newly allocated C2paReader, or NULL on error.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_from_context(context: *mut C2paContext) -> *mut C2paReader {
    let context = deref_or_return_null!(context, C2paContext);
    box_tracked!(C2paReader::from_shared_context(context))
}

/// # Example
/// ```c
/// auto result = c2pa_reader_from_stream("image/jpeg", stream);
/// if (result == NULL) {
///     let error = c2pa_error();
///     printf("Error: %s\n", error);
///     c2pa_string_free(error);
/// }
/// ```
///
/// # Safety
/// format must be a valid NULL-terminated C string pointer.
/// stream must be a valid pointer to a C2paStream.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_from_stream(
    format: *const c_char,
    stream: *mut C2paStream,
) -> *mut C2paReader {
    let format = cstr_or_return_null!(format);
    let stream = deref_mut_or_return_null!(stream, C2paStream);

    let result = C2paReader::from_stream(&format, stream);
    let result = ok_or_return_null!(post_validate(result));
    box_tracked!(result)
}

/// Configures an existing reader with a stream.
///
/// This method consumes the original reader and returns a new configured reader.
/// The original reader pointer becomes invalid after this call.
///
/// # Safety
///
/// * `reader` must be a valid pointer to a C2paReader.
/// * `format` must be a valid null-terminated string with the MIME type.
/// * `stream` must be a valid pointer to a C2paStream.
/// * After calling this function, the `reader` pointer is INVALID.
///
/// # Returns
///
/// A pointer to a newly configured C2paReader, or NULL on error.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_with_stream(
    reader: *mut C2paReader,
    format: *const c_char,
    stream: *mut C2paStream,
) -> *mut C2paReader {
    // Take ownership of the reader (consumes it)
    let reader = Box::from_raw(reader);
    let format = cstr_or_return_null!(format);
    let stream = deref_mut_or_return_null!(stream, C2paStream);

    let result = (*reader).with_stream(&format, stream);
    let result = ok_or_return_null!(post_validate(result));
    box_tracked!(result)
}

/// Configures an existing reader with a fragment stream.
///
/// This is used for fragmented BMFF media formats where manifests are stored
/// in separate fragments. This method consumes the original reader and returns
/// a new configured reader. The original reader pointer becomes invalid after this call.
///
/// # Safety
///
/// * `reader` must be a valid pointer to a C2paReader.
/// * `format` must be a valid null-terminated string with the MIME type.
/// * `stream` must be a valid pointer to a C2paStream (the main asset stream).
/// * `fragment` must be a valid pointer to a C2paStream (the fragment stream).
/// * After calling this function, the `reader` pointer is INVALID.
///
/// # Returns
///
/// A pointer to a newly configured C2paReader, or NULL on error.
///
/// # Example
///
/// ```c
/// C2paReader* reader = c2pa_reader_from_context(ctx);
/// C2paReader* new_reader = c2pa_reader_with_fragment(reader, "video/mp4", main_stream, fragment_stream);
/// // reader is now invalid, use new_reader
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_with_fragment(
    reader: *mut C2paReader,
    format: *const c_char,
    stream: *mut C2paStream,
    fragment: *mut C2paStream,
) -> *mut C2paReader {
    // Take ownership of the reader (consumes it)
    let reader = Box::from_raw(reader);
    let format = cstr_or_return_null!(format);
    let stream = deref_mut_or_return_null!(stream, C2paStream);
    let fragment = deref_mut_or_return_null!(fragment, C2paStream);

    let result = (*reader).with_fragment(&format, stream, fragment);
    let result = ok_or_return_null!(post_validate(result));
    box_tracked!(result)
}

/// Creates a new C2paReader from a shared Context.
///
/// # Safety
///
/// * `context` must be a valid pointer to a C2paContext object.
/// * The context pointer remains valid after this call and can be reused.
///
/// # Returns
///
/// A pointer to a newly allocated C2paReader, or NULL on error.
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
    let path = cstr_or_return_null!(path);
    let result = C2paReader::from_file(&path);
    box_tracked!(ok_or_return_null!(post_validate(result)))
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
    ptr_or_return_null!(manifest_data);
    let format = cstr_or_return_null!(format);
    let stream = deref_mut_or_return_null!(stream, C2paStream);

    // Safe bounds validation for manifest data
    let manifest_bytes =
        match safe_slice_from_raw_parts(manifest_data, manifest_size, "manifest_data") {
            Ok(bytes) => bytes,
            Err(err) => {
                CimplError::from(err).set_last();
                return std::ptr::null_mut();
            }
        };

    let result = C2paReader::from_manifest_data_and_stream(manifest_bytes, &format, stream);
    box_tracked!(ok_or_return_null!(post_validate(result)))
}

/// Frees a C2paReader allocated by Rust.
///
/// # Safety
/// The C2paReader can only be freed once and is invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_free(reader_ptr: *mut C2paReader) {
    cimpl_free!(reader_ptr);
}

/// Returns a JSON string generated from a C2paReader.
///
/// # Safety
/// The returned value MUST be released by calling c2pa_string_free
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_json(reader_ptr: *mut C2paReader) -> *mut c_char {
    let c2pa_reader = deref_or_return_null!(reader_ptr, C2paReader);
    to_c_string(c2pa_reader.json())
}

/// Returns a detailed JSON string generated from a C2paReader.
///
/// # Safety
/// The returned value MUST be released by calling c2pa_string_free
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_detailed_json(reader_ptr: *mut C2paReader) -> *mut c_char {
    let c2pa_reader = deref_or_return_null!(reader_ptr, C2paReader);

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
    let c2pa_reader = deref_or_return_null!(reader_ptr, C2paReader);

    option_to_c_string!(c2pa_reader.remote_url())
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
    let c2pa_reader = deref_or_return_false!(reader_ptr, C2paReader);

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
    let uri = cstr_or_return_int!(uri);
    let reader = guard_boxed_int!(reader_ptr);
    let result = reader.resource_to_stream(&uri, &mut (*stream));
    let len = ok_or_return_int!(result);
    len as i64
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
    let manifest_json = cstr_or_return_null!(manifest_json);
    let result = C2paBuilder::from_json(&manifest_json);
    let result = ok_or_return_null!(result);
    box_tracked!(result)
}

/// Creates a C2paBuilder from a shared Context.
///
/// The context can be reused to create multiple builders and readers.
/// The builder will inherit the context's settings, signers, and resolvers.
///
/// # Safety
///
/// * `context` must be a valid pointer to a C2paContext object.
/// * The context pointer remains valid after this call and can be reused.
///
/// # Returns
///
/// A pointer to a newly allocated C2paBuilder, or NULL on error.
///
/// # Example
///
/// ```c
/// C2paContext* ctx = c2pa_context_new();
/// C2paBuilder* builder = c2pa_builder_from_context(ctx);
/// // context can still be used
/// C2paReader* reader = c2pa_reader_from_context(ctx);
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_from_context(context: *mut C2paContext) -> *mut C2paBuilder {
    let context = deref_or_return_null!(context, C2paContext);
    box_tracked!(C2paBuilder::from_shared_context(context))
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
    let stream = deref_mut_or_return_null!(stream, C2paStream);
    box_tracked!(ok_or_return_null!(C2paBuilder::from_archive(
        &mut (*stream)
    )))
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
    cimpl_free!(builder_ptr);
}

/// Updates the builder with a new manifest definition.
///
/// This consumes the original builder and returns a new configured builder.
/// The original builder pointer becomes invalid after this call.
///
/// # Safety
///
/// * `builder` must be a valid pointer to a C2paBuilder.
/// * `manifest_json` must be a valid null-terminated JSON string.
/// * After calling this function, the `builder` pointer is INVALID.
///
/// # Returns
///
/// A pointer to a newly configured C2paBuilder, or NULL on error.
///
/// # Example
///
/// ```c
/// C2paBuilder* builder = c2pa_builder_from_context(ctx);
/// const char* json = "{\"title\": \"Updated Title\"}";
/// C2paBuilder* new_builder = c2pa_builder_with_definition(builder, json);
/// // builder is now invalid, use new_builder
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_with_definition(
    builder: *mut C2paBuilder,
    manifest_json: *const c_char,
) -> *mut C2paBuilder {
    // Take ownership of the builder (consumes it)
    let builder = Box::from_raw(builder);
    let manifest_json = cstr_or_return_null!(manifest_json);

    let result = (*builder).with_definition(manifest_json);
    box_tracked!(ok_or_return_null!(result))
}

/// Configures an existing builder with an archive stream.
///
/// This consumes the original builder and returns a new configured builder.
/// The original builder pointer becomes invalid after this call.
///
/// # Safety
///
/// * `builder` must be a valid pointer to a C2paBuilder.
/// * `stream` must be a valid pointer to a C2paStream.
/// * After calling this function, the `builder` pointer is INVALID.
///
/// # Returns
///
/// A pointer to a newly configured C2paBuilder, or NULL on error.
///
/// # Example
///
/// ```c
/// C2paBuilder* builder = c2pa_builder_from_context(ctx);
/// C2paBuilder* new_builder = c2pa_builder_with_archive(builder, archive_stream);
/// // builder is now invalid, use new_builder
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_with_archive(
    builder: *mut C2paBuilder,
    stream: *mut C2paStream,
) -> *mut C2paBuilder {
    // Take ownership of the builder (consumes it)
    let builder = Box::from_raw(builder);
    let stream = deref_mut_or_return_null!(stream, C2paStream);

    let result = (*builder).with_archive(stream);
    box_tracked!(ok_or_return_null!(result))
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
    let builder = guard_boxed_int!(builder_ptr);

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
    let builder = deref_mut_or_return!(builder_ptr, C2paBuilder, ());
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
    let builder = deref_mut_or_return_neg!(builder_ptr, C2paBuilder);
    let remote_url = cstr_or_return_int!(remote_url);
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
    let builder = deref_mut_or_return_neg!(builder_ptr, C2paBuilder);
    let base_path = cstr_or_return_int!(base_path);
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
    let builder = deref_mut_or_return_neg!(builder_ptr, C2paBuilder);
    let uri = cstr_or_return_int!(uri);
    let result = builder.add_resource(&uri, &mut (*stream));
    ok_or_return_int!(result);
    0 // returns 0 on success
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
    ptr_or_return_int!(builder_ptr);
    ptr_or_return_int!(source);
    let builder = deref_mut_or_return_neg!(builder_ptr, C2paBuilder);
    let ingredient_json = cstr_or_return_int!(ingredient_json);
    let format = cstr_or_return_int!(format);
    let result = builder.add_ingredient_from_stream(&ingredient_json, &format, &mut (*source));
    ok_or_return_int!(result);
    0 // returns 0 on success
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
    let builder = deref_mut_or_return_neg!(builder_ptr, C2paBuilder);
    let action_json = cstr_or_return_int!(action_json);

    // Parse the JSON into a serde Value to use with the Builder
    let action_value: serde_json::Value = ok_or_return_int!(serde_json::from_str(&action_json));

    ok_or_return_int!(builder.add_action(action_value));

    0
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
    ptr_or_return_int!(builder_ptr);
    ptr_or_return_int!(stream);
    let builder = deref_mut_or_return_neg!(builder_ptr, C2paBuilder);
    let result = builder.to_archive(&mut (*stream));
    ok_or_return_int!(result);
    0 // returns 0 on success
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
    ptr_or_return_int!(builder_ptr);
    let format = cstr_or_return_int!(format);
    ptr_or_return_int!(source);
    ptr_or_return_int!(dest);
    ptr_or_return_int!(signer_ptr);
    ptr_or_return_int!(manifest_bytes_ptr);

    let builder = guard_boxed_int!(builder_ptr);
    let c2pa_signer = guard_boxed_int!(signer_ptr);

    let result = builder.sign(
        c2pa_signer.signer.as_ref(),
        &format,
        &mut *source,
        &mut *dest,
    );
    let manifest_bytes = ok_or_return_int!(result);
    let len = manifest_bytes.len() as i64;
    if !manifest_bytes_ptr.is_null() {
        *manifest_bytes_ptr = Box::into_raw(manifest_bytes.into_boxed_slice()) as *const c_uchar;
    }
    len
}

/// Frees a C2PA manifest returned by c2pa_builder_sign.
///
/// # Safety
/// The bytes can only be freed once and are invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_manifest_bytes_free(manifest_bytes_ptr: *const c_uchar) {
    cimpl_free!(manifest_bytes_ptr);
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
    ptr_or_return_int!(builder_ptr);
    ptr_or_return_int!(manifest_bytes_ptr);
    let builder = deref_mut_or_return_neg!(builder_ptr, C2paBuilder);
    let format = cstr_or_return_int!(format);
    let result = builder.data_hashed_placeholder(reserved_size, &format);
    let manifest_bytes = ok_or_return_int!(result);
    let len = manifest_bytes.len() as i64;
    if !manifest_bytes_ptr.is_null() {
        *manifest_bytes_ptr = Box::into_raw(manifest_bytes.into_boxed_slice()) as *const c_uchar;
    }
    len
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
    ptr_or_return_int!(builder_ptr);
    ptr_or_return_int!(signer_ptr);
    let data_hash_json = cstr_or_return_int!(data_hash);
    let format = cstr_or_return_int!(format);
    ptr_or_return_int!(manifest_bytes_ptr);

    let mut data_hash: DataHash = match serde_json::from_str(&data_hash_json) {
        Ok(data_hash) => data_hash,
        Err(err) => {
            CimplError::from(Error::from_c2pa_error(c2pa::Error::JsonError(err))).set_last();
            return -1;
        }
    };
    if !asset.is_null() {
        // calc hashes from the asset stream
        match data_hash.gen_hash_from_stream(&mut *asset) {
            Ok(_) => {}
            Err(err) => {
                CimplError::from(Error::from_c2pa_error(err)).set_last();
                return -1;
            }
        }
    }

    let builder = guard_boxed_int!(builder_ptr);
    let c2pa_signer = guard_boxed_int!(signer_ptr);

    let result =
        builder.sign_data_hashed_embeddable(c2pa_signer.signer.as_ref(), &data_hash, &format);

    let manifest_bytes = ok_or_return_int!(result);
    let len = manifest_bytes.len() as i64;
    if !manifest_bytes_ptr.is_null() {
        *manifest_bytes_ptr = Box::into_raw(manifest_bytes.into_boxed_slice()) as *const c_uchar;
    }
    len
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
    let format = cstr_or_return_int!(format);
    ptr_or_return_int!(manifest_bytes_ptr);
    ptr_or_return_int!(result_bytes_ptr);

    // Safe bounds validation for manifest bytes
    let bytes = match safe_slice_from_raw_parts(
        manifest_bytes_ptr,
        manifest_bytes_size,
        "manifest_bytes_ptr",
    ) {
        Ok(bytes) => bytes,
        Err(err) => {
            CimplError::from(err).set_last();
            return -1;
        }
    };

    let result = c2pa::Builder::composed_manifest(bytes, &format);
    let result_bytes = ok_or_return_int!(result);
    let len = result_bytes.len() as i64;
    if !result_bytes_ptr.is_null() {
        *result_bytes_ptr = Box::into_raw(result_bytes.into_boxed_slice()) as *const c_uchar;
    }
    len
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
    let certs = cstr_or_return_null!(certs);
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
        alg: cstr_or_return_null!(signer_info.alg),
        sign_cert: cstr_or_return_null!(signer_info.sign_cert).into_bytes(),
        private_key: cstr_or_return_null!(signer_info.private_key).into_bytes(),
        ta_url: from_cstr_option!(signer_info.ta_url),
    };

    let signer = signer_info.signer();
    match signer {
        Ok(signer) => Box::into_raw(Box::new(C2paSigner {
            signer: Box::new(signer),
        })),
        Err(err) => {
            CimplError::from(err).set_last();
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
    let signer = ok_or_return_null!(C2paSettings::signer());
    box_tracked!(C2paSigner {
        signer: Box::new(signer),
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
    ptr_or_return_int!(signer_ptr);
    let c2pa_signer = guard_boxed_int!(signer_ptr);
    c2pa_signer.signer.reserve_size() as i64
}

/// Frees a C2paSigner allocated by Rust.
///
/// # Safety
/// The C2paSigner can only be freed once and is invalid after this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_signer_free(signer_ptr: *const C2paSigner) {
    cimpl_free!(signer_ptr);
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
    ptr_or_return_null!(bytes);
    let private_key = cstr_or_return_null!(private_key);

    // Safe bounds validation for input bytes
    let bytes = match safe_slice_from_raw_parts(bytes, len, "bytes") {
        Ok(bytes) => bytes,
        Err(err) => {
            CimplError::from(err).set_last();
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
    cimpl_free!(signature_ptr);
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
    let mut mime_ptrs: Vec<*mut c_char> = strs.into_iter().map(to_c_string).collect();
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
    use std::{ffi::CString, io::Seek, panic::catch_unwind};

    use super::*;
    use crate::TestStream;

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
        let mut source_stream = TestStream::new(source_image.to_vec());
        let dest_vec = Vec::new();
        let mut dest_stream = TestStream::new(dest_vec);

        let (signer, builder) = setup_signer_and_builder_for_signing_tests();

        let format = CString::new("image/jpeg").unwrap();
        let mut manifest_bytes_ptr = std::ptr::null();
        let _ = unsafe {
            c2pa_builder_sign(
                builder,
                format.as_ptr(),
                source_stream.as_ptr(),
                dest_stream.as_ptr(),
                signer,
                &mut manifest_bytes_ptr,
            )
        };
        // let error = unsafe { c2pa_error() };
        // let error = unsafe { CString::from_raw(error) };
        // assert_eq!(error.to_str().unwrap(), "Other Invalid signing algorithm");
        // assert_eq!(result, 65485);
        unsafe {
            c2pa_manifest_bytes_free(manifest_bytes_ptr);
        }
        unsafe { c2pa_builder_free(builder) };
        unsafe { c2pa_signer_free(signer) };
    }

    #[test]
    fn builder_add_actions_and_sign() {
        let source_image = include_bytes!(fixture_path!("IMG_0003.jpg"));
        let mut source_stream = TestStream::new(source_image.to_vec());
        let dest_vec = Vec::new();
        let mut dest_stream = TestStream::new(dest_vec);

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
                source_stream.as_ptr(),
                dest_stream.as_ptr(),
                signer,
                &mut manifest_bytes_ptr,
            )
        };

        // Verify we can read the signed data back
        dest_stream.stream_mut().rewind().unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), dest_stream.as_ptr()) };
        if let Some(msg) = CimplError::last_message() {
            println!("last error: {}", msg);
        }
        assert!(!reader.is_null());

        let json = unsafe { c2pa_reader_json(reader) };
        assert!(!json.is_null());
        let json_str = unsafe { CString::from_raw(json) };
        let json_content = json_str.to_str().unwrap();

        assert!(json_content.contains("manifest"));
        assert!(json_content.contains("com.example.test-action"));

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
        let mut source_stream = TestStream::new(source_image.to_vec());
        let dest_vec = Vec::new();
        let mut dest_stream = TestStream::new(dest_vec);

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
                source_stream.as_ptr(),
                dest_stream.as_ptr(),
                signer,
                &mut manifest_bytes_ptr,
            )
        };

        // Verify we can read the signed data back
        dest_stream.stream_mut().rewind().unwrap();
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), dest_stream.as_ptr()) };
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
        let mut source_stream = TestStream::new(source_image.to_vec());
        let dest_vec = Vec::new();
        let mut dest_stream = TestStream::new(dest_vec);

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
                source_stream.as_ptr(),
                dest_stream.as_ptr(),
                signer,
                &mut manifest_bytes_ptr,
            )
        };

        // Verify we can read the signed data back
        dest_stream.stream_mut().rewind().unwrap();
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), dest_stream.as_ptr()) };
        assert!(!reader.is_null());

        let json = unsafe { c2pa_reader_json(reader) };
        assert!(!json.is_null());

        let json_str = unsafe { CString::from_raw(json) };
        let json_content = json_str.to_str().unwrap();

        assert!(json_content.contains("c2pa.created"));
        // Verify the digital source type we picked was used
        assert!(json_content.contains("digitalsourcetype/empty"));

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
        let mut source_stream = TestStream::new(signed_source_image.to_vec());
        let dest_vec = Vec::new();
        let mut dest_stream = TestStream::new(dest_vec);

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
                source_stream.as_ptr(),
                dest_stream.as_ptr(),
                signer,
                &mut manifest_bytes_ptr,
            )
        };

        dest_stream.stream_mut().rewind().unwrap();
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), dest_stream.as_ptr()) };
        assert!(!reader.is_null());

        let json = unsafe { c2pa_reader_json(reader) };
        assert!(!json.is_null());
        let json_str = unsafe { CString::from_raw(json) };
        let json_content = json_str.to_str().unwrap();

        assert!(json_content.contains("c2pa.opened"));
        // Verify the digital source type parameter was ignored for Edit intent
        // and no "empty" source type appears in the JSON
        assert!(!json_content.contains("digitalsourcetype/empty"));

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
        let mut stream = TestStream::new(include_bytes!(fixture_path!("cloud.jpg")).to_vec());

        let format = CString::new("image/jpeg").unwrap();
        let result = unsafe { c2pa_reader_from_stream(format.as_ptr(), stream.as_ptr()) };
        if result.is_null() {
            if let Some(msg) = CimplError::last_message() {
                panic!("Reader creation failed: {}", msg);
            } else {
                panic!("Reader creation failed with no error message");
            }
        }
        assert!(!result.is_null());
        let remote_url = unsafe { c2pa_reader_remote_url(result) };
        assert!(!remote_url.is_null());
        let remote_url = unsafe { std::ffi::CStr::from_ptr(remote_url) };
        assert_eq!(remote_url, c"https://cai-manifests.adobe.com/manifests/adobe-urn-uuid-5f37e182-3687-462e-a7fb-573462780391");
    }

    // cargo test test_reader_file_with_wrong_label -- --nocapture
    #[test]
    fn test_reader_file_with_wrong_label() {
        let mut stream = TestStream::new(
            include_bytes!(fixture_path!("adobe-20220124-E-clm-CAICAI.jpg")).to_vec(),
        );

        let format = CString::new("image/jpeg").unwrap();
        let result: *mut C2paReader =
            unsafe { c2pa_reader_from_stream(format.as_ptr(), stream.as_ptr()) };
        assert!(!result.is_null());
    }

    #[test]
    fn test_c2pa_reader_from_stream_null_format() {
        let mut stream = TestStream::new(Vec::new());

        let result = unsafe { c2pa_reader_from_stream(std::ptr::null(), stream.as_ptr()) };
        assert!(result.is_null());
        let error = unsafe { c2pa_error() };
        let error_str = unsafe { CString::from_raw(error) };
        assert_eq!(error_str.to_str().unwrap(), "NullParameter: format");
    }

    #[test]
    fn test_c2pa_reader_from_stream_cawg() {
        let source_image = include_bytes!(
            "../../sdk/src/identity/tests/fixtures/claim_aggregation/ica_validation/success.jpg"
        );
        let mut stream = TestStream::new(source_image.to_vec());
        let format = CString::new("image/jpeg").unwrap();
        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), stream.as_ptr()) };
        assert!(!reader.is_null());
        let json = unsafe { c2pa_reader_json(reader) };
        assert!(!json.is_null());
        let json_str = unsafe { CString::from_raw(json) };
        assert!(json_str.to_str().unwrap().contains("Silly Cats 929"));
        assert!(json_str
            .to_str()
            .unwrap()
            .contains("cawg.ica.credential_valid"));
    }

    #[test]
    fn test_c2pa_reader_with_stream_from_context() {
        // Create a context with custom settings
        let builder = unsafe { c2pa_context_builder_new() };
        assert!(!builder.is_null());

        let settings = unsafe { c2pa_settings_new() };
        assert!(!settings.is_null());

        let json = CString::new(r#"{"verify": {"verify_after_sign": true}}"#).unwrap();
        let format = CString::new("json").unwrap();
        let result =
            unsafe { c2pa_settings_update_from_string(settings, json.as_ptr(), format.as_ptr()) };
        assert_eq!(result, 0);

        let result = unsafe { c2pa_context_builder_set_settings(builder, settings) };
        assert_eq!(result, 0);

        let context = unsafe { c2pa_context_builder_build(builder) };
        assert!(!context.is_null());

        // Create a reader from the context
        let reader = unsafe { c2pa_reader_from_context(context) };
        assert!(!reader.is_null());

        // Create a stream with test image data
        let source_image = include_bytes!(fixture_path!("adobe-20220124-E-clm-CAICAI.jpg"));
        let mut stream = TestStream::new(source_image.to_vec());

        // Use with_stream to configure the reader
        let format = CString::new("image/jpeg").unwrap();
        let configured_reader =
            unsafe { c2pa_reader_with_stream(reader, format.as_ptr(), stream.as_ptr()) };
        assert!(!configured_reader.is_null());

        // Verify we can read the manifest
        let json = unsafe { c2pa_reader_json(configured_reader) };
        assert!(!json.is_null());
        let json_str = unsafe { CString::from_raw(json) };
        let json_content = json_str.to_str().unwrap();
        // Verify the manifest has expected content (the fixture contains Adobe claims)
        assert!(
            json_content.contains("claim") || json_content.contains("manifest"),
            "Expected manifest content in JSON"
        );

        unsafe {
            c2pa_free(settings as *mut c_void);
            c2pa_free(context as *mut c_void);
            c2pa_free(configured_reader as *mut c_void);
            // Original reader was consumed by with_stream, don't free it
        };
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
        let mut stream = TestStream::new(Vec::new());
        let result =
            unsafe { c2pa_builder_add_resource(builder, std::ptr::null(), stream.as_ptr()) };
        assert_eq!(result, -1);
        let error = unsafe { c2pa_error() };
        let error_str = unsafe { CString::from_raw(error) };
        assert_eq!(error_str.to_str().unwrap(), "NullParameter: uri");
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
        let mut source_stream = TestStream::new(source_image.to_vec());
        let dest_vec = Vec::new();
        let mut dest_stream = TestStream::new(dest_vec);

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
                source_stream.as_ptr(),
                dest_stream.as_ptr(),
                signer,
                &mut manifest_bytes_ptr,
            )
        };
        assert!(result > 0);

        // Verify we can read the signed data back
        dest_stream.stream_mut().rewind().unwrap();
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), dest_stream.as_ptr()) };
        if let Some(msg) = CimplError::last_message() {
            println!("last error: {}", msg);
        }
        assert!(!reader.is_null());

        let json = unsafe { c2pa_reader_json(reader) };
        assert!(!json.is_null());
        let json_str = unsafe { CString::from_raw(json) };
        let json_content = json_str.to_str().unwrap();

        assert!(json_content.contains("manifest"));

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
    fn test_c2pa_settings_new() {
        let settings = unsafe { c2pa_settings_new() };
        assert!(!settings.is_null());
        unsafe { c2pa_free(settings as *mut c_void) };
    }

    #[test]
    fn test_c2pa_settings_update_from_json_string() {
        let settings = unsafe { c2pa_settings_new() };
        assert!(!settings.is_null());

        let json = CString::new(r#"{"verify": {"verify_after_sign": true}}"#).unwrap();
        let format = CString::new("json").unwrap();

        let result =
            unsafe { c2pa_settings_update_from_string(settings, json.as_ptr(), format.as_ptr()) };
        assert_eq!(result, 0);

        unsafe { c2pa_free(settings as *mut c_void) };
    }

    #[test]
    fn test_c2pa_settings_update_from_toml_string() {
        let settings = unsafe { c2pa_settings_new() };
        assert!(!settings.is_null());

        let toml = CString::new(
            r#"
[verify]
verify_after_sign = true
"#,
        )
        .unwrap();
        let format = CString::new("toml").unwrap();

        let result =
            unsafe { c2pa_settings_update_from_string(settings, toml.as_ptr(), format.as_ptr()) };
        assert_eq!(result, 0);

        unsafe { c2pa_free(settings as *mut c_void) };
    }

    #[test]
    fn test_c2pa_settings_update_from_string_invalid() {
        let settings = unsafe { c2pa_settings_new() };
        assert!(!settings.is_null());

        let invalid_json = CString::new(r#"{"verify": {"verify_after_sign": "#).unwrap();
        let format = CString::new("json").unwrap();

        let result = unsafe {
            c2pa_settings_update_from_string(settings, invalid_json.as_ptr(), format.as_ptr())
        };
        assert_ne!(result, 0); // Should fail with invalid JSON

        unsafe { c2pa_free(settings as *mut c_void) };
    }

    #[test]
    fn test_c2pa_settings_set_value() {
        let settings = unsafe { c2pa_settings_new() };
        assert!(!settings.is_null());

        let path = CString::new("verify.verify_after_sign").unwrap();
        let value = CString::new("true").unwrap();

        let result = unsafe { c2pa_settings_set_value(settings, path.as_ptr(), value.as_ptr()) };
        assert_eq!(result, 0);

        unsafe { c2pa_free(settings as *mut c_void) };
    }

    #[test]
    fn test_c2pa_settings_set_value_string() {
        let settings = unsafe { c2pa_settings_new() };
        assert!(!settings.is_null());

        // Test setting array of strings which is a common string value type
        let path = CString::new("core.allowed_network_hosts").unwrap();
        let value = CString::new(r#"["example.com", "test.org"]"#).unwrap(); // JSON array of strings

        let result = unsafe { c2pa_settings_set_value(settings, path.as_ptr(), value.as_ptr()) };
        assert_eq!(result, 0);

        unsafe { c2pa_free(settings as *mut c_void) };
    }

    #[test]
    fn test_c2pa_settings_set_value_number() {
        let settings = unsafe { c2pa_settings_new() };
        assert!(!settings.is_null());

        let path = CString::new("verify.max_memory_usage").unwrap();
        let value = CString::new("1000000").unwrap();

        let result = unsafe { c2pa_settings_set_value(settings, path.as_ptr(), value.as_ptr()) };
        assert_eq!(result, 0);

        unsafe { c2pa_free(settings as *mut c_void) };
    }

    #[test]
    fn test_c2pa_settings_set_value_invalid_json() {
        let settings = unsafe { c2pa_settings_new() };
        assert!(!settings.is_null());

        let path = CString::new("verify.verify_after_sign").unwrap();
        let invalid_value = CString::new("not valid json").unwrap(); // Not valid JSON

        let result =
            unsafe { c2pa_settings_set_value(settings, path.as_ptr(), invalid_value.as_ptr()) };
        assert_ne!(result, 0); // Should fail with invalid JSON

        unsafe { c2pa_free(settings as *mut c_void) };
    }

    #[test]
    fn test_c2pa_context_new() {
        let context = unsafe { c2pa_context_new() };
        assert!(!context.is_null());
        unsafe { c2pa_free(context as *mut c_void) };
    }

    #[test]
    fn test_c2pa_context_builder_new() {
        let builder = unsafe { c2pa_context_builder_new() };
        assert!(!builder.is_null());
        unsafe { c2pa_free(builder as *mut c_void) };
    }

    #[test]
    fn test_c2pa_context_builder_set_settings() {
        let builder = unsafe { c2pa_context_builder_new() };
        assert!(!builder.is_null());

        let settings = unsafe { c2pa_settings_new() };
        assert!(!settings.is_null());

        // Update settings
        let json = CString::new(r#"{"verify": {"verify_after_sign": true}}"#).unwrap();
        let format = CString::new("json").unwrap();
        let result =
            unsafe { c2pa_settings_update_from_string(settings, json.as_ptr(), format.as_ptr()) };
        assert_eq!(result, 0);

        // Set settings on builder
        let result = unsafe { c2pa_context_builder_set_settings(builder, settings) };
        assert_eq!(result, 0);

        unsafe {
            c2pa_free(settings as *mut c_void);
            c2pa_free(builder as *mut c_void);
        };
    }

    #[test]
    fn test_c2pa_context_builder_build() {
        let builder = unsafe { c2pa_context_builder_new() };
        assert!(!builder.is_null());

        let settings = unsafe { c2pa_settings_new() };
        assert!(!settings.is_null());

        let json = CString::new(r#"{"verify": {"verify_after_sign": true}}"#).unwrap();
        let format = CString::new("json").unwrap();
        let result =
            unsafe { c2pa_settings_update_from_string(settings, json.as_ptr(), format.as_ptr()) };
        assert_eq!(result, 0);

        let result = unsafe { c2pa_context_builder_set_settings(builder, settings) };
        assert_eq!(result, 0);

        // Build the context (consumes builder)
        let context = unsafe { c2pa_context_builder_build(builder) };
        assert!(!context.is_null());

        unsafe {
            c2pa_free(settings as *mut c_void);
            c2pa_free(context as *mut c_void);
            // builder is now invalid - don't free it
        };
    }

    #[test]
    fn test_c2pa_context_builder_set_settings_multiple_times() {
        let builder = unsafe { c2pa_context_builder_new() };
        assert!(!builder.is_null());

        // First settings
        let settings1 = unsafe { c2pa_settings_new() };
        assert!(!settings1.is_null());
        let json1 = CString::new(r#"{"verify": {"verify_after_sign": true}}"#).unwrap();
        let format = CString::new("json").unwrap();
        let result =
            unsafe { c2pa_settings_update_from_string(settings1, json1.as_ptr(), format.as_ptr()) };
        assert_eq!(result, 0);

        let result = unsafe { c2pa_context_builder_set_settings(builder, settings1) };
        assert_eq!(result, 0);

        // Second settings (update builder again)
        let settings2 = unsafe { c2pa_settings_new() };
        assert!(!settings2.is_null());
        let json2 = CString::new(r#"{"verify": {"verify_after_sign": false}}"#).unwrap();
        let result =
            unsafe { c2pa_settings_update_from_string(settings2, json2.as_ptr(), format.as_ptr()) };
        assert_eq!(result, 0);

        let result = unsafe { c2pa_context_builder_set_settings(builder, settings2) };
        assert_eq!(result, 0);

        // Build context
        let context = unsafe { c2pa_context_builder_build(builder) };
        assert!(!context.is_null());

        unsafe {
            c2pa_free(settings1 as *mut c_void);
            c2pa_free(settings2 as *mut c_void);
            c2pa_free(context as *mut c_void);
        };
    }

    #[test]
    fn test_c2pa_context_builder_with_full_config() {
        let builder = unsafe { c2pa_context_builder_new() };
        assert!(!builder.is_null());

        let settings = unsafe { c2pa_settings_new() };
        assert!(!settings.is_null());

        // Load full settings from test file
        const SETTINGS: &str = include_str!("../../sdk/tests/fixtures/test_settings.json");
        let settings_str = CString::new(SETTINGS).unwrap();
        let format = CString::new("json").unwrap();
        let result = unsafe {
            c2pa_settings_update_from_string(settings, settings_str.as_ptr(), format.as_ptr())
        };
        assert_eq!(result, 0);

        // Apply to builder
        let result = unsafe { c2pa_context_builder_set_settings(builder, settings) };
        assert_eq!(result, 0);

        // Build context
        let context = unsafe { c2pa_context_builder_build(builder) };
        assert!(!context.is_null());

        unsafe {
            c2pa_free(settings as *mut c_void);
            c2pa_free(context as *mut c_void);
        };
    }

    #[test]
    fn test_c2pa_context_can_be_shared() {
        // Test that a context can be used to create multiple readers
        let context = unsafe { c2pa_context_new() };
        assert!(!context.is_null());

        // Create multiple readers from the same context
        let reader1 = unsafe { c2pa_reader_from_context(context) };
        assert!(!reader1.is_null());

        let reader2 = unsafe { c2pa_reader_from_context(context) };
        assert!(!reader2.is_null());

        // Context is still valid and can be reused
        unsafe {
            c2pa_free(reader1 as *mut c_void);
            c2pa_free(reader2 as *mut c_void);
            c2pa_free(context as *mut c_void);
        };
    }

    #[test]
    fn test_c2pa_free_works_for_all_types() {
        // Test that c2pa_free works for different object types
        let settings = unsafe { c2pa_settings_new() };
        assert!(!settings.is_null());
        let result = unsafe { c2pa_free(settings as *mut c_void) };
        assert_eq!(result, 0);

        let context = unsafe { c2pa_context_new() };
        assert!(!context.is_null());
        let result = unsafe { c2pa_free(context as *mut c_void) };
        assert_eq!(result, 0);

        // Test with a string
        let test_str = CString::new("test").unwrap();
        let c_str = to_c_string(test_str.to_str().unwrap().to_string());
        assert!(!c_str.is_null());
        let result = unsafe { c2pa_free(c_str as *mut c_void) };
        assert_eq!(result, 0);
    }
}
