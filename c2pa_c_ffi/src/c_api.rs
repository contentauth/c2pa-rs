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

// C has no namespace so we prefix things with C2PA to make them unique (as namespace)
#[cfg(feature = "file_io")]
use c2pa::Ingredient;
use c2pa::{
    assertions::DataHash, identity::validator::CawgValidator, Builder as C2paBuilder,
    CallbackSigner, Context, ProgressPhase, Reader as C2paReader, Settings as C2paSettings,
    SigningAlg,
};
use tokio::runtime::Builder;

#[cfg(feature = "file_io")]
use crate::json_api::{read_file, sign_file};
#[cfg(test)]
use crate::safe_slice_from_raw_parts;
// Import macros and utilities from cimpl
#[allow(unused_imports)] // Usage varies by feature flags and test/non-test builds
use crate::{
    box_tracked, bytes_or_return_int, bytes_or_return_null, c2pa_stream::C2paStream, cimpl_free,
    cstr_or_return_int, cstr_or_return_null, deref_mut_or_return, deref_mut_or_return_int,
    deref_mut_or_return_null, deref_or_return_int, deref_or_return_null, error::Error,
    ok_or_return_int, ok_or_return_null, option_to_c_string, ptr_or_return_int,
    signer_info::SignerInfo, to_c_bytes, to_c_string, CimplError,
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

    #[repr(C)]
    #[allow(dead_code)]
    pub struct C2paHttpResolver;
}

type C2paContextBuilder = Context;
type C2paContext = Arc<Context>;

/// Progress phase constants passed to C progress callbacks.
/// These mirror [`c2pa::ProgressPhase`] variants.
#[repr(C)]
pub enum C2paProgressPhase {
    Reading = 0,
    VerifyingManifest = 1,
    VerifyingSignature = 2,
    VerifyingIngredient = 3,
    VerifyingAssetHash = 4,
    AddingIngredient = 5,
    Thumbnail = 6,
    Hashing = 7,
    Signing = 8,
    Embedding = 9,
    FetchingRemoteManifest = 10,
    Writing = 11,
    FetchingOCSP = 12,
    FetchingTimestamp = 13,
}

impl From<ProgressPhase> for C2paProgressPhase {
    fn from(phase: ProgressPhase) -> Self {
        match phase {
            ProgressPhase::Reading => Self::Reading,
            ProgressPhase::VerifyingManifest => Self::VerifyingManifest,
            ProgressPhase::VerifyingSignature => Self::VerifyingSignature,
            ProgressPhase::VerifyingIngredient => Self::VerifyingIngredient,
            ProgressPhase::VerifyingAssetHash => Self::VerifyingAssetHash,
            ProgressPhase::AddingIngredient => Self::AddingIngredient,
            ProgressPhase::Thumbnail => Self::Thumbnail,
            ProgressPhase::Hashing => Self::Hashing,
            ProgressPhase::Signing => Self::Signing,
            ProgressPhase::Embedding => Self::Embedding,
            ProgressPhase::FetchingRemoteManifest => Self::FetchingRemoteManifest,
            ProgressPhase::Writing => Self::Writing,
            ProgressPhase::FetchingOCSP => Self::FetchingOCSP,
            ProgressPhase::FetchingTimestamp => Self::FetchingTimestamp,
            _ => Self::Reading, // fallback for #[non_exhaustive]
        }
    }
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

/// Hash binding type for embeddable signing workflows.
#[repr(C)]
pub enum C2paHashType {
    /// Placeholder + exclusions + hash + sign (JPEG, PNG, etc.).
    DataHash = 0,

    /// Placeholder + hash + sign (MP4, AVIF, HEIF/HEIC).
    BmffHash = 1,

    /// Hash + sign, no placeholder needed.
    BoxHash = 2,
}

#[repr(C)]
pub struct C2paSigner {
    pub signer: Box<dyn crate::maybe_send_sync::C2paSignerObject>,
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

/// HTTP request passed to the resolver callback.
///
/// All string fields are NULL-terminated UTF-8. The struct and all
/// pointed-to data remain valid for the duration of the callback.
#[repr(C)]
pub struct C2paHttpRequest {
    /// URL (e.g. `https://example.com/manifest`)
    pub url: *const c_char,
    /// HTTP method (e.g. "GET", "POST")
    pub method: *const c_char,
    /// Newline-delimited "Name: Value\n" pairs, or NULL if none
    pub headers: *const c_char,
    /// Request body bytes, or NULL if none
    pub body: *const c_uchar,
    /// Length of `body` in bytes
    pub body_len: usize,
}

/// HTTP response filled in by the resolver callback.
///
/// The callback must set `status`, `body`, and `body_len`.
/// `body` must be allocated with `malloc()`. Rust will call `free()` on it
/// after copying the data.
#[repr(C)]
pub struct C2paHttpResponse {
    /// HTTP status code (e.g. 200, 404)
    pub status: i32,
    /// Response body bytes, allocated by the callback with `malloc()`.
    /// Rust takes ownership and will call `free()`.
    pub body: *mut c_uchar,
    /// Length of `body` in bytes
    pub body_len: usize,
}

/// Owns the backing storage for a [`C2paHttpRequest`].
///
/// Use [`as_ffi`](OwnedC2paHttpRequest::as_ffi) to obtain the `#[repr(C)]` view
/// whose pointers borrow from this struct.
struct OwnedC2paHttpRequest {
    url: std::ffi::CString,
    method: std::ffi::CString,
    headers: std::ffi::CString,
    body: Vec<u8>,
}

impl TryFrom<c2pa::http::http::Request<Vec<u8>>> for OwnedC2paHttpRequest {
    type Error = c2pa::http::HttpResolverError;

    fn try_from(request: c2pa::http::http::Request<Vec<u8>>) -> Result<Self, Self::Error> {
        use std::ffi::CString;

        use c2pa::http::HttpResolverError;

        let url = CString::new(request.uri().to_string())
            .map_err(|e| HttpResolverError::Other(Box::new(e)))?;
        let method = CString::new(request.method().as_str())
            .map_err(|e| HttpResolverError::Other(Box::new(e)))?;
        let headers_str: String = request
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|v| format!("{k}: {v}\n")))
            .collect();
        let headers =
            CString::new(headers_str).map_err(|e| HttpResolverError::Other(Box::new(e)))?;
        let body = request.into_body();

        Ok(Self {
            url,
            method,
            headers,
            body,
        })
    }
}

impl OwnedC2paHttpRequest {
    /// Returns the `#[repr(C)]` view. The returned struct borrows from `self`
    /// and must not outlive it.
    fn as_ffi(&self) -> C2paHttpRequest {
        let (body, body_len) = if self.body.is_empty() {
            (std::ptr::null(), 0)
        } else {
            (self.body.as_ptr(), self.body.len())
        };
        C2paHttpRequest {
            url: self.url.as_ptr(),
            method: self.method.as_ptr(),
            headers: self.headers.as_ptr(),
            body,
            body_len,
        }
    }
}

/// Converts a [`C2paHttpResponse`] into an `http::Response`.
///
/// Copies the body, then calls `free()` on the C-allocated `body` pointer.
///
/// # Safety
/// `body` must have been allocated with `malloc()` (or be null).
/// This impl is intentionally *not* marked `unsafe` because `TryFrom`
/// does not support it; callers must uphold the `malloc` invariant.
impl TryFrom<C2paHttpResponse> for c2pa::http::http::Response<Box<dyn std::io::Read>> {
    type Error = c2pa::http::HttpResolverError;

    fn try_from(resp: C2paHttpResponse) -> Result<Self, Self::Error> {
        let body_vec = if resp.body.is_null() || resp.body_len == 0 {
            Vec::new()
        } else {
            let v = unsafe { std::slice::from_raw_parts(resp.body, resp.body_len) }.to_vec();
            unsafe { libc::free(resp.body as *mut c_void) };
            v
        };

        c2pa::http::http::Response::builder()
            .status(resp.status as u16)
            .body(Box::new(std::io::Cursor::new(body_vec)) as Box<dyn std::io::Read>)
            .map_err(c2pa::http::HttpResolverError::Http)
    }
}

/// Callback type for custom HTTP request resolution.
///
/// Called synchronously by Rust when an HTTP request is needed
/// (remote manifest fetch, OCSP, timestamp, etc.).
///
/// Returns 0 on success, non-zero on error. On error, call
/// `c2pa_error_set_last()` before returning.
pub type C2paHttpResolverCallback = unsafe extern "C" fn(
    context: *mut c_void,
    request: *const C2paHttpRequest,
    response: *mut C2paHttpResponse,
) -> c_int;

/// Opaque handle for a C-callback-based HTTP resolver.
/// Created by `c2pa_http_resolver_create()`. Either consumed by
/// `c2pa_context_builder_set_http_resolver()` or freed via `c2pa_free()`.
pub struct C2paHttpResolver {
    context: *const c_void,
    callback: C2paHttpResolverCallback,
}

// Safety: the caller guarantees that `context` is safe to use from any thread.
// On wasm32, MaybeSend/MaybeSync are blanket-implemented so these are not needed,
// but they are harmless and keep the code uniform.
unsafe impl Send for C2paHttpResolver {}
unsafe impl Sync for C2paHttpResolver {}

impl c2pa::http::SyncHttpResolver for C2paHttpResolver {
    fn http_resolve(
        &self,
        request: c2pa::http::http::Request<Vec<u8>>,
    ) -> Result<c2pa::http::http::Response<Box<dyn std::io::Read>>, c2pa::http::HttpResolverError>
    {
        use c2pa::http::HttpResolverError;

        let owned = OwnedC2paHttpRequest::try_from(request)?;
        let c_request = owned.as_ffi();

        let mut c_response = C2paHttpResponse {
            status: 0,
            body: std::ptr::null_mut(),
            body_len: 0,
        };

        let rc =
            unsafe { (self.callback)(self.context as *mut c_void, &c_request, &mut c_response) };

        if rc != 0 {
            // Free any body the callback may have allocated before the error.
            if !c_response.body.is_null() {
                unsafe { libc::free(c_response.body as *mut c_void) };
            }
            let msg = CimplError::last_message()
                .unwrap_or_else(|| "HTTP callback returned error".to_string());
            return Err(HttpResolverError::Other(msg.into()));
        }

        c_response.try_into()
    }
}

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
    let error_str = cstr_or_return_int!(error_str);
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
#[deprecated(
    note = "Use c2pa_settings_new() and c2pa_context_builder_set_settings() to configure a context explicitly."
)]
pub unsafe extern "C" fn c2pa_load_settings(
    settings: *const c_char,
    format: *const c_char,
) -> c_int {
    let settings = cstr_or_return_int!(settings);
    let format = cstr_or_return_int!(format);
    // The C API is inherently stateful: callers invoke c2pa_load_settings once and subsequent
    // C API calls inherit those settings via thread-local storage. This is by design.
    #[allow(deprecated)]
    let result = C2paSettings::from_string(&settings, &format);
    ok_or_return_int!(result);
    0 // returns 0 on success
}

/// Creates a new C2PA settings object with default values.
///
/// # Safety
///
/// The returned pointer must be freed with `c2pa_free()`.
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
    let settings = deref_mut_or_return_int!(settings, C2paSettings);
    let settings_str = cstr_or_return_int!(settings_str);
    let format = cstr_or_return_int!(format);
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
    let settings = deref_mut_or_return_int!(settings, C2paSettings);
    let path = cstr_or_return_int!(path);
    let value_str = cstr_or_return_int!(value);

    // Parse JSON value to determine type
    let parsed_value: serde_json::Value = ok_or_return_int!(serde_json::from_str(&value_str)
        .map_err(|e| c2pa::Error::BadParam(format!("Invalid JSON value: {e}"))));

    // Convert to appropriate type and set value
    let result = match parsed_value {
        serde_json::Value::Bool(b) => settings.set_value(&path, b),
        serde_json::Value::Number(n) if n.is_i64() => {
            settings.set_value(&path, n.as_i64().unwrap())
        }
        serde_json::Value::Number(n) if n.is_f64() => {
            settings.set_value(&path, n.as_f64().unwrap())
        }
        serde_json::Value::Number(_) => {
            Err(c2pa::Error::BadParam("Invalid number format".to_string()))
        }
        serde_json::Value::String(s) => settings.set_value(&path, s),
        serde_json::Value::Array(arr) => {
            // Convert array to Vec<serde_json::Value> and try to extract strings
            let strings: Result<Vec<String>, _> = arr
                .into_iter()
                .map(|v| {
                    v.as_str().map(String::from).ok_or_else(|| {
                        c2pa::Error::BadParam("Array values must be strings".to_string())
                    })
                })
                .collect();
            strings.and_then(|vec| settings.set_value(&path, vec))
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
/// The returned pointer must be freed by calling
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
    let builder = deref_mut_or_return_int!(builder, C2paContextBuilder);
    let settings = deref_or_return_int!(settings, C2paSettings);
    let result = builder.set_settings(settings);
    ok_or_return_int!(result);
    0
}

/// Set a Signer into the Builder's context.
/// (The context will own the Signer from that point on).
/// The signer will be available via `context.signer()` after
/// building the context. If a signer is also configured in settings,
/// the programmatic signer takes priority regardless of call order.
///
/// Works with any C2paSigner pointer, whether created by
/// `c2pa_signer_from_info` or `c2pa_signer_create`.
///
/// # Safety
///
/// * `builder` must be a valid C2paContextBuilder pointer (not yet built).
/// * `signer_ptr` must be a valid C2paSigner pointer. It is consumed by this
///   call and must not be used or freed afterward.
///
/// # Returns
///
/// 0 on success, negative value on error.
#[no_mangle]
pub unsafe extern "C" fn c2pa_context_builder_set_signer(
    builder: *mut C2paContextBuilder,
    signer_ptr: *mut C2paSigner,
) -> c_int {
    let builder = deref_mut_or_return_int!(builder, C2paContextBuilder);
    // Untrack the signer before taking ownership via Box::from_raw.
    // This prevents double-free if C code later calls c2pa_signer_free().
    untrack_or_return_int!(signer_ptr, C2paSigner);
    let c2pa_signer = Box::from_raw(signer_ptr);
    let result = builder.set_signer(c2pa_signer.signer);
    ok_or_return_int!(result);
    0
}

/// C-callable progress callback function type.
///
/// # Parameters
/// * `context` – the opaque `user_data` pointer passed to
///   `c2pa_context_builder_set_progress_callback`.
/// * `phase`   – a [`C2paProgressPhase`] value identifying the current operation.
///   Callers should derive any user-visible text from this value in the appropriate language.
/// * `step`    – monotonically increasing counter within the current phase, starting at
///   `1`.  Resets to `1` at the start of each new phase.  Use as a liveness heartbeat:
///   a rising `step` means the SDK is making forward progress.  The unit is
///   phase-specific and should otherwise be treated as opaque.
/// * `total`   – `0` = indeterminate (show a spinner, use `step` as liveness signal);
///   `1` = single-shot phase (the callback itself is the notification);
///   `> 1` = determinate (`step / total` gives a completion fraction for a progress bar).
///
/// # Return value
/// Return non-zero to continue the operation, zero to cancel.
pub type ProgressCCallback = unsafe extern "C" fn(
    context: *const c_void,
    phase: C2paProgressPhase,
    step: u32,
    total: u32,
) -> c_int;

/// Attaches a C progress callback to a context builder.
///
/// The `callback` is invoked at key checkpoints during signing and reading
/// operations.  Returning `0` from the callback requests cancellation; the SDK
/// will return an error at the next safe stopping point.
///
/// # Parameters
/// * `builder`  – a valid `C2paContextBuilder` pointer.
/// * `user_data` – opaque `void*` captured by the closure and passed as the first argument
///   of every `callback` invocation.  Pass `NULL` if the callback does not need user data.
/// * `callback` – C function pointer matching [`ProgressCCallback`].
///
/// # Returns
/// `0` on success, non-zero on error (check `c2pa_error()`).
///
/// # Safety
/// * `builder` must be valid and not yet built.
/// * `user_data` must remain valid for the entire lifetime of the built context.
#[no_mangle]
pub unsafe extern "C" fn c2pa_context_builder_set_progress_callback(
    builder: *mut C2paContextBuilder,
    user_data: *const c_void,
    callback: ProgressCCallback,
) -> c_int {
    let builder = deref_mut_or_return_int!(builder, C2paContextBuilder);
    let ud = user_data as usize;
    let c_callback = move |phase: ProgressPhase, step: u32, total: u32| unsafe {
        (callback)(ud as *const c_void, phase.into(), step, total) != 0
    };
    builder.set_progress_callback(c_callback);
    0
}

/// Creates a new HTTP resolver backed by a C callback.
///
/// The `context` pointer is passed unmodified to every callback invocation and
/// must remain valid for the lifetime of the resolver and any context built from it.
///
/// # Safety
///
/// * `callback` must be a valid function pointer that remains valid for the
///   lifetime of the resolver.
/// * `context` must remain valid for the lifetime of the resolver and any
///   context that uses it.
/// * `context` must be safe to use from any thread (i.e. the caller upholds
///   `Send + Sync` semantics for the pointed-to data).
///
/// # Returns
///
/// A new `C2paHttpResolver*`, or NULL on error. Must be freed with `c2pa_free()`
/// OR consumed by `c2pa_context_builder_set_http_resolver()`.
#[no_mangle]
pub unsafe extern "C" fn c2pa_http_resolver_create(
    context: *const c_void,
    callback: C2paHttpResolverCallback,
) -> *mut C2paHttpResolver {
    box_tracked!(C2paHttpResolver { context, callback })
}

/// Sets a custom HTTP resolver on the context builder.
///
/// The builder takes ownership of the resolver; the caller must NOT free it afterward.
///
/// # Safety
///
/// * `builder` must be a valid C2paContextBuilder pointer (not yet built).
/// * `resolver_ptr` is consumed and must not be used or freed afterward.
///
/// # Returns
///
/// 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn c2pa_context_builder_set_http_resolver(
    builder: *mut C2paContextBuilder,
    resolver_ptr: *mut C2paHttpResolver,
) -> c_int {
    let builder = deref_mut_or_return_int!(builder, C2paContextBuilder);
    untrack_or_return_int!(resolver_ptr, C2paHttpResolver);
    let c2pa_resolver = Box::from_raw(resolver_ptr);
    let result = builder.set_resolver(*c2pa_resolver);
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
    untrack_or_return_null!(builder, C2paContextBuilder);
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
/// The returned pointer must be freed with `c2pa_free()`.
///
/// # Returns
///
/// A pointer to a newly allocated immutable C2paContext object, or NULL on allocation failure.
#[no_mangle]
pub unsafe extern "C" fn c2pa_context_new() -> *mut C2paContext {
    box_tracked!(Context::new().into_shared())
}

/// Requests cancellation of any in-progress operation on this context.
///
/// Thread-safe — may be called from any thread that holds a valid `C2paContext`
/// pointer.  The SDK will return an `OperationCancelled` error at the next safe
/// checkpoint inside the running operation.
///
/// # Parameters
/// * `ctx` – a valid, non-null `C2paContext` pointer obtained from
///   `c2pa_context_builder_build()` or `c2pa_context_new()`.
///
/// # Returns
/// `0` on success, non-zero if `ctx` is null or invalid.
///
/// # Safety
/// `ctx` must be a valid pointer and must not be freed concurrently with this call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_context_cancel(ctx: *mut C2paContext) -> c_int {
    let ctx = deref_or_return_int!(ctx, C2paContext);
    ctx.cancel();
    0
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
#[deprecated(
    note = "Use c2pa_reader_from_context() with an explicit context for new implementations."
)]
#[allow(deprecated)]
pub unsafe extern "C" fn c2pa_read_file(
    path: *const c_char,
    data_dir: *const c_char,
) -> *mut c_char {
    let path = cstr_or_return_null!(path);
    let data_dir = cstr_option!(data_dir);

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
#[deprecated(
    note = "Use c2pa_builder_add_ingredient_from_stream() with an explicit context for new implementations."
)]
#[allow(deprecated)]
pub unsafe extern "C" fn c2pa_read_ingredient_file(
    path: *const c_char,
    data_dir: *const c_char,
) -> *mut c_char {
    let path = cstr_or_return_null!(path);
    let data_dir = cstr_or_return_null!(data_dir);
    // Legacy C API: uses thread-local settings. Use c2pa_reader_from_context for new implementations.
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
#[deprecated(
    note = "Use c2pa_builder_from_context() with c2pa_builder_sign_to_stream() for new implementations."
)]
#[allow(deprecated)]
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
    ok_or_return_null!(result); // we don't return the bytes, just an empty string for ok
    to_c_string("".to_string())
}

/// Frees a string allocated by Rust.
///
/// # Safety
/// The string must not have been modified in C.
/// The string can only be freed once and is invalid after this call.
#[no_mangle]
#[deprecated(note = "Use c2pa_free() instead, which works for all pointer types.")]
pub unsafe extern "C" fn c2pa_release_string(s: *mut c_char) {
    cimpl_free!(s);
}

/// Frees any pointer allocated by this library.
///
/// This is the **recommended** free function for all C2PA objects. It replaces the
/// type-specific free functions (like `c2pa_string_free`, `c2pa_reader_free`, etc.)
/// which are maintained only for backward compatibility.
///
/// ## Why use c2pa_free?
///
/// - **Simpler API**: One function to remember instead of multiple type-specific functions
/// - **Less error-prone**: No need to match the correct free function to each type
/// - **Consistent**: Works uniformly across all pointer types
/// - **Returns error codes**: Returns 0 on success, -1 on error for better error handling
///
/// ## Supported Types
///
/// This function works for all C2PA objects including:
/// - C2paContext
/// - C2paSettings
/// - C2paBuilder
/// - C2paReader
/// - C2paSigner
/// - strings (c_char*)
/// - byte arrays (c_uchar*)
/// - manifest bytes
/// - signatures
/// - and any other objects created by this library
///
/// # Safety
///
/// * The pointer must have been allocated by this library (e.g., from c2pa_context_new(),
///   c2pa_settings_new(), c2pa_builder_from_json(), etc.)
/// * The pointer must not have been modified in C.
/// * The pointer can only be freed once and is invalid after this call.
/// * Do not mix this with type-specific free functions for the same pointer.
///
/// # Returns
///
/// 0 on success, -1 on error (e.g., if the pointer was not allocated by this library).
///
/// # Example (C)
///
/// ```c
/// // Create various objects
/// C2paReader* reader = c2pa_reader_from_file("image.jpg", "json");
/// char* json = c2pa_reader_json(reader);
/// C2paBuilder* builder = c2pa_builder_from_json(json);
///
/// // Free everything with the same function
/// c2pa_free(json);
/// c2pa_free(reader);
/// c2pa_free(builder);
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_free(ptr: *const c_void) -> c_int {
    cimpl_free!(ptr as *mut c_void)
}

/// Frees a string allocated by Rust.
///
/// **Note**: This function is maintained for backward compatibility. New code should
/// use [`c2pa_free`] instead, which works for all pointer types.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The string must not have been modified in C.
/// The string can only be freed once and is invalid after this call.
#[no_mangle]
#[deprecated(note = "Use c2pa_free() instead, which works for all pointer types.")]
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
    #[allow(deprecated)]
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
            #[cfg(target_arch = "wasm32")]
            let runtime = Builder::new_current_thread().enable_all().build();

            #[cfg(not(target_arch = "wasm32"))]
            let runtime = Builder::new_multi_thread().enable_all().build();

            let runtime = match runtime {
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

/// Creates a new C2paReader from a default context.
///
/// # Safety
///
/// This function is safe to call with no preconditions.
///
/// # Returns
/// A pointer to a newly allocated C2paReader, or NULL on error.
/// The returned pointer must be freed with `c2pa_free()`.
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
#[deprecated(
    note = "Use c2pa_reader_from_context() with an explicit context instead of relying on thread-local settings."
)]
pub unsafe extern "C" fn c2pa_reader_from_stream(
    format: *const c_char,
    stream: *mut C2paStream,
) -> *mut C2paReader {
    let format = cstr_or_return_null!(format);
    let stream = deref_mut_or_return_null!(stream, C2paStream);

    // Legacy C API: inherits thread-local settings set by c2pa_load_settings.
    // Prefer c2pa_reader_from_context for new C API usage.
    #[allow(deprecated)]
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
    // Validate inputs first, while reader is still tracked
    let format = cstr_or_return_null!(format);
    let stream = deref_mut_or_return_null!(stream, C2paStream);

    // Now safe to take ownership - all validations passed
    untrack_or_return_null!(reader, C2paReader);
    let reader = Box::from_raw(reader);
    let result = (*reader).with_stream(&format, stream);
    let result = ok_or_return_null!(post_validate(result));
    box_tracked!(result)
}

/// Configures an existing passed in Reader with manifest data and a stream.
/// This covers the case when a Reader needs to be able to re-read signed
/// manifest bytes. This method consumes the original Reader and returns a
/// new configured Reader. The original Reader pointer becomes invalid after
/// this call and should not be reused.
///
/// # Safety
///
/// * `reader` must be a valid pointer to a configured C2paReader
///   (usually with a Context).
/// * `format` must be a valid null-terminated string with the MIME type.
/// * `stream` must be a valid pointer to a C2paStream.
/// * `manifest_data` must be a valid pointer to manifest bytes.
/// * `manifest_size` must be the length of the manifest_data buffer.
/// * After calling this function, the `reader` pointer becomes invalid.
///
/// # Returns
///
/// A pointer to a newly configured C2paReader, or NULL on error.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_with_manifest_data_and_stream(
    reader: *mut C2paReader,
    format: *const c_char,
    stream: *mut C2paStream,
    manifest_data: *const c_uchar,
    manifest_size: usize,
) -> *mut C2paReader {
    let format = cstr_or_return_null!(format);
    let stream = deref_mut_or_return_null!(stream, C2paStream);
    let manifest_bytes = bytes_or_return_null!(manifest_data, manifest_size, "manifest_data");

    // Take ownership of the Reader (needs to remove it from tracking to take it)
    untrack_or_return_null!(reader, C2paReader);
    let reader = Box::from_raw(reader);
    let result = (*reader).with_manifest_data_and_stream(manifest_bytes, &format, stream);
    let result = ok_or_return_null!(post_validate(result));

    // New reader, will be tracked now too
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
    // Validate inputs first, while reader is still tracked
    let format = cstr_or_return_null!(format);
    let stream = deref_mut_or_return_null!(stream, C2paStream);
    let fragment = deref_mut_or_return_null!(fragment, C2paStream);

    // Now safe to take ownership - all validations passed
    untrack_or_return_null!(reader, C2paReader);
    let reader = Box::from_raw(reader);
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
/// The returned value MUST be released by calling c2pa_free
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
#[deprecated(
    note = "Use c2pa_reader_from_context() with an explicit context instead of relying on thread-local settings."
)]
#[allow(deprecated)]
pub unsafe fn c2pa_reader_from_file(path: *const c_char) -> *mut C2paReader {
    let path = cstr_or_return_null!(path);
    // Legacy C API: inherits thread-local settings set by c2pa_load_settings.
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
/// The returned value MUST be released by calling c2pa_free
/// and it is no longer valid after that call.
#[no_mangle]
#[deprecated(
    note = "Use c2pa_reader_from_context() then c2pa_reader_with_manifest_data_and_stream() instead."
)]
pub unsafe extern "C" fn c2pa_reader_from_manifest_data_and_stream(
    format: *const c_char,
    stream: *mut C2paStream,
    manifest_data: *const c_uchar,
    manifest_size: usize,
) -> *mut C2paReader {
    let format = cstr_or_return_null!(format);
    let stream = deref_mut_or_return_null!(stream, C2paStream);

    let manifest_bytes = bytes_or_return_null!(manifest_data, manifest_size, "manifest_data");

    // Legacy C API: inherits thread-local settings set by c2pa_load_settings.
    #[allow(deprecated)]
    let result = C2paReader::from_manifest_data_and_stream(manifest_bytes, &format, stream);
    box_tracked!(ok_or_return_null!(post_validate(result)))
}

/// Frees a C2paReader allocated by Rust.
///
/// **Note**: This function is maintained for backward compatibility. New code should
/// use [`c2pa_free`] instead, which works for all pointer types.
///
/// # Safety
/// The C2paReader can only be freed once and is invalid after this call.
#[no_mangle]
#[deprecated(note = "Use c2pa_free() instead, which works for all pointer types.")]
pub unsafe extern "C" fn c2pa_reader_free(reader_ptr: *mut C2paReader) {
    cimpl_free!(reader_ptr);
}

/// Returns a JSON string generated from a C2paReader.
///
/// # Safety
/// The returned value MUST be released by calling c2pa_free
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_reader_json(reader_ptr: *mut C2paReader) -> *mut c_char {
    let c2pa_reader = deref_or_return_null!(reader_ptr, C2paReader);
    to_c_string(c2pa_reader.json())
}

/// Returns a detailed JSON string generated from a C2paReader.
///
/// # Safety
/// The returned value MUST be released by calling c2pa_free
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
    let reader = deref_mut_or_return_int!(reader_ptr, C2paReader);
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
/// The returned value MUST be released by calling c2pa_free
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
#[deprecated(note = "Use c2pa_builder_from_context() then c2pa_builder_set_definition() instead.")]
pub unsafe extern "C" fn c2pa_builder_from_json(manifest_json: *const c_char) -> *mut C2paBuilder {
    let manifest_json = cstr_or_return_null!(manifest_json);
    // Legacy C API: inherits thread-local settings set by c2pa_load_settings.
    // Prefer c2pa_builder_from_context for new C API usage.
    #[allow(deprecated)]
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
/// The returned value MUST be released by calling c2pa_free
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
#[deprecated(note = "Use c2pa_builder_from_context() then c2pa_builder_with_archive() instead.")]
#[allow(deprecated)]
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
/// **Note**: This function is maintained for backward compatibility. New code should
/// use [`c2pa_free`] instead, which works for all pointer types.
///
/// # Safety
/// The C2paBuilder can only be freed once and is invalid after this call.
#[no_mangle]
#[deprecated(note = "Use c2pa_free() instead, which works for all pointer types.")]
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
    // Validate inputs first, while builder is still tracked
    let manifest_json = cstr_or_return_null!(manifest_json);

    // Now safe to take ownership - all validations passed
    untrack_or_return_null!(builder, C2paBuilder);
    let builder = Box::from_raw(builder);
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
    // Validate stream first, while builder is still tracked
    let stream = deref_mut_or_return_null!(stream, C2paStream);

    // Now safe to take ownership - stream is valid
    untrack_or_return_null!(builder, C2paBuilder);
    let builder = Box::from_raw(builder);
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
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);

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
#[allow(clippy::unused_unit)] // clippy doesn't like the () return type on the macro
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
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
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
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
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
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
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
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
    let ingredient_json = cstr_or_return_int!(ingredient_json);
    let format = cstr_or_return_int!(format);
    let source = deref_mut_or_return_int!(source, C2paStream);
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
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
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
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
    let stream = deref_mut_or_return_int!(stream, C2paStream);
    let result = builder.to_archive(&mut *stream);
    ok_or_return_int!(result);
    0 // returns 0 on success
}

/// Adds an ingredient to the C2paBuilder from a C2PA ingredient archive stream.
///
/// The stream must contain a C2PA ingredient archive produced by
/// `c2pa_builder_write_ingredient_archive`. Use
/// `c2pa_builder_add_ingredient_from_stream` for regular asset streams.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * stream: pointer to a readable, seekable C2paStream containing the ingredient archive.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns 0.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Pointers must be valid and non-NULL.
///
/// # Example
/// ```c
/// // Write the ingredient archive first
/// C2paStream* archive = c2pa_create_stream(...);
/// int result = c2pa_builder_write_ingredient_archive(ingredient_builder, "ingredient-id", archive);
///
/// // Rewind and add it to the parent builder
/// c2pa_stream_seek(archive, 0, C2PA_SEEK_START);
/// result = c2pa_builder_add_ingredient_from_archive(parent_builder, archive);
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_add_ingredient_from_archive(
    builder_ptr: *mut C2paBuilder,
    stream: *mut C2paStream,
) -> c_int {
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
    let stream = deref_mut_or_return_int!(stream, C2paStream);
    let result = builder.add_ingredient_from_archive(&mut *stream);
    ok_or_return_int!(result);
    0 // returns 0 on success
}

/// Writes a single-ingredient C2PA archive to the destination stream.
///
/// The archive can later be loaded with `c2pa_builder_add_ingredient_from_archive`.
/// This requires the `generate_c2pa_archive` builder setting to be enabled via
/// `c2pa_builder_with_settings` / `c2pa_context_with_settings` before calling.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * ingredient_id: pointer to a C string identifying the ingredient within the builder.
/// * stream: pointer to a writable C2paStream.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns 0.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// Reads from NULL-terminated C strings. Pointers must be valid and non-NULL.
///
/// # Example
/// ```c
/// C2paStream* archive = c2pa_create_stream(...);
/// int result = c2pa_builder_write_ingredient_archive(builder, "my-ingredient", archive);
/// if (result < 0) {
///     char* error = c2pa_error();
///     printf("Error: %s\n", error);
///     c2pa_string_free(error);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_write_ingredient_archive(
    builder_ptr: *mut C2paBuilder,
    ingredient_id: *const c_char,
    stream: *mut C2paStream,
) -> c_int {
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
    let ingredient_id = cstr_or_return_int!(ingredient_id);
    let stream = deref_mut_or_return_int!(stream, C2paStream);
    let result = builder.write_ingredient_archive(&ingredient_id, &mut *stream);
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
/// If manifest_bytes_ptr is not NULL, the returned value MUST be released by calling c2pa_free
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
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
    let format = cstr_or_return_int!(format);
    let source = deref_mut_or_return_int!(source, C2paStream);
    let dest = deref_mut_or_return_int!(dest, C2paStream);
    let c2pa_signer = deref_mut_or_return_int!(signer_ptr, C2paSigner);
    ptr_or_return_int!(manifest_bytes_ptr);

    let result = builder.sign(
        c2pa_signer.signer.as_ref(),
        &format,
        &mut *source,
        &mut *dest,
    );
    let manifest_bytes = ok_or_return_int!(result);
    let len = manifest_bytes.len() as i64;
    if !manifest_bytes_ptr.is_null() {
        *manifest_bytes_ptr = to_c_bytes(manifest_bytes);
    }
    len
}

/// Sign using the Signer from the Context.
///
/// Equivalent to `c2pa_builder_sign` but the signer comes from the Builder's
/// context instead of being passed explicitly.
///
/// If the context has no signer (neither programmatic via
/// `c2pa_context_builder_set_signer` nor from settings), an error
/// will be returned.
///
/// # Parameters
///
/// * `builder_ptr` - pointer to a Builder whose context has a signer set.
/// * `format` - MIME type or file extension (null-terminated C string).
/// * `source` - pointer to a readable C2paStream.
/// * `dest` - pointer to a read+write+seek C2paStream.
/// * `manifest_bytes_ptr` - out-pointer for the manifest bytes.
///
/// # Safety
///
/// Reads from NULL-terminated C strings.
/// The returned bytes MUST be released by calling `c2pa_free`.
///
/// # Returns
///
/// The length of the manifest bytes on success, or -1 on error.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_sign_context(
    builder_ptr: *mut C2paBuilder,
    format: *const c_char,
    source: *mut C2paStream,
    dest: *mut C2paStream,
    manifest_bytes_ptr: *mut *const c_uchar,
) -> i64 {
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
    let format = cstr_or_return_int!(format);
    let source = deref_mut_or_return_int!(source, C2paStream);
    let dest = deref_mut_or_return_int!(dest, C2paStream);
    ptr_or_return_int!(manifest_bytes_ptr);

    let result = builder.save_to_stream(&format, &mut *source, &mut *dest);
    let manifest_bytes = ok_or_return_int!(result);
    let len = manifest_bytes.len() as i64;
    if !manifest_bytes_ptr.is_null() {
        *manifest_bytes_ptr = to_c_bytes(manifest_bytes);
    }
    len
}

/// Frees a C2PA manifest returned by c2pa_builder_sign.
///
/// **Note**: This function is maintained for backward compatibility. New code should
/// use [`c2pa_free`] instead, which works for all pointer types.
///
/// # Safety
/// The bytes can only be freed once and are invalid after this call.
#[no_mangle]
#[deprecated(note = "Use c2pa_free() instead, which works for all pointer types.")]
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
/// If manifest_bytes_ptr is not NULL, the returned value MUST be released by calling c2pa_free
/// and it is no longer valid after that call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_data_hashed_placeholder(
    builder_ptr: *mut C2paBuilder,
    reserved_size: usize,
    format: *const c_char,
    manifest_bytes_ptr: *mut *const c_uchar,
) -> i64 {
    ptr_or_return_int!(manifest_bytes_ptr);
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
    let format = cstr_or_return_int!(format);
    let result = builder.data_hashed_placeholder(reserved_size, &format);
    let manifest_bytes = ok_or_return_int!(result);
    let len = manifest_bytes.len() as i64;
    if !manifest_bytes_ptr.is_null() {
        *manifest_bytes_ptr = to_c_bytes(manifest_bytes);
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
/// If manifest_bytes_ptr is not NULL, the returned value MUST be released by calling c2pa_free
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
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
    let c2pa_signer = deref_mut_or_return_int!(signer_ptr, C2paSigner);
    let data_hash_json = cstr_or_return_int!(data_hash);
    let format = cstr_or_return_int!(format);
    ptr_or_return_int!(manifest_bytes_ptr);

    let mut data_hash: DataHash = ok_or_return_int!(serde_json::from_str(&data_hash_json)
        .map_err(|e| Error::from_c2pa_error(c2pa::Error::JsonError(e))));

    if !asset.is_null() {
        // calc hashes from the asset stream
        ok_or_return_int!(data_hash
            .gen_hash_from_stream(&mut *asset)
            .map_err(Error::from_c2pa_error));
    }

    let result =
        builder.sign_data_hashed_embeddable(c2pa_signer.signer.as_ref(), &data_hash, &format);

    let manifest_bytes = ok_or_return_int!(result);
    let len = manifest_bytes.len() as i64;
    if !manifest_bytes_ptr.is_null() {
        *manifest_bytes_ptr = to_c_bytes(manifest_bytes);
    }
    len
}

/// Returns whether a placeholder manifest is required for the given format.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * format: pointer to a C string with the mime type or extension.
///
/// # Returns
/// Returns 1 if a placeholder is required, 0 if not, or -1 on error.
/// Use [`c2pa_error`] to retrieve the error message when -1 is returned.
///
/// # Safety
/// Reads from NULL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_needs_placeholder(
    builder_ptr: *mut C2paBuilder,
    format: *const c_char,
) -> c_int {
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
    let format = cstr_or_return_int!(format);
    if builder.needs_placeholder(&format) {
        1
    } else {
        0
    }
}

/// Returns the hash binding type that the builder will use for the given format.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * format: pointer to a C string with the MIME type or extension.
/// * out_hash_type: pointer to a C2paHashType that receives the result on success.
///
/// # Returns
/// 0 on success, -1 on error (null pointer or invalid string).
///
/// # Safety
/// Reads from NULL-terminated C strings. Writes to `out_hash_type` only on success.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_hash_type(
    builder_ptr: *mut C2paBuilder,
    format: *const c_char,
    out_hash_type: *mut C2paHashType,
) -> c_int {
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
    let format = cstr_or_return_int!(format);
    if out_hash_type.is_null() {
        return -1;
    }
    let hash_type = match builder.hash_type(&format) {
        c2pa::HashType::Data => C2paHashType::DataHash,
        c2pa::HashType::Bmff => C2paHashType::BmffHash,
        c2pa::HashType::Box => C2paHashType::BoxHash,
    };
    *out_hash_type = hash_type;
    0
}

/// Creates a composed placeholder manifest from a Builder.
///
/// The placeholder is a format-specific (e.g. C2PA UUID box for MP4, APP11 for JPEG)
/// byte sequence that can be embedded directly into an asset to reserve space for the
/// final signed manifest.  The placeholder JUMBF length is stored internally in the
/// Builder so that [`c2pa_builder_sign_embeddable`] returns bytes of the identical size.
///
/// The signer (including its reserve size) is obtained from the Builder's Context.
/// For BMFF assets, if `core.merkle_tree_chunk_size_in_kb` is set in the Context settings,
/// the placeholder will include pre-allocated Merkle map slots for up to 4 mdat boxes.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * format: pointer to a C string with the mime type or extension.
/// * manifest_bytes_ptr: pointer to a pointer to a c_uchar to return the composed placeholder bytes.
/// * (the pointer may be NULL if the caller does not want to receive the bytes)
///
/// # Errors
/// Returns -1 on error (call c2pa_error() for the message).
/// On success, returns the byte length of the composed placeholder.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The returned bytes MUST be released by calling c2pa_free.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_placeholder(
    builder_ptr: *mut C2paBuilder,
    format: *const c_char,
    manifest_bytes_ptr: *mut *const c_uchar,
) -> i64 {
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
    let format = cstr_or_return_int!(format);
    let result = builder.placeholder(&format);
    let manifest_bytes = ok_or_return_int!(result);
    let len = manifest_bytes.len() as i64;
    if !manifest_bytes_ptr.is_null() {
        *manifest_bytes_ptr = to_c_bytes(manifest_bytes);
    }
    len
}

/// Signs the manifest and returns composed bytes ready for embedding.
///
/// Operates in two modes:
///
/// **Placeholder mode** (after calling [`c2pa_builder_placeholder`]): The Builder knows
/// the pre-committed size of the composed placeholder.  The returned bytes are
/// zero-padded to be exactly the same size, enabling in-place patching of the asset.
///
/// **Direct mode** (no placeholder): The Builder must already contain a valid hard
/// binding assertion (DataHash, BmffHash, or BoxHash with a real hash value), set
/// either by [`c2pa_builder_update_hash_from_stream`] or directly via the assertion
/// API.  The returned bytes reflect the actual manifest size.
///
/// The signer is obtained from the Builder's Context.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * format: pointer to a C string with the mime type or extension.
/// * manifest_bytes_ptr: pointer to a pointer to a c_uchar to return the signed manifest bytes.
///
/// # Errors
/// Returns -1 on error (call c2pa_error() for the message).
/// In direct mode, also returns -1 if no valid hard binding assertion exists.
/// On success, returns the byte length of the signed manifest.
///
/// # Safety
/// Reads from NULL-terminated C strings.
/// The returned bytes MUST be released by calling c2pa_free.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_sign_embeddable(
    builder_ptr: *mut C2paBuilder,
    format: *const c_char,
    manifest_bytes_ptr: *mut *const c_uchar,
) -> i64 {
    ptr_or_return_int!(manifest_bytes_ptr);
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
    let format = cstr_or_return_int!(format);
    let result = builder.sign_embeddable(&format);
    let manifest_bytes = ok_or_return_int!(result);
    let len = manifest_bytes.len() as i64;
    if !manifest_bytes_ptr.is_null() {
        *manifest_bytes_ptr = to_c_bytes(manifest_bytes);
    }
    len
}

/// Sets the byte exclusion ranges on the DataHash assertion in a Builder.
///
/// Call this after [`c2pa_builder_placeholder`] to register the exact byte region
/// where the composed placeholder was embedded in the asset.  This step is required
/// before [`c2pa_builder_update_hash_from_stream`] so the hash covers all asset bytes
/// except the manifest slot.
///
/// Exclusions are provided as a flat array of `(start, length)` pairs, each a `uint64_t`.
/// The layout is: `[start0, length0, start1, length1, …]`, so `exclusions_ptr` must
/// point to `exclusion_count * 2` consecutive `uint64_t` values.
///
/// The existing DataHash's name and algorithm are preserved; only its exclusion list
/// is replaced.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder (must have called [`c2pa_builder_placeholder`] first).
/// * exclusions_ptr: pointer to a flat array of `(start, length)` uint64_t pairs.
/// * exclusion_count: number of exclusion ranges (not the number of uint64_t values).
///
/// # Errors
/// Returns 0 on success, -1 on error (call c2pa_error() for the message).
/// Fails if no DataHash assertion exists on the Builder.
///
/// # Safety
/// `exclusions_ptr` must point to at least `exclusion_count * 2` valid `uint64_t` values.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_set_data_hash_exclusions(
    builder_ptr: *mut C2paBuilder,
    exclusions_ptr: *const u64,
    exclusion_count: usize,
) -> c_int {
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);

    if exclusion_count == 0 || exclusions_ptr.is_null() {
        ok_or_return_int!(builder.set_data_hash_exclusions(vec![]));
        return 0;
    }

    let flat = std::slice::from_raw_parts(exclusions_ptr, exclusion_count * 2);
    let exclusions: Vec<c2pa::HashRange> = flat
        .chunks_exact(2)
        .map(|pair| c2pa::HashRange::new(pair[0], pair[1]))
        .collect();

    ok_or_return_int!(builder.set_data_hash_exclusions(exclusions));
    0
}

/// If set the hasher will hash fixed size chunks of data, padding the final block as needed.
/// This will produce a Merkle tree for each mdat with fixed size leaves, which can be used
/// for efficient hashing of large assets.
///
/// #Parameters
/// * builder_ptr: pointer to a Builder (must have called [`c2pa_builder_placeholder`] first).
/// * fixed_size_kb: length of fixed size blocks. The units are KB.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns 0.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// builder_ptr must not be NULL.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_set_fixed_size_merkle(
    builder_ptr: *mut C2paBuilder,
    fixed_size_kb: usize,
) -> c_int {
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);

    builder.set_bmff_hash_fixed_leaf_size(fixed_size_kb);

    0
}

/// Generate the mdat leaf hashes for the asset, the C2paHasher will accumulate the hash values for
/// each mdat_id.  The data_ptr should be supplied in the order the chunks are written to the mdat.
/// The mdat_id should be begin with 0 and increment for each mdat in the asset.  For assets with a s
/// ingle mdat, the mdat_id should be 0.  If fixed size Merkle is enabled, the data will be accumulated
/// and hashed in fixed size chunks and the final chunk will be padded.  Otherwise the data will be hashed
/// as a single leaf for each mdat chunk supplied to this call.
///
/// #Parameters
/// * builder_ptr: pointer to the C2paBuilder.
/// * mdat_id:  specifies which mdat this hash leaf belongs.
/// * data_ptr: pointer to data to hash.
/// * data_len: length of data to hash.
///
/// # Errors
/// Returns -1 if there were errors, otherwise returns 0.
/// The error string can be retrieved by calling c2pa_error.
///
/// # Safety
/// builder_ptr must not be NULL..
///
/// # Example
/// ```c
///  auto data = std::vector<std::uint8_t> buffer(1024);
///
///  c2pa_builder_hash_mdat_bytes(builder, 1, (const uint8_t*)data.data(), 1024, true);
/// ```
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_hash_mdat_bytes(
    builder_ptr: *mut C2paBuilder,
    mdat_id: usize,
    data_ptr: *const c_uchar,
    data_len: usize,
    large_size: bool,
) -> c_int {
    ptr_or_return_int!(data_ptr);
    ptr_or_return_int!(builder_ptr);

    let data = bytes_or_return_int!(data_ptr, data_len, "mdat_data");

    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);

    // save to hasher to build Merkle trees during final save
    ok_or_return_int!(builder.hash_bmff_mdat_bytes(mdat_id, data, large_size));
    0
}

/// Updates the hard binding assertion in a Builder by hashing an asset stream.
///
/// Automatically detects the type of hard binding on the Builder:
/// - **BmffHash**: uses the assertion's own path-based exclusions (UUID box, mdat when
///   Merkle hashing is enabled). The hash algorithm is read from the assertion itself.
/// - **BoxHash**: uses the format's box-hash handler to enumerate chunks, hashes each
///   one individually, and stores the result.  Triggered when a BoxHash assertion is
///   already present or when `builder.prefer_box_hash` is enabled and the format
///   supports it.
/// - **DataHash**: reads any exclusion ranges already on the existing DataHash assertion,
///   hashes the stream excluding those ranges, and stores the result.  If no DataHash
///   exists, creates one with no exclusions (hashes the entire stream — sidecar case).
///
/// The hash algorithm is resolved in this order:
/// 1. The `alg` field of the existing hard binding assertion
/// 2. The `alg` field on the ManifestDefinition (set via JSON or builder settings)
/// 3. `"sha256"` (the C2PA default)
///
/// For DataHash workflows, call [`c2pa_builder_set_data_hash_exclusions`] before this
/// function to register where the composed placeholder was embedded.
///
/// # Parameters
/// * builder_ptr: pointer to a Builder.
/// * format: MIME type or file extension of the asset (e.g. `"image/jpeg"`).
/// * stream: pointer to a C2paStream of the asset to hash.
///
/// # Errors
/// Returns 0 on success, -1 on error (call c2pa_error() for the message).
///
/// # Safety
/// The stream must remain valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn c2pa_builder_update_hash_from_stream(
    builder_ptr: *mut C2paBuilder,
    format: *const c_char,
    stream: *mut C2paStream,
) -> c_int {
    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
    let format = cstr_or_return_int!(format);
    let stream = deref_mut_or_return_int!(stream, C2paStream);
    ok_or_return_int!(builder.update_hash_from_stream(&format, &mut *stream));
    0
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
/// The returned value MUST be released by calling c2pa_free
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

    let bytes = bytes_or_return_int!(
        manifest_bytes_ptr,
        manifest_bytes_size,
        "manifest_bytes_ptr"
    );

    let result = c2pa::Builder::composed_manifest(bytes, &format);
    let result_bytes = ok_or_return_int!(result);
    let len = result_bytes.len() as i64;
    if !result_bytes_ptr.is_null() {
        *result_bytes_ptr = to_c_bytes(result_bytes);
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
/// The returned value MUST be released by calling c2pa_free
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
    let tsa_url = cstr_option!(tsa_url);
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
    box_tracked!(C2paSigner {
        signer: Box::new(signer),
    })
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
/// The returned value MUST be released by calling c2pa_free
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
        ta_url: cstr_option!(signer_info.ta_url),
    };

    let signer = signer_info.signer();
    match signer {
        Ok(signer) => box_tracked!(C2paSigner {
            signer: Box::new(signer),
        }),
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
/// The returned value MUST be released by calling c2pa_free
/// and it is no longer valid after that call.
#[no_mangle]
#[deprecated(
    note = "Use c2pa_context_builder_set_signer() to configure a signer on a context instead."
)]
pub unsafe extern "C" fn c2pa_signer_from_settings() -> *mut C2paSigner {
    // Legacy C API: reads signer configuration from thread-local settings (set by c2pa_load_settings).
    #[allow(deprecated)]
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
    let c2pa_signer = deref_mut_or_return_int!(signer_ptr, C2paSigner);
    c2pa_signer.signer.reserve_size() as i64
}

/// Frees a C2paSigner allocated by Rust.
///
/// **Note**: This function is maintained for backward compatibility. New code should
/// use [`c2pa_free`] instead, which works for all pointer types.
///
/// # Safety
/// The C2paSigner can only be freed once and is invalid after this call.
#[no_mangle]
#[deprecated(note = "Use c2pa_free() instead, which works for all pointer types.")]
pub unsafe extern "C" fn c2pa_signer_free(signer_ptr: *const C2paSigner) {
    cimpl_free!(signer_ptr);
}

#[no_mangle]
/// Signs a byte array using the Ed25519 algorithm.
/// # Safety
/// The returned value MUST be freed by calling c2pa_free
/// and it is no longer valid after that call.
pub unsafe extern "C" fn c2pa_ed25519_sign(
    bytes: *const c_uchar,
    len: usize,
    private_key: *const c_char,
) -> *const c_uchar {
    let private_key = cstr_or_return_null!(private_key);

    let bytes = bytes_or_return_null!(bytes, len, "bytes");

    let signed_bytes =
        ok_or_return_null!(CallbackSigner::ed25519_sign(bytes, private_key.as_bytes()));

    to_c_bytes(signed_bytes)
}

#[no_mangle]
/// Frees a signature allocated by Rust.
///
/// **Note**: This function is maintained for backward compatibility. New code should
/// use [`c2pa_free`] instead, which works for all pointer types.
///
/// # Safety
/// The signature can only be freed once and is invalid after this call.
#[deprecated(note = "Use c2pa_free() instead, which works for all pointer types.")]
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
#[allow(deprecated)]
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
        if reader.is_null() {
            if let Some(msg) = CimplError::last_message() {
                panic!("Reader creation failed: {}", msg);
            }
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
    #[cfg(feature = "file_io")]
    fn test_c2pa_sign_file_success() {
        use std::{fs, path::PathBuf};

        // Setup paths
        let base = env!("CARGO_MANIFEST_DIR");
        let source = format!("{base}/../sdk/tests/fixtures/IMG_0003.jpg");
        let temp_dir = PathBuf::from(base).join("../target/tmp");
        fs::create_dir_all(&temp_dir).unwrap();
        let dest = temp_dir.join("c2pa_sign_file_test_output.jpg");

        let source_path = CString::new(source).unwrap();
        let dest_path = CString::new(dest.to_str().unwrap()).unwrap();
        let manifest = CString::new("{}").unwrap();

        // Setup signer info
        let alg = CString::new("es256").unwrap();
        let cert = CString::new(include_str!(fixture_path!("certs/es256.pub"))).unwrap();
        let key =
            CString::new(include_bytes!(fixture_path!("certs/es256.pem")).as_slice()).unwrap();

        let signer_info = C2paSignerInfo {
            alg: alg.as_ptr(),
            sign_cert: cert.as_ptr(),
            private_key: key.as_ptr(),
            ta_url: std::ptr::null(),
        };

        // Call c2pa_sign_file
        let result = unsafe {
            c2pa_sign_file(
                source_path.as_ptr(),
                dest_path.as_ptr(),
                manifest.as_ptr(),
                &signer_info,
                std::ptr::null(),
            )
        };

        // Verify result is not null and is an empty string
        assert!(
            !result.is_null(),
            "c2pa_sign_file should return non-null on success"
        );
        let result_str = unsafe { CString::from_raw(result) };
        assert_eq!(
            result_str.to_str().unwrap(),
            "",
            "c2pa_sign_file should return empty string on success"
        );

        // Verify the output file was created and has content
        assert!(dest.exists(), "Output file should exist");
        let metadata = fs::metadata(&dest).unwrap();
        assert!(metadata.len() > 0, "Output file should have content");

        // Clean up
        fs::remove_file(dest).ok();
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
        unsafe { c2pa_reader_free(result) };
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
        unsafe { c2pa_reader_free(result) };
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
        unsafe { c2pa_reader_free(reader) };
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

        // Verify consumed reader is no longer tracked
        let free_result = unsafe { c2pa_free(reader as *const c_void) };
        assert_eq!(free_result, -1);

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
        };
    }

    #[test]
    fn test_c2pa_reader_with_manifest_data_and_stream() {
        // Sign an image to get manifest bytes
        let source_image = include_bytes!(fixture_path!("IMG_0003.jpg"));
        let mut source_stream = TestStream::new(source_image.to_vec());
        let mut dest_stream = TestStream::new(Vec::new());

        let (signer, builder) = setup_signer_and_builder_for_signing_tests();

        let format = CString::new("image/jpeg").unwrap();
        let mut manifest_bytes_ptr = std::ptr::null();

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
        assert!(result > 0, "Signing should succeed");
        assert!(
            !manifest_bytes_ptr.is_null(),
            "Manifest bytes should be returned"
        );
        let manifest_size = result as usize;

        // Create a context and reader from it
        let context = unsafe { c2pa_context_new() };
        assert!(!context.is_null());

        let reader = unsafe { c2pa_reader_from_context(context) };
        assert!(!reader.is_null());

        // Consume the reader with manifest data and stream
        let mut validation_stream = TestStream::new(source_image.to_vec());
        let configured_reader = unsafe {
            c2pa_reader_with_manifest_data_and_stream(
                reader,
                format.as_ptr(),
                validation_stream.as_ptr(),
                manifest_bytes_ptr,
                manifest_size,
            )
        };
        assert!(
            !configured_reader.is_null(),
            "Reader should be configured with manifest data and stream"
        );

        // Verify the original reader was consumed
        let free_result = unsafe { c2pa_free(reader as *const c_void) };
        assert_eq!(free_result, -1);

        // Verify we can read the manifest
        let json = unsafe { c2pa_reader_json(configured_reader) };
        assert!(!json.is_null(), "Should be able to get JSON from reader");

        unsafe {
            c2pa_free(json as *const c_void);
            c2pa_free(configured_reader as *const c_void);
            c2pa_free(manifest_bytes_ptr as *const c_void);
            c2pa_free(builder as *const c_void);
            c2pa_free(signer as *const c_void);
            c2pa_free(context as *const c_void);
        }
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
    fn test_c2pa_builder_add_ingredient_from_archive_null_stream() {
        let manifest_def = CString::new("{}").unwrap();
        let builder = unsafe { c2pa_builder_from_json(manifest_def.as_ptr()) };
        assert!(!builder.is_null());
        let result =
            unsafe { c2pa_builder_add_ingredient_from_archive(builder, std::ptr::null_mut()) };
        assert_eq!(result, -1);
        let error = unsafe { c2pa_error() };
        let error_str = unsafe { CString::from_raw(error) };
        assert_eq!(error_str.to_str().unwrap(), "NullParameter: stream");
        unsafe { c2pa_builder_free(builder) };
    }

    #[test]
    fn test_c2pa_builder_add_ingredient_from_archive_null_builder() {
        let archive_bytes = include_bytes!(fixture_path!("cloud.jpg"));
        let mut stream = TestStream::new(archive_bytes.to_vec());
        let result = unsafe {
            c2pa_builder_add_ingredient_from_archive(std::ptr::null_mut(), stream.as_ptr())
        };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_c2pa_builder_write_ingredient_archive_null_stream() {
        let manifest_def = CString::new("{}").unwrap();
        let builder = unsafe { c2pa_builder_from_json(manifest_def.as_ptr()) };
        assert!(!builder.is_null());
        let ingredient_id = CString::new("test-ingredient").unwrap();
        let result = unsafe {
            c2pa_builder_write_ingredient_archive(
                builder,
                ingredient_id.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(result, -1);
        let error = unsafe { c2pa_error() };
        let error_str = unsafe { CString::from_raw(error) };
        assert_eq!(error_str.to_str().unwrap(), "NullParameter: stream");
        unsafe { c2pa_builder_free(builder) };
    }

    #[test]
    fn test_c2pa_builder_write_ingredient_archive_null_ingredient_id() {
        let manifest_def = CString::new("{}").unwrap();
        let builder = unsafe { c2pa_builder_from_json(manifest_def.as_ptr()) };
        assert!(!builder.is_null());
        let archive_bytes = vec![0u8; 0];
        let mut stream = TestStream::new(archive_bytes);
        let result = unsafe {
            c2pa_builder_write_ingredient_archive(builder, std::ptr::null(), stream.as_ptr())
        };
        assert_eq!(result, -1);
        let error = unsafe { c2pa_error() };
        let error_str = unsafe { CString::from_raw(error) };
        assert_eq!(error_str.to_str().unwrap(), "NullParameter: ingredient_id");
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
        let mut ptrs = vec![to_c_string("image/jpeg".to_string())];
        let count = ptrs.len();
        let ptr = ptrs.as_mut_ptr() as *const *const c_char;
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
        if reader.is_null() {
            if let Some(msg) = CimplError::last_message() {
                panic!("Reader creation failed: {}", msg);
            }
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
        unsafe { c2pa_reader_free(reader) };
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

        // Verify consumed builder is no longer tracked
        let free_result = unsafe { c2pa_free(builder as *const c_void) };
        assert_eq!(free_result, -1);

        unsafe {
            c2pa_free(settings as *mut c_void);
            c2pa_free(context as *mut c_void);
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

    #[test]
    fn test_c2pa_reader_detailed_json() {
        use std::ffi::CStr;

        let source_image = include_bytes!(fixture_path!("C.jpg"));
        let mut stream = TestStream::new(source_image.to_vec());
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), stream.as_ptr()) };
        assert!(!reader.is_null());

        // Get detailed JSON
        let detailed_json = unsafe { c2pa_reader_detailed_json(reader) };
        assert!(!detailed_json.is_null());

        // Verify it's valid JSON and non-empty
        let json_str = unsafe { CStr::from_ptr(detailed_json).to_str().unwrap() };
        assert!(!json_str.is_empty(), "Detailed JSON should not be empty");

        let json_value: serde_json::Value = serde_json::from_str(json_str).unwrap();
        // Just verify it's a valid JSON object
        assert!(json_value.is_object(), "Detailed JSON should be an object");

        unsafe {
            c2pa_free(detailed_json as *mut c_void);
            c2pa_free(reader as *mut c_void);
        }
    }

    #[test]
    fn test_c2pa_reader_is_embedded() {
        // Test with embedded manifest
        let source_image = include_bytes!(fixture_path!("C.jpg"));
        let mut stream = TestStream::new(source_image.to_vec());
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), stream.as_ptr()) };
        assert!(!reader.is_null());

        // Just test that the function executes without crashing
        // The actual return value depends on the manifest structure
        let _is_embedded = unsafe { c2pa_reader_is_embedded(reader) };

        // Function should not crash - that's the main test
        unsafe {
            c2pa_free(reader as *mut c_void);
        }
    }

    #[test]
    fn test_c2pa_builder_from_context() {
        // Create a custom context
        let context = unsafe { c2pa_context_new() };
        assert!(!context.is_null());

        // Create builder from context
        let builder = unsafe { c2pa_builder_from_context(context) };
        assert!(!builder.is_null());

        // Verify builder can be used
        let manifest_json = CString::new(r#"{"claim_generator": "test"}"#).unwrap();
        let builder = unsafe { c2pa_builder_with_definition(builder, manifest_json.as_ptr()) };
        assert!(!builder.is_null());

        unsafe {
            c2pa_free(builder as *mut c_void);
            c2pa_free(context as *mut c_void);
        }
    }

    #[test]
    fn test_c2pa_format_embeddable() {
        // This function requires manifest bytes, which is complex to set up.
        // For now, test with minimal setup to verify it doesn't crash
        let jpeg_format = CString::new("image/jpeg").unwrap();
        let placeholder_bytes = b"placeholder";
        let mut result_ptr: *const c_uchar = std::ptr::null();

        let _result = unsafe {
            c2pa_format_embeddable(
                jpeg_format.as_ptr(),
                placeholder_bytes.as_ptr(),
                placeholder_bytes.len(),
                &mut result_ptr,
            )
        };

        // Function should execute without crashing - that's the main test
        // The result value depends on whether the placeholder is valid
        if !result_ptr.is_null() {
            unsafe { c2pa_free(result_ptr as *const c_void) };
        }
    }

    #[test]
    fn test_c2pa_builder_add_ingredient_from_stream() {
        let manifest_def = CString::new("{}").unwrap();
        let builder = unsafe { c2pa_builder_from_json(manifest_def.as_ptr()) };
        assert!(!builder.is_null());

        // Create ingredient stream
        let ingredient_image = include_bytes!(fixture_path!("C.jpg"));
        let mut ingredient_stream = TestStream::new(ingredient_image.to_vec());

        let ingredient_json = CString::new(r#"{"title": "Test Ingredient"}"#).unwrap();
        let format = CString::new("image/jpeg").unwrap();

        // Add ingredient - note the correct parameter order
        let result = unsafe {
            c2pa_builder_add_ingredient_from_stream(
                builder,
                ingredient_json.as_ptr(),
                format.as_ptr(),
                ingredient_stream.as_ptr(),
            )
        };
        assert_eq!(result, 0, "Should successfully add ingredient");

        unsafe {
            c2pa_free(builder as *mut c_void);
        }
    }

    #[test]
    fn test_c2pa_builder_with_definition() {
        // Create initial builder
        let manifest_def = CString::new("{}").unwrap();
        let builder = unsafe { c2pa_builder_from_json(manifest_def.as_ptr()) };
        assert!(!builder.is_null());

        // Add definition to builder (this consumes the builder and returns a new one)
        let new_manifest = CString::new(r#"{"claim_generator": "test_with_definition"}"#).unwrap();
        let new_builder = unsafe { c2pa_builder_with_definition(builder, new_manifest.as_ptr()) };
        assert!(!new_builder.is_null(), "Should return new builder");

        // Verify consumed builder is no longer tracked
        let free_result = unsafe { c2pa_free(builder as *const c_void) };
        assert_eq!(free_result, -1);

        unsafe {
            c2pa_free(new_builder as *mut c_void);
        }
    }

    #[test]
    fn test_c2pa_builder_with_definition_null_json() {
        // Create initial builder
        let manifest_def = CString::new("{}").unwrap();
        let builder = unsafe { c2pa_builder_from_json(manifest_def.as_ptr()) };
        assert!(!builder.is_null());

        // Test with null JSON: returns null, but the builder is not consumed!
        let new_builder = unsafe { c2pa_builder_with_definition(builder, std::ptr::null()) };
        assert!(
            new_builder.is_null(),
            "Should return null for invalid input"
        );

        // Builder is still tracked because validation failed before consumption
        let free_result = unsafe { c2pa_free(builder as *mut c_void) };
        assert_eq!(free_result, 0);
    }

    #[test]
    fn test_c2pa_builder_with_archive() {
        // Create initial builder
        let manifest_def = CString::new("{}").unwrap();
        let builder = unsafe { c2pa_builder_from_json(manifest_def.as_ptr()) };
        assert!(!builder.is_null());

        // Create archive stream (using a simple image as placeholder)
        let archive_bytes = include_bytes!(fixture_path!("C.jpg"));
        let mut archive_stream = TestStream::new(archive_bytes.to_vec());

        // Add archive to builder (this consumes the builder and returns a new one)
        let new_builder = unsafe { c2pa_builder_with_archive(builder, archive_stream.as_ptr()) };

        // Verify consumed builder is no longer tracked
        let free_result = unsafe { c2pa_free(builder as *const c_void) };
        assert_eq!(free_result, -1);

        if !new_builder.is_null() {
            unsafe {
                c2pa_free(new_builder as *mut c_void);
            }
        }
    }

    #[test]
    fn test_c2pa_builder_with_archive_null_stream() {
        // Create initial builder
        let manifest_def = CString::new("{}").unwrap();
        let builder = unsafe { c2pa_builder_from_json(manifest_def.as_ptr()) };
        assert!(!builder.is_null());

        // Test with null stream: returns null, but the builder is NOT consumed
        let new_builder = unsafe { c2pa_builder_with_archive(builder, std::ptr::null_mut()) };
        assert!(
            new_builder.is_null(),
            "Should return null for invalid stream"
        );

        // Builder is still tracked because validation failed before consumption
        let free_result = unsafe { c2pa_free(builder as *mut c_void) };
        assert_eq!(free_result, 0);
    }

    #[test]
    fn test_c2pa_reader_with_fragment() {
        // Create initial reader
        let source_image = include_bytes!(fixture_path!("C.jpg"));
        let mut stream = TestStream::new(source_image.to_vec());
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), stream.as_ptr()) };
        assert!(!reader.is_null());

        // Create fragment stream
        let fragment_bytes = include_bytes!(fixture_path!("C.jpg"));
        let mut fragment_stream = TestStream::new(fragment_bytes.to_vec());
        let mut main_stream = TestStream::new(source_image.to_vec());

        // Add fragment to reader (this consumes the reader and returns a new one)
        let new_reader = unsafe {
            c2pa_reader_with_fragment(
                reader,
                format.as_ptr(),
                main_stream.as_ptr(),
                fragment_stream.as_ptr(),
            )
        };

        // Verify consumed reader is no longer tracked
        let free_result = unsafe { c2pa_free(reader as *const c_void) };
        assert_eq!(free_result, -1);

        if !new_reader.is_null() {
            unsafe {
                c2pa_free(new_reader as *mut c_void);
            }
        }
    }

    #[test]
    fn test_c2pa_reader_with_fragment_null_format() {
        // Create initial reader
        let source_image = include_bytes!(fixture_path!("C.jpg"));
        let mut stream = TestStream::new(source_image.to_vec());
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), stream.as_ptr()) };
        assert!(!reader.is_null());

        let mut fragment_stream = TestStream::new(source_image.to_vec());
        let mut main_stream = TestStream::new(source_image.to_vec());

        // Test with null format: returns null, but the reader is NOT consumed
        let new_reader = unsafe {
            c2pa_reader_with_fragment(
                reader,
                std::ptr::null(),
                main_stream.as_ptr(),
                fragment_stream.as_ptr(),
            )
        };
        assert!(
            new_reader.is_null(),
            "Should return null for invalid format"
        );

        // Reader is still tracked because validation failed before consumption
        let free_result = unsafe { c2pa_free(reader as *const c_void) };
        assert_eq!(free_result, 0);
    }

    // ========== High-Value Coverage Tests ==========

    #[test]
    fn test_c2pa_reader_new() {
        let reader = unsafe { c2pa_reader_new() };
        assert!(!reader.is_null(), "Should create a default reader");

        unsafe {
            c2pa_free(reader as *mut c_void);
        }
    }

    #[test]
    fn test_c2pa_reader_is_embedded_null() {
        // Test null pointer - should return false via deref_or_return_false!
        let result = unsafe { c2pa_reader_is_embedded(std::ptr::null_mut()) };
        assert!(!result, "Null reader should return false");
    }

    #[test]
    fn test_c2pa_reader_remote_url_null() {
        // Test null pointer - should return null
        let result = unsafe { c2pa_reader_remote_url(std::ptr::null_mut()) };
        assert!(result.is_null(), "Null reader should return null URL");
    }

    #[test]
    fn test_c2pa_builder_set_intent_null() {
        // Test null pointer - should return error
        let result = unsafe {
            c2pa_builder_set_intent(
                std::ptr::null_mut(),
                C2paBuilderIntent::Create,
                C2paDigitalSourceType::DigitalCapture,
            )
        };
        assert_eq!(result, -1, "Null builder should return -1");
    }

    #[test]
    fn test_c2pa_builder_add_action_null_builder() {
        let action = CString::new(r#"{"action": "c2pa.edited"}"#).unwrap();
        let result = unsafe { c2pa_builder_add_action(std::ptr::null_mut(), action.as_ptr()) };
        assert_eq!(result, -1, "Null builder should return error");
    }

    #[test]
    fn test_c2pa_builder_add_action_null_action() {
        let manifest_def = CString::new("{}").unwrap();
        let builder = unsafe { c2pa_builder_from_json(manifest_def.as_ptr()) };
        assert!(!builder.is_null());

        let result = unsafe { c2pa_builder_add_action(builder, std::ptr::null()) };
        assert_eq!(result, -1, "Null action should return error");

        unsafe {
            c2pa_free(builder as *mut c_void);
        }
    }

    #[test]
    fn test_c2pa_context_builder_set_settings_null_settings() {
        let builder = unsafe { c2pa_context_builder_new() };
        assert!(!builder.is_null());

        // Test with null settings pointer
        let result = unsafe { c2pa_context_builder_set_settings(builder, std::ptr::null_mut()) };
        assert_eq!(result, -1, "Null settings should return -1");

        unsafe {
            c2pa_free(builder as *mut c_void);
        }
    }

    #[test]
    fn test_c2pa_signer_reserve_size() {
        let (signer, builder) = setup_signer_and_builder_for_signing_tests();

        let size = unsafe { c2pa_signer_reserve_size(signer) };
        assert!(size > 0, "Reserve size should be positive");

        unsafe {
            c2pa_free(signer as *mut c_void);
            c2pa_free(builder as *mut c_void);
        }
    }

    #[test]
    fn test_c2pa_signer_reserve_size_null() {
        let size = unsafe { c2pa_signer_reserve_size(std::ptr::null_mut()) };
        assert_eq!(size, -1, "Null signer should return -1");
    }

    #[test]
    fn test_c2pa_string_free_backward_compat() {
        // Test that string_free works for backward compatibility
        let test_str = CString::new("test string").unwrap();
        let c_str = to_c_string(test_str.to_str().unwrap().to_string());
        assert!(!c_str.is_null());

        // Should not crash
        unsafe {
            c2pa_string_free(c_str);
        }
    }

    #[test]
    fn test_c2pa_string_free_null() {
        // Should handle null gracefully
        unsafe {
            c2pa_string_free(std::ptr::null_mut());
        }
        // If we get here, it handled null without crashing
    }

    #[test]
    fn test_c2pa_release_string() {
        // Test the deprecated c2pa_release_string function
        let test_str = CString::new("test string for release").unwrap();
        let c_str = to_c_string(test_str.to_str().unwrap().to_string());
        assert!(!c_str.is_null());

        // Should not crash
        unsafe {
            c2pa_release_string(c_str);
        }
    }

    #[test]
    fn test_c2pa_ed25519_sign_actually_calls_function() {
        // Fix: The existing test_ed25519_sign doesn't call c2pa_ed25519_sign!
        let bytes = b"test data to sign";
        let private_key_pem = include_bytes!(fixture_path!("certs/ed25519.pem"));
        let private_key = CString::new(private_key_pem.as_slice()).unwrap();

        let signature =
            unsafe { c2pa_ed25519_sign(bytes.as_ptr(), bytes.len(), private_key.as_ptr()) };

        assert!(!signature.is_null(), "Should return signature");

        unsafe {
            c2pa_signature_free(signature);
        }
    }

    #[test]
    fn test_c2pa_ed25519_sign_null_bytes() {
        let private_key_path = CString::new(fixture_path!("certs/ed25519.pem")).unwrap();

        let signature =
            unsafe { c2pa_ed25519_sign(std::ptr::null(), 10, private_key_path.as_ptr()) };

        assert!(signature.is_null(), "Null bytes should return null");
    }

    #[test]
    fn test_c2pa_ed25519_sign_null_key() {
        let bytes = b"test data";

        let signature = unsafe { c2pa_ed25519_sign(bytes.as_ptr(), bytes.len(), std::ptr::null()) };

        assert!(signature.is_null(), "Null key should return null");

        // Verify error was set
        let error = unsafe { c2pa_error() };
        assert!(!error.is_null());
        unsafe {
            c2pa_string_free(error);
        }
    }

    #[test]
    fn test_c2pa_reader_detailed_json_null() {
        let result = unsafe { c2pa_reader_detailed_json(std::ptr::null_mut()) };
        assert!(result.is_null(), "Null reader should return null");
    }

    #[test]
    fn test_c2pa_reader_json_better_coverage() {
        // The existing test only tests null, let's test with valid reader
        let source_image = include_bytes!(fixture_path!("C.jpg"));
        let mut stream = TestStream::new(source_image.to_vec());
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), stream.as_ptr()) };
        assert!(!reader.is_null());

        let json = unsafe { c2pa_reader_json(reader) };
        assert!(!json.is_null(), "Should return JSON");

        // Verify it's valid JSON
        use std::ffi::CStr;
        let json_str = unsafe { CStr::from_ptr(json).to_str().unwrap() };
        assert!(!json_str.is_empty());
        let _: serde_json::Value = serde_json::from_str(json_str).unwrap();

        unsafe {
            c2pa_free(json as *mut c_void);
            c2pa_free(reader as *mut c_void);
        }
    }

    #[test]
    fn test_c2pa_error_set_last() {
        let error_msg = CString::new("Custom error message").unwrap();
        let result = unsafe { c2pa_error_set_last(error_msg.as_ptr()) };
        assert_eq!(result, 0, "c2pa_error_set_last should return 0 on success");

        // Verify the error was set
        let error = unsafe { c2pa_error() };
        assert!(
            !error.is_null(),
            "Error should be retrievable after set_last"
        );
        let error_str = unsafe { CString::from_raw(error) };
        // Error messages are prefixed with "Other: "
        assert_eq!(
            error_str.to_str().unwrap(),
            "Other: Custom error message",
            "Error message should match what was set"
        );
    }

    #[test]
    fn test_c2pa_error_set_last_null() {
        let result = unsafe { c2pa_error_set_last(std::ptr::null()) };
        assert_eq!(
            result, -1,
            "c2pa_error_set_last should return -1 for null parameter"
        );
    }

    #[test]
    fn test_c2pa_reader_from_manifest_data_and_stream() {
        // First, create a signed image to get manifest bytes
        let source_image = include_bytes!(fixture_path!("IMG_0003.jpg"));
        let mut source_stream = TestStream::new(source_image.to_vec());
        let dest_vec = Vec::new();
        let mut dest_stream = TestStream::new(dest_vec);

        let (signer, builder) = setup_signer_and_builder_for_signing_tests();

        let format = CString::new("image/jpeg").unwrap();
        let mut manifest_bytes_ptr = std::ptr::null();

        // Sign to get manifest bytes
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
        assert!(result > 0, "Signing should succeed");
        assert!(
            !manifest_bytes_ptr.is_null(),
            "Manifest bytes should be returned"
        );

        let manifest_size = result as usize;

        // Now test c2pa_reader_from_manifest_data_and_stream
        // Reset the source stream for validation
        let mut validation_stream = TestStream::new(source_image.to_vec());

        let reader = unsafe {
            c2pa_reader_from_manifest_data_and_stream(
                format.as_ptr(),
                validation_stream.as_ptr(),
                manifest_bytes_ptr,
                manifest_size,
            )
        };

        assert!(
            !reader.is_null(),
            "Reader should be created from manifest data and stream"
        );

        // Verify we can get JSON from the reader
        let json = unsafe { c2pa_reader_json(reader) };
        assert!(!json.is_null(), "Should be able to get JSON from reader");

        // Clean up
        unsafe {
            c2pa_free(json as *const c_void);
            c2pa_free(reader as *const c_void);
            c2pa_free(manifest_bytes_ptr as *const c_void);
            c2pa_free(builder as *const c_void);
            c2pa_free(signer as *const c_void);
        }
    }

    #[test]
    fn test_c2pa_reader_from_manifest_data_and_stream_null_format() {
        let source_image = include_bytes!(fixture_path!("C.jpg"));
        let mut stream = TestStream::new(source_image.to_vec());
        let manifest_data = [0u8; 100];

        let reader = unsafe {
            c2pa_reader_from_manifest_data_and_stream(
                std::ptr::null(),
                stream.as_ptr(),
                manifest_data.as_ptr(),
                manifest_data.len(),
            )
        };

        assert!(reader.is_null(), "Reader should be null for null format");
        let error = unsafe { c2pa_error() };
        let error_str = unsafe { CString::from_raw(error) };
        assert_eq!(error_str.to_str().unwrap(), "NullParameter: format");
    }

    #[test]
    fn test_c2pa_reader_resource_to_stream() {
        // Use an existing fixture with C2PA data
        let source_image = include_bytes!(fixture_path!("C.jpg"));
        let mut stream = TestStream::new(source_image.to_vec());
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), stream.as_ptr()) };
        assert!(
            !reader.is_null(),
            "Reader should be created from C2PA image"
        );

        // Try to get a resource (use a generic URI pattern)
        let resource_uri =
            CString::new("self#jumbf=c2pa.assertions/c2pa.thumbnail.claim.jpeg").unwrap();
        let mut output_stream = TestStream::new(Vec::new());

        let result = unsafe {
            c2pa_reader_resource_to_stream(reader, resource_uri.as_ptr(), output_stream.as_ptr())
        };

        // Result can be 0 if resource doesn't exist (which is fine)
        // or positive if resource was written. Either is valid.
        assert!(result >= 0, "resource_to_stream should return >= 0");

        // Clean up
        unsafe {
            c2pa_free(reader as *const c_void);
        }
    }

    #[test]
    fn test_c2pa_reader_resource_to_stream_null_reader() {
        let resource_uri = CString::new("some_uri").unwrap();
        let mut output_stream = TestStream::new(Vec::new());

        let result = unsafe {
            c2pa_reader_resource_to_stream(
                std::ptr::null_mut(),
                resource_uri.as_ptr(),
                output_stream.as_ptr(),
            )
        };

        assert_eq!(
            result, -1,
            "resource_to_stream should return -1 for null reader"
        );
        let error = unsafe { c2pa_error() };
        let error_str = unsafe { CString::from_raw(error) };
        assert_eq!(error_str.to_str().unwrap(), "NullParameter: reader_ptr");
    }

    #[test]
    fn test_c2pa_reader_resource_to_stream_null_uri() {
        // Use an existing fixture with C2PA data
        let source_image = include_bytes!(fixture_path!("C.jpg"));
        let mut stream = TestStream::new(source_image.to_vec());
        let format = CString::new("image/jpeg").unwrap();

        let reader = unsafe { c2pa_reader_from_stream(format.as_ptr(), stream.as_ptr()) };
        assert!(!reader.is_null());

        let mut output_stream = TestStream::new(Vec::new());

        let result = unsafe {
            c2pa_reader_resource_to_stream(reader, std::ptr::null(), output_stream.as_ptr())
        };

        assert_eq!(
            result, -1,
            "resource_to_stream should return -1 for null uri"
        );

        // Clean up
        unsafe {
            c2pa_free(reader as *const c_void);
        }
    }

    #[test]

    fn test_data_hash_embeddable_workflow() {
        // Build a context with signer configured via test_settings.json.
        // The settings include a PS256 local signer so sign_embeddable can use it.
        const SETTINGS: &str = include_str!(fixture_path!("test_settings.json"));

        let settings = unsafe { c2pa_settings_new() };
        assert!(!settings.is_null());
        let json_str = CString::new(SETTINGS).unwrap();
        let fmt = CString::new("json").unwrap();
        let result =
            unsafe { c2pa_settings_update_from_string(settings, json_str.as_ptr(), fmt.as_ptr()) };
        assert_eq!(result, 0);

        let ctx_builder = unsafe { c2pa_context_builder_new() };
        assert!(!ctx_builder.is_null());
        let result = unsafe { c2pa_context_builder_set_settings(ctx_builder, settings) };
        assert_eq!(result, 0);
        let context = unsafe { c2pa_context_builder_build(ctx_builder) };
        assert!(!context.is_null());

        // Create a manifest builder from the context.
        let builder = unsafe { c2pa_builder_from_context(context) };
        assert!(!builder.is_null());

        let format = CString::new("image/jpeg").unwrap();
        // needs_placeholder returns 0 or 1 (never -1) for valid builder+format.
        let needs = unsafe { c2pa_builder_needs_placeholder(builder, format.as_ptr()) };
        assert!(needs >= 0, "needs_placeholder should not error");
        assert!(needs <= 1, "needs_placeholder returns 0 or 1");

        // Hash the entire JPEG stream — auto-creates a DataHash (direct mode, no placeholder).
        let source_image = include_bytes!(fixture_path!("IMG_0003.jpg"));
        let mut source_stream = TestStream::new(source_image.to_vec());
        let result = unsafe {
            c2pa_builder_update_hash_from_stream(builder, format.as_ptr(), source_stream.as_ptr())
        };
        assert_eq!(result, 0, "update_hash_from_stream failed");

        // Sign without a placeholder (direct mode) — signer comes from the builder's Context.
        let mut signed_bytes_ptr: *const c_uchar = std::ptr::null();
        let len = unsafe {
            c2pa_builder_sign_embeddable(builder, format.as_ptr(), &mut signed_bytes_ptr)
        };
        assert!(len > 0, "sign_embeddable should return positive length");
        assert!(!signed_bytes_ptr.is_null());

        unsafe {
            c2pa_free(signed_bytes_ptr as *mut c_void);
            c2pa_free(settings as *mut c_void);
            c2pa_free(context as *mut c_void);
            c2pa_free(builder as *mut c_void);
        }
    }

    #[test]

    fn test_bmff_embeddable_workflow_with_mdat_hashes() {
        // Build a context with signer + Merkle chunk size for the external-mdat-hash workflow.
        const SETTINGS: &str = include_str!(fixture_path!("test_settings.json"));

        let settings = unsafe { c2pa_settings_new() };
        assert!(!settings.is_null());
        let json_str = CString::new(SETTINGS).unwrap();
        let fmt = CString::new("json").unwrap();
        let result =
            unsafe { c2pa_settings_update_from_string(settings, json_str.as_ptr(), fmt.as_ptr()) };
        assert_eq!(result, 0);

        let ctx_builder = unsafe { c2pa_context_builder_new() };
        assert!(!ctx_builder.is_null());
        let result = unsafe { c2pa_context_builder_set_settings(ctx_builder, settings) };
        assert_eq!(result, 0);
        let context = unsafe { c2pa_context_builder_build(ctx_builder) };
        assert!(!context.is_null());

        // Create builder from context.
        let builder = unsafe { c2pa_builder_from_context(context) };
        assert!(!builder.is_null());

        let format = CString::new("video/mp4").unwrap();
        // BMFF formats always need a placeholder.
        let needs = unsafe { c2pa_builder_needs_placeholder(builder, format.as_ptr()) };
        assert_eq!(
            needs, 1,
            "needs_placeholder should be 1 for video/mp4 before placeholder"
        );

        // Passing null for manifest_bytes_ptr returns size without error (caller may only need the length).
        let size_only =
            unsafe { c2pa_builder_placeholder(builder, format.as_ptr(), std::ptr::null_mut()) };
        assert!(
            size_only > 0,
            "placeholder with null output should return positive size"
        );
        assert_ne!(
            size_only, -1,
            "placeholder with null output should not error"
        );

        // Create a BMFF placeholder (adds a BmffHash with pre-allocated Merkle slots).
        let mut placeholder_ptr: *const c_uchar = std::ptr::null();
        let placeholder_len =
            unsafe { c2pa_builder_placeholder(builder, format.as_ptr(), &mut placeholder_ptr) };
        assert!(
            placeholder_len > 0,
            "placeholder should return non-empty bytes"
        );
        assert!(!placeholder_ptr.is_null());

        // break the mdat in fixed sized chunks (1kb) in this example
        unsafe {
            c2pa_builder_set_fixed_size_merkle(builder, 1);
        }

        // Supply a single dummy SHA-256 leaf hash for one mdat box (1 chunk).
        // The Merkle leaves is derived from these; the video will not validate but
        // this exercises the full C API call path.
        let leaf_data: [u8; 4096] = [0xab; 4096];
        let result = unsafe {
            c2pa_builder_hash_mdat_bytes(builder, 0, leaf_data.as_ptr(), leaf_data.len(), true)
        };
        assert_eq!(result, 0, "set_bmff_mdat_hashes failed");

        // Hash the video stream (BmffHash uses its own path-based exclusions internally).
        let video = include_bytes!(fixture_path!("video1.mp4"));
        let mut video_stream = TestStream::new(video.to_vec());
        let result = unsafe {
            c2pa_builder_update_hash_from_stream(builder, format.as_ptr(), video_stream.as_ptr())
        };
        assert_eq!(result, 0, "update_hash_from_stream failed");

        // Sign in placeholder mode — signer comes from the builder's Context.
        let mut signed_bytes_ptr: *const c_uchar = std::ptr::null();
        let len = unsafe {
            c2pa_builder_sign_embeddable(builder, format.as_ptr(), &mut signed_bytes_ptr)
        };
        assert!(len > 0, "sign_embeddable should return positive length");
        assert!(!signed_bytes_ptr.is_null());

        unsafe {
            c2pa_free(placeholder_ptr as *mut c_void);
            c2pa_free(signed_bytes_ptr as *mut c_void);
            c2pa_free(settings as *mut c_void);
            c2pa_free(context as *mut c_void);
            c2pa_free(builder as *mut c_void);
        }
    }

    #[test]
    fn test_context_builder_set_signer() {
        let certs = include_str!(fixture_path!("certs/ed25519.pub"));
        let private_key = include_bytes!(fixture_path!("certs/ed25519.pem"));
        let alg = CString::new("Ed25519").unwrap();
        let sign_cert = CString::new(certs).unwrap();
        let private_key = CString::new(private_key.as_slice()).unwrap();
        let signer_info = C2paSignerInfo {
            alg: alg.as_ptr(),
            sign_cert: sign_cert.as_ptr(),
            private_key: private_key.as_ptr(),
            ta_url: std::ptr::null(),
        };
        let signer = unsafe { c2pa_signer_from_info(&signer_info) };
        assert!(!signer.is_null());

        let builder = unsafe { c2pa_context_builder_new() };
        assert!(!builder.is_null());

        let result = unsafe { c2pa_context_builder_set_signer(builder, signer) };
        assert_eq!(result, 0);

        // Verify the signer is consumed: freeing it should fail cleanly (-1)
        let free_result = unsafe { c2pa_free(signer as *const c_void) };
        assert_eq!(free_result, -1);

        let context = unsafe { c2pa_context_builder_build(builder) };
        assert!(!context.is_null());

        let builder = unsafe { c2pa_builder_from_context(context) };
        assert!(!builder.is_null());

        unsafe {
            c2pa_free(builder as *mut c_void);
            c2pa_free(context as *mut c_void);
        }
    }

    #[test]
    fn test_context_builder_set_signer_null() {
        let builder = unsafe { c2pa_context_builder_new() };
        assert!(!builder.is_null());

        let result = unsafe { c2pa_context_builder_set_signer(builder, std::ptr::null_mut()) };
        assert_eq!(result, -1, "Null signer should be rejected");

        unsafe { c2pa_free(builder as *mut c_void) };
    }

    #[test]
    fn test_c2pa_context_builder_set_progress_callback() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let call_count = Arc::new(AtomicU32::new(0));
        let raw_ptr = Arc::as_ptr(&call_count) as *const c_void;

        unsafe extern "C" fn progress_cb(
            context: *const c_void,
            _phase: C2paProgressPhase,
            _step: u32,
            _total: u32,
        ) -> c_int {
            let counter = &*(context as *const AtomicU32);
            counter.fetch_add(1, Ordering::SeqCst);
            1
        }

        let builder = unsafe { c2pa_context_builder_new() };
        assert!(!builder.is_null());

        let result =
            unsafe { c2pa_context_builder_set_progress_callback(builder, raw_ptr, progress_cb) };
        assert_eq!(result, 0, "set_progress_callback should succeed");

        let context = unsafe { c2pa_context_builder_build(builder) };
        assert!(!context.is_null());

        unsafe { c2pa_free(context as *mut c_void) };
        // Arc still alive here so the AtomicU32 is valid throughout.
    }

    #[test]
    fn test_c2pa_context_builder_set_progress_callback_null_user_data() {
        unsafe extern "C" fn progress_cb(
            _context: *const c_void,
            _phase: C2paProgressPhase,
            _step: u32,
            _total: u32,
        ) -> c_int {
            1
        }

        let builder = unsafe { c2pa_context_builder_new() };
        assert!(!builder.is_null());

        let result = unsafe {
            c2pa_context_builder_set_progress_callback(builder, std::ptr::null(), progress_cb)
        };
        assert_eq!(result, 0, "NULL user_data should be accepted");

        let context = unsafe { c2pa_context_builder_build(builder) };
        assert!(!context.is_null());

        unsafe { c2pa_free(context as *mut c_void) };
    }

    #[test]
    fn test_c2pa_context_builder_set_progress_callback_null_builder() {
        unsafe extern "C" fn progress_cb(
            _context: *const c_void,
            _phase: C2paProgressPhase,
            _step: u32,
            _total: u32,
        ) -> c_int {
            1
        }

        let result = unsafe {
            c2pa_context_builder_set_progress_callback(
                std::ptr::null_mut(),
                std::ptr::null(),
                progress_cb,
            )
        };
        assert_eq!(result, -1, "NULL builder should return error");
    }

    #[test]
    fn test_progress_phase_to_c2pa_progress_phase() {
        let cases: &[(ProgressPhase, i32)] = &[
            (ProgressPhase::Reading, 0),
            (ProgressPhase::VerifyingManifest, 1),
            (ProgressPhase::VerifyingSignature, 2),
            (ProgressPhase::VerifyingIngredient, 3),
            (ProgressPhase::VerifyingAssetHash, 4),
            (ProgressPhase::AddingIngredient, 5),
            (ProgressPhase::Thumbnail, 6),
            (ProgressPhase::Hashing, 7),
            (ProgressPhase::Signing, 8),
            (ProgressPhase::Embedding, 9),
            (ProgressPhase::FetchingRemoteManifest, 10),
            (ProgressPhase::Writing, 11),
            (ProgressPhase::FetchingOCSP, 12),
            (ProgressPhase::FetchingTimestamp, 13),
        ];
        for (sdk_phase, expected) in cases {
            let c_phase = C2paProgressPhase::from(sdk_phase.clone());
            assert_eq!(c_phase as i32, *expected, "mismatch for {sdk_phase:?}");
        }
    }

    #[test]
    fn test_c2pa_context_cancel() {
        let context = unsafe { c2pa_context_new() };
        assert!(!context.is_null());

        let result = unsafe { c2pa_context_cancel(context) };
        assert_eq!(result, 0, "cancel should succeed on a valid context");

        unsafe { c2pa_free(context as *mut c_void) };
    }

    #[test]
    fn test_c2pa_context_cancel_null() {
        let result = unsafe { c2pa_context_cancel(std::ptr::null_mut()) };
        assert_eq!(result, -1, "NULL context should return error");
    }

    #[test]
    fn test_c2pa_context_cancel_via_builder() {
        let builder = unsafe { c2pa_context_builder_new() };
        assert!(!builder.is_null());

        let context = unsafe { c2pa_context_builder_build(builder) };
        assert!(!context.is_null());

        let result = unsafe { c2pa_context_cancel(context) };
        assert_eq!(result, 0, "cancel should work on a built context");

        unsafe { c2pa_free(context as *mut c_void) };
    }
}
