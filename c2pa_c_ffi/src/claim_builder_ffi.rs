// Copyright 2026 Adobe. All rights reserved.
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

//! DESIGN SKETCH — not wired into `lib.rs`/cbindgen yet.
//!
//! What a C FFI surface for [`c2pa::ClaimBuilder`] would look like, following this crate's
//! existing `cimpl`-based conventions (see `c_api.rs` for the `Builder`/`Reader`/
//! `ContextBuilder` precedent).
//!
//! ## `ClaimAssertion`: owning the stream instead of borrowing it
//!
//! [`c2pa::ClaimAssertion`] is a Rust-side builder — `with_json`/`with_stream`/
//! `with_c2pa_data`/`with_exclusions` — and `with_stream` *borrows* the caller's stream
//! (`ClaimAssertion<'a>` -> `ClaimAssertion<'b>`). A borrow can't be split across separate FFI
//! calls the way `C2paBuilder`'s methods are (`cimpl`'s pointer registry keys on `TypeId`, which
//! requires `T: 'static` — see `track_box`'s bound in `cimpl/utils.rs` — so a non-`'static`
//! `ClaimAssertion<'a>` can't even be tracked, let alone safely outlive one call).
//!
//! The fix isn't to flatten everything into one call — it's to *own* the stream at the FFI
//! layer instead, the same way [`crate::c_api::c2pa_context_builder_set_signer`] absorbs a
//! `C2paSigner`: `C2paStream` itself is `'static` and `unsafe impl Send + Sync` (see
//! `c2pa_stream.rs`) — it's just a `*mut StreamContext` plus function pointers into whatever
//! runtime created it (Python, JS, ...), so taking ownership of the `C2paStream` value via
//! `untrack_or_return_int!` (which does `*Box::from_raw(ptr)`) works regardless of which
//! language built it. [`C2paClaimAssertion`] below is a plain, fully-owned, `'static` staging
//! struct — *not* `c2pa::ClaimAssertion` itself — that collects each `with_*` call's data,
//! including an owned `C2paStream` once `with_stream` absorbs one. Only the terminal
//! `add_gathered_assertion`/`add_created_assertion` call constructs a real
//! `c2pa::ClaimAssertion` from those owned pieces; the short-lived borrow it needs never has to
//! survive past that one call, so there's no `unsafe` lifetime extension anywhere and no change
//! needed to the `c2pa` crate itself. This also means `C2paClaimAssertion` behaves exactly like
//! `C2paContextBuilder`/`C2paBuilder` from the C caller's side: build it up across as many calls
//! as you like, then hand it to something that consumes it.

use std::{
    os::raw::{c_char, c_int, c_uchar},
    sync::Arc,
};

use c2pa::{ClaimAssertion, ClaimBuilder as C2paClaimBuilder, Context, HashRange};

// Import macros and utilities from cimpl — same pattern (and same reason for the
// `allow(unused_imports)`) as c_api.rs: `#[macro_use] mod cimpl;` in lib.rs already puts these
// macros in scope crate-wide, so this `use` is purely for readability/documentation of which
// ones this file relies on.
#[allow(unused_imports)]
use crate::{
    box_tracked, bytes_or_return_int, c2pa_stream::C2paStream, cstr_or_return_int,
    cstr_or_return_null, deref_mut_or_return_int, deref_or_return_int, deref_or_return_null,
    ok_or_return_int, ok_or_return_null, ptr_or_return_int, to_c_bytes, to_c_string,
    untrack_or_return_int, untrack_or_return_null,
};

// `c_api.rs` already defines `type C2paContext = Arc<Context>;`, but it's private to that
// module. Re-declared here (same underlying type, so still ABI-compatible with `*mut
// c_api::C2paContext`) rather than making that `pub(crate)` for a sketch that isn't wired in —
// a real integration would just reuse the one in `c_api.rs`.
type C2paContext = Arc<Context>;

// Work around limitations in cbindgen, same as every other opaque type in `c_api.rs`.
mod cbindgen_fix {
    #[repr(C)]
    #[allow(dead_code)]
    pub struct C2paClaimBuilder;

    #[repr(C)]
    #[allow(dead_code)]
    pub struct C2paClaimAssertion;
}

/// FFI-side staging object for building a [`c2pa::ClaimAssertion`] across multiple calls — see
/// the module doc for why this holds owned data (including an owned `C2paStream`) rather than
/// being `c2pa::ClaimAssertion` itself.
pub(crate) struct C2paClaimAssertion {
    label: String,
    value: Option<serde_json::Value>,
    as_json: bool,
    stream: Option<(String, C2paStream)>,
    c2pa_data: Option<Vec<u8>>,
    exclusions: Option<Vec<HashRange>>,
}

impl C2paClaimAssertion {
    fn new(label: String) -> Self {
        Self {
            label,
            value: None,
            as_json: false,
            stream: None,
            c2pa_data: None,
            exclusions: None,
        }
    }
}

/// Starts building an assertion under `label` (e.g. `"c2pa.actions"`, `"c2pa.ingredient"`,
/// `"c2pa.hash.data"`/`"c2pa.hash.bmff"`/`"c2pa.hash.boxes"` for a hard binding, or any custom
/// label).
///
/// # Safety
/// Reads a NULL-terminated C string. The returned value MUST eventually be released, either by
/// calling `c2pa_free` directly or by passing it to
/// `c2pa_claim_builder_add_gathered_assertion`/`_add_created_assertion` (which consumes it).
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_assertion_new(label: *const c_char) -> *mut C2paClaimAssertion {
    let label = cstr_or_return_null!(label);
    box_tracked!(C2paClaimAssertion::new(label))
}

/// Sets structured data for this assertion. If `label` matches a known assertion type, `json`
/// is decoded into that concrete type so it's stored with its native schema; otherwise it's
/// wrapped generically. See [`ClaimAssertion::with_json`].
///
/// # Safety
/// Reads a NULL-terminated C string. Returns -1 if there were errors, otherwise 0.
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_assertion_with_json(
    assertion_ptr: *mut C2paClaimAssertion,
    json: *const c_char,
) -> c_int {
    let assertion = deref_mut_or_return_int!(assertion_ptr, C2paClaimAssertion);
    let json = cstr_or_return_int!(json);
    let value: serde_json::Value = ok_or_return_int!(serde_json::from_str(&json));
    assertion.value = Some(value);
    0
}

/// Requests JSON encoding (instead of the default CBOR) for a custom assertion. See
/// [`ClaimAssertion::as_json`].
///
/// # Safety
/// `assertion_ptr` must be a valid, non-null `C2paClaimAssertion` pointer.
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_assertion_as_json(
    assertion_ptr: *mut C2paClaimAssertion,
) -> c_int {
    let assertion = deref_mut_or_return_int!(assertion_ptr, C2paClaimAssertion);
    assertion.as_json = true;
    0
}

/// Attaches a stream to this assertion — the asset to hash (hard-binding labels), the asset to
/// extract provenance from (`c2pa.ingredient`), or raw binary content (everything else). See
/// [`ClaimAssertion::with_stream`].
///
/// This *absorbs* `stream_ptr` — exactly like `c2pa_context_builder_set_signer` absorbs a
/// `C2paSigner` — untracking it and moving the owned `C2paStream` value into `assertion`. The C
/// caller must not free `stream_ptr` separately afterward (and, since it's untracked, calling
/// `c2pa_free` on it will correctly report it as no longer a tracked pointer rather than
/// double-freeing).
///
/// # Safety
/// Reads a NULL-terminated C string. Returns -1 if there were errors, otherwise 0.
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_assertion_with_stream(
    assertion_ptr: *mut C2paClaimAssertion,
    format: *const c_char,
    stream_ptr: *mut C2paStream,
) -> c_int {
    let assertion = deref_mut_or_return_int!(assertion_ptr, C2paClaimAssertion);
    let format = cstr_or_return_int!(format);
    let stream = untrack_or_return_int!(stream_ptr, C2paStream);
    assertion.stream = Some((format, stream));
    0
}

/// Supplies the ingredient's manifest store directly (JUMBF bytes) instead of extracting it
/// from the stream in-band — for a sidecar or remote manifest. See
/// [`ClaimAssertion::with_c2pa_data`].
///
/// # Safety
/// Reads a raw byte buffer of `len` bytes at `data`. Returns -1 if there were errors, otherwise
/// 0.
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_assertion_with_c2pa_data(
    assertion_ptr: *mut C2paClaimAssertion,
    data: *const c_uchar,
    len: usize,
) -> c_int {
    let assertion = deref_mut_or_return_int!(assertion_ptr, C2paClaimAssertion);
    let data = bytes_or_return_int!(data, len, "c2pa_data");
    assertion.c2pa_data = Some(data.to_vec());
    0
}

/// Sets the byte ranges to exclude when hashing — the region where the caller embedded the
/// manifest placeholder. `exclusions_json` is a JSON array of `{"start": u64, "length": u64}`.
/// See [`ClaimAssertion::with_exclusions`].
///
/// # Safety
/// Reads a NULL-terminated C string. Returns -1 if there were errors, otherwise 0.
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_assertion_with_exclusions(
    assertion_ptr: *mut C2paClaimAssertion,
    exclusions_json: *const c_char,
) -> c_int {
    let assertion = deref_mut_or_return_int!(assertion_ptr, C2paClaimAssertion);
    let exclusions_json = cstr_or_return_int!(exclusions_json);
    let exclusions: Vec<HashRange> = ok_or_return_int!(serde_json::from_str(&exclusions_json));
    assertion.exclusions = Some(exclusions);
    0
}

/// Creates a `C2paClaimBuilder` sharing an existing `C2paContext` (see `c2pa_context_new`/
/// `c2pa_context_builder_build`), with an auto-generated claim label.
///
/// # Safety
/// `context` must be a valid, non-null `C2paContext` pointer.
/// The returned value MUST be released by calling `c2pa_free`.
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_builder_from_context(
    context: *mut C2paContext,
) -> *mut C2paClaimBuilder {
    let context = deref_or_return_null!(context, C2paContext);
    box_tracked!(C2paClaimBuilder::new(context.clone()))
}

/// Same as [`c2pa_claim_builder_from_context`], but with a caller-supplied claim label instead
/// of an auto-generated UUID. `label` must already be a valid C2PA v2 manifest label.
///
/// # Safety
/// `context` must be a valid, non-null `C2paContext` pointer. Reads a NULL-terminated C string.
/// The returned value MUST be released by calling `c2pa_free`.
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_builder_with_label(
    context: *mut C2paContext,
    label: *const c_char,
) -> *mut C2paClaimBuilder {
    let context = deref_or_return_null!(context, C2paContext);
    let label = cstr_or_return_null!(label);
    box_tracked!(ok_or_return_null!(C2paClaimBuilder::with_label(
        context.clone(),
        label
    )))
}

/// Marks `builder` as an update manifest — `c2pa_claim_builder_sign` then commits it as one
/// instead of a regular claim. Consumes `builder_ptr`, matching
/// [`c2pa::ClaimBuilder::update`]'s `fn update(mut self) -> Self` — same untrack-then-rebox
/// pattern as `c2pa_builder_with_definition`.
///
/// # Safety
/// `builder_ptr` must be a valid, non-null `C2paClaimBuilder` pointer. It is INVALID after this
/// call; use the returned pointer instead. The returned value MUST be released by calling
/// `c2pa_free`.
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_builder_update(
    builder_ptr: *mut C2paClaimBuilder,
) -> *mut C2paClaimBuilder {
    let builder = untrack_or_return_null!(builder_ptr, C2paClaimBuilder);
    box_tracked!(builder.update())
}

/// Sets the claim title.
///
/// # Safety
/// Reads NULL-terminated C strings. Returns -1 if there were errors, otherwise 0.
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_builder_set_title(
    builder_ptr: *mut C2paClaimBuilder,
    title: *const c_char,
) -> c_int {
    let builder = deref_mut_or_return_int!(builder_ptr, C2paClaimBuilder);
    let title = cstr_or_return_int!(title);
    builder.set_title(title);
    0
}

/// Sets the instance ID (e.g. an `xmp:iid:...` URN) of the asset this claim describes.
///
/// # Safety
/// Reads NULL-terminated C strings. Returns -1 if there were errors, otherwise 0.
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_builder_set_instance_id(
    builder_ptr: *mut C2paClaimBuilder,
    instance_id: *const c_char,
) -> c_int {
    let builder = deref_mut_or_return_int!(builder_ptr, C2paClaimBuilder);
    let instance_id = cstr_or_return_int!(instance_id);
    builder.set_instance_id(instance_id);
    0
}

/// Sets the claim's default hash algorithm (e.g. `"sha384"`). Defaults to `"sha256"`.
///
/// # Safety
/// Reads NULL-terminated C strings. Returns -1 if there were errors, otherwise 0.
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_builder_set_hash_alg(
    builder_ptr: *mut C2paClaimBuilder,
    alg: *const c_char,
) -> c_int {
    let builder = deref_mut_or_return_int!(builder_ptr, C2paClaimBuilder);
    let alg = cstr_or_return_int!(alg);
    builder.set_hash_alg(alg);
    0
}

/// Records a JUMBF URI to redact the next time a matching ingredient is merged in via
/// `c2pa_claim_builder_add_gathered_assertion`/`_add_created_assertion` (with a stream
/// attached). See [`c2pa::ClaimBuilder::add_redaction`].
///
/// # Safety
/// Reads NULL-terminated C strings. Returns -1 if there were errors, otherwise 0.
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_builder_add_redaction(
    builder_ptr: *mut C2paClaimBuilder,
    uri: *const c_char,
) -> c_int {
    let builder = deref_mut_or_return_int!(builder_ptr, C2paClaimBuilder);
    let uri = cstr_or_return_int!(uri);
    builder.add_redaction(uri);
    0
}

/// Adds `assertion` to the claim as *gathered*. Consumes `assertion_ptr` — builds the real
/// `c2pa::ClaimAssertion` from its owned fields (see the module doc) and hands it to
/// [`c2pa::ClaimBuilder::add_gathered_assertion`].
///
/// # Returns
/// A newly allocated JSON string encoding the assertion's `HashedUri`, or NULL on error (check
/// `c2pa_error`). Errors if `assertion`'s label names a hard-binding type — hard bindings must
/// be added via `c2pa_claim_builder_add_created_assertion` instead.
///
/// # Safety
/// `builder_ptr`/`assertion_ptr` must be valid, non-null pointers of their respective types.
/// `assertion_ptr` is INVALID after this call, whether it succeeds or fails. The returned string
/// MUST be released by calling `c2pa_free`.
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_builder_add_gathered_assertion(
    builder_ptr: *mut C2paClaimBuilder,
    assertion_ptr: *mut C2paClaimAssertion,
) -> *mut c_char {
    add_claim_assertion(builder_ptr, assertion_ptr, false)
}

/// Same as [`c2pa_claim_builder_add_gathered_assertion`], but adds the assertion as *created*
/// rather than *gathered*. Required for hard-binding labels (`c2pa.hash.data`/`c2pa.hash.bmff`/
/// `c2pa.hash.boxes`), which `Claim` only ever stores as created.
///
/// # Safety
/// Same as [`c2pa_claim_builder_add_gathered_assertion`].
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_builder_add_created_assertion(
    builder_ptr: *mut C2paClaimBuilder,
    assertion_ptr: *mut C2paClaimAssertion,
) -> *mut c_char {
    add_claim_assertion(builder_ptr, assertion_ptr, true)
}

/// Shared body for [`c2pa_claim_builder_add_gathered_assertion`]/
/// [`c2pa_claim_builder_add_created_assertion`] — the only difference between the two is which
/// `ClaimBuilder` method the reconstructed `ClaimAssertion` gets handed to.
unsafe fn add_claim_assertion(
    builder_ptr: *mut C2paClaimBuilder,
    assertion_ptr: *mut C2paClaimAssertion,
    created: bool,
) -> *mut c_char {
    let builder = deref_mut_or_return_null!(builder_ptr, C2paClaimBuilder);
    let state = untrack_or_return_null!(assertion_ptr, C2paClaimAssertion);

    let mut assertion = ClaimAssertion::new(state.label);
    if let Some(value) = state.value {
        assertion = ok_or_return_null!(assertion.with_json(&value));
    }
    if state.as_json {
        assertion = assertion.as_json();
    }

    // `with_stream` narrows `assertion`'s lifetime to borrow `stream` — a plain local variable
    // owned by `state`, so that borrow only has to last for the remainder of this call. That's
    // the entire point of absorbing the stream back in `c2pa_claim_assertion_with_stream`
    // instead of storing a reference to it.
    let hashed_uri = if let Some((format, mut stream)) = state.stream {
        let mut assertion = assertion.with_stream(&format, &mut stream);
        if let Some(data) = state.c2pa_data {
            assertion = assertion.with_c2pa_data(data);
        }
        if let Some(exclusions) = state.exclusions {
            assertion = assertion.with_exclusions(exclusions);
        }
        if created {
            ok_or_return_null!(builder.add_created_assertion(assertion))
        } else {
            ok_or_return_null!(builder.add_gathered_assertion(assertion))
        }
    } else {
        if let Some(exclusions) = state.exclusions {
            assertion = assertion.with_exclusions(exclusions);
        }
        if created {
            ok_or_return_null!(builder.add_created_assertion(assertion))
        } else {
            ok_or_return_null!(builder.add_gathered_assertion(assertion))
        }
    };

    let json = ok_or_return_null!(serde_json::to_string(&hashed_uri));
    to_c_string(json)
}

/// Signs the manifest and returns the raw signed JUMBF bytes, using the signer configured on
/// `builder`'s `Context`. Unlike `c2pa_builder_sign`, there's no `format`/`source`/`dest` —
/// `ClaimBuilder::sign` doesn't compose into a format-specific container or manage a
/// placeholder; the caller does both themselves (e.g. via a `C2paStore`-level API not sketched
/// here), the same way they own placeholder embedding before calling this.
///
/// # Parameters
/// * `builder_ptr` — pointer to a `C2paClaimBuilder`.
/// * `manifest_bytes_ptr` — pointer to a pointer to receive the signed manifest bytes (optional,
///   can be NULL).
///
/// # Returns
/// The size of the manifest data, or -1 on error (check `c2pa_error`).
///
/// # Safety
/// If `manifest_bytes_ptr` is not NULL, the returned value MUST be released by calling
/// `c2pa_free`.
#[no_mangle]
pub unsafe extern "C" fn c2pa_claim_builder_sign(
    builder_ptr: *mut C2paClaimBuilder,
    manifest_bytes_ptr: *mut *const c_uchar,
) -> i64 {
    let builder = deref_or_return_int!(builder_ptr, C2paClaimBuilder);
    ptr_or_return_int!(manifest_bytes_ptr);

    let manifest_bytes = ok_or_return_int!(builder.sign());
    let len = manifest_bytes.len() as i64;
    if !manifest_bytes_ptr.is_null() {
        *manifest_bytes_ptr = to_c_bytes(manifest_bytes);
    }
    len
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use std::ffi::CString;

    use super::*;
    use crate::c_api::c2pa_context_new;

    #[test]
    fn test_claim_builder_from_context_and_free() {
        unsafe {
            let context = c2pa_context_new();
            assert!(!context.is_null());

            let builder = c2pa_claim_builder_from_context(context as *mut C2paContext);
            assert!(!builder.is_null());

            let title = CString::new("Test claim").unwrap();
            let result = c2pa_claim_builder_set_title(builder, title.as_ptr());
            assert_eq!(result, 0);

            crate::c2pa_free(builder as *const std::os::raw::c_void);
            crate::c2pa_free(context as *const std::os::raw::c_void);
        }
    }

    #[test]
    fn test_claim_assertion_multi_call_generic_json() {
        unsafe {
            let context = c2pa_context_new();
            let builder = c2pa_claim_builder_from_context(context as *mut C2paContext);

            let label = CString::new("org.test.custom").unwrap();
            let assertion = c2pa_claim_assertion_new(label.as_ptr());
            assert!(!assertion.is_null());

            let json = CString::new(r#"{"value": 1}"#).unwrap();
            assert_eq!(c2pa_claim_assertion_with_json(assertion, json.as_ptr()), 0);

            let result = c2pa_claim_builder_add_gathered_assertion(builder, assertion);
            assert!(!result.is_null(), "error: {:?}", crate::c2pa_error());

            let hashed_uri_json = CString::from_raw(result).into_string().unwrap();
            assert!(hashed_uri_json.contains("org.test.custom"));

            crate::c2pa_free(builder as *const std::os::raw::c_void);
            crate::c2pa_free(context as *const std::os::raw::c_void);
        }
    }

    #[test]
    fn test_claim_assertion_with_stream_absorbs_stream() {
        unsafe {
            let context = c2pa_context_new();
            let builder = c2pa_claim_builder_from_context(context as *mut C2paContext);

            let label = CString::new("c2pa.hash.data").unwrap();
            let assertion = c2pa_claim_assertion_new(label.as_ptr());

            let format = CString::new("image/jpeg").unwrap();
            let mut stream = crate::c2pa_stream::TestStream::new(vec![1u8; 64]);
            let stream_ptr = stream.as_ptr();
            assert_eq!(
                c2pa_claim_assertion_with_stream(assertion, format.as_ptr(), stream_ptr),
                0
            );

            // The stream is now owned by `assertion` — freeing it again should report an error
            // (it's no longer tracked) rather than double-freeing.
            let free_result = crate::c2pa_free(stream_ptr as *const std::os::raw::c_void);
            assert!(free_result < 0, "absorbed stream should no longer be tracked");

            let result = c2pa_claim_builder_add_created_assertion(builder, assertion);
            assert!(!result.is_null(), "error: {:?}", crate::c2pa_error());

            crate::c2pa_free(builder as *const std::os::raw::c_void);
            crate::c2pa_free(context as *const std::os::raw::c_void);
            // NOTE: not calling `stream.drop()`'s inner free here — the pointer it wraps was
            // already absorbed/untracked above, so `TestStream`'s own `Drop` (which frees it
            // again) would panic on double-free-detection. A real `TestStream` API for this
            // pattern would want a way to disarm its own cleanup once absorbed.
            std::mem::forget(stream);
        }
    }

    #[test]
    fn test_claim_builder_hard_binding_as_gathered_errors() {
        unsafe {
            let context = c2pa_context_new();
            let builder = c2pa_claim_builder_from_context(context as *mut C2paContext);

            let label = CString::new("c2pa.hash.data").unwrap();
            let assertion = c2pa_claim_assertion_new(label.as_ptr());

            let format = CString::new("image/jpeg").unwrap();
            let mut stream = crate::c2pa_stream::TestStream::new(vec![1u8; 64]);
            assert_eq!(
                c2pa_claim_assertion_with_stream(assertion, format.as_ptr(), stream.as_ptr()),
                0
            );

            let result = c2pa_claim_builder_add_gathered_assertion(builder, assertion);
            assert!(
                result.is_null(),
                "a hard binding added as gathered should error"
            );

            crate::c2pa_free(builder as *const std::os::raw::c_void);
            crate::c2pa_free(context as *const std::os::raw::c_void);
            std::mem::forget(stream);
        }
    }
}
