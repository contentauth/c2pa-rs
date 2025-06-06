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

use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong, jstring};
use jni::JNIEnv;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use crate::{
    c2pa_builder_add_ingredient_from_stream, c2pa_builder_add_resource, c2pa_builder_free,
    c2pa_builder_from_json, c2pa_builder_set_no_embed, c2pa_builder_set_remote_url,
    c2pa_builder_sign, c2pa_builder_to_archive, c2pa_error, c2pa_load_settings,
    c2pa_manifest_bytes_free, c2pa_read_file, c2pa_read_ingredient_file, c2pa_reader_free,
    c2pa_reader_from_stream, c2pa_reader_json, c2pa_reader_resource_to_stream,
    c2pa_signer_free, c2pa_signer_from_info, c2pa_signer_reserve_size,
    c2pa_string_free, c2pa_version, C2paSignerInfo, C2paSigner,
};

// Import the opaque types
use c2pa::{Builder as C2paBuilder, Reader as C2paReader};
use crate::c2pa_stream::C2paStream;

/// Helper macro to handle Java string conversion for jstring return types
macro_rules! java_string_to_cstring_jstring {
    ($env:expr, $jstring:expr) => {
        match $env.get_string(&$jstring) {
            Ok(java_str) => match CString::new(java_str.to_str().unwrap_or("")) {
                Ok(c_str) => c_str,
                Err(_) => return ptr::null_mut(),
            },
            Err(_) => return ptr::null_mut(),
        }
    };
}

/// Helper macro to handle Java string conversion for jint return types
macro_rules! java_string_to_cstring_jint {
    ($env:expr, $jstring:expr) => {
        match $env.get_string(&$jstring) {
            Ok(java_str) => match CString::new(java_str.to_str().unwrap_or("")) {
                Ok(c_str) => c_str,
                Err(_) => return -1,
            },
            Err(_) => return -1,
        }
    };
}

/// Helper macro to handle Java string conversion for jlong return types
macro_rules! java_string_to_cstring_jlong {
    ($env:expr, $jstring:expr) => {
        match $env.get_string(&$jstring) {
            Ok(java_str) => match CString::new(java_str.to_str().unwrap_or("")) {
                Ok(c_str) => c_str,
                Err(_) => return 0,
            },
            Err(_) => return 0,
        }
    };
}

/// Helper macro to handle optional Java string conversion for jstring return types
macro_rules! java_string_to_cstring_opt_jstring {
    ($env:expr, $jstring:expr) => {
        if $jstring.is_null() {
            None
        } else {
            match $env.get_string(&$jstring.into()) {
                Ok(java_str) => match CString::new(java_str.to_str().unwrap_or("")) {
                    Ok(c_str) => Some(c_str),
                    Err(_) => return ptr::null_mut(),
                },
                Err(_) => return ptr::null_mut(),
            }
        }
    };
}

/// Helper macro to handle optional Java string conversion for jlong return types
macro_rules! java_string_to_cstring_opt_jlong {
    ($env:expr, $jstring:expr) => {
        if $jstring.is_null() {
            None
        } else {
            match $env.get_string(&$jstring.into()) {
                Ok(java_str) => match CString::new(java_str.to_str().unwrap_or("")) {
                    Ok(c_str) => Some(c_str),
                    Err(_) => return 0,
                },
                Err(_) => return 0,
            }
        }
    };
}

/// Helper function to convert C string to Java string
fn c_string_to_java_string(env: &mut JNIEnv, c_str: *mut c_char) -> jstring {
    if c_str.is_null() {
        return ptr::null_mut();
    }
    
    let rust_str = unsafe {
        match CStr::from_ptr(c_str).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };
    
    match env.new_string(rust_str) {
        Ok(jstring) => {
            unsafe { c2pa_string_free(c_str) };
            jstring.into_raw()
        }
        Err(_) => {
            unsafe { c2pa_string_free(c_str) };
            ptr::null_mut()
        }
    }
}

/// Returns a version string for logging
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_getVersion(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let version = unsafe { c2pa_version() };
    c_string_to_java_string(&mut env, version)
}

/// Returns the last error message
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_getError(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let error = unsafe { c2pa_error() };
    c_string_to_java_string(&mut env, error)
}

/// Load Settings from a string
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_loadSettings(
    mut env: JNIEnv,
    _class: JClass,
    settings: JString,
    format: JString,
) -> jint {
    let settings_cstr = java_string_to_cstring_jint!(env, settings);
    let format_cstr = java_string_to_cstring_jint!(env, format);
    
    unsafe { c2pa_load_settings(settings_cstr.as_ptr(), format_cstr.as_ptr()) }
}

/// Returns a ManifestStore JSON string from a file path
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_readFile(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
    data_dir: JString,
) -> jstring {
    let path_cstr = java_string_to_cstring_jstring!(env, path);
    let data_dir_cstr = java_string_to_cstring_opt_jstring!(env, data_dir);
    
    let data_dir_ptr = data_dir_cstr.as_ref().map_or(ptr::null(), |s| s.as_ptr());
    let result = unsafe { c2pa_read_file(path_cstr.as_ptr(), data_dir_ptr) };
    
    c_string_to_java_string(&mut env, result)
}

/// Returns an Ingredient JSON string from a file path
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_readIngredientFile(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
    data_dir: JString,
) -> jstring {
    let path_cstr = java_string_to_cstring_jstring!(env, path);
    let data_dir_cstr = java_string_to_cstring_jstring!(env, data_dir);
    
    let result = unsafe { c2pa_read_ingredient_file(path_cstr.as_ptr(), data_dir_cstr.as_ptr()) };
    
    c_string_to_java_string(&mut env, result)
}

/// Creates a C2paBuilder from a JSON manifest definition string
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_builderFromJson(
    mut env: JNIEnv,
    _class: JClass,
    manifest_json: JString,
) -> jlong {
    let manifest_json_cstr = java_string_to_cstring_jlong!(env, manifest_json);
    
    let builder = unsafe { c2pa_builder_from_json(manifest_json_cstr.as_ptr()) };
    builder as jlong
}

/// Frees a C2paBuilder
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_builderFree(
    _env: JNIEnv,
    _class: JClass,
    builder_ptr: jlong,
) {
    if builder_ptr != 0 {
        unsafe { c2pa_builder_free(builder_ptr as *mut C2paBuilder) };
    }
}

/// Sets the no-embed flag on the Builder
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_builderSetNoEmbed(
    _env: JNIEnv,
    _class: JClass,
    builder_ptr: jlong,
) {
    if builder_ptr != 0 {
        unsafe { c2pa_builder_set_no_embed(builder_ptr as *mut C2paBuilder) };
    }
}

/// Sets the remote URL on the Builder
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_builderSetRemoteUrl(
    mut env: JNIEnv,
    _class: JClass,
    builder_ptr: jlong,
    remote_url: JString,
) -> jint {
    if builder_ptr == 0 {
        return -1;
    }
    
    let remote_url_cstr = java_string_to_cstring_jint!(env, remote_url);
    
    unsafe { c2pa_builder_set_remote_url(builder_ptr as *mut C2paBuilder, remote_url_cstr.as_ptr()) }
}

/// Creates and verifies a C2paReader from an asset stream with the given format
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_readerFromStream(
    mut env: JNIEnv,
    _class: JClass,
    format: JString,
    stream_ptr: jlong,
) -> jlong {
    if stream_ptr == 0 {
        return 0;
    }
    
    let format_cstr = java_string_to_cstring_jlong!(env, format);
    
    let reader = unsafe { c2pa_reader_from_stream(format_cstr.as_ptr(), stream_ptr as *mut C2paStream) };
    reader as jlong
}

/// Frees a C2paReader
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_readerFree(
    _env: JNIEnv,
    _class: JClass,
    reader_ptr: jlong,
) {
    if reader_ptr != 0 {
        unsafe { c2pa_reader_free(reader_ptr as *mut C2paReader) };
    }
}

/// Returns a JSON string generated from a C2paReader
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_readerJson(
    mut env: JNIEnv,
    _class: JClass,
    reader_ptr: jlong,
) -> jstring {
    if reader_ptr == 0 {
        return ptr::null_mut();
    }
    
    let json = unsafe { c2pa_reader_json(reader_ptr as *mut C2paReader) };
    c_string_to_java_string(&mut env, json)
}

/// Creates a C2paSigner from SignerInfo
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_signerFromInfo(
    mut env: JNIEnv,
    _class: JClass,
    alg: JString,
    sign_cert: JString,
    private_key: JString,
    ta_url: JString,
) -> jlong {
    let alg_cstr = java_string_to_cstring_jlong!(env, alg);
    let sign_cert_cstr = java_string_to_cstring_jlong!(env, sign_cert);
    let private_key_cstr = java_string_to_cstring_jlong!(env, private_key);
    let ta_url_cstr = java_string_to_cstring_opt_jlong!(env, ta_url);
    
    let ta_url_ptr = ta_url_cstr.as_ref().map_or(ptr::null(), |s| s.as_ptr());
    
    let signer_info = C2paSignerInfo {
        alg: alg_cstr.as_ptr(),
        sign_cert: sign_cert_cstr.as_ptr(),
        private_key: private_key_cstr.as_ptr(),
        ta_url: ta_url_ptr,
    };
    
    let signer = unsafe { c2pa_signer_from_info(&signer_info) };
    signer as jlong
}

/// Frees a C2paSigner
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_signerFree(
    _env: JNIEnv,
    _class: JClass,
    signer_ptr: jlong,
) {
    if signer_ptr != 0 {
        unsafe { c2pa_signer_free(signer_ptr as *const C2paSigner) };
    }
}

/// Returns the size to reserve for the signature for this signer
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_signerReserveSize(
    _env: JNIEnv,
    _class: JClass,
    signer_ptr: jlong,
) -> jlong {
    if signer_ptr == 0 {
        return -1;
    }
    
    unsafe { c2pa_signer_reserve_size(signer_ptr as *mut C2paSigner) }
}

/// Creates and writes signed manifest from the C2paBuilder to the destination stream
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_builderSign(
    mut env: JNIEnv,
    _class: JClass,
    builder_ptr: jlong,
    format: JString,
    source_ptr: jlong,
    dest_ptr: jlong,
    signer_ptr: jlong,
) -> jlong {
    if builder_ptr == 0 || source_ptr == 0 || dest_ptr == 0 || signer_ptr == 0 {
        return -1;
    }
    
    let format_cstr = java_string_to_cstring_jlong!(env, format);
    let mut manifest_bytes_ptr = ptr::null();
    
    let result = unsafe {
        c2pa_builder_sign(
            builder_ptr as *mut C2paBuilder,
            format_cstr.as_ptr(),
            source_ptr as *mut C2paStream,
            dest_ptr as *mut C2paStream,
            signer_ptr as *mut C2paSigner,
            &mut manifest_bytes_ptr,
        )
    };
    
    if manifest_bytes_ptr != ptr::null() {
        unsafe { c2pa_manifest_bytes_free(manifest_bytes_ptr) };
    }
    
    result
}

/// Writes an Archive of the Builder to the destination stream
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_builderToArchive(
    _env: JNIEnv,
    _class: JClass,
    builder_ptr: jlong,
    stream_ptr: jlong,
) -> jint {
    if builder_ptr == 0 || stream_ptr == 0 {
        return -1;
    }
    
    unsafe { c2pa_builder_to_archive(builder_ptr as *mut C2paBuilder, stream_ptr as *mut C2paStream) }
}

/// Adds a resource to the C2paBuilder
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_builderAddResource(
    mut env: JNIEnv,
    _class: JClass,
    builder_ptr: jlong,
    uri: JString,
    stream_ptr: jlong,
) -> jint {
    if builder_ptr == 0 || stream_ptr == 0 {
        return -1;
    }
    
    let uri_cstr = java_string_to_cstring_jint!(env, uri);
    
    unsafe {
        c2pa_builder_add_resource(
            builder_ptr as *mut C2paBuilder,
            uri_cstr.as_ptr(),
            stream_ptr as *mut C2paStream,
        )
    }
}

/// Adds an ingredient to the C2paBuilder
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_builderAddIngredientFromStream(
    mut env: JNIEnv,
    _class: JClass,
    builder_ptr: jlong,
    ingredient_json: JString,
    format: JString,
    source_ptr: jlong,
) -> jint {
    if builder_ptr == 0 || source_ptr == 0 {
        return -1;
    }
    
    let ingredient_json_cstr = java_string_to_cstring_jint!(env, ingredient_json);
    let format_cstr = java_string_to_cstring_jint!(env, format);
    
    unsafe {
        c2pa_builder_add_ingredient_from_stream(
            builder_ptr as *mut C2paBuilder,
            ingredient_json_cstr.as_ptr(),
            format_cstr.as_ptr(),
            source_ptr as *mut C2paStream,
        )
    }
}

/// Writes a C2paReader resource to a stream given a URI
#[no_mangle]
pub extern "system" fn Java_org_c2pa_C2PA_readerResourceToStream(
    mut env: JNIEnv,
    _class: JClass,
    reader_ptr: jlong,
    uri: JString,
    stream_ptr: jlong,
) -> jlong {
    if reader_ptr == 0 || stream_ptr == 0 {
        return -1;
    }
    
    let uri_cstr = java_string_to_cstring_jlong!(env, uri);
    
    unsafe {
        c2pa_reader_resource_to_stream(
            reader_ptr as *mut C2paReader,
            uri_cstr.as_ptr(),
            stream_ptr as *mut C2paStream,
        )
    }
}
