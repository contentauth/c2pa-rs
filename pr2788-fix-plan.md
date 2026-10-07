# Fix plan: c2pa-rs #2788 (backport of #2781 to `stable`)

## Why the checks fail

Every failing job fails on the same three compiler errors in `c2pa_c_ffi/src/c_api.rs`. The unused-dependencies job fails on the same `CStr` errors, because it has to compile first.

1. **Line 3607 and line 3657, `cannot find type CStr`.** The two new tests call `CStr::from_ptr`. On `main` the test module imports `ffi::{CStr, CString}`. On `stable` it imports only `ffi::CString`, and the backport carried the tests but not the import.

2. **Line 1802, `variable does not need to be mutable`** (an error because the job runs with `-D warnings`). On `main`, `deref_mut_or_return!` returns a guard from `checkout_exclusive`, and writing through a guard needs `let mut`. On `stable` the same macro returns a plain `&mut C2paBuilder`, so `mut` on the binding is unused.

## The fix (two lines, one file)

```diff
--- a/c2pa_c_ffi/src/c_api.rs
+++ b/c2pa_c_ffi/src/c_api.rs
@@ line 1802 @@ pub unsafe extern "C" fn c2pa_builder_set_label(
-    let mut builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
+    let builder = deref_mut_or_return_int!(builder_ptr, C2paBuilder);
@@ line 3177 @@ mod tests {
     use std::{
-        ffi::CString,
+        ffi::{CStr, CString},
```

Behavior is unchanged: `builder` is already a mutable reference, so `builder.definition.label = Some(label)` writes through it exactly as before.

## Verification (run on the pull request head `d023a885` with the fix applied)

Feature set computed the same way the workflow computes it: `add_thumbnails default_http diagnostics fetch_remote_manifests file_io http http_reqwest http_reqwest_blocking http_ureq http_wasi http_wstd json_schema openssl pdf rust_native_crypto`.

| Check | Command | Result |
|---|---|---|
| Format | `cargo fmt --all -- --check` | exit 0 |
| Clippy | `cargo clippy --features "$FEATURES" --all-targets -- -Dwarnings` | exit 0 |
| Workspace test build | `cargo test --workspace --features "$FEATURES" --no-run` | exit 0 |
| Foreign-function crate tests | `cargo test -p c2pa-c-ffi` | 133 passed, 0 failed |

Both new tests ran by name and passed: `test_c2pa_builder_signs_with_configured_label`, `test_c2pa_builder_archive_roundtrips_configured_label`.

**Red test.** With `builder.definition.label = Some(label);` replaced by a no-op, both new tests FAIL (2 failed, 0 passed). So they test the setter, not something incidental. Source restored and byte-compared afterwards.

## What was not checked here

- The full workspace test RUN with all features was not executed, only built. Only `c2pa-c-ffi` tests were run.
- `cargo udeps` is not installed on this machine. Its failure log shows only the two `CStr` errors, so it should pass once those compile, but it was not run.
- Windows and macOS jobs were not reproduced. Their logs fail on the same errors, and the fix touches no platform-specific code.
- The branch is one commit behind `stable` (the v0.91.2 release commit). GitHub reports it mergeable; a rebase is not needed for this fix.

## Who pushes

The branch `backport-2781-to-stable` lives on `contentauth/c2pa-rs` and was opened by `caiopensrc`. Nothing has been pushed from here.
