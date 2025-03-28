# Contributing to the project 

The information in this page is primarily for those who wish to contribute to the c2pa-rs library project itself, rather than those who simply wish to use it in an application.  For general contribution guidelines, see [CONTRIBUTING.md](../CONTRIBUTING.md).

## Nightly builds

In most cases, you should depend on this crate as published via [crates.io](https://crates.io/crates/c2pa).

The Adobe team produces nightly snapshots of this crate via a `nightly` branch to test the impact of pending changes to upstream dependencies. To use these builds for your own testing ahead of our releases, include the library by adding the following `Cargo.toml` entry:

```toml
c2pa = { git = "https://github.com/contentauth/c2pa-rs.git", branch = "nightly", features = [...]}
```

Commits in this branch have a modified `sdk/Cargo.toml` entry which includes a version number similar to the following:

```toml
version = "0.25.3-nightly+2023-08-28-2f33ab3"
```

There is no formal support for code from a nightly release, but if you become aware of any issues, we would appreciate a bug report including this version number.

## Building for WebAssembly

This crate supports compilation to both the `wasm32-unknown-unknown` and `wasm32-wasi*` family of LLVM targets.

### Building Wasm

Building Wasm requires [Clang](https://clang.llvm.org/) due to the `ring` crate. The version of Clang that comes with XCode does not support Wasm targets.

On macOS, follow these steps:

1. Install Clang with Homebrew `brew install llvm`.
2. Set the `CC` environment variable to the Clang binary in the Cargo configuration file `.cargo/config.toml` in the project root; see the [example configuration file](#example-cargo-configuration) below.

NOTE: Only Wasm targets `wasm32-wasip2` and later can use the `file_io` feature.

As of March 2025, `wasm32-wasip2` still requires the nightly toolchain as tracked by this issue: [wasip2 target should not conditionally feature gate stdlib APIs](https://github.com/rust-lang/rust/issues/130323)

### Testing Wasm

Prerequisites:
- Testing Wasm for the browser (`wasm32-unknown-unknown`) requires [wasm-pack](https://github.com/rustwasm/wasm-pack).
- Testing WASI Wasm (`wasm32-wasip1` and later) requires [wasmtime](https://github.com/bytecodealliance/wasmtime).

### Example Cargo configuration

This example `.cargo/config.toml` specifies Homebrew Clang, which can build all targets on macOS, not only Wasm. The test runner is set for `wasm32-wasip2`.

```
[env]
CC = "/opt/homebrew/opt/llvm/bin/clang"

[target.wasm32-wasip2]
runner = "wasmtime -S cli -S http --dir ."
```

## Testing

The current set of unit tests are helpful but many are out of date.  We need a more comprehensive set of tests: The plan is to build a solid set of tests on the new streams-based API, then build everything else on that.

There is an open issue to generate test images from clean non-c2pa images. When images are checked in with manifests, they rapidly get out of date. A set of older manifests and third-party images is still needed for testing, but they need not be in the SDK.  

We need:

- A test assets folder with one public domain image in each asset format we support.
- A tool, like `make_test_images`, to generate different kinds of manifests for testing. We should maintain an archive of the manifest_store JSON generated by the previous build and compare the old build with the new ones for any significant deltas. The tool needs to ignore changes due to new GUIDs, dates, and JSON object field order.

The `make_test_images` crate has been updated to do this by default. We may make a policy to run the test comparison nightly.