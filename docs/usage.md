# Using the Rust library

## Supported platforms

The C2PA Rust library has been tested on the following operating systems:

* Windows (Intel only)
* MacOS (Intel and Apple silicon)
* Ubuntu Linux (64-bit Intel and ARM v8)
* WebAssembly (Wasm)

## Requirements

The C2PA Rust library requires **Rust version 1.76.0** or newer.

To use the library, add this to your `Cargo.toml`:

```toml
[dependencies]
c2pa = "0.36.1"
```

To read or write a manifest file, add the `file_io` dependency to your `Cargo.toml`.

<!-- Check whether thumbnail generation has been removed -->

Add the `add_thumbnails` dependency to generate thumbnails for JPEG and PNG files. For example:

```
c2pa = { version = "0.25.0", features = ["file_io", "add_thumbnails"] }
```

NOTE: If you are building for WASM, omit the `file_io` dependency.

## Crate features

The Rust library crate provides the following capabilities:

* `file_io` enables manifest generation, signing via OpenSSL, and embedding manifests in [supported file formats](supported-formats.md).
* `add_thumbnails` will generate thumbnails automatically for JPEG and PNG files. (no longer included with `file_io`)
* `serialize_thumbnails` includes binary thumbnail data in the [Serde](https://serde.rs/) serialization output.
* `no_interleaved_io` forces fully-synchronous I/O; otherwise, the library uses threaded I/O for some operations to improve performance.
* `fetch_remote_manifests` enables the verification step to retrieve externally referenced manifest stores.  External manifests are only fetched if there is no embedded manifest store and no locally adjacent .c2pa manifest store file of the same name.
* `json_schema` is used by `make schema` to produce a JSON schema document that represents the `ManifestStore` data structures.
* `psxxx_ocsp_stapling_experimental` this is an demonstration feature that will attempt to fetch the OCSP data from the OCSP responders listed in the manifest signing certificate.  The response becomes part of the manifest and is used to prove the certificate was not revoked at the time of signing.  This is only implemented for PS256, PS384 and PS512 signatures and is intended as a demonstration.
* `openssl_ffi_mutex` prevents multiple threads from accessing the C OpenSSL library simultaneously. (This library is not re-entrant.) In a multi-threaded process (such as Cargo's test runner), this can lead to unpredictable behavior.

## Example code

The [sdk/examples](https://github.com/contentauth/c2pa-rs/tree/main/sdk/examples) directory contains some minimal example code.  The [client/client.rs](https://github.com/contentauth/c2pa-rs/blob/main/sdk/examples/client/client.rs) is the most instructive and provides and example of reading the contents of a manifest store, recursively displaying nested manifests.

