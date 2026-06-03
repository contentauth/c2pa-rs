# c2pa-raw-crypto

Raw cryptographic signing and validation primitives for [C2PA](https://c2pa.org).

**IMPORTANT:** This crate is an implemementation detail for the [`c2pa`](https://crates.io/crates/c2pa) crate and not generally designed for independent use.

This crate provides the `RawSigner` and `RawSignatureValidator` traits together with built-in implementations of the digital signature algorithms required by the C2PA specification.
It deliberately stays narrow: it knows nothing about COSE framing, RFC 3161 time stamping, or OCSP — those concerns are handled by the calling code (today, the `c2pa` crate).

## Cryptography backend

Two cryptography backends are available via Cargo feature flags:

- **`rust_native_crypto`** (enabled by default) — pure-Rust crates.
- **`openssl`** — a vendored OpenSSL implementation.

**`rust_native_crypto` takes precedence.** If both features end up enabled (which can happen through Cargo feature unification in a workspace), the rust-native backend is selected at runtime and the OpenSSL backend, while compiled, is not used.
This is not considered an error.

Enabling neither is allowed (e.g. when only the type definitions are needed, or when signing is delegated to a remote service and no validation is performed); in that case the built-in signer/validator constructors report an error / return `None` at runtime.

## Status

> **Note:** This crate currently lives inside the [`c2pa-rs`](https://github.com/contentauth/c2pa-rs) workspace while the extraction is evaluated.
> It is expected to **move to its own repository** before a stable (1.0) release.

## License

Licensed under either of [Apache License, Version 2.0](../LICENSE-APACHE) or [MIT license](../LICENSE-MIT) at your option.
