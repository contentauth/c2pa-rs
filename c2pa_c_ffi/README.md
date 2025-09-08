# C2PA C API

This is the C API wrapper for the [C2PA Rust SDK](../sdk). It provides a C-compatible interface for working with content credentials, with same formats supported as the Rust SDK. This crate can also be used in Rust code to write C-compatible bindings with the exposed types.

## Overview

The C2PA C API allows developers to integrate content authenticity features into their applications using C or any language that can interface with C libraries.

## Building locally

Pre-requisite: You will need the Rust toolchain (cargo) installed.

To build and test locally, run:

```sh
make test
```

The build will have 2 features activated: `rust_native_crypto` and `file_io`.
Note that running the `make test` command will also check formatting of the code.
