# C2PA C API

This is the C API wrapper for the [C2PA Rust library](../sdk). It provides a C-compatible interface for working with Content Credentials, and supports the same formats as Rust. You can use this API to integrate content authenticity features into an application that uses C or any language that can interface with C libraries.

## Overview

The code in `c2pa_c_ffi` provides a standard exported C-based interface.
Dynamic library binaries for Linux, macOS, and Windows export this API.
Consumers can use the API without any specific knowledge of Rust, following well-known rules for linking to C-based libraries.

### Change from previous versions

The C interface was previously part of the `c2pa-c` repo, which has been renamed to `c2pa-cpp` to clarify that it provides a C++ API. The C interface is useful to other bindings, so it was previously exported as a Rust JSON API. But that led to things like `c2pa-python` importing from `c2pa-c` and then re-exporting a Python API via [UniFFI](https://mozilla.github.io/uniffi-rs/latest/). The UniFFI tools have severe limitations in what they represent, such as the inability to have mutable parameters, and there are other limitations with the tools for binding Rust to C++, Swift, and other languages. 

However, binding to C APIs is a well-established and mature practice. Every language has well-documented methods for binding to C, and Rust has built-in support for it. A solid C interface enables leveraging that work to provide other language bindings.

Since there are so many examples of this, AI engines are very good at constructing well-structured,  well-documented, and easily customizable bindings for other languages instead of using unreadable, incomprehensible auto-generated binding glue.

### Caveats

The C language is not object-oriented, does not perform garbage collection, and does not natively support things like exception handling. The API may use unsafe pointer references, so take care with pointers and memory management.

For these reasons, use the the C++ API unless you have a specific reason to use C.

## Byte-buffer ownership

The byte arrays returned by the following APIs are the library's allocations:

* `c2pa_builder_sign` and `c2pa_builder_sign_context`
* `c2pa_builder_placeholder` and `c2pa_builder_sign_embeddable`
* `c2pa_builder_compose_manifest`
* `c2pa_ed25519_sign`

Treat returned bytes as read-only. Read only the returned byte count (64 bytes
for an Ed25519 signature) and release each non-null allocation exactly once
with `c2pa_free`. The pointer is invalid after release. Never use C `free`,
`realloc`, C++ `delete`, or a foreign container's deallocator for these buffers.
Copying the bytes into application-owned storage is optional and explicit.

The cimpl allocation handoff avoids an intermediate Rust-side payload copy
when the original allocation's address is even. It retains the original
length and capacity until release, without shrinking or copying to reduce
spare capacity. Odd-addressed allocations use an even-addressed copy fallback
to preserve the registry's separation between buffer addresses and opaque
handle IDs. This does not remove SDK-internal copies or copies made by
language-binding containers.

Stream read/write callbacks borrow the buffer supplied by the Rust caller
directly. These pointers are valid only during the callback: do not retain
or free them.

HTTP resolver response bodies follow a different ownership contract: the
callback allocates `C2paHttpResponse.body` with `malloc` and transfers ownership
to Rust when it returns. Rust reads that allocation without an intermediate
body copy and calls `free` when the response body reader is dropped, not
necessarily when the callback returns or EOF is reached. The callback must
not access or free the body after returning. Non-null zero-length bodies are
also freed. A body allocated before a callback error is freed on the error path.

## Building locally

Pre-requisite: You must have the Rust toolchain (cargo) installed.

For zero-copy development, the `cimpl` dependency currently uses the sibling
checkout at `../cimpl` relative to the repository root. Check out
`contentauth/cimpl` there with the allocation-handoff changes. This local path
must be replaced with a released version containing those changes before
publishing; the current version requirement alone does not include them.

To build and test locally, run:

```sh
make test
```

The build will have two features activated: `rust_native_crypto` and `file_io`.
Note that running the `make test` command will also check formatting of the code.
