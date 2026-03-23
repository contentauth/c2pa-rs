# C API Notes

The code in `c2pa_c_ffi` provides a standard export C-based interface for binding to other languages.
Dynamic library binary images for Linux, macOS, and Windows export this API.
Consumers can then use the API without any specific knowledge of Rust following well-known rules for linking to C-based libraries.

## Change from earlier versions

The C interface is not new, but previously it was part of the `c2pa-c` repo. The C interface is useful to other bindings, so it was exported as a Rust JSON API. But that led to things like `c2pa-python` importing from `c2pa-c` and then re-exporting a Python API via [UniFFI](https://mozilla.github.io/uniffi-rs/latest/). The UniFFI tools have severe limitations in what they represent, such as the inability to have mutable parameters, and there are other limitations with the tools for binding Rust to C++, Swift, and other languages. 

## New approach

Binding to C APIs is a well-established and mature practice. Every language has well-documented methods for binding to C, and Rust has built-in support for it. A solid C interface enables leveraging that work to provide other language bindings.

Bindings must still be written for each language, but since there are so many examples of this, AI engines are very good at writing the code, resulting in well-formed, well-documented bindings, though some manual effort is required to fix some things. Instead of unreadable, incomprehensible auto-generated binding glue, the result is well-structured code bindings that can be customized as needed.

## Tradeoffs

The C language is not object-oriented, does not perform garbage collection, and does not natively support things like exception handling.  API may use unsafe pointer references, so care must be taken with pointers and memory management. 

For these reasons, you shouldn't use the C API directly. But it makes a very solid common way to bridge between Rust and other languages when used correctly. Use higher-level structures in the other languages to ensure that references to native structures are correctly managed and freed. 
