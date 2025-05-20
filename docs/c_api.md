# C API Notes

This C API provides a standard export C based interface for binding to other languages.
We provide pre-built dynamic library binary images for linux, macosx and windows that export this API.
This can be used without any specific knowledge of Rust and leverages well known rules for linking to C based libraries.

### Change from earlier versions
The C interface is not new, but it used to be part of the c2pa_c repo. We discovered that  a lot of the that interface was useful to other bindings, so we were exporting as a Rust based JSON api from there. But that led to things like the c2pa_python repo importing from c2pa_c and then re-exporting it via uniffi as a python api. There were some severe limitations in what the uniffi tools could represent such as the inability to have mutable parameters. We found other limitations with the tools designed for binding Rust to C++, Swift and other languages. 

#### New approach
Binding to C APIs is a well established and mature practice. Every language has well documented methods for binding to C.  Rust has built in support for writing C bindings. If we provide a solid C interface, we can simply bind other languages to C and leverage all the work that has gone into those bindings.  

We still need to write bindings for each language, but since there are so many examples of this, AI engines are very good at writing the code. The result is well formed, well documented bindings. I've found it takes some manual effort to fix some things. Instead of unreadable, incomprehensible auto generated binding glue, we end up with well structured code bindings that can be customized for our needs.

#### Tradeoffs
The C language is not object oriented and does not natively support things like exception handling. There is no garbage collection. APIs use unsafe pointer references. We must be very careful about pointers an memory management. So the C API is not something we want developers to use directly. But it makes a very solid common way to bridge between Rust and other languages when used correctly. Higher level structures in the other languages can ensure that references to Rust structures are correctly managed and freed. 
