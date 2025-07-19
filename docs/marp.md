---
marp: true
theme: gaia
---

# CAI Rust Integration into Adobe Apps

Gavin Peacock
Principal Scientist CAI

---

# How we started

- First Integration with Photoshop as a local REST service
- Converted to a simple REST based C API for Lightroom
- Used wasm-bindgen to create a WASM JS API for Web apps.
- The REST API became the basis for later integrations

---

# Limitations

- C FFI requires careful memory management
- Error handling was awkward
- Need for Streams instead of file paths
- Separate porting to other languages

---

# Problems with existing Rust Binding tools

- A different tool to learn for every language
- Debugging incomprehensible glue code
- Inevitable limits in what can be expressed
- Requires custom Rust code with procedural macros
- UniFFi and CXX, node-bindgen & etc...

---

# Enhanced C FFI
- Error handling conventions for exceptions
- Streams API with custom callbacks
- Opaque struct references
- cbindgen + wrapper APIs in each language
- pre-built binaries - no need for Rust 

--- 
# Languages supported this way
- C++
- Python
- Swift
- Kotlin