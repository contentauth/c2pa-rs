# C2PA Emscripten Example

Demonstrates using the c2pa C library from C++ compiled with Emscripten.

## Prerequisites

**Rust nightly** (required to rebuild stdlib with `+atomics,+bulk-memory`):
```bash
rustup toolchain install nightly
rustup target add --toolchain nightly wasm32-unknown-emscripten
```

**Emscripten SDK**:
```bash
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk && ./emsdk install latest && ./emsdk activate latest
source ./emsdk_env.sh
```

## Build and Run

```bash
# Build (compiles Rust library + C++ example)
./build_emscripten_example.sh release

# Run with Node.js
node target/emscripten-example/c2pa_example.js path/to/image.jpg
```

CMake alternative: `./build_cmake_example.sh Release`

## Browser

Output is a `.js` module. Browser use requires:
- Running in a **Web Worker** (`EMSCRIPTEN_FETCH_SYNCHRONOUS` is not available on the main thread)
- COOP/COEP headers for `SharedArrayBuffer`:
  ```
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Embedder-Policy: require-corp
  ```

## What the Example Covers

- **File read** — `c2pa_read_file`
- **Stream API** — `c2pa_reader_from_stream` with in-memory read/seek callbacks
- **Custom HTTP resolver** — `c2pa_http_resolver_create` + `c2pa_context_builder_set_http_resolver`, backed by `emscripten_fetch` for remote manifest fetching

## Common Build Errors

| Error | Fix |
|-------|-----|
| `--shared-memory is disallowed` | Use `cargo +nightly build -Z build-std=std,panic_unwind` |
| `__cpp_exception` undefined | Add `-fwasm-exceptions` to your emcc command |
| File not found at runtime | Add `-s NODERAWFS=1` for host filesystem access under Node.js |

## Further Reading

- [`EMSCRIPTEN_USAGE.md`](../EMSCRIPTEN_USAGE.md) — full integration guide
- [`c2pa.h`](../../target/wasm32-unknown-emscripten/release/c2pa.h) — generated C API header
