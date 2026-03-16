#!/bin/bash
# Builds the c2pa Rust library for wasm32-unknown-emscripten, then compiles
# the C++ example with emcc.
#
# Usage: ./build_emscripten_example.sh [release|debug]  (default: release)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WORKSPACE_ROOT="$(dirname "$PROJECT_ROOT")"
BUILD_TYPE="${1:-release}"

echo "Build type: $BUILD_TYPE"

# Step 1: Build the Rust library.
# Nightly + -Z build-std is required so stdlib is rebuilt with
# +atomics,+bulk-memory, matching USE_PTHREADS=1.
cd "$WORKSPACE_ROOT"

if ! rustup toolchain list | grep -q '^nightly'; then
    echo "Error: nightly toolchain not found. Run: rustup toolchain install nightly"
    exit 1
fi
rustup target add --toolchain nightly wasm32-unknown-emscripten 2>/dev/null || true

CARGO_FLAGS="-p c2pa-c-ffi --target wasm32-unknown-emscripten --no-default-features --features rust_native_crypto,file_io"
if [ "$BUILD_TYPE" = "debug" ]; then
    cargo +nightly build -Z build-std=std,panic_unwind $CARGO_FLAGS
    LIB_DIR="$WORKSPACE_ROOT/target/wasm32-unknown-emscripten/debug"
else
    cargo +nightly build -Z build-std=std,panic_unwind $CARGO_FLAGS --release
    LIB_DIR="$WORKSPACE_ROOT/target/wasm32-unknown-emscripten/release"
fi

C2PA_LIB="$LIB_DIR/libc2pa_c.a"
C2PA_HEADER="$LIB_DIR/c2pa.h"

[ -f "$C2PA_LIB" ]    || { echo "Error: library not found: $C2PA_LIB"; exit 1; }
[ -f "$C2PA_HEADER" ] || { echo "Error: header not found: $C2PA_HEADER"; exit 1; }
echo "✓ Rust library: $C2PA_LIB"

# Step 2: Compile the C++ example.
if ! command -v emcc &>/dev/null; then
    echo "Error: emcc not found. Install the Emscripten SDK and source emsdk_env.sh."
    exit 1
fi

OUTPUT_DIR="$WORKSPACE_ROOT/target/emscripten-example"
mkdir -p "$OUTPUT_DIR"

if [ "$BUILD_TYPE" = "debug" ]; then
    OPT_FLAGS="-g -s ASSERTIONS=1 -s SAFE_HEAP=1"
else
    OPT_FLAGS="-O3 -s ASSERTIONS=0"
fi

# -pthread and -fwasm-exceptions must match how the Rust library was compiled
# (see .cargo/config.toml for the wasm32-unknown-emscripten target).
emcc "$SCRIPT_DIR/emscripten_example.cpp" \
    -I"$LIB_DIR" \
    "$C2PA_LIB" \
    -o "$OUTPUT_DIR/c2pa_example.js" \
    -pthread \
    -fwasm-exceptions \
    -s WASM=1 \
    -s USE_PTHREADS=1 \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s INITIAL_MEMORY=256MB \
    -s MAXIMUM_MEMORY=2GB \
    -s EXPORTED_FUNCTIONS='["_main"]' \
    -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","FS"]' \
    -s FETCH=1 \
    -s ENVIRONMENT='node,worker' \
    -s NODERAWFS=1 \
    -std=c++17 \
    $OPT_FLAGS

echo ""
echo "✓ Build complete: $OUTPUT_DIR/c2pa_example.js"
echo ""
echo "Run with Node.js:"
echo "  node $OUTPUT_DIR/c2pa_example.js path/to/image.jpg"
echo ""
echo "Note: the HTTP resolver example requires a Web Worker in the browser."
