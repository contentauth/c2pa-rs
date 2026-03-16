#!/bin/bash
# CMake-based build for the Emscripten C++ example.
#
# Usage: ./build_cmake_example.sh [Release|Debug]  (default: Release)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WORKSPACE_ROOT="$(dirname "$PROJECT_ROOT")"
BUILD_TYPE="${1:-Release}"

echo "Build type: $BUILD_TYPE"

# Step 1: Build the Rust library (same as build_emscripten_example.sh).
cd "$WORKSPACE_ROOT"

if ! rustup toolchain list | grep -q '^nightly'; then
    echo "Error: nightly toolchain not found. Run: rustup toolchain install nightly"
    exit 1
fi
rustup target add --toolchain nightly wasm32-unknown-emscripten 2>/dev/null || true

CARGO_FLAGS="-p c2pa-c-ffi --target wasm32-unknown-emscripten --no-default-features --features rust_native_crypto,file_io"
if [ "$BUILD_TYPE" = "Debug" ]; then
    cargo +nightly build -Z build-std=std,panic_unwind $CARGO_FLAGS
else
    cargo +nightly build -Z build-std=std,panic_unwind $CARGO_FLAGS --release
fi
echo "✓ Rust library built"

# Step 2: Build with CMake + emcmake.
if ! command -v emcc &>/dev/null; then
    echo "Error: emcc not found. Install the Emscripten SDK and source emsdk_env.sh."
    exit 1
fi

BUILD_DIR="$SCRIPT_DIR/build-emscripten-$BUILD_TYPE"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

emcmake cmake .. \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DC2PA_ROOT="$WORKSPACE_ROOT"

emmake make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

echo ""
echo "✓ Build complete: $BUILD_DIR"
echo ""
echo "Run with Node.js:"
echo "  node $BUILD_DIR/c2pa_example.js path/to/image.jpg"
