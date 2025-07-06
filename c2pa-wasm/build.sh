#!/bin/bash

# Build script for C2PA WASM bindings
set -e

echo "Building C2PA WASM bindings..."

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo "wasm-pack is not installed. Installing..."
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
fi

# Build for web
echo "Building for web..."
wasm-pack build --target web --out-dir pkg --release

# Build for Node.js
echo "Building for Node.js..."
wasm-pack build --target nodejs --out-dir pkg-node --release

# Build for bundlers
echo "Building for bundlers..."
wasm-pack build --target bundler --out-dir pkg-bundler --release

echo "Build complete!"
echo ""
echo "Generated packages:"
echo "  - pkg/ (web)"
echo "  - pkg-node/ (Node.js)"
echo "  - pkg-bundler/ (bundlers)"
echo ""
echo "To test the web example:"
echo "  1. Start a local HTTP server in this directory:"
echo "     python3 -m http.server 8080"
echo "  2. Open http://localhost:8080/examples/index.html in your browser"
echo ""
echo "To test the Node.js example:"
echo "  1. cd examples"
echo "  2. node index.js <path-to-c2pa-file>"
echo "  3. Example: node index.js ../../sdk/tests/fixtures/C.jpg"
