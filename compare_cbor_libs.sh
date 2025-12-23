#!/bin/bash
# Script to compare c2pa SDK performance with c2pa_cbor vs serde_cbor

set -e

RESULTS_DIR="cbor_comparison_results"
mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "C2PA SDK: c2pa_cbor vs serde_cbor Comparison"
echo "=========================================="
echo ""

# Save current state
echo "📦 Saving current Cargo.toml..."
cp sdk/Cargo.toml sdk/Cargo.toml.backup

# Function to restore Cargo.toml on exit
cleanup() {
    echo ""
    echo "🔄 Restoring original Cargo.toml..."
    mv sdk/Cargo.toml.backup sdk/Cargo.toml
}
trap cleanup EXIT

# Test 1: With c2pa_cbor (current state)
echo "=========================================="
echo "Test 1: Benchmarking with c2pa_cbor"
echo "=========================================="
echo ""

echo "Current dependency in sdk/Cargo.toml:"
grep "serde_cbor" sdk/Cargo.toml || echo "Not found"
echo ""

echo "Building release binary with c2pa_cbor..."
cargo build --release --package c2pa 2>&1 | tail -5

echo ""
echo "Measuring binary size with c2pa_cbor..."
C2PA_CBOR_SIZE=$(ls -l target/release/deps/libc2pa-*.rlib | head -1 | awk '{print $5}')
echo "SDK library size: $C2PA_CBOR_SIZE bytes ($(numfmt --to=iec-i --suffix=B $C2PA_CBOR_SIZE))"

echo ""
echo "Running benchmarks with c2pa_cbor..."
cargo bench --package c2pa --bench read -- --save-baseline c2pa_cbor 2>&1 | tee "$RESULTS_DIR/c2pa_cbor_bench.txt"

# Test 2: Switch to serde_cbor
echo ""
echo "=========================================="
echo "Test 2: Benchmarking with serde_cbor"
echo "=========================================="
echo ""

echo "🔄 Switching to serde_cbor..."
sed -i.tmp 's/serde_cbor = { package = "c2pa_cbor", path = "..\/c2pa_cbor" }/serde_cbor = "0.11"/' sdk/Cargo.toml
rm -f sdk/Cargo.toml.tmp

echo "New dependency in sdk/Cargo.toml:"
grep "serde_cbor" sdk/Cargo.toml
echo ""

echo "Cleaning build to ensure fresh compilation..."
cargo clean -p c2pa

echo ""
echo "Building release binary with serde_cbor..."
cargo build --release --package c2pa 2>&1 | tail -5

echo ""
echo "Measuring binary size with serde_cbor..."
SERDE_CBOR_SIZE=$(ls -l target/release/deps/libc2pa-*.rlib | head -1 | awk '{print $5}')
echo "SDK library size: $SERDE_CBOR_SIZE bytes ($(numfmt --to=iec-i --suffix=B $SERDE_CBOR_SIZE))"

echo ""
echo "Running benchmarks with serde_cbor..."
cargo bench --package c2pa --bench read -- --save-baseline serde_cbor 2>&1 | tee "$RESULTS_DIR/serde_cbor_bench.txt"

# Compare results
echo ""
echo "=========================================="
echo "COMPARISON SUMMARY"
echo "=========================================="
echo ""

echo "Binary Size Comparison:"
echo "  c2pa_cbor:  $C2PA_CBOR_SIZE bytes ($(numfmt --to=iec-i --suffix=B $C2PA_CBOR_SIZE))"
echo "  serde_cbor: $SERDE_CBOR_SIZE bytes ($(numfmt --to=iec-i --suffix=B $SERDE_CBOR_SIZE))"
SIZE_DIFF=$((C2PA_CBOR_SIZE - SERDE_CBOR_SIZE))
if [ $SIZE_DIFF -gt 0 ]; then
    echo "  Difference: +$SIZE_DIFF bytes ($(numfmt --to=iec-i --suffix=B $SIZE_DIFF)) - c2pa_cbor is LARGER"
else
    echo "  Difference: $SIZE_DIFF bytes ($(numfmt --to=iec-i --suffix=B ${SIZE_DIFF#-})) - c2pa_cbor is SMALLER"
fi

echo ""
echo "Benchmark Results Comparison:"
echo "  (Lower is better)"
echo ""
echo "To see detailed comparison:"
echo "  cd target/criterion"
echo "  ls -la"
echo ""
echo "Results saved to: $RESULTS_DIR/"

# Try to show criterion comparison if available
if command -v critcmp &> /dev/null; then
    echo ""
    echo "Running critcmp to compare baselines..."
    critcmp serde_cbor c2pa_cbor
else
    echo ""
    echo "💡 Tip: Install critcmp for detailed benchmark comparison:"
    echo "   cargo install critcmp"
    echo "   critcmp serde_cbor c2pa_cbor"
fi

echo ""
echo "✅ Comparison complete!"

