#!/bin/bash
echo "=== CBOR DOS - OOM KILL TEST ==="
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Note: macOS doesn't support ulimit -v. Using ulimit -d (data segment) instead."
    echo "Memory limits on macOS may not work reliably. Consider monitoring Activity Monitor."
    LIMIT_CMD="ulimit -d"
    LIMIT_512MB=524288
    LIMIT_256MB=262144
else
    LIMIT_CMD="ulimit -v"
    LIMIT_512MB=524288
    LIMIT_256MB=262144
fi
echo ""

echo "[TEST 1] Normal run (no limits)"
echo "--------------------------------"
./target/release/cbor-dos-test 2>&1 | head -20
echo ""

echo "[TEST 2] Limited memory (512MB via $LIMIT_CMD)"
echo "-------------------------------------------"
echo "[*] Setting memory limit to 512MB..."
($LIMIT_CMD $LIMIT_512MB && ./target/release/cbor-dos-test) 2>&1 | head -20
EXIT_CODE=$?
echo ""
echo "Exit code: $EXIT_CODE"
if [ $EXIT_CODE -ne 0 ]; then
    echo "Exit code: $EXIT_CODE"
    echo "✓ Process killed/failed due to memory limit"
else
    # Check if error message indicates graceful OOM handling
    OUTPUT=$( ($LIMIT_CMD $LIMIT_512MB && ./target/release/cbor-dos-test) 2>&1 )
    if echo "$OUTPUT" | grep -q "out of memory\|Cannot allocate"; then
        echo "Exit code: $EXIT_CODE"
        echo "✓ Gracefully handled memory limit (returned error instead of aborting)"
    else
        echo "Exit code: $EXIT_CODE"
        echo "⚠ Process completed (limit may not have been enforced)"
    fi
fi
echo ""

echo "[TEST 3] Even tighter limit (256MB)"
echo "------------------------------------"
echo "[*] Setting memory limit to 256MB..."
($LIMIT_CMD $LIMIT_256MB && ./target/release/cbor-dos-test) 2>&1 | head -20
EXIT_CODE=$?
echo ""
if [ $EXIT_CODE -ne 0 ]; then
    echo "Exit code: $EXIT_CODE"
    echo "✓ Process killed/failed due to memory limit"
else
    # Check if error message indicates graceful OOM handling
    OUTPUT=$( ($LIMIT_CMD $LIMIT_256MB && ./target/release/cbor-dos-test) 2>&1 )
    if echo "$OUTPUT" | grep -q "out of memory\|Cannot allocate"; then
        echo "Exit code: $EXIT_CODE"
        echo "✓ Gracefully handled memory limit (returned error instead of aborting)"
    else
        echo "Exit code: $EXIT_CODE"
        echo "⚠ Process completed (limit may not have been enforced)"
    fi
fi
