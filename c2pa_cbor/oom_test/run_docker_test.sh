#!/bin/bash

echo "Building Docker image..."
docker build -f oom_test/Dockerfile.test -t cbor-dos-test .

echo ""
echo "Running OOM tests in Linux container..."
docker run --rm cbor-dos-test
