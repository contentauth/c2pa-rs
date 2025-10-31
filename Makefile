# Makefile to aid with local development and testing
# This is not required for automated builds

ifeq ($(OS),Windows_NT)
	PLATFORM := win
else
	UNAME := $(shell uname)
	ifeq ($(UNAME),Linux)
		PLATFORM := linux
	endif
	ifeq ($(UNAME),Darwin)
		PLATFORM := mac
	endif
endif

check-format:
	cargo +nightly fmt -- --check

check-docs:
	cargo doc --no-deps --workspace --features="file_io"

clippy:
	cargo clippy --features="file_io" --all-targets -- -D warnings

test-local:
	cargo test --features="file_io, fetch_remote_manifests, add_thumbnails" --all-targets

test-wasm:
	cd sdk && wasm-pack test --node -- --no-default-features --features="rust_native_crypto, fetch_remote_manifests"

test-wasm-web:
	cd sdk && WASM_BINDGEN_TEST_TIMEOUT=60 wasm-pack test --chrome --headless -- --no-default-features --features="rust_native_crypto, fetch_remote_manifests" --nocapture

# WASI testing requires upstream llvm clang (not XCode), wasmtime, and the target wasm32-wasip2 on the nightly toolchain
test-wasi:
ifeq ($(PLATFORM),mac)
	$(eval CC := /opt/homebrew/opt/llvm/bin/clang)
endif
	CC=$(CC) CARGO_TARGET_WASM32_WASIP2_RUNNER="wasmtime -S cli -S http --dir ." cargo +nightly test --target wasm32-wasip2 -p c2pa --no-default-features --features="rust_native_crypto, file_io, fetch_remote_manifests, add_thumbnails"
	rm -r sdk/Users

# Full local validation, build and test all features including wasm
# Run this before pushing a PR to pre-validate
test: check-format check-docs clippy test-local test-wasm-web

# Auto format code according to standards
fmt:
	cargo +nightly fmt

# Builds and views documentation
doc:
	cargo doc --no-deps --open

# Builds a set of test images using the make_test_images example
# Outputs to release/test-images
images:
	cargo run --release --bin make_test_images

# Exports JSON schema files so that types can easily be exported to other languages
# Outputs to release/json-schema
schema:
	cargo run --release --bin export_schema

# Runs the client example using test image and output to target/tmp/client.jpg
client:
	cargo run --example client sdk/tests/fixtures/ca.jpg target/tmp/client.jpg

# Runs the show example
show:
	cargo run --example show -- sdk/tests/fixtures/ca.jpg

release:
	cd c2pa_c_ffi && make release
