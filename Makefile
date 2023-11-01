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
	cargo doc --no-deps --workspace --all-features

clippy:
	cargo +nightly clippy --all-features --all-targets -- -D warnings

test-local:
	cargo test --all-features

test-wasm:
	cd sdk && wasm-pack test --node

test-wasm-web:
	cd sdk && wasm-pack test --chrome --headless -- --features="serialize_thumbnails"
	
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
