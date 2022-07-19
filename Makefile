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
	cargo fmt -- --check

check-docs:
	cargo doc --no-deps --workspace --all-features

clippy:
	cargo clippy --all-features --all-targets -- -D warnings

test-local:
	cargo test --all-features

test-no-defaults:
	cd sdk && cargo test --features="file_io" --no-default-features 

test-wasm:
	cd sdk && wasm-pack test --node

# Full local validation, build and test all features including wasm
# Run this before pushing a PR to pre-validate
test: check-format check-docs clippy test-local test-no-defaults test-wasm

# Builds and views documentation
doc:
	cargo doc --no-deps --open

# Builds a set of test images using the make_test_images example
# Outputs to release/test-images
images:
	cargo run --release --bin make_test_images

# Runs the client example using test image and output to target/tmp/client.jpg
client:
	cargo run --example client sdk/tests/fixtures/ca.jpg target/tmp/client.jpg

# Runs the show example
show:
	cargo run --example show -- sdk/tests/fixtures/ca.jpg
