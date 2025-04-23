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

TARGET_DIR := $(realpath ../target)

check-format:
	cargo +nightly fmt -- --check

clippy:
	cargo clippy -- -D warnings

test-local:
	cargo test

# Full local validation, build and test all features including wasm
# Run this before pushing a PR to pre-validate
test: check-format clippy test-local

fmt:
	cargo +nightly fmt

# These are for building the c2patool release bin on various platforms
build-release-win:
	rustup target add x86_64-pc-windows-msvc
	cargo build --target=x86_64-pc-windows-msvc --release
	cargo run --release --bin make_zip $(TARGET_DIR)/x86_64-pc-windows-msvc/release

build-release-mac-arm:
	rustup target add aarch64-apple-darwin
	MACOSX_DEPLOYMENT_TARGET=11.1 cargo build --target=aarch64-apple-darwin --release
	cargo run --release --bin make_zip $(TARGET_DIR)/aarch64-apple-darwin/release

build-release-mac-x86:
	rustup target add x86_64-apple-darwin
	MACOSX_DEPLOYMENT_TARGET=10.15 cargo build --target=x86_64-apple-darwin --release
	cargo run --release --bin make_zip $(TARGET_DIR)/x86_64-apple-darwin/release

build-release-mac-universal: build-release-mac-arm build-release-mac-x86
	rm -rf $(TARGET_DIR)/universal-apple-darwin
	mkdir -p $(TARGET_DIR)/universal-apple-darwin/release
	lipo -create -output $(TARGET_DIR)/universal-apple-darwin/release/libc2pa_c.dylib $(TARGET_DIR)/aarch64-apple-darwin/release/libc2pa_c.dylib ../target/x86_64-apple-darwin/release/libc2pa_c.dylib
# copy some files from the arm build to the universal build since we don't directly build this
	cp $(TARGET_DIR)/aarch64-apple-darwin/release/c2pa.h $(TARGET_DIR)/universal-apple-darwin/release/c2pa.h
	cp $(TARGET_DIR)/aarch64-apple-darwin/release/c2pa_version.txt $(TARGET_DIR)/universal-apple-darwin/release/c2pa_version.txt
	cargo run --release --bin make_zip $(TARGET_DIR)/universal-apple-darwin/release

build-release-linux-musl-x86:
	rustup target add x86_64-unknown-linux-musl
	cargo build --target=x86_64-unknown-linux-musl --release
	cargo run --release --bin make_zip $(TARGET_DIR)/x86_64-unknown-linux-musl/release

build-release-linux-musl-arm:
	rustup target add aarch64-unknown-linux-musl	
	cargo build --target=aarch64-unknown-linux-musl --release
	cargo run --release --bin make_zip $(TARGET_DIR)/aarch64-unknown-linux-musl/release


# make release
# Builds and packages a zip for c2pa_c for each platform
ifeq ($(PLATFORM), mac)
release: build-release-mac-universal
endif
ifeq ($(PLATFORM), win)
release: build-release-win
endif
ifeq ($(PLATFORM), linux)
release: build-release-linux-musl-arm
endif
