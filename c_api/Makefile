# Makefile to aid with local development and testing
# This is not required for automated builds

# Detect architecture
ARCH := $(shell uname -m)
# Detect OS
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
release-win:
	rustup target add x86_64-pc-windows-msvc
	cargo build --target=x86_64-pc-windows-msvc --release
	cargo run --release --bin make_zip $(TARGET_DIR)/x86_64-pc-windows-msvc/release

release-mac-arm:
	rustup target add aarch64-apple-darwin
	MACOSX_DEPLOYMENT_TARGET=11.1 cargo build --target=aarch64-apple-darwin --release
	cargo run --release --bin make_zip $(TARGET_DIR)/aarch64-apple-darwin/release

release-mac-x86:
	rustup target add x86_64-apple-darwin
	MACOSX_DEPLOYMENT_TARGET=10.15 cargo build --target=x86_64-apple-darwin --release
	cargo run --release --bin make_zip $(TARGET_DIR)/x86_64-apple-darwin/release

release-mac-universal: release-mac-arm release-mac-x86
	rm -rf $(TARGET_DIR)/universal-apple-darwin
	mkdir -p $(TARGET_DIR)/universal-apple-darwin/release
	lipo -create -output $(TARGET_DIR)/universal-apple-darwin/release/libc2pa_c.dylib $(TARGET_DIR)/aarch64-apple-darwin/release/libc2pa_c.dylib ../target/x86_64-apple-darwin/release/libc2pa_c.dylib
# copy some files from the arm build to the universal build since we don't directly build this
	cp $(TARGET_DIR)/aarch64-apple-darwin/release/c2pa.h $(TARGET_DIR)/universal-apple-darwin/release/c2pa.h
	cp $(TARGET_DIR)/aarch64-apple-darwin/release/c2pa_version.txt $(TARGET_DIR)/universal-apple-darwin/release/c2pa_version.txt
	cargo run --release --bin make_zip $(TARGET_DIR)/universal-apple-darwin/release

release-linux-gnu-x86:
	rustup target add x86_64-unknown-linux-gnu
	cargo build --target=x86_64-unknown-linux-gnu --release
	cargo run --release --bin make_zip $(TARGET_DIR)/x86_64-unknown-linux-gnu/release

release-linux-gnu-arm:
	rustup target add aarch64-unknown-linux-gnu
	cargo build --target=aarch64-unknown-linux-gnu --release
	cargo run --release --bin make_zip $(TARGET_DIR)/aarch64-unknown-linux-gnu/release

release-linux-musl-x86:
	rustup target add x86_64-unknown-linux-musl
	cargo build --target=x86_64-unknown-linux-musl --release
	cargo run --release --bin make_zip $(TARGET_DIR)/x86_64-unknown-linux-musl/release

release-linux-musl-arm:
	rustup target add aarch64-unknown-linux-musl	
	cargo build --target=aarch64-unknown-linux-musl --release
	cargo run --release --bin make_zip $(TARGET_DIR)/aarch64-unknown-linux-musl/release


# make release
# Builds and packages a zip for c_api for each platform
ifeq ($(PLATFORM), mac)
release: release-mac-universal
endif
ifeq ($(PLATFORM), win)
ifeq ($(ARCH), x86_64)
release: release-win
endif
ifeq ($(ARCH), aarch64)
echo "No release build for aarch64 on Windows"
endif
endif
ifeq ($(PLATFORM), linux)
release: release-linux-gnu-x86 release-linux-gnu-arm
endif
