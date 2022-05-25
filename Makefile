# Makefile to aid with local development and testing

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
	@echo $("Enforcing standard Rust code format")
	cargo fmt -- --check

check-docs:
	@echo $("Enforcing documentation syntax")
	cargo doc --no-deps --workspace --all-features

clippy:
	@echo $("Clippy checks")
	cargo clippy --all-features --all-targets -- -D warnings

test-local:
	@echo $("Running unit tests")
	cargo test --all-features

test-wasm:
	@echo $("Running unit tests in WASM build")
	cd sdk && wasm-pack test --node

test: check-format check-docs clippy test-local test-wasm
	cargo test --all-features
	@echo $("DONE")

c2patool-package:
	rm -rf target/c2patool*
	mkdir -p target/c2patool
	mkdir -p target/c2patool/sample
	cp target/release/c2patool target/c2patool/c2patool
	cp c2patool/src/README.md target/c2patool/README.md
	cp c2patool/sample/* target/c2patool/sample
	cp CHANGELOG.md target/c2patool/CHANGELOG.md
	cp sdk/tests/fixtures/IMG_0003.jpg target/c2patool/image.jpg
	cp sdk/tests/fixtures/claim.json target/c2patool/claim.json

build-release-win:
	cargo build --release

build-release-mac-arm:
	rustup target add aarch64-apple-darwin
	MACOSX_DEPLOYMENT_TARGET=11.1 cargo build --target=aarch64-apple-darwin --release

build-release-mac-x86:
	rustup target add x86_64-apple-darwin
	MACOSX_DEPLOYMENT_TARGET=10.15 cargo build --target=x86_64-apple-darwin --release

build-release-mac-universal: build-release-mac-arm build-release-mac-x86
	lipo -create -output target/release/c2patool target/aarch64-apple-darwin/release/c2patool target/x86_64-apple-darwin/release/c2patool

build-release-linux:
	cargo build --release

ifeq ($(PLATFORM), mac)
c2patool-release: build-release-mac-universal c2patool-package
	cd target && zip -r c2patool_mac.zip c2patool && cd ..
endif
ifeq ($(PLATFORM), win)
c2patool-release: build-release-win c2patool-package
	cd target && tar.exe -a -c -f c2patool_win.zip c2patool && cd ..
endif
ifeq ($(PLATFORM), linux)
c2patool-release: build-release-linux c2patool-package
	cd target && tar -czvf c2patool_linux.tar.gz c2patool && cd ..
endif

# Build and view documentation
doc: 
	cargo doc --no-deps --open

# Builds a set of test images using the make_tests example
# Outputs to release/test-images
images:
	@echo $("Generating test images")
	cargo run --release --example make_tests
