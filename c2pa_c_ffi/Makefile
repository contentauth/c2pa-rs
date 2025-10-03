# Makefile for local testing and automated builds

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

TARGET_DIR := ../target

CARGO_BUILD_FLAGS = --release -p c2pa-c-ffi --no-default-features --features "rust_native_crypto, file_io"

IPHONEOS_DEPLOYMENT_TARGET ?= 15.0

# Workaround for cross installation issue with static-mut-refs warning
# See: https://github.com/cross-rs/cross/issues/1561
# This clears RUSTFLAGS to prevent -D warnings from failing the cross installation
CROSS_INSTALL_RUSTFLAGS = RUSTFLAGS=""

# Helper function to create a zip file
define make_zip
	set -e; \
	echo "Reading version from $(1)/c2pa.h"; \
	if [ "$(PLATFORM)" = "win" ]; then \
		VERSION=$$(findstr "^// Version:" $(1)/c2pa.h | awk -F": " "{print \$$2}"); \
	else \
		VERSION=$$(grep '^// Version:' $(1)/c2pa.h | sed 's/^\/\/ Version: //'); \
	fi; \
	mkdir -p $(TARGET_DIR)/artifacts $(1)/include $(1)/lib; \
	cp $(1)/c2pa.h $(1)/include/; \
	if echo "$(2)" | grep -q "ios"; then \
		cp $(1)/libc2pa_c.a $(1)/lib/; \
	else \
		find $(1) -name "libc2pa_c.*" ! -name "*.a" ! -path "*/deps/*" -exec cp {} $(1)/lib/ \;; \
	fi; \
	(cd $(1) && zip -9 -r ../../artifacts/c2pa-v$${VERSION}-$(2).zip include lib); \
	echo "Zip file created: $(TARGET_DIR)/artifacts/c2pa-v$${VERSION}-$(2).zip"
endef

check-format:
	cargo +nightly fmt -- --check

clippy:
	cargo clippy --features "rust_native_crypto, file_io" -- -D warnings

test-local:
	cargo test --features "rust_native_crypto, file_io"

# Full local validation, build and test all features including wasm
# Run this before pushing a PR to pre-validate
test: check-format clippy test-local

fmt:
	cargo +nightly fmt

# These are for building the c2patool release bin on various platforms
release-win-x86_64:
	rustup update stable-msvc
	rustup target add x86_64-pc-windows-msvc
	cargo build --target=x86_64-pc-windows-msvc $(CARGO_BUILD_FLAGS)

release-win-aarch64:
	rustup update stable-msvc
	rustup target add aarch64-pc-windows-msvc
	cargo build --target=aarch64-pc-windows-msvc $(CARGO_BUILD_FLAGS)
#  powershell -ExecutionPolicy Bypass -File ../../setup-rust-openssl.ps1

release-mac-arm:
	rustup target add aarch64-apple-darwin
	MACOSX_DEPLOYMENT_TARGET=11.1 cargo build --target=aarch64-apple-darwin $(CARGO_BUILD_FLAGS)
	install_name_tool -id @rpath/libc2pa_c.dylib $(TARGET_DIR)/aarch64-apple-darwin/release/libc2pa_c.dylib
	strip -x $(TARGET_DIR)/aarch64-apple-darwin/release/libc2pa_c.dylib
	@$(call make_zip,$(TARGET_DIR)/aarch64-apple-darwin/release,aarch64-apple-darwin)

release-mac-x86:
	rustup target add x86_64-apple-darwin
	MACOSX_DEPLOYMENT_TARGET=10.15 cargo build --target=x86_64-apple-darwin $(CARGO_BUILD_FLAGS)
	install_name_tool -id @rpath/libc2pa_c.dylib $(TARGET_DIR)/x86_64-apple-darwin/release/libc2pa_c.dylib
	strip -x $(TARGET_DIR)/x86_64-apple-darwin/release/libc2pa_c.dylib
	@$(call make_zip,$(TARGET_DIR)/x86_64-apple-darwin/release,x86_64-apple-darwin)

release-mac-universal: release-mac-arm release-mac-x86
	rm -rf $(TARGET_DIR)/universal-apple-darwin
	mkdir -p $(TARGET_DIR)/universal-apple-darwin/release
	lipo -create -output $(TARGET_DIR)/universal-apple-darwin/release/libc2pa_c.dylib $(TARGET_DIR)/aarch64-apple-darwin/release/libc2pa_c.dylib $(TARGET_DIR)/x86_64-apple-darwin/release/libc2pa_c.dylib
	cp $(TARGET_DIR)/aarch64-apple-darwin/release/c2pa.h $(TARGET_DIR)/universal-apple-darwin/release/c2pa.h
	install_name_tool -id @rpath/libc2pa_c.dylib $(TARGET_DIR)/universal-apple-darwin/release/libc2pa_c.dylib
	dsymutil $(TARGET_DIR)/universal-apple-darwin/release/libc2pa_c.dylib

	cd $(TARGET_DIR)/universal-apple-darwin/release && \
		zip -r9 libc2pa_c.dylib.dSYM.zip libc2pa_c.dylib.dSYM && \
		rm -rf libc2pa_c.dylib.dSYM && \
		ls -l

	strip -x $(TARGET_DIR)/universal-apple-darwin/release/libc2pa_c.dylib
	@$(call make_zip,$(TARGET_DIR)/universal-apple-darwin/release,universal-apple-darwin)

release-linux-gnu-x86:
	rustup target add x86_64-unknown-linux-gnu
	cargo build --target=x86_64-unknown-linux-gnu  $(CARGO_BUILD_FLAGS)
	@$(call make_zip,$(TARGET_DIR)/x86_64-unknown-linux-gnu/release,x86_64-unknown-linux-gnu)

release-linux-gnu-arm:
	rustup target add aarch64-unknown-linux-gnu
	sudo apt-get update && sudo apt-get install -y gcc-aarch64-linux-gnu libc6-dev-arm64-cross
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc cargo build --target=aarch64-unknown-linux-gnu  $(CARGO_BUILD_FLAGS)
	@$(call make_zip,$(TARGET_DIR)/aarch64-unknown-linux-gnu/release,aarch64-unknown-linux-gnu)

# iOS physical devices
release-ios-arm64:
	rustup target add aarch64-apple-ios
	SDKROOT=$$(xcrun -sdk iphoneos --show-sdk-path) \
	IPHONEOS_DEPLOYMENT_TARGET=$(IPHONEOS_DEPLOYMENT_TARGET) \
	cargo build --target=aarch64-apple-ios $(CARGO_BUILD_FLAGS)
	@$(call make_zip,$(TARGET_DIR)/aarch64-apple-ios/release,aarch64-apple-ios)

# iOS simulators running on Intel Macs
release-ios-x86_64:
	rustup target add x86_64-apple-ios
	SDKROOT=$$(xcrun -sdk iphonesimulator --show-sdk-path) \
	IPHONEOS_DEPLOYMENT_TARGET=$(IPHONEOS_DEPLOYMENT_TARGET) \
	cargo build --target=x86_64-apple-ios $(CARGO_BUILD_FLAGS)
	@$(call make_zip,$(TARGET_DIR)/x86_64-apple-ios/release,x86_64-apple-ios)

# iOS simulators running on Apple Silicon Macs
release-ios-arm64-sim:
	rustup target add aarch64-apple-ios-sim
	SDKROOT=$$(xcrun -sdk iphonesimulator --show-sdk-path) \
	IPHONEOS_DEPLOYMENT_TARGET=$(IPHONEOS_DEPLOYMENT_TARGET) \
	cargo build --target=aarch64-apple-ios-sim $(CARGO_BUILD_FLAGS)
	@$(call make_zip,$(TARGET_DIR)/aarch64-apple-ios-sim/release,aarch64-apple-ios-sim)

# 64-bit Android devices
release-android-arm64:
	$(CROSS_INSTALL_RUSTFLAGS) cargo install cross --git https://github.com/cross-rs/cross
	cross build --target=aarch64-linux-android $(CARGO_BUILD_FLAGS)
	@$(call make_zip,$(TARGET_DIR)/aarch64-linux-android/release,aarch64-linux-android)

# 32-bit Android devices
release-android-armv7:
	$(CROSS_INSTALL_RUSTFLAGS) cargo install cross --git https://github.com/cross-rs/cross
	cross build --target=armv7-linux-androideabi $(CARGO_BUILD_FLAGS)
	@$(call make_zip,$(TARGET_DIR)/armv7-linux-androideabi/release,armv7-linux-androideabi)

# 32-bit x86 Android emulators
release-android-x86:
	$(CROSS_INSTALL_RUSTFLAGS) cargo install cross --git https://github.com/cross-rs/cross
	cross build --target=i686-linux-android $(CARGO_BUILD_FLAGS)
	@$(call make_zip,$(TARGET_DIR)/i686-linux-android/release,i686-linux-android)

# 64-bit x86 Android emulators
release-android-x86_64:
	$(CROSS_INSTALL_RUSTFLAGS) cargo install cross --git https://github.com/cross-rs/cross
	cross build --target=x86_64-linux-android $(CARGO_BUILD_FLAGS)
	@$(call make_zip,$(TARGET_DIR)/x86_64-linux-android/release,x86_64-linux-android)


# make release
# Builds and packages a zip for c2pa_c_ffi folder (c2pa-c-ffi) for each platform

# If TARGET is explicity set, use that
ifdef TARGET
# Desktop targets
ifeq ($(TARGET),x86_64-pc-windows-msvc)
release: release-win-x86_64
else ifeq ($(TARGET),aarch64-pc-windows-msvc)
release: release-win-aarch64
else ifeq ($(TARGET),aarch64-apple-darwin)
release: release-mac-arm
else ifeq ($(TARGET),x86_64-apple-darwin)
release: release-mac-x86
else ifeq ($(TARGET),universal-apple-darwin)
release: release-mac-universal
else ifeq ($(TARGET),x86_64-unknown-linux-gnu)
release: release-linux-gnu-x86
else ifeq ($(TARGET),aarch64-unknown-linux-gnu)
release: release-linux-gnu-arm
# Mobile targets
else ifeq ($(TARGET),aarch64-apple-ios)
release: release-ios-arm64
else ifeq ($(TARGET),x86_64-apple-ios)
release: release-ios-x86_64
else ifeq ($(TARGET),aarch64-apple-ios-sim)
release: release-ios-arm64-sim
else ifeq ($(TARGET),aarch64-linux-android)
release: release-android-arm64
else ifeq ($(TARGET),armv7-linux-androideabi)
release: release-android-armv7
else ifeq ($(TARGET),i686-linux-android)
release: release-android-x86
else ifeq ($(TARGET),x86_64-linux-android)
release: release-android-x86_64
endif
endif

# If TARGET is not set, use platform detection
ifndef TARGET
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
ifeq ($(ARCH), x86_64)
release: release-linux-gnu-x86
endif
ifeq ($(ARCH), aarch64)
release: release-linux-gnu-arm
endif
endif
endif
