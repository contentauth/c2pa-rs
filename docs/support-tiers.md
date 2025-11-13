# Support tiers for C2PA Rust SDK products

The CAI open-source projects define three levels of support for various build configurations.
These levels of support are inspired by the Rust language project’s [Target Tier Policy](https://doc.rust-lang.org/rustc/target-tier-policy.html) and uses similar language.

The CAI team will determine at its discretion – with input from various internal and external client teams – which configurations are supported at which tier.
A change in tier support will always be announced with at least a minor semantic version bump.

## Definition of a build configuration

A _build configuration_ will specify:

* A Rust build tuple (e.g. `aarch64-apple-darwin` for ARM-based MacOS)
  * Unless otherwise specified this is executed on the `(platform)-latest` runner image [provided by GitHub](https://github.com/actions/runner-images).
* A Rust version specifier, which will be one of:
  * `stable` ([the most recent “stable” release](https://blog.rust-lang.org/releases/latest))
  * `MSRV` (the oldest release supported by this project)
* A feature flag set, which will be either `all` (all flags defined in the c2pa-rs crate) or a list of specific features.
* A crypto library flag, which will be either `rust_native_crypto` or `openssl`, depicting which cryptogrpahy stack is being built and tested.
* On platforms where relevant, a C library identifier (i.e. `glibc` or `musl`).

## Tier 1A

Tier 1A configurations are the most actively supported.
A Tier 1A configuration will:

* Have continuous integration tests that build and pass for this build configuration on every commit to `main`.
A pull request will be blocked if the tests do not pass.
* This test suite is the most complete set of tests available for this component.
* Tier 1A configurations _may_ also have built artifacts generated for each versioned release.
The location where these artifacts are published will be documented.

These requirements are enforced in the [Tier 1A workflow](/.github/workflows/tier-1a.yml).

### Tier 1A for c2pa-rs

* **Ubuntu:** `x86_64-unknown-linux-gnu`, Rust `stable`, `all` features, `openssl` | `rust_native_crypto`, `glibc`
* **Wasm:** `wasm32-unknown-unknown`, Rust `stable`, `fetch_remote_manifests` feature, `rust_native_crypto`
* **WASI:** `wasm32-wasip2`, Rust `nightly-2025-08-25`, `all` features

### Tier 1A for c2pa-c-ffi

* **Ubuntu:** `x86_64-unknown-linux-gnu`, Rust `stable`, `all` features, `openssl` | `rust_native_crypto`, `glibc`

### Tier 1A for c2patool

* **Ubuntu:** `x86_64-unknown-linux-gnu`, Rust `stable`, `all` features, `openssl` | `rust_native_crypto`, `glibc`

## Tier 1B

A Tier 1B configuration will:

* Have continuous integration tests that build and pass for every versioned release.
A release will be blocked if the tests do not pass.
* This test suite should be the same as for Tier 1A.
* Tier 1B configurations _may_ also have built artifacts generated for each versioned release.
The location where these artifacts are published will be documented.

A decision to place a configuration in Tier 1B is typically made because the CI test suite for this configuration adds significantly to the time required to complete a PR validation and the likelihood of finding issues that are specific to this configuration is deemed low.

These requirements are enforced in the [Tier 1B workflow](/.github/workflows/tier-1b.yml).

### Tier 1B for c2pa-rs

* **Ubuntu:** `x86_64-unknown-linux-gnu`, Rust `MSRV`, `all` features, `openssl` | `rust_native_crypto`, `glibc`
* **Ubuntu (ARM):** `aarch-unknown-linux-gnu`, Rust `stable` | `MSRV`, `all` features, `openssl` | `rust_native_crypto`, `glibc`
* **MacOS:** `aarch64-apple-darwin`, Rust `stable` | `MSRV`, `all` features, `openssl` | `rust_native_crypto`
* **Windows:** `x86_64-pc-windows-msvc`, Rust `stable` | `MSRV`, `all` features, `openssl` | `rust_native_crypto`

### Tier 1B for c2pa-c-ffi

* **Ubuntu:** `x86_64-unknown-linux-gnu`, Rust `MSRV`, `all` features, `openssl` | `rust_native_crypto`, `glibc`
* **Ubuntu (ARM):** `aarch-unknown-linux-gnu`, Rust `stable` | `MSRV`, `all` features, `openssl` | `rust_native_crypto`, `glibc`
* **MacOS:** `aarch64-apple-darwin`, Rust `stable` | `MSRV`, `all` features, `openssl` | `rust_native_crypto`
* **Windows:** `x86_64-pc-windows-msvc`, Rust `stable` | `MSRV`, `all` features, `openssl` | `rust_native_crypto`

### Tier 1B for c2patool

* **Ubuntu:** `x86_64-unknown-linux-gnu`, Rust `MSRV`, `all` features, `openssl` | `rust_native_crypto`, `glibc`
* **Ubuntu (ARM):** `aarch-unknown-linux-gnu`, Rust `stable` | `MSRV`, `all` features, `openssl` | `rust_native_crypto`, `glibc`
* **MacOS:** `aarch64-apple-darwin`, Rust `stable` | `MSRV`, `all` features, `openssl` | `rust_native_crypto`
* **Windows:** `x86_64-pc-windows-msvc`, Rust `stable` | `MSRV`, `all` features, `openssl` | `rust_native_crypto`

## Tier 2

A Tier 2 configuration will:

* Have continuous integration tests that _build_ for this build configuration for each versioned release.
A release will be blocked if the build fails.
This test suite may be triggered for a PR by adding the `release-readiness` label to the PR.
* A test suite that is a subset of the Tier 1 test suite may be defined for this build configuration.
If it exists, a release will be blocked if the test suite fails.
* Tier 2 should generally be avoided, but may necessary when a fully-native execution environment is not available to us.
(As an example, we can run iOS code in a _simulator,_ but we do not currently pay for hosted iPhone test machines that we can use from GitHub, so iOS native builds can not be in Tier 1.)
* If built artifacts are generated for this build configuration, they should be built for every versioned release and the location should be documented.

These requirements are enforced in the [Tier 2 workflow](/.github/workflows/tier-2.yml).

### Tier 2 for c2pa-rs

* **Ubuntu:** `x86_64-unknown-linux-gnu`, Rust `stable`, no default features, `openssl`, `glibc`
* **iOS:** `aarch64-apple-ios` | `x86_64-apple-ios` | `aarch64-apple-ios-sim`, `file_io`, `rust_native_crypto`
* **Android:** `aarch64-linux-android` | `armv7-linux-androideabi` | `i686-linux-android` | `x86_64-linux-android`, `file_io`, `rust_native_crypto`

### Tier 2 for c2pa-c-ffi

* **Ubuntu:** `x86_64-unknown-linux-gnu`, Rust `stable`, `file_io`, `rust_native_crypto`, `glibc`, **build artifacts**
* **MacOS:** `aarch64-apple-darwin`, Rust `stable`, `file_io`, `rust_native_crypto`, **build artifacts**
* **Windows:** `x86_64-pc-windows-msvc`, Rust `stable`, `file_io`, `rust_native_crypto`, **build artifacts**
* **iOS:** `aarch64-apple-ios` | `x86_64-apple-ios` | `aarch64-apple-ios-sim`, `file_io`, `rust_native_crypto`
* **Android:** `aarch64-linux-android` | `armv7-linux-androideabi` | `i686-linux-android` | `x86_64-linux-android`, `file_io`, `rust_native_crypto`

Build artifacts are posted to the [releases](https://github.com/contentauth/c2pa-rs/releases) page for each versioned release.

## Tier 3

A Tier 3 configuration is experimental and minimally supported.
It has been shown to work at one time, but no special effort is made to ensure that such a configuration can be built on an ongoing basis.

There are no current Tier 3 configurations.
