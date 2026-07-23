# Support tiers for C2PA Rust SDK products

The CAI open-source projects define three levels of support for various build configurations.
These levels of support are inspired by the Rust language project’s [Target Tier Policy](https://doc.rust-lang.org/rustc/target-tier-policy.html) and use similar language.

The CAI team will determine, at its discretion and with input from various internal and external client teams, which configurations are supported at which tier.
The CAI team will always announce a change in tier support with at least a minor semantic version bump.

## Definition of a build configuration

A _build configuration_ will specify:

* A Rust build tuple (e.g. `aarch64-apple-darwin` for ARM-based macOS)
  * Unless otherwise specified this is executed on the `(platform)-latest` runner image [provided by GitHub](https://github.com/actions/runner-images).
* A Rust version specifier, which will be one of:
  * `stable` ([the most recent “stable” release](https://blog.rust-lang.org/releases/latest))
  * `MSRV` (the oldest release supported by this project)
* A feature flag set, which will be either `all` (all flags defined in the c2pa-rs crate) or a list of specific features.
* A crypto library flag, which will be either `rust_native_crypto` or `openssl`, specifying the cryptography stack to build and test.
* On platforms where relevant, a C library identifier (i.e. `glibc` or `musl`).

## How the tiers gate merges and releases

The tiers map directly onto the branching model in the [release process](release-process.md):

* **Tier 1A is the merge gate for `main`.** Every pull request must pass Tier 1A before it can merge, on `main` and on every release-line and release-candidate branch.
* **Tiers 1B and 2 are additionally required for any pull request targeting a release-line (`stable`, `v0.x`) or release-candidate (`*-rc*`) branch.** This includes [backport PRs](release-process.md#backport-bot), release-candidate bake bugfixes, and the [`release-plz` release PR](release-process.md#release-plz). In short, anything headed for a published (or soon-to-be-published) artifact must pass all three tiers.
* **All three tiers also run against `main` on a daily schedule** (a nightly run), so regressions that only surface under the heavier Tier 1B/2 configurations are caught even when no release-targeting PR is open.
* On a `main` pull request you can run the full Tier 1B + 2 suite on demand by adding the `check-release` label, which is handy for assessing release readiness before a change is backported.

See [validation gating](release-process.md#validation-gating) in the release process for how this fits the overall flow.

## Tier 1A

Tier 1A configurations are the most actively supported.
A Tier 1A configuration will:

* Have continuous integration tests that build and pass for this build configuration on every commit to `main`, as well as to the release-line (`stable`, `v0.x`) and release-candidate (`*-rc*`) branches described in the [release process](release-process.md).
Failing tests block the pull request. This is the merge gate for `main` (see [How the tiers gate merges and releases](#how-the-tiers-gate-merges-and-releases)).
* This test suite is the most complete set of tests available for this component.
* Tier 1A configurations _may_ also have built artifacts generated for each versioned release.
The location where these artifacts are published will be documented.

The [Tier 1A workflow](../.github/workflows/tier-1a.yml) enforces these requirements.

### Tier 1A for c2pa-rs

* **Ubuntu:** `x86_64-unknown-linux-gnu`, Rust `stable`, `all` features, `openssl` | `rust_native_crypto`, `glibc`
* **Windows (ARM):** `aarch64-pc-windows-msvc`, Rust `stable`, `all` features, `openssl` | `rust_native_crypto`
* **Wasm:** `wasm32-unknown-unknown`, Rust `stable`, `fetch_remote_manifests` feature, `rust_native_crypto`
* **WASI:** `wasm32-wasip2`, Rust `nightly-2026-01-16`, `all` features

### Tier 1A for c2pa-c-ffi

* **Ubuntu:** `x86_64-unknown-linux-gnu`, Rust `stable`, `all` features, `openssl` | `rust_native_crypto`, `glibc`
* **Windows (ARM):** `aarch64-pc-windows-msvc`, Rust `stable`, `all` features, `openssl` | `rust_native_crypto`

### Tier 1A for c2patool

* **Ubuntu:** `x86_64-unknown-linux-gnu`, Rust `stable`, `all` features, `openssl` | `rust_native_crypto`, `glibc`
* **Windows (ARM):** `aarch64-pc-windows-msvc`, Rust `stable`, `all` features, `openssl` | `rust_native_crypto`

## Tier 1B

A Tier 1B configuration will:

* Have continuous integration tests that build and pass for every versioned release.
Failing tests block the release.
In practice these run on every pull request targeting a release-line or release-candidate branch, including backport PRs and the `release-plz` release PR, and on every push to a release-candidate branch during a train's bake. You can also invoke them on a `main` PR by adding the `check-release` label. (See [How the tiers gate merges and releases](#how-the-tiers-gate-merges-and-releases).)
* This test suite should be the same as for Tier 1A.
* Tier 1B configurations _may_ also have built artifacts generated for each versioned release.
The location where these artifacts are published will be documented.

A decision to place a configuration in Tier 1B is typically made because the CI test suite for this configuration adds significantly to the time required to complete a PR validation and the likelihood of finding issues that are specific to this configuration is deemed low.

The [Tier 1B workflow](../.github/workflows/tier-1b.yml) enforces these requirements.

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
A failing build blocks the release.
Like Tier 1B, these run on every pull request targeting a release-line or release-candidate branch (including backport PRs and the `release-plz` release PR), and you can also invoke them on a `main` PR with the `check-release` label. (See [How the tiers gate merges and releases](#how-the-tiers-gate-merges-and-releases).)
* A test suite that is a subset of the Tier 1 test suite may be defined for this build configuration.
If it exists, a failing test suite blocks the release.
* Generally avoid Tier 2, but it may be necessary when a fully-native execution environment is not available to us.
(As an example, we can run iOS code in a _simulator,_ but we do not currently pay for hosted iPhone test machines that we can use from GitHub, so iOS native builds can not be in Tier 1.)
* If built artifacts are generated for this build configuration, they should be built for every versioned release and the location should be documented.

The [Tier 2 workflow](../.github/workflows/tier-2.yml) enforces these requirements.

### Tier 2 for c2pa-rs

* **Ubuntu:** `x86_64-unknown-linux-gnu`, Rust `stable`, no default features, `openssl`, `glibc`
* **iOS:** `aarch64-apple-ios` | `x86_64-apple-ios` | `aarch64-apple-ios-sim`, `file_io`, `rust_native_crypto`
* **Android:** `aarch64-linux-android` | `armv7-linux-androideabi` | `i686-linux-android` | `x86_64-linux-android`, `file_io`, `rust_native_crypto`

### Tier 2 for c2pa-c-ffi

* **Ubuntu:** `x86_64-unknown-linux-gnu`, Rust `stable`, `file_io`, `rust_native_crypto`, `glibc`, **build artifacts**
* **Emscripten:** `wasm32-unknown-emscripten`, Rust `stable`, `file_io`, `fetch_remote_manifests`, `rust_native_crypto`, **build artifacts**
* **MacOS:** `aarch64-apple-darwin`, Rust `stable`, `file_io`, `rust_native_crypto`, **build artifacts**
* **Windows:** `x86_64-pc-windows-msvc`, Rust `stable`, `file_io`, `rust_native_crypto`, **build artifacts**
* **iOS:** `aarch64-apple-ios` | `x86_64-apple-ios` | `aarch64-apple-ios-sim`, `file_io`, `rust_native_crypto`, **build artifacts**
* **Android:** `aarch64-linux-android` | `armv7-linux-androideabi` | `i686-linux-android` | `x86_64-linux-android`, `file_io`, `rust_native_crypto`, **build artifacts**

Build artifacts are posted to the [releases](https://github.com/contentauth/c2pa-rs/releases) page for each versioned release.

## Tier 3

A Tier 3 configuration is experimental and minimally supported.
It has been shown to work at one time, but no special effort is made to ensure that such a configuration can be built on an ongoing basis.

There are no current Tier 3 configurations.
