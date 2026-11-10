# Release notes

Refer to the [CHANGELOG](https://github.com/contentauth/c2pa-rs/blob/main/CHANGELOG.md) for detailed changes derived from Git commit history.

## Changes from v0.90.16 to v0.90.23

This analysis uses the published release notes, merged changes, and tagged
source for the [v0.90.16 to v0.90.23 comparison](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.90.16...c2pa-v0.90.23).
The comparison treats v0.90.16 as the baseline; its changes are included below
for context, not counted as new in v0.90.17 or later. Release dates are UTC.
This section describes the **v0.90 release line**, not additional changes
implemented on this v0.87 branch.

The interval combines security hardening, validation correctness, new
ZIP/document-format support, cross-platform interoperability, and build/release
maintenance. It is not a security-only update. The SDK's declared Rust minimum
remains **1.88.0** at both endpoints. The companion CLI advances from
`c2patool` 0.27.16 to 0.27.23; the range contains no changes to C FFI source files.
Native bindings still need to be rebuilt to incorporate updated SDK code and
embedded TLS dependencies.

### v0.90.16 baseline - 27 August 2026

[Published release](https://github.com/contentauth/c2pa-rs/releases/tag/c2pa-v0.90.16).
Already present at the start of this comparison:

- Reject BMFF Merkle-map locations that overflow the `u32` chunk index
  ([#2500](https://github.com/contentauth/c2pa-rs/pull/2500)).
- Update `h2` for RUSTSEC-2026-0258 and resolve the Rust 1.98
  `chunks_exact_to_as_chunks` Clippy lint
  ([#2515](https://github.com/contentauth/c2pa-rs/pull/2515),
  [#2531](https://github.com/contentauth/c2pa-rs/pull/2531)).
- Include the underlying `Error::AssertionEncoding` source in error messages,
  honor the `ingredient` argument in filtering functions, allow v3 ingredient
  `validationResults` to serialize without `activeManifest`, and remove a
  debugging call
  ([#2549](https://github.com/contentauth/c2pa-rs/pull/2549),
  [#2546](https://github.com/contentauth/c2pa-rs/pull/2546),
  [#2537](https://github.com/contentauth/c2pa-rs/pull/2537),
  [#2552](https://github.com/contentauth/c2pa-rs/pull/2552)).

### v0.90.17 - 3 September 2026

[Published release](https://github.com/contentauth/c2pa-rs/releases/tag/c2pa-v0.90.17).
The main security-hardening batch is
[#2579](https://github.com/contentauth/c2pa-rs/pull/2579):

- **BMFF manifest pairing:** reject an update manifest without its paired
  original manifest instead of silently ignoring the still-signed update.
- **BMFF Merkle-map lookup:** use the original `local_id` key with a checked
  lookup, avoiding a panic when a large identifier truncates to a different
  track-map key. This is separate from the chunk-index overflow fix in v0.90.16.
- **Resource extraction:** sanitize paths derived from untrusted manifest
  resource labels before `Reader::to_folder` writes them. Reject traversal and
  unsafe paths rather than writing outside the destination directory, while
  constructing valid paths consistently on Windows.
- **JPEG XL parsing:** reject boxes whose declared extent exceeds the asset,
  before an oversized declared box can drive an unbounded allocation.
- **Validation integrity:** prevent ingredient-attested statuses from canceling
  genuine active-manifest failures during status de-duplication, including
  failures logged while an ingredient scope is active.

Also update the locked `chacha20` version from yanked 0.10.1 to 0.10.2
([#2560](https://github.com/contentauth/c2pa-rs/pull/2560)), use an
organization-owned crates.io publishing token
([#2383](https://github.com/contentauth/c2pa-rs/pull/2383)), and lower dangling
hashed-URI diagnostics from error to debug logging without removing the
corresponding validation failure
([#2565](https://github.com/contentauth/c2pa-rs/pull/2565)).

**Consumer impact:** malformed assets can now fail explicitly where an update
was previously ignored, a resource path escaped extraction, or a validation
failure was suppressed. Lower log severity does not mean validation succeeded.

### v0.90.18 - 4 September 2026

[Published release](https://github.com/contentauth/c2pa-rs/releases/tag/c2pa-v0.90.18).
CAWG identity signer-payload checks now recognize actual hard-binding assertion
labels rather than accepting any label beginning with `c2pa.hash.`
([#2581](https://github.com/contentauth/c2pa-rs/pull/2581)).
For example, `c2pa.hash.fake` no longer satisfies the required hard-binding
reference. This tightens identity validation, not TLS certificate trust.

### v0.90.19 - 4 September 2026

[Published release](https://github.com/contentauth/c2pa-rs/releases/tag/c2pa-v0.90.19).
Handle ingredient manifests that share a label but have different content:
the first conflicting copy receives version 1 instead of failing because no
previous conflict version exists; subsequent conflicts increment the version
([#2595](https://github.com/contentauth/c2pa-rs/pull/2595)).
This implements the C2PA 2.4 section 18.16.12 copying rule and allows ingredient
histories arriving through different paths to coexist.

### v0.90.20 - 4 September 2026

[Published release](https://github.com/contentauth/c2pa-rs/releases/tag/c2pa-v0.90.20).
Add ZIP asset reading/writing and a Collection Data Hash assertion, including
EPUB, Office Open XML, OpenDocument, and OpenXPS support
([#2596](https://github.com/contentauth/c2pa-rs/pull/2596)).

The ZIP handler embeds the manifest at `META-INF/content_credential.c2pa`.
Collection hashing binds individual file entries and the ZIP central directory;
the new assertion and handler are integrated into signing and validation.
This is **new asset-format functionality**, distinct from using ZIP internally
for builder archives. It must not be inferred to exist on v0.87 merely because
that branch's ZIP dependency is upgraded.

### v0.90.21 - 9 September 2026

[Published release](https://github.com/contentauth/c2pa-rs/releases/tag/c2pa-v0.90.21).
Identity assertion validation now uses the caller's `Context` settings instead
of constructing a new default context
([#2604](https://github.com/contentauth/c2pa-rs/pull/2604)).
Caller-configured `cawg_trust` policy, including its allowed list, therefore
reaches the identity-certificate trust check. The regression test exercises
the public `Reader` path with identity assertion decoding enabled.

**Consumer impact:** applications configuring CAWG trust can get different,
policy-correct trust results. This fix concerns identity-signing certificates;
it is separate from the HTTPS server trust changes in v0.90.23.

### v0.90.22 - 10 September 2026

[Published release](https://github.com/contentauth/c2pa-rs/releases/tag/c2pa-v0.90.22).
Normalize collection-hash path separators to `/` during generation and
verification, including Windows-style backslashes
([#2625](https://github.com/contentauth/c2pa-rs/pull/2625)).
Regression fixtures cover ZIPs signed on Linux, macOS, and Windows; separate
checks ensure path normalization does not hide a hash mismatch.

CI also installs the cross-compilation tool with `cargo install cross --locked`
in the beta-preflight and Tier 1B workflows, using the tool's own lockfile
instead of resolving a fresh dependency set
([#2626](https://github.com/contentauth/c2pa-rs/pull/2626)).

### v0.90.23 - 10 November 2026

[Published release](https://github.com/contentauth/c2pa-rs/releases/tag/c2pa-v0.90.23).
Two main backports restore current-tooling compatibility and update HTTPS trust:

- **Crypto and archive compatibility**
  ([#3047](https://github.com/contentauth/c2pa-rs/pull/3047)):
  migrate `ecdsa` to 0.17 and all three NIST curve crates to 0.14 together,
  use curve-native PKCS#8 decoding and P-521 SPKI decoding, forward getrandom
  0.4 support for browser Wasm, and adapt archive/ZIP asset handling to ZIP 9.
  P-521 Rust-native signing becomes deterministic RFC6979. All-curve signer
  regressions check signature lengths, verification, and tampered-message
  rejection. The SDK keeps its existing crypto API and Rust 1.88 minimum
  rather than adopting the extracted `c2pa_raw_crypto` crate.
- **HTTPS trust remediation**
  ([#3043](https://github.com/contentauth/c2pa-rs/pull/3043)):
  native HTTP features require `webpki-roots >= 1.0.11` and
  `rustls-webpki >= 0.103.16`. These remove eMudhra trust anchors and reject
  compromised intermediate keys, including Sectigo cross-signs. Offline tests
  check both root removal and rejection even if an issuer is explicitly trusted.
  Rebuild and redistribute native applications/bindings; updating only the OS
  trust store does not replace the embedded verifier/root bundle. C2PA
  signing-certificate trust is unchanged; custom HTTP resolvers, browsers, and
  WASI hosts manage their own TLS policy.

Other tooling changes fix the OCSP Rust 1.99 Clippy diagnostic and the
`create_signer` rustdoc link. The final maintenance CI change allows only
`clippy::result_large_err` while retaining `-Dwarnings`, avoiding a public
Error API change; it replaces the intermediate per-file allowances rather
than adding three independent runtime fixes. Release/backport workflows also
switch GitHub access to the organization-owned release token
([token change](https://github.com/contentauth/c2pa-rs/commit/2e4e07759144f9cb0abfbdd353e510771fc6c39b),
[final Clippy change](https://github.com/contentauth/c2pa-rs/commit/48f363c4cd10ca10bf24058ad6931096bf2e5c6f)).

### Dependency versions and backport boundaries

These are **resolved versions in the tagged lockfiles**, not necessarily the
minimum versions required by the manifests:

| Dependency | v0.90.16 | v0.90.23 |
| --- | --- | --- |
| `chacha20` | 0.10.1 | 0.10.2 |
| `ecdsa` | 0.16.9 | 0.17.0 |
| `p256` / `p384` / `p521` | 0.13.2 / 0.13.1 / 0.13.3 | 0.14.0 / 0.14.0 / 0.14.0 |
| `crypto-bigint` | 0.5.5 | 0.7.11 |
| `zip` | 8.6.0 | 9.5.0 |
| `rustls` | 0.23.43 | 0.23.46 |
| `rustls-webpki` | 0.103.15 | 0.103.16 |
| `webpki-roots` | 1.0.9 | 1.0.11 |
| `tokio` | 1.53.1 | 1.54.1 |

The v0.90.23 tooling prerequisite was validated with ZIP 9.0.4 and Tokio 1.53.3;
the [release commit](https://github.com/contentauth/c2pa-rs/commit/9702451cbe99ea8817547b45567fcb66f4c054d2)
subsequently refreshed the lockfile to ZIP 9.5.0 and Tokio 1.54.1. The current
v0.87 backport retains the prerequisite's ZIP 9.0.4 and Tokio 1.53.3 versions,
not the final v0.90.23 lockfile wholesale.

Only the applicable v0.90.23 patches are included in this branch, as described
in the [v0.87 scope](#v087-maintenance-backport-scope) below. Documenting
v0.90.16-v0.90.22 here does **not** imply that their security fixes, CAWG behavior,
ingredient-collision handling, ZIP asset support, or collection-path fixes have
all been backported. The additional dependency-security fixes and remaining
limitations are listed below.

## v0.87 maintenance backport scope

This maintenance branch starts at `c2pa-v0.87.0` and backports the changes
introduced in `c2pa-v0.90.23`: eMudhra TLS distrust, coordinated Rust-native ECDSA
dependency updates, ZIP archive compatibility, and the accompanying tooling,
documentation, and release-credential fixes. It does not import newer SDK
features or all security fixes from the intervening releases. It additionally
updates the dependencies needed to pass the security audit and repairs
compatibility with the current CI toolchain. The public API and Rust 1.88 minimum
are unchanged. Native consumers must rebuild and redistribute their binaries to
receive the TLS updates; see [usage](usage.md).

### Additional dependency-security and CI fixes

The maintenance lockfile now resolves the following older dependency issues,
without advisory exemptions:

| Dependency | Previous version | Resolved version | Known issue |
| --- | --- | --- | --- |
| `anyhow` | 1.0.102 | 1.0.104 | [RUSTSEC-2026-0190](https://rustsec.org/advisories/RUSTSEC-2026-0190) |
| `crossbeam-epoch` | 0.9.18 | 0.9.21 | [RUSTSEC-2026-0204](https://rustsec.org/advisories/RUSTSEC-2026-0204): invalid pointer dereference in pointer formatting |
| `h2` | 0.4.14 | 0.4.20 | [RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258): unbounded empty DATA frames |
| `lopdf` | 0.39.0 | 0.44.0 | [RUSTSEC-2026-0187](https://rustsec.org/advisories/RUSTSEC-2026-0187): stack overflow on deeply nested PDF objects |
| `quick-xml` | 0.39.4 | 0.41.0 | [RUSTSEC-2026-0194](https://rustsec.org/advisories/RUSTSEC-2026-0194) and [RUSTSEC-2026-0195](https://rustsec.org/advisories/RUSTSEC-2026-0195): XML CPU and memory exhaustion |
| `ttf-parser` | 0.25.1 | Removed through `lopdf` update | [RUSTSEC-2026-0192](https://rustsec.org/advisories/RUSTSEC-2026-0192): unmaintained |
| `spin` | 0.9.8 | 0.9.9 | Yanked dependency version |

The PDF feature also requires `time` 0.3.55 so consumers with older lockfiles do
not select a version lacking `lopdf`'s required date-formatting API. Native and
atomics-enabled WebAssembly builds retain `lopdf`'s parallel processing;
single-threaded WebAssembly and WASI disable its default features to avoid
thread-spawn panics. XMP text extraction is adapted to `quick-xml` 0.41 while
preserving UTF-8 decoding and the existing escaped-entity behavior.

`async-trait` 0.1.92 fixes generated `must_use` attributes rejected by the current
Clippy. Other fixes remove redundant formatting borrows, simplify iteration and
control flow, and correct the redundant `TextSelector` rustdoc link. The existing
Clippy size-warning allowances are retained rather than boxing public enum
variants or changing the error API. Regression tests cover legacy archive
resources, invalid paths and indices, invalid ECDSA private keys, invalid stapled
OCSP responses in both sync and async paths, and XMP text compatibility.

### Older known issues not addressed by this backport

Earlier ID3 decoder and BMFF sample-reader hardening from the v0.90 line is also
outside this backport. This branch is not security-equivalent to v0.90.23 and is
not a substitute for upgrading to a supported release containing those fixes.

## Version 0.79.4

### Deprecation of thread-local settings APIs

Release 0.79.4 deprecates all legacy thread-local configuration APIs in favor of explicit [`Context`](https://docs.rs/c2pa/latest/c2pa/struct.Context.html)-based equivalents. These are not breaking changes: All deprecated methods retain their original behavior and continue to work, but will produce compiler warnings.

### Rust API

`Builder::default()` and `Reader::default()` are now the idiomatic way to construct with default settings, replacing the more verbose `Builder::from_context(Context::new())` and `Reader::from_context(Context::new())`.

The following methods are now deprecated:

| Deprecated | Use instead |
|---|---|
| `Builder::new()` | `Builder::default()` |
| `Builder::from_json(json)` | `Builder::default().with_definition(json)` |
| `Builder::from_archive(stream)` | `Builder::default().with_archive(stream)` |
| `Reader::from_stream(format, stream)` | `Reader::default().with_stream(format, stream)` |
| `Reader::from_file(path)` | `Reader::default().with_file(path)` |
| `Reader::from_manifest_data_and_stream(...)` | `Reader::default().with_manifest_data_and_stream(...)` |
| `Reader::from_fragmented_files(path, fragments)` | `Reader::default().with_fragmented_files(path, fragments)` |
| `Settings::from_toml(toml)` | `Settings::new().with_toml(toml)` |
| `Settings::from_string(str, format)` | `Settings::new().with_json(str)` or `Settings::new().with_toml(str)` |
| `Settings::signer()` | Configure a signer on a `Context` and pass it to `Builder::from_context` |

To use custom settings, create a `Context` with `Context::new().with_settings(...)` and pass it to `Builder::from_context(context)` or `Reader::from_context(context)`.

### C FFI

The following C API functions are deprecated:

| Deprecated | Use instead |
|---|---|
| `c2pa_load_settings` | `c2pa_settings_new()` + `c2pa_context_builder_set_settings()` |
| `c2pa_reader_from_stream` | `c2pa_reader_from_context()` |
| `c2pa_reader_from_file` | `c2pa_reader_from_context()` |
| `c2pa_reader_from_manifest_data_and_stream` | `c2pa_reader_from_context()` + `c2pa_reader_with_manifest_data_and_stream()` |
| `c2pa_builder_from_json` | `c2pa_builder_from_context()` + `c2pa_builder_set_definition()` |
| `c2pa_builder_from_archive` | `c2pa_builder_from_context()` + `c2pa_builder_with_archive()` |
| `c2pa_signer_from_settings` | `c2pa_context_builder_set_signer()` |
| `c2pa_read_file`, `c2pa_read_ingredient_file`, `c2pa_sign_file` | Context-based equivalents |
| `c2pa_reader_free`, `c2pa_builder_free`, `c2pa_string_free`, `c2pa_manifest_bytes_free`, `c2pa_signer_free`, `c2pa_release_string`, `c2pa_signature_free` | `c2pa_free()` |

C and C++ headers now emit compiler deprecation warnings when deprecated functions are called.

## Version 0.77.0

### Embeddable API

Release [0.77.0](https://github.com/contentauth/c2pa-rs/releases/tag/c2pa-v0.77.0) adds a new embeddable manifest API with Context/Settings, CAWG, and BMFF.v3 support. For details, see [Embeddable signing API](embeddable-api.md).

### API Changes for C2PA 2.2

`Reader` has some new methods: 
- `validation_state()` returns `ValidationState`, which can be `Invalid`, `Valid` or `Trusted`. Use this method instead of checking for `validation_status() = None`.
- `validation_results()` returns `ValidationResults`, which is a more complete form of `ValidationStatus` and returns `success`, `informational`, and `failure` codes for the active manifest and ingredients. `ValidationStatus` is deprecated in favor of `ValidationResults`.

`Ingredient` now supports a `validation_results()` method and a `validation_results` field.

An `AssetType` assertion is now supported.
<!-- Can we say more about this? ASK MAURICE -->

### C2PA v2 claims

> [!NOTE]
> The library now supports [C2PA v2 claims](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_claims) by default. V2 claims have many new checks and status codes.  Additionally:

- The `title()` and `format()` methods of both `Manifest` and `Ingredient` objects now return an `Option<String>` because in v2 claims, `title` is optional and `format` does not exist.
- The first `action` must be `c2pa.created` or `c2pa.opened` (which requires an ingredient). 

> [!WARNING]
> Implementations should not generate deprecated v1 claims.  If needed, though, you can generate v1 claims by setting the `Builder` manifest definition `claim_version` field to `1`.
