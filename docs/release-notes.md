# Release notes

Refer to the [CHANGELOG](https://github.com/contentauth/c2pa-rs/blob/main/CHANGELOG.md) for detailed changes derived from Git commit history.

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
