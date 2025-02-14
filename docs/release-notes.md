# Release notes

Refer to the [CHANGELOG](https://github.com/contentauth/c2pa-rs/blob/main/CHANGELOG.md) for detailed changes derived from Git commit history.

## New API 

The current release has a new API that replaces the previous methods of reading and writing C2PA data, which are still supported but will be deprecated.  

The new API focuses on streaming I/O and supports the following structs:
- [Builder](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html)
- [Reader](https://docs.rs/c2pa/latest/c2pa/struct.Reader.html)
- [ManifestDefinition](https://docs.rs/c2pa/latest/c2pa/struct.ManifestDefinition.html)

### Goals

The goals of this release are to provide a consistent, flexible, well-tested API; specifically:

- Move toward a JSON + binary resources model that ports well to multiple languages.
- Eliminate multiple variations of functions for file/memory/stream, sync/async & etc.
- Have one stream-based version of each function that works sync and async.
- Design APIs that work well for multiple language bindings.
- Enable sign-only/verify-only and support usage without OpenSSL.
- Support Box Hash and Data Hashed signing models.
- Enable builds for cameras and other embedded environments.
- Provide a consistent model for setting runtime options.
- Keep porting as simple as possible.

### Enabling 

These features are now standard and the `unstable_api` feature is no longer used.

You can still use the deprecated API by enabling the `v1_api` feature; for example:

```
c2pa = {version="0.45.2", features=["v1_api"]}
```

### API Changes for C2PA 2.1

Support for claims as described in the [C2PA 2.1 specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_claims) is experimental at this point and not fully implemented yet. 

`Reader` has a new method: `validation_state()` which returns the a `ValidationState`.
The `ValidationState` can be `Invalid`, `Valid` or `Trusted`.
Use this method instead of checking for `validation_status()` = `None`.

`Reader` also now has a `validation_results()` method that returns `ValidationResults`.
`ValidationResults` are a more complete form of `ValidationStatus` and will return `success`, `informational` and `failure` codes for the active manifest and ingredients. `ValidationStatus` will be deprecated in favor of `ValidationResults`.

The `Manifest` `title` is optional and `format` is not supported in v2 claims, so these methods now return an `Option<String>` and may not appear in serialized JSON.

The `Ingredient` `title` and `format` are optional in v3 ingredients, so these methods now return an `Option<String>` and may not appear in serialized JSON.

`Ingredient` now supports a `validation_results` method and a `validation_results` field.

An `AssetType` assertion is now supported.

A `claim_version` field is now allowed in a manifest definition for `Builder` and, if set to `2` will generate v2 claims.

In v2 claims, the first `action` must be `c2pa.created` or `c2pa.opened`. 

There are many more checks and status codes added for v2 claims.

## Language binding support

<!-- Not sure where this really belongs... -->

 | Module         | Method                             |  C++ | Python | WASM | Node  |
 | --------       | ---------------------------------- |----- | ------ | ---- | ----- |
 | Builder        |                                    |      |        |      |       |
 |                | new                                |      |        |      |       |          
 |                | from_json                          |   X  |   X    |   X  |       |
 |                | set_claim_generator_info           |      |        |      |       |  
 |                | set_format                         |      |        |      |       | 
 |                | set_remote_url                     |      |   X    |      |       | 
 |                | set_no_embed                       |      |   X    |      |       | 
 |                | set_thumbnail                      |      |        |      |       | 
 |                | add_assertion                      |      |        |      |       | 
 |                | add_assertion_json                 |      |        |      |       | 
 |                | add_ingredient_from_stream         |   X  |    X   |      |       | 
 |                | add_ingredient_from_stream_async   |      |        |      |       | 
 |                | add_ingredient                     |      |        |      |       | 
 |                | add_resource                       |   X  |    X   |      |       | 
 |                | to_archive                         |   X  |    X   |      |       | 
 |                | from_archive                       |   X  |    X   |      |       | 
 |                | data_hashed_placeholder            |      |        |      |       | 
 |                | sign_data_hashed_embeddable        |      |        |      |       | 
 |                | sign_data_hashed_embeddable_async  |      |        |      |       | 
 |                | sign_box_hashed_embeddable         |      |        |      |       | 
 |                | sign_box_hashed_embeddable_async   |      |        |      |       | 
 |                | sign                               |   X  |    X   |      |       | 
 |                | sign_async                         |      |        |      |       | 
 |                | sign_fragmented_files              |      |        |      |       | 
 |                | sign_file                          |   X  |    X   |      |       | 
 | Reader         |                                    |      |        |      |       | 
 |                | from_stream                        |      |    X   |      |       | 
 |                | from_stream_async                  |      |        |      |       | 
 |                | from_file                          |      |    X   |      |       | 
 |                | from_file_async                    |      |        |      |       | 
 |                | from_json                          |      |        |      |       | 
 |                | from_manifest_data_and_stream      |      |    X   |      |       | 
 |                | from_manifest_data_and_stream_async|      |        |      |       | 
 |                | from_fragment                      |      |        |      |       | 
 |                | from_fragment_async                |      |        |      |       | 
 |                | from_fragmented_files              |      |        |      |       | 
 |                | json                               |      |        |      |       | 
 |                | validation_status                  |      |        |      |       | 
 |                | active_manifest                    |      |    X   |      |       | 
 |                | active_label                       |      |        |      |       | 
 |                | iter_manifests                     |      |        |      |       | 
 |                | get_manifest                       |      |    X   |      |       | 
 |                | resource_to_stream                 |  X   |    X   |      |       | 
 |                | to_folder                          |      |        |      |       | 
 | CallbackSigner |                                    |      |        |      |       | 
 |                | new                                |      |        |      |       | 
 |                | set_tsa_url                        |      |        |      |       | 
 |                | set_context                        |      |        |      |       | 
 |                | ed25519_sign                       |      |        |      |       | 
