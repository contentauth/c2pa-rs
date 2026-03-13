# Release notes

Refer to the [CHANGELOG](https://github.com/contentauth/c2pa-rs/blob/main/CHANGELOG.md) for detailed changes derived from Git commit history.

## Embeddable API

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

<!-- THIS IS OUTDATED.  COMMENTING OUT FOR NOW

Language binding support


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
 |                | from_stream                        |   X  |    X   |      |       | 
 |                | from_stream_async                  |      |        |      |       | 
 |                | from_file                          |   X  |    X   |      |       | 
 |                | from_file_async                    |      |        |      |       | 
 |                | from_json                          |      |        |      |       | 
 |                | from_manifest_data_and_stream      |   X  |    X   |      |       | 
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

-->