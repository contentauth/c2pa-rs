# Release notes

### 1.0

The version 1.0 release has a new API that replaces the previous methods of reading and writing C2PA data, which are still supported but are deprecated.  

The goals of this release are to provide a consistent, flexible, well-tested API; specifically:

- Move toward a JSON + binary resources model that ports well to multiple languages.
- Eliminate multiple variations of functions for file/memory/stream, sync/async & etc.
- Have one stream-based version of each function that works sync and async.
- Design APIs that work well for multiple language bindings.
- Enable sign-only/verify-only and support usage without OpenSSL.
- Support Box Hash and Data Hashed signing models.
- Enable builds for cameras and other embedded environments.
- Provide a consistent model for setting runtime options.
- Write thorough unit tests, integration tests and documentation; see [Testing](testing.md) for details.
- Keep porting as simple as possible.



To use this API, enable the `unstable_api` feature; for example:

```
c2pa = {version="0.33.1", features=["unstable_api"]}
```

The new API focuses on streaming I/O and supports the following structs:
- [Builder](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html)
- [Reader](https://docs.rs/c2pa/latest/c2pa/struct.Reader.html)
- [ManifestDefinition](https://docs.rs/c2pa/latest/c2pa/struct.ManifestDefinition.html)

### Resource references

A resource reference in the API is associated with a HashedUri as a superset.
- The C2PA specification refers to both a hashed-uri-map and a hashed-ext-uri-map 
- In some cases either one can be used.
- The resource reference is a superset of both. 
- It also adds local references to things like the filesystem or any abstracted storage.
I've been using the identifier field to distinguish from the url field, but they are really the same. However, the specification will only allow for JUMBF and http/https references, so if the external identifier is not http/https, it must be converted to 
a JUMBF reference before embedding into a manifest.

When defining a resource for the ManifestStoreBuilder, existing resources in other manifests may be identified via JUMBF urls. This allows a new manifest to inherit an existing thumbnail and is also used to reference parent ingredients. The API will generally do this resolution as needed so users do not need to know about JUMBF URL referencing on manifest creation.

The specification often requires adding a hashed-uri to an assertion. Since the JUMBF uris for a new manifest are not known when defining the manifest, this creates a chicken and egg scenario. We resolve this with local resource references. When constructing the JUMBF for a manifest, the api will convert all local uri references into JUMBF references and fixup the associated cross references.

URI schemes in a resource reference could take the following forms:
- self#jumbf=  an internal JUMBF reference
- file:///   a local file reference
- app://contentauth/  a working store reference
- http://  remote uri
- https:// remote secure uri

Note that the file: and app: schemes are only used in the context of ManifestStoreBuilder and will never be in JUMBF data. This is proposal, currently there is no implementation for file or app schemes and we do not yet handle http/https schemes this way.

Lack of a scheme will be interpreted as a file:/// reference when file_io is enabled, otherwise as an app: reference.

### Source asset vs parent asset

The source asset isn't always the parent asset.
The source asset is the asset that we will hash and sign. It can the output from an editing application that has not preserved the manifest store from the parent. In that case the application should have extracted a parent ingredient from the parent asset and added that to the manifest definition. 

- Parent asset: with a manifest store.
- Parent ingredient: generated from that parent asset (hashed and validated)
- Source asset: may be a generated rendition after edits from the parent asset (manifest?)
- Signed output which will include the source asset, and the new manifest store with parent ingredient.

If there is no parent ingredient defined, and the source has a manifest store, the sdk will generate a parent ingredient from the parent.

### Remote URLs and embedding

The default operation of C2PA signing is to embed a C2PA manifest store into an asset.
We also return the C2PA manifest store so that it can be written to a sidecar or uploaded to a remote service.
- The API supports embedding a remote url reference into the asset. 
- The remote URL is stored in different ways depending on the asset, but is often stored in XMP data.
- The remote URL must be added to the asset before signing so that it can be hashed along with the asset.
- Not all file formats support embedding remote URLs or embedding manifests stores.
- If you embed a manifest or a remote URL, a new asset will be created with the new data embedded.
- If you don't embed, then the original asset is unmodified and there is no need to write one out.
- The remote url can be set with builder.remote_url.
- If embedding is not needed, set the builder.no_embed flag to true.

## Language bindings for 1.0 API methods

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
