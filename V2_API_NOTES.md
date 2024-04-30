## V2 API Notes

### Goals
Provide a consistent flexible well tested API focusing on core functionality.

- Move toward a JSON + binary resources model that ports well to multiple languages.
- Eliminate multiple variations of functions for file/memory/stream, sync/async & etc.
- Have one stream based version of each function that works sync and async.
- Design APIs keeping in mind support for multiple language bindings.
- Enable sign only/verify only and no openssl configuration.
- Support Box Hash and Data Hashed signing models.
- Enable builds for cameras and other embedded environments.
- Provide a consistent model for setting runtime options.
- Write unit tests, integration tests and documentation for all the v2 APIs.
- Keep v1 to v2 porting as simple as possible.


### Resource References
A resource reference in the API is associated with a HashedUri as a superset.
- The c2pa spec refers to both a hashed-uri-map and a hashed-ext-uri-map 
- In some cases either one can be used.
- The resource reference is a superset of both. 
- It also adds local references to things like the filesystem or any abstracted storage.
I've been using the identifier field to distinguish from the url field, but they are really the same. However, the spec will only allow for JUMBF and http/https references, so if the external identifier is not http/https, it must be converted to 
a JUMBF reference before embedding into a manifest.

When defining a resource for the ManifestStoreBuilder, existing resources in other manifests may be identified via JUMBF urls. This allows a new manifest to inherit an existing thumbnail and is also used to reference parent ingredients. The API will generally do this resolution as needed so users do not need to know about JUMBF URL referencing on manifest creation.

The spec will often require adding a hashed-uri to an assertion. Since the JUMBF uris for a new manifest are not known when defining the manifest, this creates a chicken and egg scenario. We resolve this with local resource references. When constructing the JUMBF for a manifest, the api will convert all local uri references into JUMBF references and fixup the associated cross references.

URI schemes in a resource reference could take the following forms:
- self#jumbf=  an internal JUMBF reference
- file:///   a local file reference
- app://contentauth/  a working store reference
- http://  remote uri
- https:// remote secure uri

Note that the file: and app: schemes are only used in the context of ManifestStoreBuilder and will never be in JUMBF data. This is proposal, currently there is no implementation for file or app schemes and we do not yet handle http/https schemes this way.

Lack of a scheme will be interpreted as a file:/// reference when file_io is enabled, otherwise as an app: reference.

### Source asset vs Parent asset
- The source asset isn't always the parent asset.
The source asset is the asset that we will hash and sign. It can the output from an editing application that has not preserved the manifest store from the parent. In that case the application should have extracted a parent ingredient from the parent asset and added that to the manifest definition. 

- Parent asset: with a manifest store.
- Parent ingredient: generated from that parent asset (hashed and validated)
- Source asset: may be a generated rendition after edits from the parent asset (manifest?)
- Signed output which will include the source asset, and the new manifest store with parent ingredient.

If there is no parent ingredient defined, and the source has a manifest store, the sdk will generate a parent ingredient from the parent.

### Remote URLs and embedding
The default operation of c2pa signing is to embed a c2pa manifest store into an asset.
We also return the c2pa manifest store so that it can be written to a sidecar or uploaded to a remote service.
- The API supports embedding a a remote url reference into the asset. 
- The remote URL is stored in different ways depending on the asset, but is often stored in XMP data.
- The remote URL must be added to the asset before signing so that it can be hashed along with the asset.
- Not all file formats support embedding remote URLs or embedding manifests stores.
- If you embed a manifest or a remote URL, a new asset will be created with the new data embedded.
- If you don't embed, then the original asset is unmodified and there is no need to write one out.
- The remote url can be set with builder.remote_url.
- If embedding is not needed, set the builder.no_embed flag to true.


## Testing
We need a more comprehensive set of tests for the rust codebase.

The plan is to build a solid set of tests on the new streams based API.
Then we will build everything else on top of that as stable base.
The current set of unit tests are helpful but many are out of date.
I've had a long standing issue to generate the test images from clean non-c2pa images.
When we check in images with manifests, they rapidly get out of date.
We do need some set of older manifests and third party images to test with
but I'm not sure if those need to be in the SDK.

- A test assets folder with one public domain image in each asset format we support.
- A tool, like make_test_images, to generate different kinds of manifests for testing.
We should maintain an archive of the manifest_store json generated by the previous build
and compare the old build with the new ones for any significant deltas.
The tool needs to ignore changes due to new GUIDs, dates, and json object field order.

The make_test_images crate has been updated to do this by default. We may make a policy to run the test comparison nightly.
