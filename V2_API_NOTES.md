## V2 API Notes

### Resource References
A resource reference in the API is associated with a HashedUri as a superset.
The c2pa spec refers to both a hashed-uri-map and a hashed-ext-uri-map 
In some cases either one can be used.
The resource reference is a superset of both. 
It also adds local references to things like the filesystem or any abstracted storage.
I've been using the identifier field to distinguish from the url field, but they are really the same. However, the spec will only allow for jumbf and http/https references, so if the external identifier is not http/https, it must be converted to 
a jumbf reference before embedding into a manifest.

When defining a resource for the ManifestStoreBuilder, existing resources in other manifests may be identified via jumbf urls. This allows a new manifest to inherit an existing thumbnail and is also used to reference parent ingredients. The API will generally do this resolution as needed so users do not need to know about jumbf url referencing on manifest creation.

The spec will often require adding a hashed-uri to an assertion. Since the jumbf uris for a new manifest are not known when defining the manifest, this creates a chicken and egg scenario. We resolve this with local resource references. When constructing the jumbf for a manifest, the api will convert all local uri references into jumbf references and fixup the associated cross references.

uri schemes in a resource reference can take the following forms:
self#jumbf=  an internal jumbf reference
file:///   a local file reference
app://contentauth/  a working store reference
http://  remote uri
https:// remote secure uri

note that the file: and app: schemes are only used in the context of ManifestStoreBuilder and will never be in jumbf data

lack of a scheme will be interpreted as a file:/// reference when file_io is enabled, otherwise as an app: reference.

### Source asset vs Parent asset
The source asset isn't always the parent asset:
The source asset is the asset that we will hash and sign. It can the output from an editing application that has not preserved the manifest store from the parent. In that case the application should have extracted a parent ingredient from the parent asset and added that to the manifest definition. 
So there's an parent asset with a manifest store
A parent ingredient generated from that parent asset (hashed and validated)
The source, which is a generated rendition after edits from the parent asset
The signed output which will include the source asset, and the new manifest store with parent ingredient.

If there is no parent ingredient defined, and the source has a manifest store, the sdk will generate a parent ingredient from the parent