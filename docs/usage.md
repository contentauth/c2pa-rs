# Using the Rust library

## Supported platforms

The C2PA Rust library has been tested on:

* Windows (Intel only)
* MacOS (Intel and Apple silicon)
* Ubuntu Linux (64-bit Intel and ARM v8)
* WebAssembly (Wasm); see [Building for WebAssembly](project-contributions.md#building-for-webassembly) for details.

## Requirements

The C2PA Rust library requires **Rust version 1.86.0** or newer.

To use the library, add this to your `Cargo.toml`:

```toml
[dependencies]
c2pa = "0.45.2"
```

To read or write a manifest file, add the `file_io` dependency to your `Cargo.toml`.

<!-- Check whether thumbnail generation has been removed -->

Add the `add_thumbnails` dependency to generate thumbnails for JPEG and PNG files. For example:

```
c2pa = { version = "0.45.2", features = ["file_io", "add_thumbnails"] }
```

## Features

You can enable any of the following features:

- **default_http** *(enabled by default)*: Enables default http features for sync and async http resolvers (`http_req`, `http_reqwest`, `http_wasi`, and `http_std`).
- **openssl** *(enabled by default)*: Use the vendored `openssl` implementation for cryptography.
- **rust_native_crypto**: Use Rust native cryptography.
- **add_thumbnails**: Adds the [`image`](https://github.com/image-rs/image) crate to enable auto-generated thumbnails, if possible and enabled in settings.
- **fetch_remote_manifests**: Fetches remote manifests over the network when no embedded manifest is present and that option is enabled in settings.
- **file_io**: Enables APIs that use filesystem I/O.
- **json_schema**: Adds the [`schemars`](https://github.com/GREsau/schemars) crate to derive JSON schemas for JSON-compatible structs.
- **pdf**: Enables basic PDF read support.
- **http_ureq**: Enables `ureq` for sync HTTP requests.
- **http_reqwest**: Enables `reqwest` for async HTTP requests.
- **http_reqwest_blocking**: Enables the `blocking` feature of `reqwest` for sync HTTP requests.
- **http_wasi**: Enables `wasi` for sync HTTP requests on WASI.
- **http_wstd**: Enables `wstd` for async HTTP requests on WASI.

> [!NOTE]
> If both `rust_native_crypto` and `openssl` are enabled, then only `rust_native_crypto` will be enabled.
> To avoid including `openssl` as a dependency, disable default features when using `rust_native_crypto`.

### Features no longer supported

The following features are no longer supported:

* **v1_api**. The old API that this enabled has been removed.
* **serialize_thumbnails**. Thumbnails can be serialized by accessing resources directly.

### Resource references

A resource reference is a superset of a `HashedUri`, which the C2PA specification refers to as both `hashed-uri-map` and  `hashed-ext-uri-map`. In some cases either can be used.

A resource reference also adds local references to things like the file system or any abstracted storage. You can use the identifier field to distinguish from the URL field, but they are really the same. However, the specification will only allow for JUMBF and HTTP(S) references, so if the external identifier is not HTTP(S), it must be converted to a JUMBF reference before embedding into a manifest.

When defining a resource for the [ManifestStoreBuilder](https://docs.rs/c2pa/latest/c2pa/struct.Builder.html), existing resources in other manifests may be identified via JUMBF URLs. This allows a new manifest to inherit an existing thumbnail and is also used to reference parent ingredients. The API will generally do this resolution as needed, so you do not need to know about JUMBF URL references when creating a manifest.

The specification often requires adding a `HashedUri` to an assertion. Since the JUMBF URIs for a new manifest are not known when defining the manifest, this creates a "chicken and egg" scenario, resolved with local resource references. When constructing the JUMBF for a manifest, the library converts all local URI references into JUMBF references and corrects the the associated cross references.

URI schemes in a resource reference can have the following forms:

- `self#jumbf` - An internal JUMBF reference
- `file:///` - A local file reference
- `app://contentauth/` - A working store reference
- `http://` - Remote URI
- `https://` - Remote secure URI

Note that the `file:` and `app:` schemes are only used in the context of `ManifestStoreBuilder` and will never be in JUMBF data. This is proposal, currently there is no implementation for file or app schemes and we do not yet handle HTTP/HTTPS schemes this way.

<!-- Is the above still true? "This is proposal, currently there is no implementation" -->

When `file_io` is enabled, the lack of a scheme will be interpreted as a `file:///` reference, otherwise as an `app:` reference.

### Source asset versus parent asset

The source asset isn't always the parent asset: The source asset is the asset that is hashed and signed. It can be the output from an editing application that has not preserved the manifest store from the parent. In that case, the application should have extracted a parent ingredient from the parent asset and added that to the manifest definition.

- Parent asset: with a manifest store.
- Parent ingredient: generated from that parent asset (hashed and validated)
- Source asset: may be a generated rendition after edits from the parent asset (manifest?)
- Signed output which will include the source asset, and the new manifest store with parent ingredient.

If there is no parent ingredient defined, and the source has a manifest store, the sdk will generate a parent ingredient from the parent.

### Remote URLs and embedding

The default operation of C2PA signing is to embed a C2PA manifest store into an asset. The library also returns the C2PA manifest store so that it can be written to a sidecar or uploaded to a remote service.

- The API supports embedding a remote URL reference into the asset.
- The remote URL is stored in different ways depending on the asset, but is often stored in XMP data.
- The remote URL must be added to the asset before signing so that it can be hashed along with the asset.
- Not all file formats support embedding remote URLs or embedding manifests stores.
- If you embed a manifest or a remote URL, a new asset will be created with the new data embedded.
- If you don't embed, then the original asset is unmodified and there is no need to write one out.
- The remote URL can be set with `builder.remote_url`.
- If embedding is not needed, set the `builder.no_embed` flag to `true`.

## Example code

The [sdk/examples](https://github.com/contentauth/c2pa-rs/tree/main/sdk/examples) directory contains some minimal example code.  The [client/client.rs](https://github.com/contentauth/c2pa-rs/blob/main/sdk/examples/client/client.rs) is the most instructive and provides and example of reading the contents of a manifest store, recursively displaying nested manifests.
