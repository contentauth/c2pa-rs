# Content Credential Proposal

## Background
We have long struggled with the need to save and later continue to edit C2PA manifests.
The spec doesn't call out a specific way to do this. It only allows for appending new signed manifests.
But there are many scenarios where we need a work in progress.
- Validating an ingredient once and saving it for later use.
- Applications that want to keep track of changes over time and export later.
- Frequent small edits over time without creating a long chain of signed manifests

We created the concept of a Builder archive to help address this. But the archive is a new format
that needs to be documented and supported over time as content changes.

## Proposal
A new proposal is that we always store data as standard JUMBF c2pa manifest stores.

The same format can be used for signed manifests, working stores and saved ingredients. 

- in binary JUMBF (application/c2pa) format
- the JUMBF may be embedded in a file, in the cloud or in a sidecar.c2pa 
- We MAY want to allow the JUMBF manifest to not be signed or associated with an asset.


## Goals

1) Provide a way to save validated ingredients so they can be added to Builders later.
2) Archive the current state of a Builder and restore it later to continue work.

For Ingredients - you can create a Builder and add ingredients to it. This builder can then be signed and saved either embedded in content or standalone as a .c2pa. Later you can use Reader to read the saved asset. Any ingredient in the Reader can be added to a Builder using builder.add_ingredient_from_reader(reader, ingredient_uri); // note there should be a shorthand for using the parent ingredient.

For Builder archives - Sign and save a manifest, either embedded or sidecar.  If you want to continue editing a saved manifest, then use Reader to read it, and then use reader.to_builder() (or Builder::from_reader?()) to convert it back into an editable manifest.

- Note that this will work when reading any content. You can always extract an ingredient to a Builder.


- The signature here can be local and does not need to be on a trust list. The purpose is to be able to detect any tampering of the data. But you could also use a trusted signature.


- You can store the c2pa data as a .c2pa sidecar without modifying the source. The dest file can be a data sink.

- signing the bits of the source image and capturing a thumbnail are optional.

### Code support

- Adds the ability to box hash sign a .c2pa asset
- Allows add_ingredient_from_stream with a .c2pa asset.
- Builder.to_archive() generates a .c2pa asset.
- Builder.from_archive() reads from a .c2pa asset (or the older archive format)

#### To capture, save and add an individual ingredient
- Capture an ingredient by adding an ingredient to a new builder and then signing/archiving it.
- Add a captured .c2pa archived ingredient using add_ingredient_from_stream. This will use the parent ingredient in the archive as the ingredient added.


### Test cases

1) Validate an ingredient without a manifest, store in Builder and save.
2) Validate an ingredient with a manifest, store in Builder and save.
3) Read and display these saved Builders
4) Create new Builder, add component Ingredient from Reader from asset.
5) Add two ingredients to a builder, save, read, and then add both to new Builder and save/read.
6) Create Builder and add opened Ingredient, save, read and convert to a Builder, add componentOf Ingredient, sign

## Content Credentials API

A future lower level API will wrap the Claim and Store structures providing a single object interface for C2PA. This would have the same underlying JUMBF object, but would not provide the declarative JSON api. It would also not have the higher level Ingredient and Resource APIs. Assertions would be added directly to a the content_credential and read directly from it. This will include direct access to CBOR and Binary assertions. Ingredient assertions would be built by first adding binary assertions for thumbnails and icons and then adding those references directly to the a Ingredient assertion before adding it. Content Credentials can be added to Content Credentials as Ingredients and Ingredient read as another Credential. In this model there are no Builder, Reader or Ingredient objects.

- Content Credentials will always be created with Settings and be the common context.
- Content Credentials will interact only with Assets which will abstract data i/o.

## Asset objects (not directly related to the above)

An Asset object creates a semi-persistent layer over the asset_io traits. Currently we parse entire asset every time we need to access information about it. We have separate passes for XMP, JUMBF, Offset/box generation & etc..

- The details of file i/o, in memory, streamed, or remote web access are handled here. 
- This will parse the asset, extract XMP, and C2PA data and allow 
- ReadOnlyAsset - Will generate and keep a map of asset offsets/ boxes and extract remote_url, xmp and c2pa data.
- ReadWriteAsset - ReadOnlyAsset + write updated remote_url, xmp and c2pa_data.

```let source = Asset::from_stream(format, stream)?;
let source = Asset::from_file(path:: Path)?;

let cc = ContentCredential::new(settings)

cc.read_asset(source)

cc.sign_asset(dest)

set cc2 = ContentCredential::new(settings)

cc2.add_ingredient(cc)
```

