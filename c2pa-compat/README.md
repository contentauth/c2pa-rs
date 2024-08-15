# `c2pa-compat`
A tool for generating a "compatibility snapshot" of all supported asset types with embedded and remote manifests.

## Rationale
`c2pa-rs` needs thorough tests for backwards compatibility and correctness. Currently, assets of various configuration may be periodically saved for testing. This is cumbersome for three reasons: each asset is saved with limited configuration, each asset has an explicit test, and each asset is saved manually. 

`c2pa-compat` solves this issue by creating a "compatibiity snapshot," meaning a comprehensive set of asset configurations with embedded and remote manifests, automatically generated to cover as many variants as possible for the current `c2pa-rs` version. This not only tests that we can read the manifest content the same, but also that we can properly read the manifest even if the parsers change and they are stored differently.

## How it works
When `c2pa-compat` is executed, it will create a compatibility snapshot in `sdk/tests/fixtures/compat/<VERSION>`, where `<VERSON>` represents the current `c2pa-rs` version. Take a look at what an example snapshot might look like:

    .
    ├── gif                     # Snapshot for a gif asset 
    │   ├── embedded.c2pa       # Binary C2PA manifest for embedded asset
    │   ├── embedded.json       # JSON C2PA manifest (read after signing) for embedded asset
    │   ├── embedded.patch      # Asset embedded with C2PA manifest diffed against original asset
    │   ├── remote.c2pa         # Binary C2PA manifest for remote asset
    │   ├── remote.json         # JSON C2PA manifest (read after signing), for remote manifest
    │   └── remote.patch        # Asset embedded with remote URL diffed against original asset
    ├── jpeg
    │   └── ...
    ├── mp3
    │   └── ...
    ├── png
    │   └── ...
    ├── riff
    │   └── ...
    ├── svg
    │   └── ...
    ├── tiff
    │   └── ...
    ├── compat-details.json     # Details about all of the assets in the snapshot
    └── manifest.json           # Original JSON manifest used for signing

> [!NOTE]
> Some asset types (e.g. SVG) do not support remote manifests.

Starting from the top, `compat-details.json` stores important information, such as the certificate, private key, algorithm, and details of each asset (e.g. path, size, etc.). This information will be used in an integration test, which will be described later on.

`manifest.json` stores the original manifest used for signing remote/embedded manifests. This manifest corresponds to `c2pa-compat/src/full-manifest.json` and holds as many fields as possible for each `c2pa-rs` version (needs to be constantly updated).  

Getting into each asset folder, there will be either 3 or 6 files, depending on if the asset supports remote manifests. Each folder will contain an embedded/remote binary C2PA manifest, a JSON manifest which is the result of reading the signed asset, and a patch file. The JSON manifest is used in the integration test for the expected comparison, and the patch file is a diffed and compressed binary file of the original asset containing the signed manifest (diffing drastically reduces storage size).

With this information, an integration test located at `sdk/tests/compat.rs` will attempt to read each asset and verify the result against the expected JSON manifest. If they match, compatibility ensured, if not, something went wrong. A potential issue that may occur is when a new version of `c2pa-rs` introduces a new field, removes an old field, or changes the location of an existing field. Currently, there is no method to verify this. The integration test will ignore unknown fields that aren't available in both JSON manifests (the expected and read value). In the case where some fields/values may change after each sign (e.g. UUIDs, XMP IDs, etc.), the integration test will filter these values into something like "[URN_UUID]" or "[XMP_ID]". For more information, [read here](https://github.com/contentauth/c2pa-rs/pull/513#issuecomment-2291265657).

## How to maintain it
- `src/full-manifest.json` should always contain every possible manifest feature for every release.
- If an "unstable" field (a field that changes between signing) changes, add it to the `Stabilizer` in `sdk/tests/compat.rs`. 
