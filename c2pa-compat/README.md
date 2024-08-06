# `c2pa-compat`
A tool for generating a compatibility snapshot of all asset types with remote and embedded manifests.

These snapshots are typically created every release and saved to `sdk/tests/fixtures/compat/<VERSION>` for each c2pa-rs version. They are used in the compatibility tests found in `sdk/tests/compat.rs`.

`src/full-manifest.json` should always contain every possible manifest feature for every release.
