# Migrating From C2PA v1 Claim Signing

C2PA v1 claim signing was deprecated in **0.92.0** and removed in **0.93.0**.
Signing with `claim_version` set to `1` now fails with an error. This change
does not affect reading or validating existing C2PA v1 claims, including using
them as ingredients.

Signing support is consolidated on C2PA v2 rather than maintaining both claim
formats for new signatures.

The removal follows the [deprecation policy](deprecation-policy.md): 0.92.x still
signs v1 claims but logs a deprecation warning.

## Migration

C2PA v2 signing is already supported and is the default. In a JSON manifest
definition, remove `"claim_version": 1` or replace it with `"claim_version": 2`.
In Rust, use `ManifestDefinition::default()`'s `claim_version: None` or set
`claim_version: Some(2)` instead of `Some(1)`.

Ensure any assertions in the definition satisfy the C2PA v2 requirements; in
particular, author actions with `c2pa.actions.v2` rather than the v1
`c2pa.actions` assertion. Test the updated definition by signing an asset and
validating the result.

`Reader::into_builder()` returns an error for a v1 manifest, because the result
could only be re-signed as a v1 claim. This also applies to
`Builder::with_archive()` on an archive that holds a v1 claim, such as one
written from a builder with `claim_version` set to `1`. Rebuild the manifest
with a v2 claim instead: for an asset, add it as a parent ingredient of a new
manifest; for an archive, recreate the builder from its definition and write a
new archive.
