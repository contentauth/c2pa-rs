# Migrating From C2PA v1 Claim Signing

C2PA v1 claim signing is deprecated in **0.92.0** and will be removed in
**0.93.0**, scheduled for **mid-January 2027**. Version 0.92 continues to sign
v1 claims, with a deprecation warning. This change will not affect reading or
validating existing C2PA v1 claims, including using them as ingredients.

Signing support is being consolidated on C2PA v2 rather than maintaining both
claim formats for new signatures.

The deprecation and subsequent removal land on `main` only, with no backport to
the active release line, following the [deprecation policy](deprecation-policy.md).

## Migration

C2PA v2 signing is already supported and is the default. In a JSON manifest
definition, remove `"claim_version": 1` or replace it with `"claim_version": 2`.
In Rust, use `ManifestDefinition::default()`'s `claim_version: None` or set
`claim_version: Some(2)` instead of `Some(1)`.

Ensure any assertions in the definition satisfy the C2PA v2 requirements; in
particular, author actions with `c2pa.actions.v2` rather than the v1
`c2pa.actions` assertion. Test the updated definition by signing an asset and
validating the result before upgrading to 0.93.
