# Fix: `created` flag dropped for metadata assertions on read-back

## Context

`Reader` reports `created() == false` for every metadata assertion, even when the assertion was
signed into the claim's `created_assertions` list. The JUMBF on disk is correct; only the Rust-struct
view that `Reader` hands back is wrong.

`Manifest::from_store` computes the flag once at
[sdk/src/manifest.rs:552](sdk/src/manifest.rs#L552):

```rust
let created = claim_assertion.assertion_type() == ClaimAssertionType::Created;
```

Three branches consume it — actions ([:593](sdk/src/manifest.rs#L593)) and the two `_` fallbacks
([:666](sdk/src/manifest.rs#L666), [:675](sdk/src/manifest.rs#L675)). Two metadata branches build a
`ManifestAssertion` and never call `.set_created(created)`:

```rust
labels::ASSERTION_METADATA => {                                   // :611
    let assertion_metadata = AssertionMetadata::from_assertion(assertion)?;
    let manifest_assertion =
        ManifestAssertion::from_assertion(&assertion_metadata)?
            .set_instance(claim_assertion.instance());
    manifest.assertions.push(manifest_assertion);
}
label if label.ends_with(".metadata") => {                        // :618
    let metadata = Metadata::from_assertion(assertion)?;
    let manifest_assertion = ManifestAssertion::from_assertion(&metadata)?
        .set_kind(ManifestAssertionKind::Json)
        .set_instance(claim_assertion.instance());
    manifest.assertions.push(manifest_assertion);
}
```

`ManifestAssertion::from_assertion` constructs with `created: false`
([manifest_assertion.rs:61](sdk/src/manifest_assertion.rs#L61)), so the flag is silently lost.

This surfaced while fixing the Builder archive round-trip, where `Reader::into_builder` was dropping
`created`. That fix forwards whatever the `Reader` reports — so for metadata assertions it forwards
`false`, because the value was already wrong one hop earlier. **This is the separate, earlier defect
that fix could not reach.**

### Branching

Branch from `main` (currently `bcb1eddd`), **not** from
`mathern/multi-assertions-builder-roundtrip`. The two fixes are independent: this one is entirely
within `Manifest::from_store`'s read-back loop and touches no file the archive work touches
(`reader.rs`, and `builder.rs`'s `add_action`). They can land in either order and will not conflict.

Consequence for verification: the archive round-trip fix is **not** present on this branch, so
`sdk/src/builder.rs`'s `test_archive_round_trip_*` and `test_add_action_preserves_created_flag` do
not exist here — do not expect to run them. The interaction between the two is real but only
observable once both have landed; see Verification.

### Why it matters

C2PA spec §10.2.2 "Fields" makes this an attribution distinction, not a cosmetic one:

> All `created_assertions` are attributed to the signer as the Trust Model is rooted in the trust of
> the signer.
>
> When present, the `gathered_assertions` field shall contain one or more URI references to
> assertions that have been provided to the claim generator by other components in the workflow. By
> putting an assertion into this list, the claim generator is declaring that the assertion is part of
> the claim, but it was not sourced from the claim generator and is not attributed to the signer.

A consumer reading `created()` to decide attribution gets the wrong answer for metadata.

The write side is correct, which is what makes this a bug rather than a consistent no-op. `to_claim`
honors `manifest_assertion.created()` on every path a metadata assertion can take — the explicit
`Metadata::LABEL` arm ([builder.rs:1885](sdk/src/builder.rs#L1885)) and the `_` fallback
([builder.rs:1890](sdk/src/builder.rs#L1890)) both pass it to `add_assertion`, which routes to
`claim.add_created_assertion`. So a user can sign a `created: true` metadata assertion and read back
`false`.

Reachable entirely through public API: `Builder::with_definition` (the `created` field is public
serde), `sign`, `Reader::with_stream`, `manifest.assertions()[i].created()`. `created()` is `pub`,
`set_created` is `pub(crate)` — callers have no workaround.

### Verified against HEAD `bcb1eddd`

- **Which labels are affected.** `labels::ASSERTION_METADATA` is `"c2pa.assertion.metadata"`
  ([labels.rs:33](sdk/src/assertions/labels.rs#L33)) — the `:611` arm matches that one label
  exactly, and being ordered first it shadows `:618` for it. `:618` catches everything else ending
  in `.metadata`: `c2pa.metadata`, `cawg.metadata`, and vendor labels like `org.myorg.metadata`.
- **`Metadata` and `AssertionMetadata` are different types.** `Metadata` is JSON-LD content metadata
  serialized as JSON ([metadata.rs:36](sdk/src/assertions/metadata.rs#L36)); `AssertionMetadata` is
  metadata *about assertions*, serialized as CBOR
  ([assertion_metadata.rs:35](sdk/src/assertions/assertion_metadata.rs#L35)). Neither is deprecated.
  That split is why the two branches exist and why one sets `kind` to Json and the other does not.
- **Not a regression.** No commit in the history of these lines ever set `created`. `created` /
  `ClaimAssertionType` is a Claims-V2-era concept added after these branches existed; when
  `set_created` was threaded through the read-back loop it reached actions and the fallbacks but
  missed the metadata arms.
- **v1 claims are unaffected** and must stay that way — `claim_assertion_type` only returns `Created`
  for claim version > 1 ([claim.rs:1417](sdk/src/claim.rs#L1417)); v1 is uniformly
  `ClaimAssertionType::V1`, so `created` is correctly always false there.
- **Correction to an initial finding.** An investigation suggested the `.ends_with(".metadata")`
  guard tests the *instanced* label, so `c2pa.metadata__2` would fall through to the `_` fallback and
  keep its flag while instance 1 lost it. **That is wrong.** The `match` scrutinee is `base_label` =
  `assertion.label()` ([manifest.rs:551](sdk/src/manifest.rs#L551), [:554](sdk/src/manifest.rs#L554)),
  the raw un-instanced label; the instanced form is the separate `label` binding at
  [:550](sdk/src/manifest.rs#L550) from `ClaimAssertion::label()`, which appends `__N`. The guard
  binds the scrutinee, so `c2pa.metadata__2` matches `:618` too. The bug is uniform across instances
  — no instance-dependent behavior to preserve or test.

Intended outcome: `Reader` reports `created()` accurately for metadata assertions, matching what was
signed.

## Scope

**In:** the two metadata branches at [manifest.rs:611](sdk/src/manifest.rs#L611) and
[:618](sdk/src/manifest.rs#L618).

**Out — `cawg.identity`** ([manifest.rs:625-658](sdk/src/manifest.rs#L625-L658)) drops `created` too,
and is deliberately left alone. It is not a one-line fix: `ma` is built from the raw assertion at
[:630](sdk/src/manifest.rs#L630), then **rebound** at [:653](sdk/src/manifest.rs#L653) to a fresh
`ManifestAssertion::new(label, v)` holding validation-results JSON whenever validation succeeds. A
naive `.set_created()` on the first construction would be discarded on the common path, leaving
`created` correct only for assertions that *fail* validation — inverted-looking behavior, worse than
today's uniform false. Fixing it properly means applying the flag where the value is pushed, which
also touches the pre-existing `set_instance` duplication across both constructions. Separate PR.

Add a short comment at that branch noting `created` is intentionally not set pending that work, so
the omission does not read as another miss.

## Approach

Two lines, in [sdk/src/manifest.rs](sdk/src/manifest.rs). `created` is already in scope at
[:552](sdk/src/manifest.rs#L552); the change mirrors the actions branch at
[:593](sdk/src/manifest.rs#L593) exactly.

Cite the spec at the fix site. The repo's convention is a bare URL in a `//` comment — see
[builder.rs:2004](sdk/src/builder.rs#L2004) and [:2078](sdk/src/builder.rs#L2078). Use the **2.3**
URL: it is what the repo cites throughout (101 occurrences of 2.3 versus none of 2.4), and the
§10.2.2 anchor and the two attribution sentences are byte-identical in 2.4.

Put one comment above the pair of branches rather than duplicating it on each:

```rust
// created/gathered is an attribution distinction, not a formatting one: created_assertions
// are attributed to the signer, gathered_assertions explicitly are not.
// https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_fields
```

**`:611`** — append to the existing chain:

```rust
ManifestAssertion::from_assertion(&assertion_metadata)?
    .set_instance(claim_assertion.instance())
    .set_created(created);
```

**`:618`** — same:

```rust
ManifestAssertion::from_assertion(&metadata)?
    .set_kind(ManifestAssertionKind::Json)
    .set_instance(claim_assertion.instance())
    .set_created(created);
```

`set_created` ([manifest_assertion.rs:135](sdk/src/manifest_assertion.rs#L135)) is `pub(crate)` and
takes `self` by value returning `Self`, so it chains like the adjacent `set_kind` / `set_instance`.
No new API, no signature changes.

The `cawg.identity` comment (see Scope) should carry the same URL, so the deliberate omission is
justified against the same normative text.

## Tests

One new test in [sdk/tests/test_builder.rs](sdk/tests/test_builder.rs), next to
`test_metadata_formats_json_manifest` ([:544](sdk/tests/test_builder.rs#L544)) and
`test_assertion_created_field` ([:452](sdk/tests/test_builder.rs#L452)) — both are the right models
for structure. Leave `test_metadata_formats_json_manifest` untouched.

Follow that file's conventions: `test_context().into_shared()`,
`Builder::from_shared_context(&context)`, `builder.sign(context.signer()?, ...)`,
`Reader::from_shared_context(&context).with_stream(...)`. Import list already has everything needed.
Keep the test self-contained — inline setup, no shared helpers.

**`test_metadata_assertion_created_flag_round_trips`.** Sign a definition covering both branches and
both flag values, then assert `created()` on read-back:

| Label | `created` | Branch exercised |
|---|---|---|
| `c2pa.metadata` | `true` | `:618` (`Metadata`, JSON) |
| `cawg.metadata` | `false` | `:618`, negative case |
| `c2pa.assertion.metadata` | `true` | `:611` (`AssertionMetadata`, CBOR) |

Assert each assertion's `created()` matches, and keep a `kind()` assertion on the `c2pa.metadata` /
`c2pa.assertion.metadata` pair so the fix cannot regress the JSON/CBOR split while adding the flag.

Payload shape: JSON-LD, an `@context` prefix→URI map plus flattened `prefix:Field` entries. Copy the
exact payloads from `test_metadata_formats_json_manifest` rather than inventing them — `Metadata` and
`AssertionMetadata` are different types with different accepted shapes, and `AssertionMetadata`
([assertion_metadata.rs:35](sdk/src/assertions/assertion_metadata.rs#L35)) has named fields
(`reviewRatings`, `dateTime`, …) plus a flattened catch-all.

**Confirm it fails first.** Run against unmodified code: the `created: true` cases must fail on the
`created()` assertion specifically — not a compile error, not a `from_assertion` decode failure. If
it fails for any other reason the payload is wrong; fix the payload and re-confirm before touching
`manifest.rs`.

## Verification

```bash
git switch -c <branch> main   # branch from main, not from the archive round-trip branch

# the new test, then the metadata and created-flag tests it sits beside
cargo test -p c2pa --test test_builder metadata
cargo test -p c2pa --test test_builder test_assertion_created_field

cargo test -p c2pa --all-features
cargo clippy -p c2pa --all-features --all-targets -- -Dwarnings
cargo fmt --check
```

Watch for signed-output changes anywhere a metadata assertion previously round-tripped as gathered
and now round-trips as created — most likely in `test_nested_ingredients_de_serialization` and
`v2_api_integration`, which re-sign through `into_builder`. Neither asserts on `created` today, so
neither should fail, but the produced manifests will differ.

**Cross-check once both branches land.** On `main` today `into_builder` discards `created`
unconditionally, so this fix is not observable through an archive round-trip — the archive branch is
what makes `Reader`'s now-correct value actually reach a rebuilt `Builder`. After both merge, confirm
a `created: true` metadata assertion survives `to_archive` → `with_archive`. Neither branch needs the
other to be correct or to pass its own tests; this is a post-merge check, not a dependency.

Two known-unrelated baseline failures, present on a clean tree — do not fix them here:

- `cargo clippy ... -Dwarnings` fails on a pre-existing `search_is_some` lint at
  [tiff_io.rs:1117](sdk/src/asset_handlers/tiff_io.rs#L1117). Confirm no *new* lints by re-running
  with `-A clippy::search_is_some`.
- Default-feature `cargo test -p c2pa` fails three `file_io` tests
  (`test_png_jumbf_generation`, `test_png_compressed_jumbf_generation`,
  `test_user_guid_external_manifest_embedded` — all `"Fixture 'libpng-test.png' not found"`). They
  pass under `--all-features`.
