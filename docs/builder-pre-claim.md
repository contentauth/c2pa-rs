# Builder pre-claim: what changed and why

## Summary

Previously, `Builder` accumulated everything into `ManifestDefinition` (a JSON-serializable struct) and only built the actual `Claim` once, inside `to_claim()`, at signing time. This branch adds a `Claim` up front (`Builder::pre_claim: Option<Claim>`) and lets several methods write directly into it as they're called, instead of staging data in `definition` for later translation.

`to_claim()` still runs the old translation logic for anything left in `definition` (JSON-set title/format, `definition.assertions`, `definition.ingredients`, `definition.thumbnail`, actions, etc.) — it clones `pre_claim` (if present) as its starting point, then does its usual pass over `definition`, skipping anything that's already been added directly. Both models coexist in the same `Builder`; nothing is removed.

## Why

Some assertions need to reference other assertions by hashed URI before the manifest is signed (this is an increasingly common pattern in the C2PA spec — e.g. an action referencing the ingredient it operated on). Under the old model, an assertion added via `add_assertion` doesn't have a knowable JUMBF URI/hash until `to_claim()` runs, so there was no way to embed such a reference directly; call sites either duplicated logic or referenced things positionally/by id, resolved later.

Building the claim eagerly means each of these calls can return a real `HashedUri` immediately, because the assertion has actually been placed at a stable claim position with its final hash computed at insertion time (not at signing time).

## New API

### `Builder::add_assertion_with_ref<S: Into<String>, T: Serialize>(&mut self, label: S, data: &T) -> Result<HashedUri>`

The core primitive. Mirrors `Builder::add_assertion` (same `label`/`data` shape), but writes directly to the pre-claim (creating it on first use) instead of deferring to `to_claim()`, and returns the assertion's `HashedUri`. Store the result and pass it into another assertion's fields before signing.

If `label` matches a known assertion type (`c2pa.actions`, `c2pa.ingredient`, `BoxHash`, `DataHash`, `BmffHash`, `Metadata`), `data` is decoded into that concrete type so it's stored with its native schema (CBOR, except `Metadata` which is always JSON). Otherwise `data` is wrapped generically in a `UserCbor` assertion under `label`.

Adds the assertion as *gathered* for Claims v2+ (`Claim::add_assertion`'s default), except hash assertions (`BoxHash`/`DataHash`/`BmffHash`), which `Claim` always adds as *created* regardless. Use `Builder::add_created_assertion_with_ref` (same signature) to add any other assertion as *created* instead. Has no effect on Claims v1.

### `Builder::add_embedded_data(&mut self, label: &str, format: &str, stream: &mut impl Read) -> Result<HashedUri>`

Convenience wrapper over `add_assertion_with_ref` for binary data (thumbnails, icons, arbitrary resources): wraps the bytes in an `EmbeddedData` assertion. `set_thumbnail`/`add_resource` now route through this for v2+ claims instead of the `ResourceStore`/`ResourceRef`-by-identifier path.

### `Builder::add_ingredient_with_reader<T>(&mut self, ingredient_assertion: T, reader: &Reader, redactions: Option<Vec<String>>) -> Result<HashedUri>`

Adds an ingredient assertion built from an already-read/validated `Reader`, without constructing a full `Ingredient`. It merges the reader's own manifest data into the pre-claim's ingredient store, fills in `activeManifest`/`claimSignature`/`validationResults` on the assertion, and returns the assertion's `HashedUri`.

`T` accepts, via `TryInto<IngredientAssertion>`:
- an `IngredientAssertion` (owned) or `&IngredientAssertion`
- JSON text (`&str`/`String`) or `serde_json::Value`, matching the assertion's own v3 JSON schema (`dc:title`, `dc:format`, `relationship`, `thumbnail`, etc.)

`redactions` is a list of JUMBF URIs of assertions to strip from the ingredient's manifest chain as it's merged in — find the URI via the `Reader` (`reader.active_label()` + `jumbf::labels::to_assertion_uri(label, assertion_label)`), then pass it here. The caller is responsible for separately recording a `c2pa.redacted` action documenting why, same as the existing redaction pattern elsewhere in `Builder` — this method only does the mechanical redaction.

For an ingredient with no manifest data of its own, skip this method: build the `IngredientAssertion` directly and add it with `add_assertion_with_ref(IngredientAssertion::LABEL, &ingredient_assertion)`.

### `Action::add_ingredient_ref(self, ingredient: HashedUri) -> Self`

Adds an ingredient reference directly from a `HashedUri` (e.g. the one returned by `add_ingredient_with_reader`), instead of by id resolved later in `to_claim()`. Matches the existing `add_ingredient_id` incremental pattern — call it once per ingredient.

### `Builder::add_created_assertion_with_ref`

Same signature as `add_assertion_with_ref`, mirroring `Claim::add_created_assertion`: adds the assertion as *created* rather than *gathered* for Claims v2+. Has no effect on Claims v1, or on hash assertions (always created regardless of which method is called).

### `IngredientAssertion` is now a public type

`assertions::Ingredient` (re-exported as `IngredientAssertion`) was previously `pub(crate)` only. It's now public, and gained `Clone`, plus `TryFrom<&str>` / `TryFrom<String>` / `TryFrom<&String>` / `TryFrom<serde_json::Value>` / a `Deserialize` impl for its v3 JSON schema (this re-encodes the input as CBOR and delegates to the existing `from_assertion` decoder, so there's one source of truth for the v3 field set).

### `Reader::assertion_refs`, `Reader::read_assertion`, `Reader::read_embedded_data_assertion`

Low-level "read" primitives, symmetric to the pre-claim "write" primitives above: given an
already-read/validated `Reader`, manually pick which assertions/ingredients to carry over into a
*new* `Builder`, one at a time — no automatic filtering, no reference rewriting.

- `assertion_refs(manifest_label) -> Result<Vec<(String, HashedUri)>>` enumerates every assertion
  in a manifest as `(label, HashedUri)`, each `HashedUri` already resolvable by the two methods
  below.
- `read_assertion::<T>(&uri) -> Result<T>` decodes an assertion into `T`, regardless of whether
  it's stored as JSON or CBOR on the wire (e.g. `T = Actions`, `IngredientAssertion`, `Metadata`).
- `read_embedded_data_assertion(&uri) -> Result<(String, Vec<u8>)>` returns `(content_type, bytes)`
  for a binary/`EmbeddedData` assertion (thumbnails, icons).

The caller re-adds whatever they choose via the `_with_ref` writers above. For ingredients
specifically, `add_ingredient_with_reader` accepts an `IngredientAssertion` decoded this way
directly: if it already carries a populated `active_manifest`/`c2pa_manifest` (true once it's been
read out of an existing manifest), the method scopes to that specific claim within the passed
`reader` rather than assuming the whole `reader` is a single-ingredient reader — so a caller can
hand it a *larger* reader (with more than just this one ingredient's chain) and pull out just the
one ingredient referenced by the decoded assertion.

### Deprecation

`Builder::add_ingredient_from_reader` (the old `reader.to_ingredient()` → `definition.ingredients` path — carries forward an *existing* parent ingredient already recorded in the reader's own manifest) is deprecated in favor of `add_ingredient_from_archive`. It's unrelated to `add_ingredient_with_reader` (the name collision is coincidental — different semantics), but keeping both names live invited confusion.

## Constraints

- The pre-claim path is **interactive only**: once you've added something via `add_assertion_with_ref` (or its wrappers), it's live in `pre_claim`, not in `definition`. You can't serialize the `Builder` to JSON mid-way and resume from a different process/session the way you can with a `definition`-only `ManifestDefinition`. Everything has to happen in one build-then-sign call sequence.
- Because of that, there's no resource/identifier indirection to manage for anything added this way — no `ResourceRef`, no id lookup at `to_claim()` time. You get the real `HashedUri` back synchronously and use it immediately.
- This also aligns the in-memory model with the crJSON report format: ingredients are assertions, and binary resources are `EmbeddedData` assertions — not a separate "resource" concept bolted on the side.
- Archives work fine since they preserve data in the claim.

## Example: manifest with an ingredient, built directly

```rust
let ingredient_reader = Reader::default().with_stream("image/jpeg", &mut ingredient_stream)?;

let mut builder = Builder::default();

// Ingredient thumbnail as a binary EmbeddedData assertion — returns a HashedUri.
let thumb_uri = builder.add_embedded_data(
    labels::INGREDIENT_THUMBNAIL,
    "image/jpeg",
    &mut thumbnail_stream,
)?;

// Ingredient assertion from JSON text, merged with the reader's manifest data.
let ing_uri = builder.add_ingredient_with_reader(
    r#"{"relationship": "parentOf", "dc:title": "source.jpg", "dc:format": "image/jpeg"}"#,
    &ingredient_reader,
    None, // redactions
)?;

// Reference the ingredient directly from an action via its HashedUri.
let action = Action::new(c2pa_action::OPENED).add_ingredient_ref(ing_uri);
builder.add_assertion_with_ref(Actions::LABEL, &Actions::new().add_action(action))?;

builder.sign(signer.as_ref(), "image/jpeg", &mut source, &mut dest)?;
```
