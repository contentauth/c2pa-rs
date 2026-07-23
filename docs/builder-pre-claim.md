# Builder pre-claim: what changed and why

## Summary

Previously, `Builder` accumulated everything into `ManifestDefinition` (a JSON-serializable struct) and only built the actual `Claim` once, inside `to_claim()`, at signing time. This branch adds a `Claim` up front (`Builder::pre_claim: Option<Claim>`) and lets several methods write directly into it as they're called, instead of staging data in `definition` for later translation.

`to_claim()` still runs the old translation logic for anything left in `definition` (JSON-set title/format, `definition.assertions`, `definition.ingredients`, `definition.thumbnail`, actions, etc.) — it clones `pre_claim` (if present) as its starting point, then does its usual pass over `definition`, skipping anything that's already been added directly. Both models coexist in the same `Builder`; nothing is removed.

## Why

Some assertions need to reference other assertions by hashed URI before the manifest is signed (this is an increasingly common pattern in the C2PA spec — e.g. an action referencing the ingredient it operated on). Under the old model, an assertion added via `add_assertion` doesn't have a knowable JUMBF URI/hash until `to_claim()` runs, so there was no way to embed such a reference directly; call sites either duplicated logic or referenced things positionally/by id, resolved later.

Building the claim eagerly means each of these calls can return a real `HashedUri` immediately, because the assertion has actually been placed at a stable claim position with its final hash computed at insertion time (not at signing time).

## New API

### `Builder::add_assertion_with_ref<A: AssertionBase>(&mut self, assertion: &A) -> Result<HashedUri>`

The core primitive. Adds any assertion directly to the pre-claim (creating it on first use) and returns its `HashedUri`. Store the result and pass it into another assertion's fields before signing.

### `Builder::add_embedded_data(&mut self, label: &str, format: &str, stream: &mut impl Read) -> Result<HashedUri>`

Convenience wrapper over `add_assertion_with_ref` for binary data (thumbnails, icons, arbitrary resources): wraps the bytes in an `EmbeddedData` assertion. `set_thumbnail`/`add_resource` now route through this for v2+ claims instead of the `ResourceStore`/`ResourceRef`-by-identifier path.

### `Builder::add_ingredient_with_reader<T>(&mut self, ingredient_assertion: T, reader: &Reader, redactions: Option<Vec<String>>) -> Result<HashedUri>`

Adds an ingredient assertion built from an already-read/validated `Reader`, without constructing a full `Ingredient`. It merges the reader's own manifest data into the pre-claim's ingredient store, fills in `activeManifest`/`claimSignature`/`validationResults` on the assertion, and returns the assertion's `HashedUri`.

`T` accepts, via `TryInto<IngredientAssertion>`:
- an `IngredientAssertion` (owned) or `&IngredientAssertion`
- JSON text (`&str`/`String`) or `serde_json::Value`, matching the assertion's own v3 JSON schema (`dc:title`, `dc:format`, `relationship`, `thumbnail`, etc.)

`redactions` is a list of JUMBF URIs of assertions to strip from the ingredient's manifest chain as it's merged in — find the URI via the `Reader` (`reader.active_label()` + `jumbf::labels::to_assertion_uri(label, assertion_label)`), then pass it here. The caller is responsible for separately recording a `c2pa.redacted` action documenting why, same as the existing redaction pattern elsewhere in `Builder` — this method only does the mechanical redaction.

For an ingredient with no manifest data of its own, skip this method: build the `IngredientAssertion` directly and add it with `add_assertion_with_ref`.

### `Action::add_ingredient_ref(self, ingredient: HashedUri) -> Self`

Adds an ingredient reference directly from a `HashedUri` (e.g. the one returned by `add_ingredient_with_reader`), instead of by id resolved later in `to_claim()`. Matches the existing `add_ingredient_id` incremental pattern — call it once per ingredient.

### `IngredientAssertion` is now a public type

`assertions::Ingredient` (re-exported as `IngredientAssertion`) was previously `pub(crate)` only. It's now public, and gained `Clone`, plus `TryFrom<&str>` / `TryFrom<String>` / `TryFrom<&String>` / `TryFrom<serde_json::Value>` / a `Deserialize` impl for its v3 JSON schema (this re-encodes the input as CBOR and delegates to the existing `from_assertion` decoder, so there's one source of truth for the v3 field set).

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
builder.add_assertion_with_ref(&Actions::new().add_action(action))?;

builder.sign(signer.as_ref(), "image/jpeg", &mut source, &mut dest)?;
```
