# ClaimBuilder: an eager, lower-level alternative to Builder

## Summary

`Builder` accumulates everything into a JSON-serializable `ManifestDefinition` and only builds
the actual `Claim` once, inside `to_claim()`, at signing time. `ClaimBuilder` is a separate,
standalone type that builds a `Claim` directly and eagerly: each writer call places its assertion
at a stable claim position immediately and returns the assertion's real `HashedUri`, instead of
staging data for later translation. It has no `ManifestDefinition`/`ResourceStore` — the two
models don't mix, so there's no dedup bookkeeping to keep them from double-adding the same data.

## Why

Some assertions need to reference other assertions by hashed URI before the manifest is signed
(e.g. an action referencing the ingredient it operated on). Under `Builder`'s model, an assertion
added via `add_assertion` doesn't have a knowable JUMBF URI/hash until `to_claim()` runs, so
there was no way to embed such a reference directly; call sites either duplicated logic or
referenced things positionally/by id, resolved later.

Building the claim eagerly means each `ClaimBuilder` call can return a real `HashedUri`
immediately, because the assertion has actually been placed at a stable claim position with its
final hash computed at insertion time (not at signing time).

## Model

- **Claims v2+ only.** `ClaimBuilder::new`/`with_label` always create a v2 claim. A v1 claim's
  `claim_generator` string is only known once every `ClaimGeneratorInfo` is known, which
  `ClaimBuilder` — having no `ManifestDefinition` to translate — has no equivalent of, so there's
  no v1 code path to opt into in the first place.
- **Interactive only.** Once you've added something, it's live in the claim. You can't
  serialize a `ClaimBuilder` to JSON mid-way and resume from a different process/session the way
  you can with a `ManifestDefinition`. Everything happens in one build-then-sign call sequence.
- **Asset input is limited to two places:** reading an already-validated ingredient `Reader`
  (`add_gathered_ingredient`/`add_created_ingredient`), and generating a hard-binding assertion
  from an asset stream (`HardBinding`). Everything else is caller-supplied in-memory data.
- **No placeholder management.** `ClaimBuilder` never reserves space for, or embeds, a manifest
  placeholder itself — the caller is expected to have already done that externally before
  calling `set_hard_binding`/`update_hard_binding`/`sign`. `ClaimBuilder::sign` is always the
  equivalent of `Builder::sign_embeddable`'s Mode 2 (direct/no-placeholder) path.

## Naming: gathered vs. created

Every writer comes in a *gathered* and *created* pair, mirroring `Claim::add_assertion`
(gathered, the default) vs. `Claim::add_created_assertion`:

- `add_gathered_assertion` / `add_created_assertion`
- `add_gathered_data` / `add_created_data`
- `add_gathered_ingredient` / `add_created_ingredient`

Hash assertions (`BoxHash`/`DataHash`/`BmffHash`) are always stored as *created* by `Claim`
regardless of which method adds them — this doesn't apply to them at all, which is why
`set_hard_binding`/`update_hard_binding` have no gathered/created split.

## API

### `ClaimBuilder::new(context: Arc<Context>) -> Self`

Creates a claim with an auto-generated label, and a single default `ClaimGeneratorInfo` entry
(pulled from `Context` settings' `builder.claim_generator_info` if configured, else
`ClaimGeneratorInfo::default()` — every v2+ claim must carry at least one). Unlike
`Builder::set_claim_generator_info`, there is currently no way to add more than this one entry.

`ClaimBuilder::with_label(context, label)` is the same, but with a caller-supplied claim label
instead of an auto-generated UUID (`label` must already be a valid C2PA v2 manifest label).

### `ClaimBuilder::update(self) -> Self`

Marks this as an update manifest — `sign()` then calls `Store::commit_update_manifest()` instead
of `Store::commit_claim()`. Chains off `new()`: `ClaimBuilder::new(context).update()`.
`ClaimBuilder` has no equivalent of `Builder`'s `BuilderIntent::Create`/`Edit` — those only govern
`Builder`'s auto-thumbnail/auto-parent/auto-action automation, none of which `ClaimBuilder` does,
since everything here is added explicitly by the caller.

### `set_title` / `set_instance_id` / `set_hash_alg`

Claim struct fields that `Builder` sources from `ManifestDefinition` (`title`/`instance_id`/
`hash_alg`) — `ClaimBuilder` has no definition, and none of these are settings-driven, so they
need direct setters.

### `ClaimBuilder::add_gathered_assertion<S: Into<String>, T: Serialize>(&mut self, label: S, data: &T) -> Result<HashedUri>`

The core primitive. If `label` matches a known assertion type (`c2pa.actions`,
`c2pa.ingredient`, `BoxHash`, `DataHash`, `BmffHash`, `Metadata`), `data` is decoded into that
concrete type so it's stored with its native schema (CBOR, except `Metadata` which is always
JSON). Otherwise `data` is wrapped generically in a `UserCbor` assertion under `label`.
`add_created_assertion` is the *created* counterpart.

### `ClaimBuilder::add_gathered_data(&mut self, label: &str, format: &str, stream: &mut impl Read) -> Result<HashedUri>`

Convenience wrapper over `add_gathered_assertion` for binary data (thumbnails, icons, arbitrary
resources): wraps the bytes in an `EmbeddedData` assertion. `add_created_data` is the *created*
counterpart.

### `ClaimBuilder::add_gathered_ingredient<T>(&mut self, ingredient_assertion: T, reader: Option<&Reader>, redactions: Vec<String>) -> Result<HashedUri>`

`T` accepts, via `TryInto<IngredientAssertion>`: an `IngredientAssertion` (owned) or
`&IngredientAssertion`, JSON text (`&str`/`String`) or `serde_json::Value`, matching the
assertion's own v3 JSON schema (`dc:title`, `dc:format`, `relationship`, `thumbnail`, etc.).

- `reader = Some(r)` — `r` has already read and validated the ingredient's own asset. Its
  manifest data is merged into this claim's ingredient store, and
  `active_manifest`/`claim_signature`/`validation_results` on the assertion are filled in from
  it. `redactions` is a list of JUMBF URIs of assertions to strip from the ingredient's manifest
  chain as it's merged in (empty if none) — this only performs the mechanical redaction; the
  caller is responsible for separately recording a `c2pa.redacted` action with a reason for each
  one, since the reason is caller-specific domain knowledge this method has no way to infer.
- `reader = None` — the ingredient has no provenance of its own to merge in (no manifest chain,
  no redactions): the assertion is added as-is, exactly like `add_gathered_assertion` would.

`add_created_ingredient` is the *created* counterpart.

### `Action::add_ingredient_ref(self, ingredient: HashedUri) -> Self`

Adds an ingredient reference directly from a `HashedUri` (e.g. the one returned by
`add_gathered_ingredient`), instead of by id resolved later. Matches the existing
`add_ingredient_id` pattern — call it once per ingredient.

### `HardBinding`

A `Claim`-agnostic component (shared with `Builder` internally) that computes a hard-binding
assertion (`DataHash`, `BmffHash`, or `BoxHash`) directly from an asset stream:

```rust
let mut hard_binding = HardBinding::new(format, &context); // resolves Data/Bmff/Box dispatch, same rules as Builder::hash_type
hard_binding.set_exclusions(exclusions); // DataHash path only — the region where you embedded the placeholder
let binding = hard_binding.generate(&context, &mut stream)?; // HardBindingAssertion
```

BMFF Merkle/mdat chunk streaming is also available: `set_fixed_leaf_size`/`hash_mdat_chunk`
before calling `generate`, mirroring `Builder::set_bmff_hash_fixed_leaf_size`/
`hash_bmff_mdat_bytes`.

### `ClaimBuilder::set_hard_binding` / `update_hard_binding`

First-time add, then replace:

- `set_hard_binding(&mut self, binding: HardBindingAssertion) -> Result<HashedUri>` — the first
  hard binding for this claim. Typically a placeholder-shaped value the caller constructs
  directly (correct type/size, dummy hash) before they've embedded anything into the real asset.
  Errors if a hard binding already exists.
- `update_hard_binding(&mut self, binding: HardBindingAssertion) -> Result<HashedUri>` —
  replaces it, once the caller has embedded the placeholder into the real asset and computed the
  real value (typically via `HardBinding::generate` reading that finished asset). For a
  `DataHash` replacement, the new value is padded to match the existing one's encoded byte length
  exactly (so the claim's byte layout doesn't shift), erroring only if the new value is already
  larger than that. Errors if there is no existing hard binding, or if the replacement's variant
  (Data/Bmff/Box) differs from the existing one.

### `ClaimBuilder::sign(&self) -> Result<Vec<u8>>`

Signs using the signer configured on this `ClaimBuilder`'s `Context` (`Context::with_signer`/the
`signer` settings key) and returns the raw signed JUMBF bytes. Builds a `Store` directly from
this claim (no `ManifestDefinition` translation) and verifies a hard binding assertion is present
before signing. Unlike `Builder::sign_embeddable`, this does not compose the result into a
format-specific container (a JPEG APP11 segment, a BMFF UUID box, etc.) — there's no `format`
parameter for the same reason; the caller does that themselves (e.g. via
`Store::get_composed_manifest`), the same way they own placeholder embedding. There is no Mode
1/placeholder concept on `ClaimBuilder` at all — the caller must have already added a real hard
binding.

## Constraints / known gaps (first version)

- No remote/external manifest support (`Builder`'s `remote_url`/`no_embed`) yet.
- No way to add more than one `ClaimGeneratorInfo` entry.
- No TSA timestamp-fetching convenience (`Builder`'s `timestamp_manifest_labels`) — build a
  `TimeStamp` assertion yourself and add it via `add_created_assertion`.
- No async signing yet (`Builder`'s `#[async_generic]` sync/async pairing).

## Example: manifest with an ingredient, built directly

```rust
let ingredient_reader = Reader::default().with_stream("image/jpeg", &mut ingredient_stream)?;

let mut claim_builder = ClaimBuilder::new(context.clone());

// Ingredient thumbnail as a binary EmbeddedData assertion — returns a HashedUri.
let thumb_uri = claim_builder.add_gathered_data(
    labels::INGREDIENT_THUMBNAIL,
    "image/jpeg",
    &mut thumbnail_stream,
)?;

// Ingredient assertion from JSON text, merged with the reader's manifest data.
let ing_uri = claim_builder.add_gathered_ingredient(
    r#"{"relationship": "parentOf", "dc:title": "source.jpg", "dc:format": "image/jpeg"}"#,
    Some(&ingredient_reader),
    vec![], // redactions
)?;

// Reference the ingredient directly from an action via its HashedUri.
let action = Action::new(c2pa_action::OPENED).add_ingredient_ref(ing_uri);
claim_builder.add_gathered_assertion(Actions::LABEL, &Actions::new().add_action(action))?;

// Hard binding — the caller already embedded a placeholder into `source` before this point.
let binding = HardBinding::new("image/jpeg", &context).generate(&context, &mut source)?;
claim_builder.set_hard_binding(binding)?;

let jumbf = claim_builder.sign()?; // uses the signer configured on `context`
let manifest_bytes = Store::get_composed_manifest(&jumbf, "image/jpeg")?;
// ...caller embeds `manifest_bytes` into `source` themselves.
```
