# ClaimBuilder: an eager, lower-level alternative to Builder

## Summary

`Builder` accumulates everything into a JSON-serializable `ManifestDefinition` and only builds
the actual `Claim` once, inside `to_claim()`, at signing time. `ClaimBuilder` is a separate,
standalone type that builds a `Claim` directly and eagerly: each writer call places its assertion
at a stable claim position immediately and returns the assertion's real `HashedUri`, instead of
staging data for later translation. It has no `ManifestDefinition`/`ResourceStore` — the two
models don't mix, so there's no dedup bookkeeping to keep them from double-adding the same data.

Every assertion is described by a [`ClaimAssertion`](#claimassertion) — a small builder that
carries whatever a label needs (structured data, a stream, hard-binding exclusions, an
ingredient's sidecar manifest data) — so `ClaimBuilder` itself only needs two writer methods:
[`add_gathered_assertion`](#claimbuilderadd_gathered_assertionadd_created_assertion)/
`add_created_assertion`.

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
- **No placeholder management.** `ClaimBuilder` never reserves space for, or embeds, a manifest
  placeholder itself — the caller is expected to have already done that externally before adding
  a hard-binding assertion or calling `sign`. `ClaimBuilder::sign` is always the equivalent of
  `Builder::sign_embeddable`'s Mode 2 (direct/no-placeholder) path.
- **Streams live on `ClaimAssertion`, not on `ClaimBuilder`.** `ClaimBuilder`'s own methods never
  take a stream — every stream a label needs (an asset to hash, an ingredient to extract
  provenance from, raw binary content) is attached to the `ClaimAssertion` via `with_stream`
  before it's handed to `ClaimBuilder`, and is read using `ClaimBuilder`'s own `Context` only once
  `add_gathered_assertion`/`add_created_assertion` runs.

## Naming: gathered vs. created

Every writer comes in a *gathered* and *created* pair, mirroring `Claim::add_assertion`
(gathered, the default) vs. `Claim::add_created_assertion`:

- `ClaimBuilder::add_gathered_assertion` / `add_created_assertion`

Hash assertions (`BoxHash`/`DataHash`/`BmffHash`) are always stored as *created* by `Claim`
regardless of which method adds them.

## `ClaimAssertion`

`ClaimAssertion` is a builder: start with `ClaimAssertion::new(label)`, then attach whichever of
`with_json`/`with_stream`/`with_c2pa_data`/`with_exclusions` that `label` needs. Nothing is
validated or converted until the assertion is handed to `ClaimBuilder::add_gathered_assertion`/
`add_created_assertion`.

Which `with_*` calls are valid depends on `label`:

- **`DataHash::LABEL`/`BmffHash::LABEL`/`BoxHash::LABEL`** (i.e. the binding type you want, picked
  directly by the caller instead of inferred from the asset format) — require `with_stream` (the
  finished asset, with the manifest placeholder already embedded, to hash) and accept
  `with_exclusions` (`DataHash` only — the placeholder region to exclude from hashing).
- **`IngredientAssertion::LABEL`** — requires `with_json` (the ingredient's own metadata: e.g.
  `dc:title`/`dc:format`/`relationship`/`thumbnail`, matching the assertion's own v3 JSON schema)
  and accepts `with_stream` (the ingredient's own asset, to extract its provenance) plus
  `with_c2pa_data` (the ingredient's manifest store as JUMBF bytes, supplied directly instead of
  extracted from the stream in-band — for a sidecar or remote manifest; `with_c2pa_data` requires
  `with_stream` too, since the stream is still what's validated against).
- **Everything else** — takes `with_json` (structured data: if `label` matches a known assertion
  type such as `c2pa.actions`/`Metadata`, it's decoded into that concrete type so it's stored with
  its native schema; otherwise it's wrapped generically in a `UserCbor` assertion under `label`)
  or `with_stream` (binary data, e.g. a thumbnail — wrapped in an `EmbeddedData` assertion).

## `ClaimBuilder::new(context: Arc<Context>) -> Self`

Creates a claim with an auto-generated label, and a single default `ClaimGeneratorInfo` entry
(pulled from `Context` settings' `builder.claim_generator_info` if configured, else
`ClaimGeneratorInfo::default()` — every v2+ claim must carry at least one). Unlike
`Builder::set_claim_generator_info`, there is currently no way to add more than this one entry.

`ClaimBuilder::with_label(context, label)` is the same, but with a caller-supplied claim label
instead of an auto-generated UUID (`label` must already be a valid C2PA v2 manifest label).

## `ClaimBuilder::update(self) -> Self`

Marks this as an update manifest — `sign()` then calls `Store::commit_update_manifest()` instead
of `Store::commit_claim()`. Chains off `new()`: `ClaimBuilder::new(context).update()`.
`ClaimBuilder` has no equivalent of `Builder`'s `BuilderIntent::Create`/`Edit` — those only govern
`Builder`'s auto-thumbnail/auto-parent/auto-action automation, none of which `ClaimBuilder` does,
since everything here is added explicitly by the caller.

## `set_title` / `set_instance_id` / `set_hash_alg`

Claim struct fields that `Builder` sources from `ManifestDefinition` (`title`/`instance_id`/
`hash_alg`) — `ClaimBuilder` has no definition, and none of these are settings-driven, so they
need direct setters.

## `ClaimBuilder::add_redaction(&mut self, uri: impl Into<String>) -> &mut Self`

Records a JUMBF URI to redact the next time an ingredient's manifest chain is merged in via a
`ClaimAssertion` under `IngredientAssertion::LABEL` (with a stream attached). Applies to every
ingredient added afterward — a URI that isn't present in a given ingredient's chain is simply not
found there and has no effect, so accumulating redactions across several ingredients is safe.
This only performs the mechanical redaction; the caller is responsible for separately recording a
`c2pa.redacted` action with a reason for each one, since the reason is caller-specific domain
knowledge this method has no way to infer.

## `ClaimBuilder::add_gathered_assertion(&mut self, assertion: ClaimAssertion) -> Result<HashedUri>`

The only writer. Interprets `assertion` according to its label (see [`ClaimAssertion`](#claimassertion)
above) using this `ClaimBuilder`'s own `Context`, places it at a stable claim position, and
returns its real `HashedUri`. `add_created_assertion` is the *created* counterpart — see
[Naming: gathered vs. created](#naming-gathered-vs-created).

Hard-binding labels (`DataHash`/`BmffHash`/`BoxHash`) are handled specially: the first one added
becomes the claim's hard binding; every one added after that must be the same kind and no larger
than the existing one — the claim's byte layout must not grow — and replaces it. A `DataHash`
replacement that's smaller is padded back up to match exactly; `BmffHash`/`BoxHash` have no
padding field, so a smaller replacement is accepted as-is (the container tolerates the resulting
slack; see `Builder::placeholder`'s note on converting extra reserved space to a "free" box).
There can only be one hard binding per claim.

## `Action::add_ingredient_ref(self, ingredient: HashedUri) -> Self`

Adds an ingredient reference directly from a `HashedUri` (e.g. the one returned by
`add_gathered_assertion` for an ingredient), instead of by id resolved later. Matches the existing
`add_ingredient_id` pattern — call it once per ingredient.

## `ClaimBuilder::sign(&self) -> Result<Vec<u8>>`

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
- No configurable hard-binding hash algorithm yet — always `sha256`, independent of
  `ClaimBuilder::set_hash_alg` (which only affects the claim's own default).
- No BMFF Merkle/fixed-leaf-size mdat chunk streaming yet (`Builder`'s
  `set_bmff_hash_fixed_leaf_size`/`hash_bmff_mdat_bytes` equivalents) — a `BmffHash` `with_stream`
  always reads and hashes the whole asset in one pass.
- No async signing yet (`Builder`'s `#[async_generic]` sync/async pairing).

## Example: manifest with an ingredient, built directly

```rust
let mut claim_builder = ClaimBuilder::new(context.clone());

// Ingredient thumbnail as a binary EmbeddedData assertion — returns a HashedUri.
let thumb_uri = claim_builder.add_gathered_assertion(
    ClaimAssertion::new(labels::INGREDIENT_THUMBNAIL)
        .with_stream("image/jpeg", &mut thumbnail_stream),
)?;

// Ingredient assertion from JSON, with its own asset stream to extract provenance from.
let ing_uri = claim_builder.add_gathered_assertion(
    ClaimAssertion::new(IngredientAssertion::LABEL)
        .with_json(&serde_json::json!({
            "relationship": "parentOf",
            "dc:title": "source.jpg",
            "dc:format": "image/jpeg",
            "thumbnail": thumb_uri,
        }))?
        .with_stream("image/jpeg", &mut ingredient_stream),
)?;

// Reference the ingredient directly from an action via its HashedUri.
let action = Action::new(c2pa_action::OPENED).add_ingredient_ref(ing_uri);
claim_builder.add_gathered_assertion(
    ClaimAssertion::new(Actions::LABEL).with_json(&Actions::new().add_action(action))?,
)?;

// Hard binding — picks BoxHash directly by label; the caller already embedded a placeholder
// into `source` before this point (or, as here, prefer_box_hash needs no placeholder at all).
claim_builder.add_gathered_assertion(
    ClaimAssertion::new(BoxHash::LABEL).with_stream("image/jpeg", &mut source),
)?;

let jumbf = claim_builder.sign()?; // uses the signer configured on `context`
let manifest_bytes = Store::get_composed_manifest(&jumbf, "image/jpeg")?;
// ...caller embeds `manifest_bytes` into `source` themselves.
```
