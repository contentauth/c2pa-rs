# Redaction

Redaction removes an assertion from a prior manifest in the C2PA claim chain.
This is useful when you need to strip sensitive metadata — such as GPS coordinates — before distributing an asset.

When an assertion is redacted, its JUMBF box is replaced with a zero-filled placeholder so verifiers can distinguish an intentional removal from data corruption.

## When to use redaction

Common scenarios include:

- **Privacy**: Removing location data (EXIF GPS) or identity before publishing.
- **Metadata cleanup**: Stripping outdated or incorrect metadata while preserving the rest of the provenance chain.

> **Tip:** To *replace* a metadata field rather than simply remove it, redact the existing
> assertion and add a new one with the updated values in the same manifest.

## Rules and constraints

The C2PA specification imposes restrictions on what can be redacted:

| Rule | Detail |
|------|--------|
| **No self-redaction** | A manifest cannot redact its own assertions. |
| **Cannot redact `c2pa.actions`** | Action assertions are protected. |
| **Cannot redact `c2pa.hash.*`** | Hash binding assertions are protected. |
| **URI must match** | Every URI in the redactions list must resolve to an assertion in an ingredient, or signing fails with `AssertionRedactionNotFound`. |

## JUMBF URI format

Each redaction target is identified by its full JUMBF URI:

```
self#jumbf=/c2pa/<manifest_label>/c2pa.assertions/<assertion_label>
```

For example:

```
self#jumbf=/c2pa/urn:c2pa:acme:12345/c2pa.assertions/c2pa.metadata
```

The `<manifest_label>` comes from the parent manifest you are redacting from. Since labels are generated at signing time, you must read the signed asset to discover them before constructing redaction URIs.

## Workflow

The recommended workflow uses a [`Reader`] to discover assertion URIs, then a [`Builder`] with an update manifest to apply the redaction.

### Step 1 — Discover the redaction target

Open the signed asset and gather URIs for all assertions you want to redact:

```rust
use c2pa::Reader;

let reader = Reader::default()
    .with_stream("image/jpeg", &mut source)?;

let manifest = reader.active_manifest().unwrap();

// assertion_references() returns HashedUri values with full JUMBF URIs.
let redacted_uri = manifest.assertion_references()
    .find(|r| r.url().contains("c2pa.metadata"))
    .map(|r| r.url())
    .expect("assertion not found");
```

### Step 2 — Build the manifest

Use `BuilderIntent::Update` if redaction is your only change. Update manifests
can only modify manifest-level information and cannot alter the asset's content.
If the redaction is part of a wider edit that also changes the asset, use
`BuilderIntent::Edit` instead.

Create a [`Builder`] and add the URI to the `redactions` list:

```rust
use c2pa::{assertions::c2pa_action, Builder, BuilderIntent};
use serde_json::json;

let mut builder = Builder::default();
builder.set_intent(BuilderIntent::Update);

// Add the JUMBF URI to the redactions list
builder.definition.redactions = Some(vec![redacted_uri.clone()]);

// Per the spec, include a c2pa.redacted action with a reason.
// Standard reasons are defined in c2pa_reason (e.g. PII_PRESENT,
// INVALID_DATA, TRADE_SECRET_PRESENT, GOVERNMENT_CONFIDENTIAL).
let redacted_action = Action::new(c2pa_action::REDACTED)
    .set_reason(c2pa_reason::PII_PRESENT)
    .set_parameter("redacted", &redacted_uri)?;
builder.add_action(redacted_action)?;
```

### Step 3 — Sign

Sign the update manifest using the previously signed asset as the source:

```rust
source.rewind()?;
let mut output = std::io::Cursor::new(Vec::new());
builder.save_to_stream("image/jpeg", &mut source, &mut output)?;
```

The `Update` intent automatically creates the source as a parent ingredient. The builder will locate the matching assertion in the parent's manifest store and replace its JUMBF box with a redaction placeholder.

### Step 4 — Verify

Read back the output and confirm the redaction is listed on the active manifest:

```rust
output.set_position(0);
let reader = Reader::default()
    .with_stream("image/jpeg", &mut output)?;

let manifest = reader.active_manifest().unwrap();
assert!(manifest.redactions()
    .is_some_and(|r| r.iter().any(|uri| uri == &redacted_uri)));
```

The SDK validates that every listed redaction was actually applied, so checking
`redactions()` is sufficient.

## JSON manifest definition

If you build manifests from JSON, set the `redactions` array on the definition, as well as the `c2pa.redacted` actions:

```json
{
  "title": "Redacted version",
  "redactions": [
    "self#jumbf=/c2pa/urn:c2pa:acme:12345/c2pa.assertions/c2pa.metadata"
  ],
  "assertions": [
    {
      "label": "c2pa.actions",
      "data": {
        "actions": [
          {
            "action": "c2pa.redacted",
            "reason": "c2pa.PII.present",
            "parameters": {
              "redacted": "self#jumbf=/c2pa/urn:c2pa:acme:12345/c2pa.assertions/c2pa.metadata"
            }
          }
        ]
      }
    }
  ]
}
```

## Multiple redactions

You can redact assertions from multiple ingredients in a single manifest by adding multiple URIs to the `redactions` array and a corresponding `c2pa.redacted` action for each:

```rust
builder.definition.redactions = Some(vec![
    redacted_uri_1.clone(),
    redacted_uri_2.clone(),
]);
```

Each URI must include the correct manifest label for the ingredient it targets. This works for both `parentOf` and `componentOf` ingredient relationships.

## Redacting from nested manifests

A redaction URI can target any manifest in an ingredient's claim chain, not just the ingredient's active manifest. If the parent itself has ingredients (grandparent manifests), you can redact from those as well — as long as the URI contains the correct manifest label.

## Complete example

See [`examples/redaction.rs`](../sdk/examples/redaction.rs) for a complete, runnable example.
