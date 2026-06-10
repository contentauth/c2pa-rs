# CAI-12311: Better error messages for assertion.action.ingredientMismatch

## Problem

When `verify_actions` fires `assertion.action.ingredientMismatch`, the explanation is generic:

```
"action must have valid ingredient with ComponentOf relationship"
```

With 10 actions in the assertion and multiple ingredients, the user has no idea:
- Which action (index) failed
- Which ingredient URL was wrong
- What relationship was actually found

## Root cause location

**`sdk/src/claim.rs`, function `verify_actions`** (~line 2099)

Three distinct validation sites all produce the same vague message:

| Section | Action types | Expected relationship | Lines (approx) |
|---------|-------------|----------------------|----------------|
| 2.b.iv.A | `c2pa.opened` | ParentOf | 2247–2303 |
| 2.b.iv.B | `c2pa.placed`, `c2pa.removed` | ComponentOf | 2306–2366 |
| 2.c | `c2pa.transcoded`, `c2pa.repackaged` | ParentOf | 2369–2438 |

### Loop structure

```rust
// Outer: iterates over all actions assertions
for (index, actions_assertion) in all_actions.iter().enumerate() {
    ...
    // Inner: iterates over individual actions — NO INDEX right now
    for action in actions.actions() {
```

## What information is available at the error site

At all three sites, the following data is accessible:

| Data | How to get it |
|------|--------------|
| Action index | Add `enumerate()` to inner loop |
| Action type string | `action.action()` → e.g. `"c2pa.placed"` |
| Ingredient URL(s) | `params.ingredient.url()` or `params.ingredients[].url()` |
| Actual relationship | Do a secondary lookup into `claim.ingredient_assertions()` after `found_good != 1` |
| Ingredient title | `Ingredient::from_assertion(...).title` |

The `Ingredient` struct (defined in `sdk/src/assertions/ingredient.rs:57`) exposes:
- `pub title: Option<String>`
- `pub relationship: Relationship`  — enum variants `ParentOf`, `ComponentOf`, `InputTo`

The `Relationship` enum derives `Debug` but has no `Display`. Its serde rename strings (`"parentOf"`, `"componentOf"`, `"inputTo"`) are the canonical user-facing names.

## Proposed changes

### 1. Add `enumerate()` to the inner action loop

```rust
// Before
for action in actions.actions() {

// After
for (action_index, action) in actions.actions().iter().enumerate() {
```

### 2. Add a `relationship_str` helper (top of `claim.rs` or inline)

```rust
fn relationship_str(r: &Relationship) -> &'static str {
    match r {
        Relationship::ParentOf  => "parentOf",
        Relationship::ComponentOf => "componentOf",
        Relationship::InputTo  => "inputTo",
    }
}
```

### 3. Helper: collect ingredient diagnostic string

After `found_good != 1`, build a one-liner showing each referenced ingredient URL and its actual relationship:

```rust
fn ingredient_mismatch_info(
    claim: &Claim,
    params: &ActionParameters,
    expected: &str,
) -> String {
    let urls: Vec<String> = {
        let mut v = Vec::new();
        if let Some(h) = &params.ingredient {
            v.push(h.url().to_string());
        }
        if let Some(hs) = &params.ingredients {
            v.extend(hs.iter().map(|h| h.url().to_string()));
        }
        v
    };

    let detail: Vec<String> = urls.iter().map(|url| {
        let actual = assertion_label_from_uri(url).and_then(|target| {
            claim.ingredient_assertions().iter().find_map(|i| {
                if i.label() == target {
                    Ingredient::from_assertion(i.assertion()).ok().map(|ing| {
                        let rel = relationship_str(&ing.relationship);
                        let title = ing.title.as_deref().unwrap_or("<no title>");
                        format!("'{}' (title='{}', relationship='{}')", url, title, rel)
                    })
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| format!("'{}' (not found in ingredient assertions)", url));
        actual
    }).collect();

    format!(
        "action[{}] ('{}') must have {} relationship; ingredient(s): [{}]",
        action_index,   // captured from enumerate()
        action.action(),
        expected,
        detail.join(", ")
    )
}
```

> **Note**: This helper closes over `action_index` and `action`; easiest to keep it as inline code or a nested closure at the error sites rather than a free function.

### 4. Replace error message strings at three sites

#### Site A — `c2pa.opened` / ParentOf (section 2.b.iv.A, ~line 2287)

```rust
if found_good != 1 {
    let msg = /* inline the diagnostic logic */;
    log_item!(label.clone(), &msg, "verify_actions")
        .validation_status(validation_status::ASSERTION_ACTION_INGREDIENT_MISMATCH)
        .failure_no_throw(
            validation_log,
            Error::ValidationRule(msg.clone()),
        );
}
```

Example output:
```
action[0] ('c2pa.opened') must have parentOf relationship;
  ingredient(s): ['self#jumbf=.../c2pa.ingredient.v3' (title='A.jpg', relationship='parentOf')]
```

#### Site B — `c2pa.placed` / `c2pa.removed` / ComponentOf (section 2.b.iv.B, ~line 2350)

Same pattern. Example output:
```
action[3] ('c2pa.placed') must have componentOf relationship;
  ingredient(s): ['self#jumbf=.../c2pa.ingredient.v3__1' (title='A.jpg', relationship='parentOf')]
```
This is exactly the case described in the Jira ticket — the ingredient exists but has `parentOf` instead of `componentOf`.

#### Site C — `c2pa.transcoded` / `c2pa.repackaged` / ParentOf (section 2.c, ~line 2421)

Same pattern.

## Test coverage

The test image `CAIAIIICAICIICAIICICA.jpg` (generated by `make images`) already triggers this failure. After the fix:

1. `cargo test` in `sdk/` — existing integration tests should still pass (error codes unchanged, only messages change)
2. Add a new assertion in `sdk/tests/integration.rs` or `sdk/tests/v2_api_integration.rs` that:
   - Loads the test image
   - Finds the `assertion.action.ingredientMismatch` validation failure
   - Asserts the explanation contains the action index, action type, and ingredient URL

## What does NOT change

- Validation status code: still `assertion.action.ingredientMismatch`
- Error type: still `Error::ValidationRule`
- Any public API surface
- JSON output structure — only the `"explanation"` string value improves

## Files to touch

| File | Change |
|------|--------|
| `sdk/src/claim.rs` | `enumerate()` on inner loop + improved messages at 3 sites |
| `sdk/src/assertions/ingredient.rs` | Optionally add `impl fmt::Display for Relationship` (or use inline match) |
| `sdk/tests/integration.rs` or `v2_api_integration.rs` | New test asserting richer explanation string |

## Estimated effort

Small — 3 error sites, same pattern each. No API changes. ~50–80 lines of code total.
