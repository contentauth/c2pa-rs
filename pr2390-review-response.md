# PR #2390 — response to review comment

**Branch:** `mathern/tighten-redaction-checks-3`
**Comment:** dcondrey, review `4838629634`, `sdk/src/claim.rs` L1826–1836.

---

## Verdict

The comment spots a real quirk in `assertion_label_from_link`, but the premise about the *stored*
side is wrong, and applying the suggested patch would break the only path that reaches
`redact_assertion` in production.

No production-logic change. The changeset is one clarifying comment plus test coverage.

Everything below was verified by running code on this branch, not by reading it.

---

## What the comment gets right

`Claim::assertion_label_from_link` (claim.rs:4107) does truncate:

| box label | parsed label | instance | round-trips |
|---|---|---|---|
| `com.example.a` | `com.example.a` | 0 | yes |
| `com.example.a__1` | `com.example.a` | 1 | yes |
| `com.example.a__b` | `com.example.a` | 0 | **no** |
| `com.example.my__cool__box` | `com.example.my` | 0 | **no** |
| `c2pa.thumbnail.ingredient__3.jpeg` | `c2pa.thumbnail.ingredient.jpeg` | 3 | yes |

Only labels whose `__` suffix is non-numeric, or which carry two or more `__`, lose information.

## Why the suggested patch is wrong

The suggestion replaces `target` with the raw final segment of the normalized URI. That compares
an un-normalized string against a normalized one.

`redact_assertion` is reachable from exactly one place — `Claim::add_ingredient_data`
(claim.rs:3762) — and its `ingredient: Vec<Claim>` always comes from
`Store::from_jumbf_with_context` (store.rs:4087, 4169). Every assertion in such a claim has been
normalized twice on the way in:

- `Store::get_assertion_from_jumbf_store` (store.rs:847) runs
  `Claim::assertion_label_from_link(label)` and passes `raw_label` to `Assertion::from_data_*`.
- `Assertion::from_assertion_data` (assertion.rs:384) normalizes again:
  `assertion_label_from_link` → `label_with_instance`.

So for a JUMBF box named `com.example.a__b`, the loaded `ClaimAssertion` has
`label_raw() == "com.example.a"` and `instance() == 0`. The current comparison matches it; the
suggested one returns `AssertionRedactionNotFound`.

## The scenario in the comment cannot occur

A label like `com.example.a__b` never reaches a signed manifest. It fails earlier, at signing:

```
sign1: AssertionMissing { url: "com.example.a__b" }
sign1: AssertionMissing { url: "com.example.my__cool__box" }
```

`add_assertion_impl` (claim.rs:1440) stores the label verbatim, while
`assertion_hashed_uri_from_label` (claim.rs:4154) looks it up in normalized form, so the two
disagree and signing aborts. Such a label cannot be written, therefore cannot be loaded,
therefore cannot reach `redact_assertion`.

That is a genuine bug, but on the write path, and pre-existing. Filed separately rather than
widening this PR. The same issue covers a second finding: `assertion_label_from_link` splits on
`split("__")` (claim.rs:4123) while `labels::parse_label` uses `rfind("__")`
(assertions/labels.rs:283). On `com.example.my__cool__box` they disagree —
`com.example.my` vs `com.example.my__cool`.

---

## What changed in this PR

### `sdk/src/claim.rs` — comment only

The correctness of the comparison depends on an invariant that was doing real work but was
written down nowhere: both sides are normalized. That is now recorded above the comparison, with
the reasoning and the file references, so the next reader does not have to re-derive it.

### Tests

`sdk/src/claim.rs`:

- `test_redact_assertion_instance_labels_are_exact` — three instances of one label
  (`com.example.a`, `__1`, `__2`); redacting each removes only its own.
- `test_redact_assertion_suffix_label_is_not_a_match` — `example.a` and `org.example.a` stored
  together; redacting `org.example.a` must not remove `example.a`. **This is the regression guard
  for the `ends_with` bug**: it is the only test in the suite that fails when the predicate is
  reverted (verified by mutation, see below).
- `test_redact_assertion_prefix_is_not_a_match` — `com.example.meta` must not match a stored
  `com.example.metadata`.
- `test_redact_assertion_label_from_link_round_trip` — pins the invariant from the comment across
  every label form the SDK emits, including thumbnail and instance forms.
- `test_lossy_label_normalization_is_the_reason` — documents *why* the lossy labels fail:
  `assertion_label_from_link` truncates them while `add_assertion` stores them raw.

`sdk/src/builder.rs`:

- `test_redact_assertion_instance_label_end_to_end` — the real path, sign → load → redact →
  re-sign → read back, against an ingredient holding both `stds.schema-org.CreativeWork` and
  `stds.schema-org.CreativeWork__1`. Runs **both directions**: redacting the `__1` URI leaves the
  base, and redacting the un-suffixed URI leaves `__1`. The second direction is the comment's
  scenario in executable form — a redaction URI with no instance suffix resolved against a store
  that also holds a `__1` sibling — and it passes on the current code.
- `test_lossy_labels_are_rejected_at_signing` — asserts `AssertionMissing` for
  `com.example.a__b` and `com.example.my__cool__box`. This is what makes the comment's scenario
  unreachable, so it is pinned rather than left as an argument: if the write path is ever fixed
  to accept these labels, this test fails and the redaction comparison gets revisited instead of
  silently relying on an assumption that no longer holds.

---

## Verification

```
cargo test -p c2pa --lib redact     32 passed (was 27)
cargo clippy -p c2pa --all-targets  clean
cargo fmt                           clean
cargo test -p c2pa --lib            855 passed, 3 failed
```

The 3 failures (`test_png_jumbf_generation`, `test_png_compressed_jumbf_generation`,
`test_user_guid_external_manifest_embedded`) are pre-existing and unrelated — missing PNG
fixtures in the embedded registry. Confirmed identical on a stashed baseline (848 passed, same 3
failed).

Mutation check — reverting the predicate to the pre-PR form:

```rust
.position(|x| assertion_uri.ends_with(&Claim::label_with_instance(&x.label_raw(), x.instance())))
```

fails `test_redact_assertion_suffix_label_is_not_a_match`, and nothing else in the suite. Worth
noting: the pre-existing tests all still pass under that mutation, so before this PR the
`ends_with` defect had no test that caught it.

---

## Suggested reply

> Good catch on the truncation in `assertion_label_from_link` — that part is real, a label like
> `com.example.a__b` does parse to `("com.example.a", 0)`.
>
> The suggested change would break this path though. `redact_assertion` only runs on ingredient
> claims that came out of `Store::from_jumbf_with_context` (via `add_ingredient_data`,
> claim.rs:3762), and both `get_assertion_from_jumbf_store` (store.rs:847) and
> `Assertion::from_assertion_data` (assertion.rs:384) already push the box label through
> `assertion_label_from_link` → `label_with_instance`. So the stored side is normalized too and
> the current comparison matches. Taking the raw final URI segment would compare an un-normalized
> string against a normalized one and return `AssertionRedactionNotFound` on exactly the
> production path.
>
> I also checked whether a label like `com.example.a__b` can reach here at all, and it can't — it
> fails earlier, at signing:
>
> ```
> sign1: AssertionMissing { url: "com.example.a__b" }
> ```
>
> `add_assertion_impl` stores it under the raw label while `assertion_hashed_uri_from_label`
> looks it up normalized, so it never makes it into a signed manifest. That's a real bug, just on
> the write path — filing it separately, along with the fact that `assertion_label_from_link`
> (`split("__")`) and `labels::parse_label` (`rfind("__")`) disagree on multi-separator labels.
>
> Leaving the comparison as is, but I didn't want "that case can't happen" to rest on my reading
> of the code, so it's pinned by tests:
>
> - an end-to-end test through sign → load covering your case in both directions: a manifest
>   holding both `stds.schema-org.CreativeWork` and `stds.schema-org.CreativeWork__1`, redacting
>   the suffixed URI (base survives) and then the un-suffixed one (`__1` survives). The second is
>   your scenario exactly, and it passes on the current code;
> - `example.a` vs `org.example.a` — one label a suffix of the other. This is the case the old
>   `ends_with` actually got wrong, and reverting the predicate is what makes it fail; the
>   existing tests all still passed under the old behaviour;
> - label/instance round-tripping across every label form we emit, so both sides of the
>   comparison are provably normalized;
> - a test asserting `com.example.a__b` and `com.example.my__cool__box` are rejected at signing.
>   That's what makes the scenario unreachable, so if the write path is ever fixed to accept them,
>   the test fails and this decision gets revisited rather than going stale.
>
> Also added a comment recording why both sides are normalized, since that invariant was
> load-bearing but undocumented.
