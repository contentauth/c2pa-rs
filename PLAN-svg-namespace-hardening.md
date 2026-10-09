# Plan: SVG namespace fix hardening (follow-up to PR #2801 / CAI-13991)

**Target:** `sdk/src/asset_handlers/svg_io.rs` on the PR #2801 branch (commit `e725d2ea`, "fix: Fix namespacing support"), quick-xml 0.41 `NsReader`.

**Goal:** Keep the PR's fix (prefixed `<ns0:svg>` roots sign, read and remove correctly). Close the gaps where element matching is ambiguous, where the writer can produce manifests the reader rejects, and where errors are misleading. Do not break any SVG that current `main` can sign or validate.

**Baseline before starting:** `cargo test --lib svg_io` passes (15 tests) and `cargo fmt --check` is clean. Both must still hold at the end.

---

## Background: what was found

Each item below was reproduced with probe tests against `e725d2ea`.

| # | Finding | Severity |
|---|---|---|
| F1 | `canonical_element_name` falls back to the raw qname even when the prefix is **bound to a different namespace**. So `<metadata xmlns="http://other">` counts as SVG metadata, `<c2pa:manifest>` with `xmlns:c2pa="http://evil"` counts as the manifest, and `<y:manifest xmlns:y="http://c2pa.org/manifest">` now also counts. | Medium |
| F2 | When a file has both `<c2pa:manifest>` and an aliased `<y:manifest>` (same namespace), this PR reads the **last** one ("OTHER"), while `main` reads the literal one ("JUMBF"). Two SDK versions therefore validate different manifests from the same bytes. | Medium |
| F3 | `write_c2pa`, Metadata arm: with two `<metadata>` children, the writer inserts **a manifest into each**. This predates the PR, and the output becomes invalid once F2 is fixed by rejecting duplicates. | Medium |
| F4 | `detect_manifest_location` overwrites `output` on every `Text` event inside the manifest. So `<c2pa:manifest>AAA<!--x-->BBB</c2pa:manifest>` decodes only "BBB", while `insertion_point` points at "AAA". The hash-exclusion range and the decoded manifest then disagree. This predates the PR. | Medium |
| F5 | If the root binds `xmlns:c2pa` to a URI other than `http://c2pa.org/manifest`, `add_c2pa_namespace_if_missing` keeps that binding. The written `<c2pa:manifest>` is then in the wrong namespace and only round-trips because of the F1 fallback. | Low |
| F6 | A self-closing root (`<svg …/>`, `<ns0:svg …/>`) produces `NoRoot` and the error "SVG root element not found", even though the root exists. A non-SVG root whose children are all self-closing also reports `NoRoot` instead of "root must be svg", because the root check only runs at depth 2. | Low |
| F7 | `NsReader` rejects `xmlns:xml="…"` (rebinding) and `xmlns:xmlns="…"` with "XML invalid". The old `Reader` accepted both. | Low (behavior change) |
| F8 | Nits: `metadata_element_name(&e)` is computed for every start element in the Empty/Xmp arm. The `Xmp` variant can never reach `write_c2pa`, because `detect_manifest_location` never returns it. | Nit |

**Compatibility constraint:** before #2113 (May 2026), c2pa-rs declared `xmlns:c2pa` on the `<c2pa:manifest>` element instead of the root. Third-party writers may have omitted the declaration entirely. An undeclared `c2pa:` prefix resolves to `ResolveResult::Unknown(b"c2pa")`, and current code reads such files successfully. **That must keep working.**

---

## Step 1: Make element matching strict (F1, F5 read side)

Replace `canonical_element_name` with explicit matchers. Keep the existing string constants so the `xml_path == [SVG, METADATA, MANIFEST]` comparisons don't change.

```rust
fn canonical_element_name(element: &BytesStart, ns: ResolveResult<'_>) -> String {
    let name = element.name();
    let local = name.local_name();
    let unprefixed = name.prefix().is_none();

    let is_svg_ns = matches!(ns, ResolveResult::Bound(n) if n.into_inner() == SVG_NS);
    let is_c2pa_ns = matches!(ns, ResolveResult::Bound(n) if n.into_inner() == C2PA_NS);
    // Unprefixed name with no default namespace in scope.
    let no_ns = unprefixed && matches!(ns, ResolveResult::Unbound);
    // Legacy: `c2pa:` prefix used without any declaration in scope.
    let legacy_c2pa = matches!(ns, ResolveResult::Unknown(ref p) if p.as_slice() == b"c2pa");

    match local.as_ref() {
        // Root: an unprefixed `svg` stays lenient (any default namespace, as on main);
        // a prefixed root must be in the SVG namespace.
        b"svg" if is_svg_ns || unprefixed => SVG.to_string(),
        b"metadata" if is_svg_ns || no_ns => METADATA.to_string(),
        b"manifest" if is_c2pa_ns || legacy_c2pa => MANIFEST.to_string(),
        // Never collides with SVG / METADATA / MANIFEST.
        _ => format!("{{other}}{}", String::from_utf8_lossy(name.as_ref())),
    }
}
```

Check that `ResolveResult::Unknown` carries a `Vec<u8>` in quick-xml 0.41 and adjust the pattern if it doesn't.

**Decisions this encodes:**
- **Unprefixed root `svg`:** matched regardless of default namespace. `main` accepts `<svg xmlns="http://not-svg">`, so tightening this would reject files that sign today. Leave a comment saying the leniency is deliberate.
- **`metadata`:** matched only in the SVG namespace, or when unprefixed with no default namespace. `<metadata xmlns="http://other">` no longer matches.
- **`manifest`:** matched only in the C2PA namespace, or under the undeclared `c2pa:` legacy case. `<c2pa:manifest>` with `xmlns:c2pa` bound to another URI no longer matches.
- **Fallback:** non-matching names get an `{other}` prefix so they can never equal a constant by accident.

**Watch out for:** `test_svg_shrunk_manifest_injection_rejected` and the `#2113` namespace tests must still pass unchanged.

## Step 2: Exactly one manifest, one text payload (F2, F4)

In `detect_manifest_location`:

1. Add a `manifest_count: usize`. On each `Start` where `xml_path == [SVG, METADATA, MANIFEST]`, increment it. If it reaches 2, return:
   `Err(Error::InvalidAsset("multiple c2pa:manifest elements".into()))`.
   This counts manifests across **all** `<metadata>` siblings, not just within one.
2. Handle a manifest that is a self-closing `Event::Empty` at the same path the same way (count it too), so `<c2pa:manifest/>` plus a real manifest is also rejected.
3. Make the manifest's content a single text node:
   - Add `manifest_text_seen: bool`, reset on the manifest `Start`.
   - A second `Text` event inside the manifest returns `InvalidAsset("c2pa:manifest must contain a single text node")`.
   - Any `Comment`, `CData`, `PI` or child `Start`/`Empty` while `xml_path` starts with `[SVG, METADATA, MANIFEST]` returns the same error.
   - Leading or trailing whitespace inside the single text node keeps its current handling.
4. In `remove_c2pa` and the `write_c2pa` Manifest arm, call `detect_manifest_location` first, or otherwise rely on it, so a file with two manifests fails instead of being half-processed. `write_c2pa` already calls `detect_manifest_location`; `remove_c2pa` does not. Add the call at the top of `remove_c2pa`, before the rewrite loop, and rewind the stream afterward.

## Step 3: Writer inserts into exactly one `<metadata>` (F3)

In the `write_c2pa` `DetectedTagsDepth::Metadata` arm:
- Add `let mut inserted = false;`.
- Insert the manifest only when `xml_path == [SVG, METADATA] && !inserted`, then set `inserted = true`.
- Use the **first** `<metadata>` child.

Also make `detect_manifest_location` record the **first** metadata position (`if !metadata_seen { … }`) rather than the last, so detection and writing agree. The returned `insertion_point` for the Metadata level isn't used by the writer today, but keep the two consistent.

## Step 4: Avoid the c2pa prefix conflict on write (F5 write side)

Change `add_c2pa_namespace_if_missing` to return `Result<()>`:
- If no `xmlns:c2pa` is present, add it as today.
- If `xmlns:c2pa` is present **with** the value `http://c2pa.org/manifest`, do nothing.
- If `xmlns:c2pa` is present with **another value**, return:
  `Err(Error::InvalidAsset("xmlns:c2pa is bound to a different namespace on the SVG root".into()))`.

Update the three call sites in `write_c2pa` to use `?`.

A rebinding of `xmlns:c2pa` *inside* `<metadata>` is not handled here. After Step 1, the written manifest would not be found and signing fails closed with `JumbfNotFound`. Add a test that locks in this fail-closed behavior; don't try to support the case.

## Step 5: Clearer root errors (F6)

In `detect_manifest_location`:
1. Validate the root on the **depth-1 `Start`**, not at depth 2. If `canonical_element_name(root) != SVG`, return the existing "root element must be \"svg\", found \"{raw}\"" error right away. Remove the depth-2 branch.
2. Handle `Event::Empty` at depth 0, which is a self-closing root:
   - If it canonicalizes to `SVG`, return `InvalidAsset("SVG root element is self-closing; cannot embed a manifest")`.
   - Otherwise, return the "root must be svg" error.

   Supporting `<svg/>` by rewriting it to `<svg>…</svg>` is out of scope.
3. Do the same in `read_xmp`, so `write_xmp` reports the same errors.

Keep `NoRoot` for genuinely element-less input (empty stream, or only a prolog and comments).

**Read-path impact:** `read_c2pa` on a non-SVG XML document returns `InvalidAsset` instead of `JumbfNotFound` in more cases. Before merging, check whether any `Reader`/validation code branches on `JumbfNotFound` for SVG (`grep -rn JumbfNotFound sdk/src`). If something depends on it, keep `JumbfNotFound` for the read path and use the new error only on write.

## Step 6: `NsReader` strictness (F7)

**Decision:** keep `NsReader`. Documents that rebind `xml` or declare `xmlns:xmlns` are not namespace-well-formed and are unlikely to occur in practice.
- Add a test that locks in the behavior (`InvalidAsset("XML invalid")`).
- Add one line to the PR description or changelog noting the behavior change.

## Step 7: Nits (F8)

- In the Empty/Xmp arm of `write_c2pa`, compute `metadata_qname` only inside `if xml_path == [SVG]`.
- Replace `DetectedTagsDepth::Empty | DetectedTagsDepth::Xmp` with `DetectedTagsDepth::Empty`, plus an explicit `DetectedTagsDepth::Xmp => unreachable_err` arm that returns `Error::OtherError("unexpected Xmp level in write_c2pa")`. Don't use `unreachable!()`, because the crate denies panics in library code.

---

## Step 8: Tests

Add these to `svg_io::tests`. Inputs are kept minimal on purpose. `JUMBF_B64` means `base64::encode(b"JUMBF")`.

| Test | Input (abbreviated) | Expected |
|---|---|---|
| `ns_wrong_ns_metadata_not_matched` | `<ns0:svg xmlns:ns0=SVG><metadata xmlns="http://other"></metadata></ns0:svg>` | detect level is `Empty`, not `Metadata`. `write_c2pa` adds a new `<ns0:metadata>` and the output round-trips. |
| `ns_c2pa_prefix_wrong_ns_not_read` | `<svg xmlns=SVG xmlns:c2pa="http://evil"><metadata><c2pa:manifest>JUMBF_B64</c2pa:manifest></metadata></svg>` | `read_c2pa` returns `JumbfNotFound`. |
| `ns_c2pa_prefix_wrong_ns_write_rejected` | `<ns0:svg xmlns:ns0=SVG xmlns:c2pa="http://evil"><ns0:rect/></ns0:svg>` | `write_c2pa` returns `InvalidAsset`. |
| `ns_legacy_undeclared_c2pa_prefix_reads` | `<svg xmlns=SVG><metadata><c2pa:manifest>JUMBF_B64</c2pa:manifest></metadata></svg>` (no `xmlns:c2pa`) | `read_c2pa` returns `b"JUMBF"`. **Regression guard.** |
| `ns_legacy_manifest_level_decl_reads` | `xmlns:c2pa` declared on `<c2pa:manifest>` itself (pre-#2113 layout) | Reads `b"JUMBF"`, and `write_c2pa` (Manifest arm) replaces the payload. |
| `ns_aliased_manifest_prefix_reads` | single `<x:manifest xmlns:x="http://c2pa.org/manifest">JUMBF_B64</x:manifest>` | Reads `b"JUMBF"`. |
| `ns_duplicate_manifest_rejected` | literal `<c2pa:manifest>` and aliased `<y:manifest>` in one `<metadata>` | `read_c2pa`, `write_c2pa`, `remove_c2pa` and `get_object_locations` all return `InvalidAsset`. |
| `duplicate_manifest_across_metadata_rejected` | two `<metadata>` elements, each with a `<c2pa:manifest>` | `InvalidAsset`. |
| `two_metadata_writes_single_manifest` | `<svg xmlns=SVG><metadata></metadata><metadata></metadata></svg>` | Output has exactly one `<c2pa:manifest>`, in the first `<metadata>`. A full sign plus `Reader` gives `Trusted`. |
| `manifest_split_text_rejected` | `<c2pa:manifest>AAA<!--x-->BBB</c2pa:manifest>` | `InvalidAsset`. |
| `manifest_cdata_rejected` | `<c2pa:manifest><![CDATA[JUMBF_B64]]></c2pa:manifest>` | `InvalidAsset`. |
| `prefixed_root_wrong_ns_rejected` | `<ns0:svg xmlns:ns0="http://not-svg"><ns0:rect/></ns0:svg>` | "root element must be \"svg\"" error from `write_c2pa`. |
| `unprefixed_root_any_default_ns_still_accepted` | `<svg xmlns="http://not-svg"><rect/></svg>` | Signs and reads back. **Locks the deliberate leniency.** |
| `self_closing_root_clear_error` | `<svg xmlns=SVG/>` and `<ns0:svg xmlns:ns0=SVG/>` | `InvalidAsset` mentioning "self-closing". |
| `ns_rebound_prefix_on_child_metadata` | `<ns0:svg xmlns:ns0=SVG><ns0:metadata xmlns:ns0="http://other"></ns0:metadata></ns0:svg>` | Child is not treated as metadata. A new `<ns0:metadata>` is inserted and the output round-trips. |
| `default_ns_root_prefixed_metadata` | `<svg xmlns=SVG xmlns:s=SVG><s:metadata></s:metadata></svg>` | Manifest is inserted into `<s:metadata>`. Output round-trips. |
| `prefixed_root_write_xmp_then_sign` | `NS0_EMPTY_CHILDREN` → `write_xmp` → `Builder::save_to_stream` | XMP lands in `<ns0:metadata>`, and the manifest goes into the **same** element. `Trusted`. |
| `metadata_rebinds_c2pa_fails_closed` | `<svg xmlns=SVG><metadata xmlns:c2pa="http://evil"></metadata></svg>` → sign | Signing returns an error (not a silently unverifiable file). |
| `nsreader_rejects_xml_prefix_rebind` | `<svg xmlns=SVG xmlns:xml="http://other"><rect/></svg>` | `InvalidAsset("XML invalid")`. |
| `unprefixed_output_byte_identical` | each existing fixture under `sdk/tests/fixtures/*.svg` | Output of `write_c2pa` matches what `main` (`58b9a092`) produces byte-for-byte. Either generate expectations once from `main`, or compare against `Reader`-based helpers. **Guards against silent format drift.** |

Reuse the TSA-disabled `Context` setup from `tests_prefixed_namespace_root_roundtrips` for the sign-and-read tests.

## Acceptance criteria

- [ ] All existing `svg_io` tests pass unchanged, including `test_svg_shrunk_manifest_injection_rejected` and the #2113 namespace tests.
- [ ] All tests in Step 8 pass.
- [ ] `cargo fmt --check`, plus `cargo clippy --all-features -- -D warnings` for the `sdk` crate, are clean.
- [ ] `read_c2pa`, `get_object_locations`, `remove_c2pa` and `write_c2pa` all agree on which element is the manifest. Any input that would make them disagree is rejected.
- [ ] No SVG that `main` signs and validates as `Trusted` today stops validating, except files with duplicate or split manifests, which are rejected on purpose.

## Out of scope

- Supporting self-closing `<svg/>` roots by expanding them.
- Choosing an alternate prefix when `c2pa` is taken. This plan errors instead.
- Rejecting unprefixed `svg` roots with a non-SVG default namespace.
- Spec-level questions about which `<metadata>` element a manifest may live in.
