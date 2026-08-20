# Experimental features policy

The Content Authenticity Initiative (CAI) SDK is an evolving project, and we welcome contributions from the wider community. From time to time, an external contributor may propose a new feature that we believe is valuable but that the CAI team is not able to commit to maintaining as part of the core SDK.

Rather than reject such contributions outright, we may accept them as **experimental features**. This document describes what that designation means, the conditions a contribution must satisfy to qualify, and the support expectations that apply on both sides.

This policy complements the [Deprecation policy](deprecation-policy.md) and [Support tiers](support-tiers.md). Experimental features sit outside the stability guarantees described in those documents.

## What is an experimental feature?

An experimental feature is functionality that has been accepted into the SDK source tree but is **not** covered by the SDK's normal stability and maintenance commitments. We accept experimental features when we judge the feature to be of value to the community but cannot commit to maintaining it ourselves.

Experimental features let us give promising contributions a home and real-world exposure without expanding the surface area that the CAI team guarantees to support indefinitely. The same mechanism also serves first-party features that the CAI team maintains but is not ready to stabilize – for example, an API built for an internal need whose long-term design is still an open question.

In particular, experimental features are **not** covered by the [Deprecation policy](deprecation-policy.md) or its timelines. An experimental feature can be changed or removed in any release, with no deprecation window – once it is removed, it is gone.

## Conditions for acceptance

To be accepted as an experimental feature, a contribution must satisfy all of the following conditions.

### 1. Gated by a non-default crate feature

The feature must be gated by a Rust crate feature named `unstable_<name>` (for example, `unstable_widget_export`). This feature **must not** be enabled by default and must not be pulled in by any default feature set.

> [!NOTE]
> Cargo feature names in this repository use `snake_case` (for example, `add_thumbnails`, `fetch_remote_manifests`, `rust_native_crypto`). Experimental feature flags follow the same convention: `unstable_<name>`, not `unstable-<name>`.
>
> The `unstable_` prefix is deliberate. [`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks) — which we run on every release-line PR (see the [release process](release-process.md#semver-checks)) — by default ignores features named `unstable`, `nightly`, `bench`, or `no_std`, and any feature whose name begins with `_`, `unstable-`, or `unstable_`. Naming experimental flags `unstable_<name>` therefore makes our tooling automatically treat them as exempt from breaking-change detection, so changing or removing an experimental API never forces a version bump on its own.

### 2. Public API changes are gated

Any changes to the public API surface must be visible **only** when the experimental feature flag is enabled. With the flag disabled, the public API must be identical to a build that does not include the feature at all (for example, by gating the affected items with `#[cfg(feature = "unstable_<name>")]`).

### 3. New dependencies are optional and gated

Any new crate dependencies introduced for the feature must be declared as `optional = true` and must be activated only by the experimental feature flag (via `dep:<crate>` in the feature definition). A default build must not compile or link these dependencies.

### 4. No adverse impact when disabled

The feature must not have an adverse effect on the performance or behavior of the SDK when the feature is disabled. A build without the feature should be indistinguishable, in performance and behavior, from one in which the feature does not exist.

### 5. Listed in the registry

The feature must be added to the [Registry of experimental features](#registry-of-experimental-features) section below, including:

- The human-readable feature name.
- The Cargo feature flag in `unstable_<name>` form.
- A brief (a few sentences) description of the feature's behavior.
- Contact information for support, including **at least one GitHub username** of a maintainer or sponsor who can answer questions about the feature.
- A link to the feature's open discussion issue (see condition 7).

### 6. Same licensing and dependency review as the rest of the SDK

Experimental features are exempt from the CAI team's *maintenance* commitments, not from the project's legal and supply-chain requirements. The contributed code must be offered under the SDK's existing license terms, and any new dependency (see condition 3) is subject to the same license-compatibility and security review as any other dependency in the tree. A feature whose license or dependencies cannot be cleared is not eligible for acceptance – experimental or otherwise.

### 7. Tracked by an open discussion issue

Before a feature is accepted, an issue must be opened on the [`c2pa-rs` issue tracker](https://github.com/contentauth/c2pa-rs/issues) proposing it as an experimental feature. The team and community use that issue to discuss and agree to host the feature in the first place; it then stays open for the life of the feature as the standing home for design discussion, change proposals, bug reports, and any argument for promotion or removal. Each registry entry links to its feature's issue. Closing the issue signals that the feature has been promoted or removed.

## Stability and support expectations

By accepting a feature as experimental, the CAI team makes **no** stability guarantees about it:

- **Unstable by design.** Any APIs or behaviors gated by an experimental feature flag are considered unstable and may be altered or removed at any time, in any release, without following the [Deprecation policy](deprecation-policy.md).
- **Best-effort maintenance.** The CAI team will make a best effort to keep experimental features building and working as the primary SDK evolves, but reserves the right to disable or remove an experimental feature if it cannot be made compatible with the primary SDK code.
- **Community-supported.** Day-to-day support for an experimental feature is primarily the responsibility of the contributor and the contacts listed in the registry, not the CAI team.
- **Security handled by responsiveness.** A security or licensing problem reported against experimental code is handled on the same best-effort, community-supported basis. If the registered contact does not address it promptly, the CAI team will disable or remove the feature immediately rather than wait out any window – protecting the primary SDK takes precedence over preserving an experimental feature.

### Exempt from breaking-change calculations

Because experimental features are gated behind a non-default flag and excluded from the public API of a default build, changing or removing one is **not** considered a breaking change under the [Deprecation policy](deprecation-policy.md), and it never forces a minor/breaking (`0.x.0`) version bump.

The `unstable_` flag prefix makes this automatic: [`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks) ignores `unstable_`-prefixed features by default, so a change confined to an experimental feature is never flagged as a break. Experimental APIs are therefore free to change at will – including breaking changes, at any time, in any release – **provided that the change does not affect any API in the public/stable surface** (a default build, or any non-experimental feature). See [Semver checks](release-process.md#semver-checks) in the release process.

This does **not** mean experimental changes are invisible to consumers. A change to an experimental feature may still ride an ordinary patch (`0.x.y`) release, and it is recorded in a dedicated **Experimental** section of the changelog so that anyone who has opted into an `unstable_` feature has a clear, human-readable signal of what changed. What the exemption removes is the *semver guarantee* (and the minor/breaking bump), not the paper trail. To get this routing, mark such commits with the `experimental` scope – for example `feat(experimental): add widget export` or `fix(experimental): correct frame ordering` – and never use the breaking (`!`) marker on them, since experimental APIs are outside semver by definition. See [Version numbering](release-process.md#version-numbering-across-a-train) and the commit-scope rules in the release process.

## Build and CI expectations

Experimental features are held to the SDK's quality bar **at contribution time** – they must build cleanly and pass `cargo +nightly fmt`, `clippy`, and their own tests when accepted – but keeping them green over time is best-effort and primarily the contact's responsibility, not the CAI team's.

To make that split concrete:

- **Not part of the merge gate.** A dedicated, **non-blocking** workflow ([`experimental-features.yml`](../.github/workflows/experimental-features.yml)) builds, lints, and tests the SDK with every `unstable_` feature enabled, on pull requests and on a daily schedule. It is advisory only – it is deliberately not a required status check, so a failure there never blocks a merge.
- **Broken features get disabled, not fixed on demand.** When an experimental feature stops building or passing – for example after a Rust toolchain update or a refactor of the primary SDK – the CAI team will notify the registered contact. If it is not repaired promptly, the feature is disabled (removed from the build, and ultimately from the tree) rather than holding up the SDK. This keeps one unmaintained feature from blocking everyone.
- **Excluded from the required build/test/lint suites.** The required [Tier 1A](../.github/workflows/tier-1a.yml), [Tier 1B](../.github/workflows/tier-1b.yml), and [Tier 2](../.github/workflows/tier-2.yml) suites – along with the [beta preflight](../.github/workflows/beta-preflight.yml) and the [cross-repo canary](../.github/workflows/canary-extracted-crates.yml) – build the non-experimental feature set only, so experimental breakage cannot fail the ordinary compile, test, or lint gates. (They compute the feature list from `cargo metadata` and filter out `unstable_`-prefixed features; Tier 2 builds no `unstable_` features to begin with.) The one deliberate exception is the Tier 1A `docs.rs` preflight: experimental APIs *are* intentionally published to docs.rs (clearly marked experimental), so that job mirrors the real docs.rs build and does compile them.

## Promotion or removal

An experimental feature is not expected to remain experimental forever. Over time, an experimental feature may be:

- **Promoted** to a fully supported feature if it proves valuable and the CAI team is able to take on its maintenance. At that point it becomes subject to the normal stability and deprecation guarantees.
- **Removed** if it falls out of maintenance, loses its last responsive contact, cannot be kept compatible with the primary SDK, or is no longer of sufficient value to justify its presence in the tree.

### Handing off or losing a contact

A registered contact is the feature's lifeline. Contacts are kept current by pull request: a contact who can no longer support a feature should hand it off by updating the registry to name a replacement. If a feature is left with **no responsive contact** – nobody who answers questions or repairs breakage – it becomes an immediate candidate for removal under the rule above; the CAI team is not obligated to adopt an orphaned experimental feature.

## Registry of experimental features

The following table lists the experimental features currently present in the SDK. See [Conditions for acceptance](#conditions-for-acceptance) for what each entry must include.

| Feature | Cargo flag | Description | Contact | Discussion |
| -- | -- | -- | -- | -- |
| Builder action/ingredient filtering | `unstable_builder_filter` | Adds `Builder::filter_actions`, `Builder::filter_ingredients`, `Builder::filter_actions_and_ingredients`, and `Ingredient::effective_id` for filtering the actions and ingredients written into a manifest. Maintained by the Adobe CAI team to serve an internal need; kept experimental because the long-term viability of the API design is not yet settled. | Adobe CAI team ([@contentauth](https://github.com/contentauth)) | [#2368](https://github.com/contentauth/c2pa-rs/issues/2368) |
| C2PA Live Video | `unstable_live_video` | Implements C2PA Technical Specification section 19 (Live Video) for DASH/HLS fMP4 streams: both the per-segment C2PA Manifest Box method (§19.3) and the Verifiable Segment Info method (§19.4), including `signerBinding` verification (§19.7.3) and per-segment `bmffHash` validation (§19.4.1). Covers signing and validation for both methods, plus `live-video`/`live-video-sign` CLI subcommands. Contributed by Qualabs as a reference implementation for live provenance. | Qualabs ([@N1Knight](https://github.com/N1Knight)) | [#2507](https://github.com/contentauth/c2pa-rs/issues/2507) |
