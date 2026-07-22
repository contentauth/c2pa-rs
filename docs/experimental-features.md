# Experimental features policy

The Content Authenticity Initiative (CAI) SDK is an evolving project, and we welcome contributions from the wider community. From time to time, an external contributor may propose a new feature that we believe is valuable but that the CAI team is not able to commit to maintaining as part of the core SDK.

Rather than reject such contributions outright, we may accept them as **experimental features**. This document describes what that designation means, the conditions a contribution must satisfy to qualify, and the support expectations that apply on both sides.

This policy complements the [Deprecation policy](deprecation-policy.md) and [Support tiers](support-tiers.md). Experimental features sit outside the stability guarantees described in those documents.

## What is an experimental feature?

An experimental feature is functionality that has been accepted into the SDK source tree but is **not** covered by the SDK's normal stability and maintenance commitments. We accept experimental features when we judge the feature to be of value to the community but cannot commit to maintaining it ourselves.

Experimental features let us give promising contributions a home and real-world exposure without expanding the surface area that the CAI team guarantees to support indefinitely.

## Conditions for acceptance

To be accepted as an experimental feature, a contribution must satisfy all of the following conditions.

### 1. Gated by a non-default crate feature

The feature must be gated by a Rust crate feature named `experimental_<name>` (for example, `experimental_widget_export`). This feature **must not** be enabled by default and must not be pulled in by any default feature set.

> [!NOTE]
> Cargo feature names in this repository use `snake_case` (for example, `add_thumbnails`, `fetch_remote_manifests`, `rust_native_crypto`). Experimental feature flags follow the same convention: `experimental_<name>`, not `experimental-<name>`.

### 2. Public API changes are gated

Any changes to the public API surface must be visible **only** when the experimental feature flag is enabled. With the flag disabled, the public API must be identical to a build that does not include the feature at all (for example, by gating the affected items with `#[cfg(feature = "experimental_<name>")]`).

### 3. New dependencies are optional and gated

Any new crate dependencies introduced for the feature must be declared as `optional = true` and must be activated only by the experimental feature flag (via `dep:<crate>` in the feature definition). A default build must not compile or link these dependencies.

### 4. No adverse impact when disabled

The feature must not have an adverse effect on the performance or behavior of the SDK when the feature is disabled. A build without the feature should be indistinguishable, in performance and behavior, from one in which the feature does not exist.

### 5. Listed in the registry

The feature must be added to the [Registry of experimental features](#registry-of-experimental-features) section below, including:

- The human-readable feature name.
- The Cargo feature flag in `experimental_<name>` form.
- A brief (a few sentences) description of the feature's behavior.
- Contact information for support, including **at least one GitHub username** of a maintainer or sponsor who can answer questions about the feature.

## Stability and support expectations

By accepting a feature as experimental, the CAI team makes **no** stability guarantees about it:

- **Unstable by design.** Any APIs or behaviors gated by an experimental feature flag are considered unstable and may be altered or removed at any time, in any release, without following the [Deprecation policy](deprecation-policy.md).
- **Best-effort maintenance.** The CAI team will make a best effort to keep experimental features building and working as the primary SDK evolves, but reserves the right to disable or remove an experimental feature if it cannot be made compatible with the primary SDK code.
- **Community-supported.** Day-to-day support for an experimental feature is primarily the responsibility of the contributor and the contacts listed in the registry, not the CAI team.

Because experimental features are gated behind a non-default flag and excluded from the public API of a default build, changing or removing one is **not** considered a breaking change under the [Deprecation policy](deprecation-policy.md).

## Promotion or removal

An experimental feature is not expected to remain experimental forever. Over time, an experimental feature may be:

- **Promoted** to a fully supported feature if it proves valuable and the CAI team is able to take on its maintenance. At that point it becomes subject to the normal stability and deprecation guarantees.
- **Removed** if it falls out of maintenance, cannot be kept compatible with the primary SDK, or is no longer of sufficient value to justify its presence in the tree.

## Registry of experimental features

The following table lists the experimental features currently present in the SDK. See [Conditions for acceptance](#conditions-for-acceptance) for what each entry must include.

| Feature | Cargo flag | Description | Contact |
| -- | -- | -- | -- |
| _(none yet)_ | | | |
