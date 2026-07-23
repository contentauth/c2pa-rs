# Open-source release process

This document describes how we release `c2pa-rs` and its related crates, and the branching model that supports it. It applies to the **0.x (pre-1.0) phase**; we will revisit it as we approach a 1.0 stability commitment.

## Goals

We have two main goals:

* **Move fast on pre-1.0 refactors.** While we're below 1.0, we may make larger refactors and breaking API changes.
* **Be stable and predictable as much as possible for users** (including ourselves and the other language bindings that build on this crate): a steady stream of features, plus breaking changes that arrive on a pre-determined *known schedule*

## Core principle: split by breaking vs. non-breaking

What matters to someone depending on this crate isn't whether a change is "big" — it's whether it breaks their build. An additive feature costs them nothing; a changed or removed API forces a migration with potential fixes and updates to their build system. So we govern those two kinds of change on two different tracks, which map directly onto pre-1.0 Cargo semantics:

| Change kind | Version slot | Cargo treats it as | Track |
| -- | -- | -- | -- |
| Additive / non-breaking | `0.x.y` (bump `y`) | compatible | **Track 1** — fast, on the current train |
| Breaking | `0.x.0` (bump `x`) | incompatible | **Track 2** — scheduled "train" |

Most changes never wait for the train: anything additive ships fairly quickly by being backported to the stable release train; only breaking changes are batched and scheduled.

## Branching model

| Branch | Role | Published to crates.io? |
| -- | -- | -- |
| `main` | Always green but API-unstable ("nightly-like"). It must always compile and pass tests, but its public API is **not** guaranteed stable — it may contain unstabilized or feature-gated work. | **No** |
| `stable` | Tracks the most-recent crates.io release and is the currently-active release line. Additive (`0.x.y`) releases, and the promoted breaking (`0.x.0`) release, are published from here. | **Yes** |
| `v0.x` (e.g. `v0.89`) | A long-lived branch for a **retired** release line, snapshotted from `stable` when that line is retired. A potential target if a security or other critical bug fix is made to a retired line. | Yes (rare backports) |
| `0.(x+1).0-rc` (release-candidate branch) | A transient breaking candidate, cut from `main`, that bakes before promotion. Its name ends in `-rc` so it is validated by CI but **never** matches a crates.io publish trigger. Individual **builds** cut from it (`-rc.1`, `-rc.2`, …) are tagged and get *prerelease* GitHub releases with binaries, but are never published to crates.io. | crates.io: **No**; GitHub-release binaries: **yes** |

The branch-name conventions are also the crates.io publish guard: the publish workflow only ever runs on `stable` and `v0.*`, and the `-rc`-named candidate branch matches neither, so a candidate can never be published to crates.io by construction. (Its build tags carry the `-rc.` prerelease marker and drive binary-only GitHub releases; see [RC builds](#release-candidate-builds).)

Two rules keep this coherent:

* **Upstream-first.** Every change lands on `main` first. Release-line branches only ever *receive* changes (via cherry-pick); nothing originates on them. This guarantees `main` is always the superset and that nothing is lost across a major bump. Two mechanisms enforce it: a proactive [upstream-first check](#upstream-first-check-proactive) on every PR to a release branch, and a scheduled [reconciliation check](#reconciliation-check-reactive) as a backstop.
* **`main` stays releasable.** Destabilizing work happens on feature branches off `main`, merged only once coherent.

> **A note on cherry-picking.** Cherry-picking transfers individual fixes between branches without merging everything. Because actively-supported lines can diverge over time, a fix that applies cleanly on one branch may not cherry-pick directly onto another. In that case the change may need to be adapted to compile, integrate, and pass tests on the target branch — or, if the branches have diverged enough, implemented separately for each supported branch.

## Track 1 — Additive releases (`0.x.y`)

Low-risk, non-breaking features and bug fixes ship quickly on the current release train:

1. The change lands on `main` (gated by Tier 1A CI like any PR).
2. It is cherry-picked onto the current release line (`stable`) by the [backport bot](#backport-bot) when you add a `backport-stable` label to the merged PR.
3. `release-plz` opens a release PR on `stable`; merging it publishes `0.x.y`.

Key points:

* **Short (~1-day) bake.** Additive releases (`0.x.y`, y ≥ 1) don't need a full release-candidate stage, but we do hold a brief bake — approximately one business day — before the crates.io publish, to re-verify compatibility against the downstream projects we maintain (the other language bindings). This is far lighter than the breaking train's bake; it exists to catch integration surprises. Larger integration challenges are avoided by deferring potentially-breaking changes to Track 2.
* **Compatibility is verified, not assumed.** Every additive release is gated on [`cargo-semver-checks`](#semver-checks) so an accidental break can't ship as a "patch."

## Track 2 — The breaking train (`0.x.0`)

Breaking changes and larger refactors are batched onto a scheduled train:

1. On the scheduled date, a release-candidate branch `0.(x+1).0-rc` is cut from `main`, and its first build `0.(x+1).0-rc.1` is cut immediately (versions set, tagged, prerelease binaries built). **RC branches are not published to crates.io** (their name keeps them off every crates.io publish trigger), but each build **does** get a prerelease GitHub release with binaries so downstream consumers that depend on pre-built binaries can validate during the bake. See [RC builds](#release-candidate-builds).
2. **Bake period: minimum 3 business days.** Only bug fixes are accepted during the bake, and they follow upstream-first (fix on `main`, cherry-pick to the candidate). After fixes land, cut a fresh build (`-rc.2`, `-rc.3`, …) so downstream has updated binaries to test. Hold longer than 3 business days if needed to validate across the downstream projects we maintain.
3. **Promote** (a deliberate, manual step): first snapshot the outgoing `stable` as `v0.<old>` so the retiring line is available for backports, then merge the candidate into `stable`. `release-plz` then opens the `0.(x+1).0` version/changelog PR on `stable`; merging it publishes the breaking release.

### Cadence: scheduled, but not forced

* **Default rhythm: every two months**, on the **second Monday of each odd-numbered month at 16:00 UTC** (when [`release-train-cut.yml`](../.github/workflows/release-train-cut.yml) cuts the candidate), published in advance so users can plan migrations. (We deliberately avoid a faster cadence: pre-1.0, breaking users frequently is too much churn.)
* **Skip if empty.** If the date arrives with no breaking changes queued, we skip the train. A major bump that breaks everyone for no new value is pure cost — and it's safe to skip because Track 1 is already delivering value on the current release train.
* **Don't hold the train.** If breaking changes are queued, the candidate is cut on the date regardless. An almost-finished breaking feature waits for the *next* train. This is what turns "we have a cadence" into "we have predictability."
* **Anchor on the cut date,** not the release date, so the bake window absorbs slippage.

A side effect of skip-if-empty: the middle version number stops being a clock and becomes a true signal that a breaking change happened. Recency therefore comes from dated changelogs, not the version number.

### Version numbering across a train

Every train advances the **minor** number by one, regardless of whether `cargo-semver-checks` detects a breaking change — a train is, by definition, a new minor line, and we want a clean, predictable number for it. Versions are **set by hand** (e.g. `cargo set-version`) rather than left to release-plz's semver detection, precisely because we are overriding that detection.

The convention:

* **`main` always carries the *next* release's version with a `-dev` suffix** — e.g. `0.91.0-dev`. Because `main` is never published, the `-dev` prerelease is purely a label that says "work in progress toward 0.91.0."
* **Cutting the train** for `0.N.0` produces the release-candidate branch `0.N.0-rc` (dropping the numeric suffix from the branch name; the number belongs to each *build*). Its builds are versioned `0.N.0-rc.1`, `0.N.0-rc.2`, … and, while never published to crates.io, are tagged and get prerelease GitHub-release binaries. On promotion the line becomes `0.N.0`.
* **Right after the cut, `main` moves to `0.(N+1).0-dev`** so ongoing development is always numbered ahead of the line that's baking. This bump is committed to `main` automatically by [`release-train-cut.yml`](#release-train-cut) as part of the cut — no separate PR.
* **`c2patool` follows the same pattern on its own numbering** (its own next minor), independent of `c2pa`. RC build numbers are kept in lockstep across the crates, so `-rc.N` identifies one coherent candidate.

Worked example (the first train, which is also the transition onto this convention):

| Crate | current `main` | RC branch | RC builds (baking) | promoted | `main` after cut |
| -- | -- | -- | -- | -- | -- |
| `c2pa` / `c2pa-c-ffi` | `0.89.3` | `0.90.0-rc` | `0.90.0-rc.1`, `0.90.0-rc.2`, … | `0.90.0` | `0.91.0-dev` |
| `c2patool` | `0.26.72` | `0.27.0-rc` | `0.27.0-rc.1`, `0.27.0-rc.2`, … | `0.27.0` | `0.28.0-dev` |

Steadily thereafter, `main` already carries `0.N.0-dev`, so the train's release version is that number with `-dev` dropped, and `main` advances to `0.(N+1).0-dev`.

## Keeping additive changes additive

The model only works if we stay disciplined about keeping the fast lane non-breaking:

* **Review norm:** "Can this ship additively? If yes, it goes out now. If it requires a break, it waits for the next train."
* **Forward-compatible tools:** prefer `#[non_exhaustive]` (enums/structs), sealed traits, and default trait methods so future additions stay compatible.
* **Deprecate-then-remove:** when we must break, add the replacement API additively now and mark the old one `#[deprecated]`. Removal of the old API rides a later train, after the deprecation window elapses. See the [deprecation policy](deprecation-policy.md). Users get the improvement immediately and a window to migrate.
* **Extract-with-re-export:** moving code into a separate crate is additive as long as the public paths are preserved by re-exporting (`pub use`). See [extracted crates](#extracted-crates-multi-repo).

## Extracted crates (multi-repo)

We are extracting stable, low-churn code out of `c2pa-rs` into independent crates, each in its own repository, so that this code is not rebuilt on every PR to `c2pa-rs` `main`. The first example is **`c2pa_cbor`** — the CBOR (de)serialization primitives used throughout C2PA manifests, now in their own [`contentauth/c2pa-cbor`](https://github.com/contentauth/c2pa-cbor) repo. These crates are versioned **independently** (lockstep versioning would re-couple the build times we're trying to separate).

Once a subproject lives in its own repo and is published, `c2pa-rs` depends on it by version (`c2pa_cbor = "0.77"`) like any third-party crate. We use a normal caret requirement (not a pinned `=x.y.z`) and let `Cargo.lock` pin the exact version for reproducible builds — the same approach we take for any other dependency. That reframes the "wait period" from a scheduling problem into a dependency-edge problem:

* **Extracted crates do not follow this release process.** Each upstream `c2pa-*` crate is released on a simple, as-needed basis. (Cut one when a change lands; update version as per `cargo-semver-checks`.) Because they rarely change, they have no meaningful wait period of their own. Incorporating those updates into `c2pa-rs` is treated exactly like any other change to `c2pa-rs`: a dependency upgrade may be backported to `stable` if it doesn't break `c2pa-rs` APIs; otherwise it waits for the next release change.
* **The extraction itself is a Track 1 change** to `c2pa-rs`: depend on the published crate, delete the inlined module, re-export the same public paths. Additive; ships quickly on the current release train.
* **Classify each extracted crate as public or internal:**
  * **Public (re-exported):** its types are part of `c2pa`'s public API, so a breaking bump of the crate is breaking for `c2pa`'s users and must ride a `c2pa-rs` train.
  * **Internal (private dependency):** its types never appear in `c2pa`'s public API, so it can be bumped — including breaking bumps — freely, without involving the train.
* **Co-evolving changes** (touching an extracted crate and `c2pa-rs` together) live behind a Cargo `[patch]` on `c2pa-rs` `main` during development:
  * `[patch.crates-io] c2pa_cbor = { git = "…", branch = "…" }` lets the inner loop and CI build against the in-flight crate without publishing.
  * A `[patch]` or git dependency **must be settled** — the dependency published at a real version and the patch removed — before `c2pa-rs` can cut any release, because crates.io requires every dependency to resolve to a published version. This is mechanically enforced by the [patch-dependency guard](#patch-dependency-guard).
* **Cross-repo canary:** a [scheduled canary](#cross-repo-canary) builds `c2pa-rs` `main` against an extracted crate's `main` (via `[patch]`) so integration drift is surfaced early, while it's cheap.

## Branch lifecycle & support

* A `0.x` release line is **retired when its successor `0.(x+1).0` ships**. By default we support only the latest stable line.
* **Backport exceptions** to a retired line are rare and reserved for a correctness or security issue with no reasonable upgrade path for the affected consumer — in practice, security fixes and critical downstream emergencies only. Such a backport targets that line's `v0.x` branch.

## Automation

Cutting a release is mostly a CI action rather than manual toil. The pieces:

### `release-plz`

We use [`release-plz`](https://release-plz.dev) (via the [GitHub Action wrapper](https://github.com/release-plz/action)), configured by [`release-plz.toml`](../release-plz.toml). Its two responsibilities are split across two workflows, both of which run on the **release-line and release-candidate branches** — never on `main`:

* [`release-pr.yml`](../.github/workflows/release-pr.yml) runs `release-plz release-pr`: for each published crate it inspects commits since the last tag and opens/updates a **release PR** that bumps the version and updates the changelog. Because that PR targets a release-line branch, it runs the full Tier 1A + 1B + 2 suite (see [validation gating](#validation-gating)).
* [`release.yml`](../.github/workflows/release.yml) runs `release-plz release`: when a release PR merges (a push to the release-line branch), it publishes the changed crates to crates.io, creates GitHub releases, and tags them `(crate-name)-v(version)`. Those tags then drive the binary builds ([`library-release.yml`](../.github/workflows/library-release.yml) on `c2pa-v*`, [`c2patool-release.yml`](../.github/workflows/c2patool-release.yml) on `c2patool-v*`) — `release.yml` no longer builds binaries itself, which is what lets release-candidate builds produce the same binaries from the same tags (see [RC builds](#release-candidate-builds)). A push whose ref contains `-rc` never publishes to crates.io.

Binary builds are therefore entirely **tag-driven**, independent of how a tag was created:

* [`library-release.yml`](../.github/workflows/library-release.yml) builds the `c2pa` / `c2pa-c-ffi` native libraries for every supported target on any `c2pa-v*` tag.
* [`c2patool-release.yml`](../.github/workflows/c2patool-release.yml) builds the `c2patool` CLI binaries and SBOMs on any `c2patool-v*` tag.

A tag whose name contains `-rc.` yields a **prerelease** GitHub release; nothing on either path publishes to crates.io.

How `release-plz` chooses a version, per crate:

* If only bug-fix commits are detected, bump the patch number (`y`).
* If API additions or breaking changes are detected, bump the middle number (`x`). (Pre-1.0, Cargo treats a middle-number bump as incompatible; this becomes the major-number bump after 1.0.)
* For library crates, `release-plz` also downloads the most recent crates.io release and compares the API surface, taking the larger of (commit-implied, surface-implied) bumps.

The set of commit types that trigger a release is configured by `release_commits` in [`release-plz.toml`](../release-plz.toml) (chore commits are ignored). Commit/PR titles must follow [Conventional Commit syntax](https://www.conventionalcommits.org/en/v1.0.0/#summary); see [Commit lint](#commit-lint-used-for-pr-title-enforcement).

> [!IMPORTANT]
> You may manually edit a proposed changelog in the release PR, but those edits will be overwritten if another update is triggered — `release-plz` force-pushes to update an existing release PR.

### Backport bot

To bring a merged `main` PR onto a release line, add a `backport-<branch>` label to it (e.g. `backport-stable`). On merge, [`backport.yml`](../.github/workflows/backport.yml) (using [`korthout/backport-action`](https://github.com/korthout/backport-action)) cherry-picks the change and opens a PR against that branch. Because that PR targets a release-line branch, it must pass the full Tier 1A + 1B + 2 suite plus `cargo-semver-checks` before it can merge (see [validation gating](#validation-gating)).

> We use a self-contained GitHub Action rather than an external service. [Mergify](https://mergify.com) is a documented alternative if we ever need richer conflict handling or merge queues.

### Upstream-first check (proactive)

[`upstream-first-check.yml`](../.github/workflows/upstream-first-check.yml) runs on every PR targeting a release-line or release-candidate branch and **blocks the merge** if the PR introduces a commit whose change is not already on `main` (compared by patch id via `git cherry`). This prevents drift rather than merely detecting it after the fact. Combined with [branch protection](#branch-protection) that requires PRs on these branches, it makes "nothing originates on a release branch" enforceable.

Two exemptions keep it practical: the `release-plz` release PR (labeled `release`) may legitimately originate version-bump/changelog commits on the release branch, and a maintainer can add the `upstream-first-verified` label to a PR whose cherry-pick had to be adapted to compile on the target branch (so its patch id no longer matches `main`).

### Reconciliation check (reactive)

As a backstop to the proactive check above, a scheduled job, [`reconciliation.yml`](../.github/workflows/reconciliation.yml), runs `git cherry main <release-branch>`; anything present on the release branch but **not** on `main` (for example, from a direct push that bypassed a PR) means something originated on a release branch, violating upstream-first. The job opens (or updates) an issue so the change can be forward-ported and isn't lost across a major bump. We deliberately do **not** auto-merge a release branch back into `main`, since merging into the actively-refactored `main` is the conflict-prone direction.

### Semver checks

[`semver-checks.yml`](../.github/workflows/semver-checks.yml) runs [`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks) on every PR targeting a release-line branch (including backport PRs), baselining against the latest crates.io release. It catches a change that would be an accidental break shipping as an additive release. It does **not** run on `-rc` branches — the train is the intended place for breaking changes.

By default, `cargo-semver-checks` ignores features named `unstable`, `nightly`, `bench`, or `no_std`, and any feature whose name begins with `_`, `unstable-`, or `unstable_`. We rely on this: [experimental features](experimental-features.md) are gated behind `unstable_<name>` flags precisely so that changes confined to them are exempt from breaking-change detection and never force a version bump. An experimental API is free to change at will, as long as the change doesn't touch the public/stable API surface.

### Patch-dependency guard

[`check-no-patch-deps.yml`](../.github/workflows/check-no-patch-deps.yml) fails if a `[patch]` section or a git dependency is present. It runs on release-branch PRs and as a required prerequisite of `release.yml`, so a `[patch]` left over from co-developing an extracted crate can never leak into a publish.

### Release-train cut

[`release-train-cut.yml`](../.github/workflows/release-train-cut.yml) runs every Monday and gates on a date check so it only acts on the second Monday of an odd-numbered month (or when dispatched manually with `force: true`). When it fires it computes the next breaking version, applies skip-if-empty, and — if there's breaking work to ship — pushes a new `0.(x+1).0-rc` candidate branch from `main`, kicks off its first build by dispatching [`release-rc.yml`](#release-candidate-builds), **advances `main` to the next `0.(x+2).0-dev` cycle** (committed directly, no PR), and opens a `release-train` tracking issue describing the bake and the manual-promotion step. The `main` bump happens after the RC branch is cut, so the candidate is taken from pre-bump `main`. (Committing to `main` directly requires the `RELEASE_PLZ_TOKEN` to be allowed to bypass `main`'s pull-request rule; see [branch protection](#branch-protection).)

### Release-candidate builds

[`release-rc.yml`](../.github/workflows/release-rc.yml) cuts a numbered candidate **build** (`-rc.1`, `-rc.2`, …) from a candidate **branch** (`0.N.0-rc`). It sets the `-rc.N` versions on the branch (bumping `c2pa`/`c2pa-c-ffi` and `c2patool` in lockstep on the build number), commits, and pushes the `c2pa-v…-rc.N` and `c2patool-v…-rc.N` tags. Those tags trigger the tag-driven binary workflows above, which publish **prerelease** GitHub releases with binaries. Nothing here reaches crates.io — the build exists so downstream projects that consume pre-built binaries (rather than building from source) can validate the candidate during its bake.

The first build (`-rc.1`) is cut automatically when the train is cut. A maintainer re-runs this workflow (via `workflow_dispatch` on the RC branch) to cut a fresh build after bugfixes have been cherry-picked onto the branch during the bake. Tags are pushed with a PAT (`RELEASE_PLZ_TOKEN`) so the tag-driven binary workflows actually run — pushes made with the default `GITHUB_TOKEN` do not cascade into other workflows.

### Cross-repo canary

[`canary-extracted-crates.yml`](../.github/workflows/canary-extracted-crates.yml) builds `c2pa-rs` `main` against the `main` of each extracted crate via a throwaway `[patch]`, and files an issue on failure. The `[patch]` exists only inside the runner; the patch-dependency guard guarantees it can never reach a release.

### Label sync

Labels the process depends on are version-controlled in [`.github/labels.yml`](../.github/labels.yml) and synced by [`labels.yml`](../.github/workflows/labels.yml).

## Validation gating

The [support tiers](support-tiers.md) map directly onto the branching model:

* **Merging to `main`** requires **Tier 1A** — the merge gate for everyday development.
* **Any PR targeting a release-line (`stable`, `v0.x`) or release-candidate (`*-rc*`) branch** must pass the **full Tier 1A + 1B + 2 suite** before it can merge. This includes **backport PRs**, RC bake bugfix PRs, and the `release-plz` release PR — anything headed for a published (or soon-to-be-published) artifact gets the most thorough validation we have. PRs targeting release lines additionally run [`cargo-semver-checks`](#semver-checks).
* During a train's bake, Tier 1A + 1B + 2 also run on every push to the `*-rc*` branch.
* **All three tiers also run against `main` on a daily schedule** (a nightly run), catching regressions that only appear under the heavier Tier 1B/2 configurations even when no release-targeting PR is open.
* On a `main` PR you can opt into the full suite on demand by adding the `check-release` label (useful to assess release-readiness before a change is backported).

See [docs/support-tiers.md](support-tiers.md) for what each tier covers and why a configuration lands in a given tier.

## Commit lint used for PR title enforcement

Because `release-plz` uses [Conventional Commit syntax](https://www.conventionalcommits.org/en/v1.0.0/#summary) to generate changelogs, all commits to long-lived branches must follow it. We [squash-merge](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/configuring-commit-squashing-for-pull-requests) PRs, and [`pr_title.yml`](../.github/workflows/pr_title.yml) checks that each PR title conforms, as configured by [`.commitlintrc.yml`](../.commitlintrc.yml) (the definitive specification).

A quick, non-authoritative summary — the PR title must have this exact format:

```
type(scope): description
```

The `type` must be one of (bold = preferred in most cases):

* **`feat`**: a new feature. Use a `!` immediately before the `:` to signal an API breaking change (which queues for the next train).
* **`fix`**: a bug fix.
* **`chore`**: maintenance; does not trigger a release PR and is omitted from the changelog.
* **`docs`**: documentation.
* `build`, `ci`, `perf`, `refactor`, `revert`, `style`, `test`, `update` (the last used by Dependabot).

`scope` is optional; if present it must be one of `c2patool`, `export_schema`, `make_test_images`, `sdk`, or `c2pa_c_ffi`. If omitted, drop the parentheses too. `description` is a short sentence, capitalized, no trailing period, preferably under 70 characters.

> MAINTENANCE NOTE: if these rules change, keep [`.github/workflows/pr_title.yml`](../.github/workflows/pr_title.yml) and [`.commitlintrc.yml`](../.commitlintrc.yml) in sync.

## Known issues

### Failure to update downstream crates

In repos that host multiple crates, an earlier crate in the dependency chain can warrant a release while a crate that depends on it has no commits of its own. `release-plz` updates the downstream version reference but doesn't always cut a new release of the downstream crate. (See [issue #2164](https://github.com/release-plz/release-plz/issues/2164) and [PR #2196](https://github.com/release-plz/release-plz/pull/2196).) Workaround: post a no-op change (a whitespace tweak or comment) to the downstream crate to trigger a release PR. Tracked in [#2298](https://github.com/contentauth/c2pa-rs/issues/2298); remove this note once resolved upstream.

### Left-behind release branches

`release-plz` sometimes creates a new release branch + PR instead of updating the existing one, leaving the old branch behind. To reduce noise, [`release-pr.yml`](../.github/workflows/release-pr.yml) deletes stale `release-plz-*` branches. Tracked in [#2299](https://github.com/contentauth/c2pa-rs/issues/2299); remove this note once resolved.

### `c2pa` crate accidentally published a 1.0.0 release

An earlier tooling experiment accidentally published (and then yanked) [`c2pa` 1.0.0](https://crates.io/crates/c2pa/1.0.0). That version is permanently unavailable, so the eventual real 1.0 release will need a different number (probably 1.0.1).

## Troubleshooting

### How to recover if the publish step fails or partially fails

Keep the core mental model in mind (see [`release-plz`](#release-plz)). The following usually works when `release-plz` fails to publish one or more crates, though it may need adapting to the specific failure:

* **Read the logs** in the [Actions tab](https://github.com/contentauth/c2pa-rs/actions/workflows/release.yml). (`cargo publish` uses a subtly different compilation environment than a normal build, which is a common root cause.)
* **Resolve the underlying issue.**
* **Only for crates that failed to publish, manually revert their `Cargo.toml` and `CHANGELOG.md`** on the release-line branch. `release-plz` only generates a new release PR for crates whose `Cargo.toml` version exactly matches crates.io; delete the failed `CHANGELOG.md` section too, or `release-plz` will error on the next PR.
* **Revert intra-project version references** that failed to publish (e.g. a `c2patool` dependency on an unpublished `c2pa` version), and let `release-plz` re-introduce them.
* **Wait for `release-plz` to open a fresh release PR** with the desired result, and otherwise **avoid manually editing `Cargo.toml`** — pushing `release-plz` outside its normal process tends to create more problems.

### Using the rp-sandbox project to preflight `release-plz` changes

To vet a new version of `release-plz` or a config change, CAI team members can use the [`rp-sandbox` project](https://github.com/scouten-adobe/rp-sandbox/), which mirrors this repo's dependency structure with dummy crates. (Contact a maintainer for access.)

## Branch protection

The upstream-first guarantees rely on release-line and release-candidate branches only receiving changes through PRs. Configure branch protection (a repository setting, not something this repo can commit) on `main`, `stable`, and each `v0.*` / `*-rc*` branch to:

* **Require a pull request before merging** — so nothing is pushed directly, which is what makes the [upstream-first check](#upstream-first-check-proactive) an effective gate rather than an after-the-fact report.
* **Require status checks to pass**, including Tier 1A on `main`, and Tier 1A + 1B + 2, `cargo-semver-checks`, and the upstream-first check on release-line/RC branches (see [validation gating](#validation-gating)).

Branch-name patterns (`v0.*`, `*-rc*`) can be covered with a single ruleset each so new release lines and candidates are protected automatically.

Some release automation pushes directly to protected branches and so must be on the ruleset **bypass list** — grant this to the identity behind `RELEASE_PLZ_TOKEN`:

* [`release-train-cut.yml`](#release-train-cut) commits the next-dev-cycle bump straight to `main`, and [`release-rc.yml`](#release-candidate-builds) commits `-rc.N` version bumps straight to the RC branch. Both bypass the pull-request rule by design (they are mechanical version bumps, not reviewed changes).

## One-time setup

Before the first train cuts over, create the `stable` branch from the latest published tag:

```sh
git fetch --tags
git branch stable c2pa-v0.89.0   # the most-recent c2pa release tag
git push origin stable
```

After that, the additive flow (backport-to-`stable`) and the train flow (`release-train-cut.yml`) operate as described above.
