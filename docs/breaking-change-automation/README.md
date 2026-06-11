# Breaking-change verification across dependent crates

When a c2pa-rs change breaks API/ABI compatibility, the downstream binding repos
may need code changes before the c2pa-rs PR can land. This automation surfaces
that *before* merge: apply the **`breaking-changes`** label to a c2pa-rs PR and
every dependent repo is built against the PR's branch, with the results gating
the PR as a required status check.

Dependent repos covered: `c2pa-node-v2`, `c2pa-js`, `c2pa-python`, `c2pa-cpp`,
`c2pa-android`, `c2pa-ios`.

## How it works

```
c2pa-rs PR  --label: breaking-changes-->  .github/workflows/breaking-changes.yml
                                              |
                          repository_dispatch (c2pa-rs-breaking-change)
                                              v
        each dependent repo's .github/workflows/test-c2pa-rs-branch.yml
            re-targets to the PR branch, opens a draft PR, builds/tests
                                              |
                       commit status "breaking-changes / <repo>"
                                              v
        breaking-changes.yml (status event) aggregates -> breaking-changes-gate
```

- **`breaking-changes-gate`** is the single required context. Because GitHub
  branch-protection required checks fire on *every* PR (there's no "only when
  labeled"), the gate is always posted:
  - PR **without** the label → gate reports **success** immediately.
  - PR **with** the label → gate goes **pending**, then **success** once all
    dependents report green, or **failure** if any dependent fails.
- **`breaking-changes / <repo>`** are informational per-dependent contexts that
  link to the draft PR opened in each dependent.
- On a new push to a labeled PR (`synchronize`), dependents are re-dispatched
  against the new commit. Removing the label passes the gate again.

The orchestrator runs on **`pull_request_target`** rather than `pull_request`.
That's required so the gate status can be posted on fork PRs too — under
`pull_request` the `GITHUB_TOKEN` is read-only for forks, which would leave the
required gate context unset and block every external-contributor PR. The
fan-out job is safe under `pull_request_target` because it never checks out or
executes PR code; it only reads trusted event metadata and posts statuses /
dispatches. **Do not add a checkout of the PR head to that workflow.**

## One-time setup

### 1. Create the label

```sh
gh label create breaking-changes \
  --repo contentauth/c2pa-rs \
  --color B60205 \
  --description "Verify all dependent crates against this PR's branch before merging"
```

### 2. Create the `CROSS_ORG_PR_TOKEN` secret

The default `GITHUB_TOKEN` is scoped to c2pa-rs only, so it cannot dispatch to
or open PRs in the dependent repos. Create a token with:

- **`contents: write`** and **`pull-requests: write`** on each dependent repo
  (push the re-target branch + open the draft PR), and
- **`statuses: write`** on `contentauth/c2pa-rs` (report results back).

Either a fine-grained PAT or (preferred) a GitHub App installation token works.
Store it as an **organization secret** named `CROSS_ORG_PR_TOKEN`, shared with
c2pa-rs and all six dependent repos. (Rename throughout if you prefer a different
name — it appears in `breaking-changes.yml` and the receiver template.)

### 3. Install the receiver in each dependent repo

Each dependent gets `.github/workflows/test-c2pa-rs-branch.yml`. Because the
repos consume c2pa-rs differently, the receivers differ — use the ready-made
ones where they exist:

| Dependent | Receiver to install | Notes |
| --- | --- | --- |
| `c2pa-node-v2` | [`receivers/c2pa-node-v2.yml`](./receivers/c2pa-node-v2.yml) | Variant A (git-branch dep), opens a draft PR |
| `c2pa-js` | [`receivers/c2pa-js.yml`](./receivers/c2pa-js.yml) | Variant A (git-branch dep, builds wasm), opens a draft PR |
| `c2pa-python` | [`receivers/c2pa-python.yml`](./receivers/c2pa-python.yml) | `build-from-source` via `C2PA_RS_PATH`, status-only |
| `c2pa-cpp` | [`receivers/c2pa-cpp.yml`](./receivers/c2pa-cpp.yml) | `build-from-source` via `C2PA_BUILD_FROM_SOURCE`, status-only |
| `c2pa-ios` | [`receivers/c2pa-ios.yml`](./receivers/c2pa-ios.yml) | downloads branch artifacts → `C2PA_LOCAL_ARTIFACTS`, status-only (unvalidated) |
| `c2pa-android` | [`receivers/c2pa-android.yml`](./receivers/c2pa-android.yml) | stages branch `.so` into `jniLibs`, `assembleRelease`, status-only (unvalidated) |

When adapting the generic template, edit the two marked sections:

- `REPO_NAME` — this repo's short name; must match its entry in the `DEPENDENTS`
  list in `breaking-changes.yml`.
- the **re-target** and **build/test** steps — see "Per-repo re-targeting" below.

### 4. Require the gate in branch protection

In c2pa-rs branch protection for `main` (and `v1_api`), add **`breaking-changes-gate`**
to the required status checks. Do **not** add the per-dependent contexts — they
are informational, and requiring them would block every unlabeled PR.

## Per-repo re-targeting

How "use the PR branch" is implemented differs by how each repo consumes c2pa-rs:

| Repo | Consumes c2pa-rs as | Re-target in receiver |
| --- | --- | --- |
| `c2pa-node-v2` | crates.io `c2pa` dep in its root `Cargo.toml` | Variant A: rewrite to `git`+`branch`, `cargo update -p c2pa` (commits a diff → draft PR) |
| `c2pa-js` | builds wasm from a `c2pa` dep in its root `Cargo.toml` | Variant A: rewrite to `git`+`branch`, `pnpm ci:check` (commits a diff → draft PR) |
| `c2pa-python` | downloads prebuilt artifacts; has a `build-from-source` path | check out the branch, `make build-from-source C2PA_RS_PATH=...` (no diff → status-only) |
| `c2pa-cpp` | prebuilt libs via CMake; has a `build-from-source` path | check out the branch as a sibling dir, `C2PA_BUILD_FROM_SOURCE=ON C2PA_RS_PATH=... make test-release` with `LD_LIBRARY_PATH` set (status-only) |
| `c2pa-ios` | prebuilt native libs from releases (xcframework) | Variant B: stage branch artifacts (see Phase 2) |
| `c2pa-android` | prebuilt `.so` libs from releases (jniLibs) | Variant B: stage branch artifacts (see Phase 2) |

Ready receivers exist for `c2pa-node-v2`, `c2pa-js`, `c2pa-python`, and
`c2pa-cpp` (see step 3). Variant B in the generic template is a placeholder
pending the iOS/Android receiver work.

## Phase 2 — branch artifacts for the prebuilt-binary dependents

Only `c2pa-ios` and `c2pa-android` truly need prebuilt native libraries (the
other four build from source). They consume the binaries that c2pa-rs publishes
from [`library-release.yml`](../../.github/workflows/library-release.yml).

**The artifact bridge is in place.** That workflow already uploads per-target
workflow artifacts (`release-artifacts-<os>-<target>`, containing the same
`c2pa-v*-<target>.zip` files as the release assets) on every run, and its
`release` job is gated to `c2pa-v*` tag pushes — so dispatching it against a
branch produces downloadable artifacts without cutting a release:

```sh
gh workflow run library-release.yml --ref <pr-branch>
```

### How the build is triggered and located

The orchestrator triggers **one** branch build of `library-release.yml` per
labeled PR (only when `BINARY_DEPENDENTS` is non-empty) and the iOS/Android
receivers locate it by SHA — cheaper than each receiver building its own. The
mechanics:

- `library-release.yml` takes a `verify_sha` input and sets a `run-name:` that
  embeds it. Receivers find the run with `gh run list --workflow
  library-release.yml` (matching `displayTitle`), wait with `gh run watch`, and
  download with `gh run download <id> --pattern 'release-artifacts-*'`.
- Triggering a workflow with the default `GITHUB_TOKEN` does **not** start a new
  run, so the orchestrator triggers it with `CROSS_ORG_PR_TOKEN`, which needs
  **Actions: write** on c2pa-rs.

The receivers are drafted in [`receivers/c2pa-ios.yml`](./receivers/c2pa-ios.yml)
and [`receivers/c2pa-android.yml`](./receivers/c2pa-android.yml):

- **`c2pa-ios`** (macOS runner): stages downloaded zips into the dir named by
  `C2PA_LOCAL_ARTIFACTS` (the build prefers local artifacts over the release
  download) and overrides `C2PA_VERSION` with the version detected from the
  artifact filenames, so the pin in `Configurations/Base.xcconfig` need not
  match. Build/test via `make test-library`.
- **`c2pa-android`** (ubuntu runner): pre-stages the branch `.so` files and the
  patched `c2pa.h` into the exact locations gradle expects; because the
  `downloadNativeLibraries` task skips any arch whose `.so` already exists, it
  no-ops and `assembleRelease` builds against the staged libs — no gradle change
  needed. Verifies the build only; instrumented tests need an emulator.

> ⚠️ Both iOS/Android receivers are **unvalidated** — they need a real labeled-PR
> run (token + runners) to confirm the make/gradle invocations, artifact layout,
> and version handling.

### To activate iOS/Android

1. Merge their receiver PRs.
2. Ensure `library-release.yml` (with the `verify_sha` input) is on the default
   branch — i.e. this PR is merged.
3. Add `c2pa-ios c2pa-android` to **both** `DEPENDENTS` and `BINARY_DEPENDENTS`
   in `breaking-changes.yml`.
4. Confirm `CROSS_ORG_PR_TOKEN` has **Actions: write** on c2pa-rs.

## Limitations

- **Fork PRs are not verified.** A fork's branch doesn't live in
  `contentauth/c2pa-rs`, so dependents can't re-target to it. If a fork PR is
  labeled, the gate passes with a note (it does not block) and emits a warning;
  to actually verify, push the branch to `contentauth/c2pa-rs` and open the PR
  from there.
- Each labeled push re-dispatches to all six dependents.
