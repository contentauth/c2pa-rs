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

| Dependent | Receiver to install | Phase |
| --- | --- | --- |
| `c2pa-node-v2` | [`receivers/c2pa-node-v2.yml`](./receivers/c2pa-node-v2.yml) — Variant A, opens a draft PR | 1 (ready) |
| `c2pa-python` | [`receivers/c2pa-python.yml`](./receivers/c2pa-python.yml) — `build-from-source`, status-only | 1 (ready) |
| `c2pa-cpp`, `c2pa-ios`, `c2pa-android`, `c2pa-js` | start from [`test-c2pa-rs-branch.yml`](./test-c2pa-rs-branch.yml) (Variant B) | 2 (blocked on the artifact bridge) |

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
| `c2pa-python` | downloads prebuilt artifacts; has a `build-from-source` path | check out the branch and `make build-from-source C2PA_RS_PATH=...` (no diff → status-only) |
| `c2pa-cpp` | prebuilt native libs from c2pa-rs **releases** | Variant B: download branch artifacts (bridge ready; receiver TODO) |
| `c2pa-ios` | prebuilt native libs from releases | Variant B (receiver TODO) |
| `c2pa-android` | prebuilt native libs from releases | Variant B (receiver TODO) |
| `c2pa-js` | wasm / `c2pa-node` artifacts | Variant B (receiver TODO) |

Ready receivers exist for `c2pa-node-v2` and `c2pa-python` (see step 3). Variant
B in the generic template is a placeholder pending the per-repo receiver work.

## Phase 2 — branch artifacts for prebuilt-binary dependents

`c2pa-cpp`, `c2pa-ios`, `c2pa-android`, and `c2pa-js` consume prebuilt native
libraries that c2pa-rs publishes from
[`library-release.yml`](../../.github/workflows/library-release.yml).

**The artifact bridge is now in place.** That workflow already uploads per-target
workflow artifacts (`release-artifacts-<os>-<target>`) on every run, and its
`release` job is gated to `c2pa-v*` tag pushes — so dispatching it against a
branch produces downloadable artifacts without cutting a release:

```sh
gh workflow run library-release.yml --ref <pr-branch>
```

A Variant B receiver then downloads them (e.g. `gh run download <run-id>
--pattern 'release-artifacts-*'`) and stages them where the build expects the
release-downloaded libraries.

**Still TODO (receiver side, per repo):** decide who triggers the branch build
and how the run id reaches the receivers — either the orchestrator builds once
and passes the run id in the dispatch payload (cheaper; one build per labeled
PR), or each receiver triggers and polls its own build (simpler; N builds). Then
wire the download + stage + build steps into each of the four repos. Phase 1
fully covers the Rust-dependency dependents.

## Limitations

- **Fork PRs are not verified.** A fork's branch doesn't live in
  `contentauth/c2pa-rs`, so dependents can't re-target to it. If a fork PR is
  labeled, the gate passes with a note (it does not block) and emits a warning;
  to actually verify, push the branch to `contentauth/c2pa-rs` and open the PR
  from there.
- Each labeled push re-dispatches to all six dependents.
