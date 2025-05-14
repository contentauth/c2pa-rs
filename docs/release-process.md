# How to release c2pa-rs and related crates

The build process for the crates in this repo is automated using [release-plz](https://release-plz.dev), a Rust-specific CI tool. Release-plz is two components: a Rust-based command-line tool ([GitHub](https://github.com/release-plz/release-plz)) and a pre-packaged GitHub Actions wrapper ([GitHub](https://github.com/release-plz/action)). We use the pre-packaged GitHub Actions wrapper in this project. Colin and Eric have both submitted fixes to release-plz. The developer is generally responsive and PRs are typically merged and released within a week or two.

Release-plz leverages information contains in the various `Cargo.toml` files and its own [`release-plz.toml`](../release-plz.toml) configuration file. In this document, we will talk only about how it release-plz is configured for this project. For more detail about the available settings in release-plz, we recommend reading the [release-plz documentation site](https://release-plz.dev/docs), which is quite extensive.

## How it works

We use the pre-packaged [release-plz GitHub Actions wrapper](https://github.com/release-plz/action) to trigger builds. This is configured in our [`release.yml`](../.github/workflows/release.yml) task.

For additional information, please read the [release-plz documentation for GitHub Action](https://release-plz.dev/docs/github/quickstart).

In this repo, the build automation is triggered for each commit to the `main` branch.

This task runs using a GitHub access token tied to Eric's `@scouten-adobe` account, which is why all PRs and releases are under Eric's name. (See ticket CAI-7621 for moving this to a team-owned bot account.)

### Create a release pull request

This runs [`release-plz release-pr`](https://release-plz.dev/docs/usage/release-pr). For each published crate in the repo, it looks for certain types of commits since the last tagged release _within_ the source tree for the crate. The exact list of commit types that trigger a release PR is configured by the `release-commits` section of [`release-plz.toml`](../release-plz.toml), but notably is set to ignore `chore` commits and include `feat`, `fix`, and `docs` commits. If it finds any matching, it will open a new release pull request or update the existing release. (NOTE: When Colin's [PR #2196 to release-plz](https://github.com/release-plz/release-plz/pull/2196) lands there will be a new trigger here which will reference intra-project dependency updates even if the downstream project has no commits of its own.)

For each project that is to be updated, release-plz will generate the following changes:

* `cargo.toml`: **Update version number.**
  * If any API breaking changes are detected, bump the minor version number. (This will change to a major version number once we do 1.0 release.)
  * If any feature changes (API additions) are detected, bump the minor version number. (This will _not_ change when we do 1.0 release.)
  * If only bug-fix changes are detected, bump the patch version number.
  * For all crates, `release-plz` will evaluate the commit history since the previous release tag using [Conventional Commit syntax](https://www.conventionalcommits.org/en/v1.0.0/#summary) to determine API breaking changes, feature changes, or only bug-fix changes.
  * For library crates _only,_ `release-plz` will also download the most recent release from [crates.io](https://crates.io) to verify any API surface changes. The larger scope (patch -> minor -> major) will be used to select the new version number.

* `cargo.toml`: **Update version references for other crates in the same repo.**
  * For each dependency that also exists in this repo, update the version number to match what is generated for that project.

* `CHANGELOG.md`: **Add description of new release.**
  * This adds a new section to the top of the changelog file with a link to the diffs between this version and the previous release.
  * The changelog section also contains a list of commits that affected this crate's source, grouped by the commit type. (See [Conventional Commit syntax](https://www.conventionalcommits.org/en/v1.0.0/#summary).)

IMPORTANT: It _is_ permissible to manually edit the proposed changelog in the PR, but be aware those changes will be overwritten if another update is triggered. release-plz uses force-push to update any existing release PR.

IMPORTANT: If the version number of the crate in `main` is _different_ from the version number on [crates.io](https://crates.io), this job will NOT run. (See the next section, "Publish new crates.")

### Publish new crates

For each crate in the repo, if the version number of the crate in `main` is _different_ from the version number on [crates.io](https://crates.io), release-plz will attempt to publish the crate to [crates.io](https://crates.io). This typically occurs after a maintainer has merged a release PR as generated in the previous step.

Specifically, it performs the following steps for each commit to `main`:

* **Verifies that the most recent commit to `main` is from a release-plz PR.** If not, skips the rest of this process.
* **Compares the crate version in `Cargo.toml` to what is published on [crates.io](https://crates.io).** If the versions match, skips the rest of this process.
* **Runs [`cargo publish`](https://doc.rust-lang.org/cargo/commands/cargo-publish.html)** for the crate and waits for notification that the crate has been successfully uploaded.
* **Creates a [GitHub release](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)** for the uploaded crate. This creates an annotated git tag of the form `(crate-name)-v(version-number)`, which – among other things – is used to drive the previous-version comparison for future release PRs. This also creates a ZIP archive of the source at this crate version which is stored on GitHub with the release.

### Publish `c2patool` binary builds

If a new version of `c2patool` is generated by the previous step, an additional job runs after the publish job to build and publish binary versions of `c2patool`.

This is specified by the `publish-c2patool-binaries` job in our [`release.yml`](../.github/workflows/release.yml) task.

For each supported command-line platform (MacOS, Windows, and Ubuntu), it performs the following steps:

* **Runs the `release` task in [`cli/Makefile`](../cli/Makefile)**. This builds the platform-appropriate binary image.

* **Runs [`cargo sbom`](https://crates.io/crates/cargo-sbom)** to generate an [SPDX-formatted](https://spdx.dev) software bill of materials (SBOM).

* **Uploads the binary and SBOM files to GitHub.** These are attached as additional outputs to the GitHub release generated in the publish step above.

## Commit lint used for PR title enforcement

Since release-plz makes use of [Conventional Commit syntax](https://www.conventionalcommits.org/en/v1.0.0/#summary) when generating changelogs, we want all commits to `main` to follow this syntax.

We [enforce commit squashing](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/configuring-commit-squashing-for-pull-requests) for pull requests in this repo to simplify our git history. When squashing commits for pull request merges, GitHub defaults to using the PR title as the first line of the commit message. For that reason, our [`pr-title.yml`](../.github/workflows/pr-title.yml) task is configured to read the PR title and ensure that it confirms to [Conventional Commit syntax](https://www.conventionalcommits.org/en/v1.0.0/#summary). This enforcement is configured by [`.commitlintrc.yml`](../.commitlintrc.yml), which is the definitive specification of what constitutes an acceptable PR title.

A quick, non-authoritative, summary of the PR title rules follows. As a quick reminder, the summary line (and thus the PR title) must have this exact format, including punctuation:

```
type(scope): description
```

The `type` field describes the nature of changes you are making. This project requires the type to be one of these exact names (bold names are preferred in most cases):

* **`feat`**: Adding a new feature. (Will cause a minor version bump.)
  * Use an `!` immediately before the `:` to signal an API breaking change. Once we release 1.0, this will cause a major version bump. Also note that for library crates, release-plz will independently evaluate all changes to the API surface and call for minor or major version bumps as appropriate.
* **`fix`**: Bug fix. (Will cause a patch version bump.)
* **`chore`**: Maintenance work. (Will not trigger a release PR and will not be included in changelog.)
* **`docs`**: Revising documentation.
* `build` or `ci`: Adjusting the build system.
* `perf`: Performance optimization.
* `refactor`
* `revert`
* `style`
* `test`
* `update`: Updating a dependency. (Used by Dependabot.)

The `scope` field describes where the change is made. This project allows the scope to be omitted, but if it is present, it must be one of these exact names:

* `c2patool`
* `crypto`
* `export_schema`
* `make_test_images`
* `sdk`

If `scope` is omitted, the parenthesis must also be omitted.

`description` is a short human-readable summary of the changes being made. It is required. We prefer that the `description` be less than 70 characters and will issue a warning (which you can ignore) if it is longer.

The following items are not enforced, but we ask that you observe the following preferences in `description`:

* The entire description should be written and capitalized as an English-language sentence, except that the trailing period should be omitted.
* Any acronyms such as JSON or YAML should be capitalized as per common usage in English-language sentences.

The "body" of the commit message (everything after the PR title) is not subject to any restrictions and may be empty. GitHub, by default, will create a bullet list of the commits that went into the PR. It is _recommended,_ but not enforced, that you delete this list (because it typically contains a lot of signal noise) and either replace it with additional context of why you made the change or leave it empty.

MAINTENANCE NOTE: If this list of rules is changed, please keep in sync with [`.github/workflows/pr_title.yml`](../.github/workflows/pr_title.yml) and [`.commitlintrc`](../.commitlintrc).

## Known issues

### Failure to update downstream crates

There is a known issue involving repos such as ours which host multiple crates. Consider the dependency tree in our current configuration (`c2pa-crypto` -> `c2pa-rs` -> `c2patool`). It's possible for a crate that's earlier in the dependency cycle (e.g. `c2pa-crypto`) to have changes that warrant a new release and the crate that depends on it (`c2pa-rs` or `c2patool`) to have no commits since their prior releases.

The current behavior of release-plz is to update the version reference in the downstream crate (`c2pa-rs` or `c2patool` in this example), but _not_ to generate a new release of the downstream crate.

We've filed ([issue #2164](https://github.com/release-plz/release-plz/issues/2164)) to describe this issue and ([PR #2196](https://github.com/release-plz/release-plz/pull/2196)) to fix the issue. The developer of release-plz agrees that this is a bug, but the PR has not been merged as of this writing.

In the meantime, the workaround that seems easiest is to post a no-op change to any downstream crates that need to be re-released. A whitespace change or a comment that could benefit from some proofreading is typically enough to cause release-plz to call for a new release.

### Left-behind release branches

When performing the "Create a release pull request" step described above, release-plz sometimes updates the existing release branch and sometimes creates a new release branch with a new pull request. We don't understand how it makes that choice. When it creates a new pull request, it closes the old pull request, but does not delete the old release branch.

In order to reduce the signal noise in the git repo, we've added a step in the release process to search for and delete old release branches. Search for "Clean up stale release-plz branches" in the [`release.yml`](../.github/workflows/release.yml) task.

### `c2pa` crate accidentally published a 1.0.0 release

When building and testing an earlier version of our release tooling (before adopting release-plz), we accidentally published a [version 1.0.0 of the `c2pa` crate](https://crates.io/crates/c2pa/1.0.0). We immediately yanked that version, but that means version 1.0.0 is permanently unavailable. When we do decide to release 1.0 of the `c2pa` crate, we will have to manually bump the version number to some other version (probably 1.0.1).

## Troubleshooting

### How to recover if the publish step fails or partially fails

We have safeguards in place to ensure that a release PR will result in a successful publish, but they are not 100% effective. When there is a failure in the workflow, it's important to keep the core mental model in mind. (See "how it works" earlier in this document.) The following strategy _should_ work when release-plz fails to publish one or more crates from this project, though it may need some adaptation based on the specific failure mode:

* **Read the logs to understand why the release did not go as planned.** You'll find this in the ["Release-plz" section of the Actions tab](https://github.com/contentauth/c2pa-rs/actions/workflows/release.yml) for this project. As one example, consider [this recent failure](https://github.com/contentauth/c2pa-rs/actions/runs/14339524696/job/40212226853), in which the crate failed to compile during the publish step. (Be aware that `cargo publish` uses a subtly different compilation environment than typical builds, which appears to be the root cause for this failure.)

* **Resolve the issues indicated by the log.** This will vary depending on the failure mode.

* **_ONLY_ for crates that failed to publish, manually revert `Cargo.toml` and `CHANGELOG.md` files.** Remember that release-plz will only generate a new release PR for crates where the `Cargo.toml` version exactly matches what's published on [crates.io](https://crates.io). This change should be made directly to `main` branch or via a new PR that targets `main`. (Remember that the previous release PR will have been merged, so it no longer exists.) Be sure to delete the generated section in `CHANGELOG.md` that failed to publish; otherwise, release-plz will raise an error when trying to generate the next release PR.

* **Revert intra-project version references that failed to publish.** For example, if the main SDK (`c2pa`) failed to publish, it's likely that `c2patool` will have a `Cargo.toml` dependency on the new/unpublished version. You may need to manually revert that change and allow release-plz to re-introduce it. _(From Eric: I'm not 100% sure about this step; experiment as needed to make things work.)_

* **Wait for release-plz to create a new release PR with the desired results.**

* **Avoid manually changing `Cargo.toml` files, other than the aforementioned reversions.** In general, attempts to push release-plz to release outside of its normal process tend to create more problems to be resolved.

### Using `rp-sandbox` project to preflight release-plz upgrades or strategies

If you have questions about how release-plz works or are wanting to vet a new version of release-plz, CAI team members are invited to use the [`rp-sandbox` project](https://github.com/scouten-adobe/rp-sandbox/) to test changes or ideas. (CAI team members: Please contaact Eric for collaborator access.) This repo has a dependency structure that is structurally similar to the `c2pa-rs` repo, but has dummy implementations of its three crates.
