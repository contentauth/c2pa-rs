# How we release c2pa-rs and related crates

The build process for the crates in this repo is automated using [release-plz](https://release-plz.dev), a Rust-specific CI tool.

Release-plz leverages information contains in the various `Cargo.toml` files and its own [`release-plz.toml`](../release-plz.toml) configuration file. 

There are many options available for [configuring release-plz](https://release-plz.dev/docs/config). In this document, we will talk only about how it is configured for this project.

## How it works

We use the pre-packaged [GitHub Actions wrapper](https://github.com/release-plz/action) to trigger builds. This is configured in our [`release.yml`](../.github/workflows/release.yml) task.

For additional information, please read the [release-plz documentation for GitHub Action](https://release-plz.dev/docs/github/quickstart).

In this repo, the build automation is triggered for each commit to the `main` branch.

This task runs using a GitHub access token tied to Eric's `@scouten-adobe` account, which is why all PRs and releases are under Eric's name. (See ticket CAI-7621 for moving this to a team-owned bot account.)

### Create a release pull request

This runs [`release-plz release-pr`](https://release-plz.dev/docs/usage/release-pr). For each published crate in the repo, it looks for commits since the last tagged release (ignoring commits with the `chore:` prefix). If it finds any, it will open a new release pull request or update the existing release. (NOTE: When Colin's [PR #2196 to release-plz](https://github.com/release-plz/release-plz/pull/2196) lands there will be a new trigger here which will reference intra-project dependency updates even if the downstream project has no commits of its own.)

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

IMPORTANT: If the version number of the crate in `main` is _different_ from the version number on [crates.io](https://crates.io), this job will NOT run. (See the next task.)

### Publish new crates

For each crate in the repo, if the version number of the crate in `main` is _different_ from the version number on [crates.io](https://crates.io), release-plz will attempt to publish the crate to [crates.io](https://crates.io).

Typically, this will happen because a maintainer merged a release PR created from the previous step. However, that is not absolutely required. (This is **strongly discouraged,** but technically you _could_ manually edit the version number in a `Cargo.toml` file and submit that directly to `main` yourself.)

Specifically, it performs the following steps when the version number doesn't match what's on [crates.io](https://crates.io):

* **Runs [`cargo publish`](https://doc.rust-lang.org/cargo/commands/cargo-publish.html)** for the crate and waits for notification that the crate has been successfully uploaded.
* **Creates a [GitHub release](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)** for the uploaded crate. This creates an annotated git tag of the form `(crate-name)-v(version-number)`, which -- among other things -- is used to drive the previous-version comparison for future release PRs. This also creates a ZIP archive of the source at this crate version which is stored on GitHub with the release.

### Publish `c2patool` binary builds

If a new version of `c2patool` is generated by the previous step, an additional job runs after the publish job to build and publish binary versions of `c2patool`.

This is specified by the `publish-c2patool-binaries` job in our [`release.yml`](../.github/workflows/release.yml) task.

For each supported command-line platform (MacOS, Windows, and Ubuntu), it performs the following steps:

* **Runs the `release` task in [`cli/Makefile`](../cli/Makefile)**. This builds the platform-appropriate binary image.

* **Runs [`cargo sbom`](https://crates.io/crates/cargo-sbom)** to generate an [SPDX-formatted](https://spdx.dev) software bill of materials (SBOM).

* **Uploads the binary and SBOM files to GitHub.** These are attached as additional outputs to the GitHub release generated in the publish step above.

## Related: Commit lint used for PR title enforcement

Since release-plz makes use of [Conventional Commit syntax](https://www.conventionalcommits.org/en/v1.0.0/#summary) when generating changelogs, we want all commits to `main` to follow this syntax.

We [enforce commit squashing](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/configuring-commit-squashing-for-pull-requests) for pull requests in this repo to simplify our git history.

When squashing commits for pull request merges, GitHub defaults to using the PR title as the first line of the commit message, so our [`pr-title.yml`](../.github/workflows/pr-title.yml) task is configured to read the PR title and ensure that it confirms to [Conventional Commit syntax](https://www.conventionalcommits.org/en/v1.0.0/#summary).

This enforcement is configured by [`.commitlintrc.yml](../.commitlintrc.yml), which is the definitive specification of what constitutes an acceptable PR title.

As a quick reminder, the summary line (and thus the PR title) must have this exact format, including punctuation:

```
type(scope): description
```

The `type` field describes the nature of changes you are making. This project requires the type to be one of these exact names (bold names are preferred in most cases):

* **`feat`**: Adding a new feature. (Will cause a minor version bump.)
* **`fix`**: Bug fix. (Will cause a patch version bump.)
* **`chore`**: Maintenance work. (Will not be included in changelog.)
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
* `cawg_identity`
* `crypto`
* `export_schema`
* `make_test_images`
* `sdk`

If `scope` is omitted, the parenthesis must also be omitted.

`description` is a short human-readable summary of the changes being made. It is required. We prefer that the `description` be less than 70 characters and will issue a warning (which you can ignore) if it is longer.

The following items are not enforced, but we ask that you observe the following preferences in `description`:

* The entire description should be written and capitalized as an English-language sentence, except (as noted earlier) that the trailing period must be omitted.
* Any acronyms such as JSON or YAML should be capitalized as per common usage in English-language sentences.

The "body" of the commit message (everything after the PR title) is not subject to any restrictions and may be empty. GitHub, by default, will create a bullet list of the commits that went into the PR. It is _recommended,_ but not enforced, that you delete this list (because it typically contains a lot of signal noise) and either replace it with additional context of why you made the change or leave it empty.

MAINTENANCE NOTE: If this list of rules is changed, please keep in sync with `.github/workflows/pr_title.yml` and `.commitlintrc`.

## Known issues

### Failure to update downstream crates

(link to open issue and Colin's PR)

### Left-behind release branches

(mention job in `release.yml` task)

## Troubleshooting

(link to rp-sandbox project)

(watch out for 1.0.0 release)

## For more information

* [release-plz documentation](https://release-plz.dev/docs)
* [release-plz GitHub repo (main project)](https://github.com/release-plz/release-plz)
* [release-plz GitHub repo (GitHub action wrapper)[https://github.com/release-plz/action)

## Related

* (semver crate?)
* (nightly build process)
* (c2patool binary build process)

## Behind the scenes

Release-plz is two components: a Rust-based command-line tool ([GitHub](https://github.com/release-plz/release-plz)) and a pre-packaged GitHub Actions wrapper ([GitHub](https://github.com/release-plz/action)). We use the pre-packaged GitHub Actions wrapper in this project.

Colin and Eric have both submitted fixes to release-plz. The developer is generally responsive and PRs are typically merged and released within a week or two.
