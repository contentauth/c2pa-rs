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

* `cargo.toml`: Update version number.
  * If any API breaking changes are detected, bump the minor version number. (This will change to a major version number once we do 1.0 release.)
  * If any feature changes (API additions) are detected, bump the minor version number. (This will _not_ change when we do 1.0 release.)
  * If only bug-fix changes are detected, bump the patch version number.
  * For all crates, `release-plz` will evaluate the commit history since the previous release tag using [Conventional Commit syntax](https://www.conventionalcommits.org/en/v1.0.0/#summary) to determine API breaking changes, feature changes, or only bug-fix changes.
  * For library crates _only,_ `release-plz` will also download the most recent release from [crates.io](https://crates.io) to verify any API surface changes. The larger scope (patch -> minor -> major) will be used to select the new version number.

* `cargo.toml`: Update version references for other crates in the same repo.
  * For each dependency that also exists in this repo, update the version number to match what is generated for that project.

* `CHANGELOG.md`: Add description of new release
  * This adds a new section to the top of the changelog file with a link to the diffs between this version and the previous release.
  * The changelog section also contains a list of commits that affected this crate's source, grouped by the commit type. (See [Conventional Commit syntax](https://www.conventionalcommits.org/en/v1.0.0/#summary).)

IMPORTANT: It _is_ permissible to manually edit the proposed changelog in the PR, but be aware those changes will be overwritten if another update is triggered. release-plz uses force-push to update any existing release PR.

IMPORTANT: If the version number of the crate in `main` is _different_ from the version number on [crates.io](https://crates.io), this job will NOT run.

### Publish new crates

(to do)

## Behind the scenes

Release-plz is two components: a Rust-based command-line tool ([GitHub](https://github.com/release-plz/release-plz)) and a pre-packaged GitHub Actions wrapper ([GitHub](https://github.com/release-plz/action)). We use the pre-packaged GitHub Actions wrapper in this project.

Colin and I have both submitted fixes to release-plz. The developer is generally responsive and PRs are typically merged and released within a week or two.

### Related: commit-lint

(reference `.commitlintrc.yml` and how it supports release-plz)

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
* nightly build process
* c2patool binary build process
