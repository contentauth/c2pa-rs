# Contributing

We welcome contributions to this project!

Before you start, we ask that you understand the following guidelines.

## Code of conduct

This project adheres to the Adobe [code of conduct](CODE_OF_CONDUCT.md). By participating,
you are expected to uphold this code. Please report unacceptable behavior to
[Grp-opensourceoffice@adobe.com](mailto:Grp-opensourceoffice@adobe.com).

## Have a question?

Start by filing an issue. The existing committers on this project work to reach
consensus around project direction and issue solutions within issue threads
(when appropriate).

### Current areas of work

The Adobe CAI team has been using this crate as the foundation of Adobe's Content Authenticity Initiative-related products and services since late 2020. 
Groad categories of work (and thus things you might expect to change) are:

* We'll be reviewing and refining our APIs for ease of use and comprehension. We'd appreciate feedback on areas that you find confusing or unnecessarily difficult.
* We'll also be reviewing our APIs for compliance with Rust community best practices. There are some areas (for example, use of public fields and how we take ownership vs references) where we know some work is required.
* Our documentation is incomplete. We'll be working on refining the documentation.
* Our testing infrastructure is incomplete. We'll be working on improving test coverage, memory efficiency, and performance benchmarks.  See [docs/testing.md] for more details.

### Desired feedback

We welcome feedback on:

* API design
* Prioritization of upcoming development, especially:
  * File format support
  * Assertion support
* Optimizations and performance concerns
* Bugs or non-compliance with the C2PA spec
* Additional platform support

## Contributor license agreement

All third-party contributions to this project must be accompanied by a signed contributor
license agreement. This gives Adobe permission to redistribute your contributions
as part of the project. [Sign our CLA](https://opensource.adobe.com/cla.html). You
only need to submit an Adobe CLA one time, so if you have submitted one previously,
you are good to go!

### Code reviews

All submissions should come in the form of pull requests and need to be reviewed
by project committers. Read [GitHub's pull request documentation](https://help.github.com/articles/about-pull-requests/)
for more information on sending pull requests.

Code submissions will need to pass all automated tests in place at the time of submission.
These include such things as Rust code format, Clippy/lint checks, and unit test coverage.

We encourage you to raise an issue in GitHub before starting work on a major addition to the crate.
This will give us an opportunity to discuss API design and avoid duplicate efforts.

### Pull request titles

Titles of pull requests that target a long-lived branch such as _main_ or a release-specific branch should follow [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/#specification). The repository's [commit lint rules](https://github.com/contentauth/c2pa-rs/blob/main/.commitlintrc.yml) require that the first word of the pull request title must be one of the following:

- `fix`
- `feat`
- `chore`
- `update`
- `doc`

Optionally, but preferred, a scope can be added in parentheses after the type. The scope should be the name of the module or component that the commit affects. For example, `feat(api): Introduce a new API to validate 1.0 claims`.

If more detail is warranted, add a blank line and then continue with sentences (these sentences should be punctuated as such) and paragraphs as needed to provide that detail. There is no need to word-wrap this message.

For example:

```text
feat(api): Introduce a new API to validate 1.0 claims

Repurpose existing v2 API for 0.8 compatibility (read: no validation) mode.
```

The conventional commit message requirement does not apply to individual commits within a pull request, provided that those commits will be squashed when the PR is merged and the resulting squash commit does follow the conventional commit requirement. This may require the person merging the PR to verify the commit message syntax when performing the squash merge.  

TIP: For single-commit PRs, ensure the commit message conforms to the conventional commit requirement, since by default that will also be the title of the PR.

## From contributor to committer

We love contributions from our community! If you'd like to go a step beyond contributor
and become a committer with full write access and a say in the project, you must
be invited to the project. The existing committers employ an internal nomination
process that must reach lazy consensus (silence is approval) before invitations
are issued. If you feel you are qualified and want to get more deeply involved,
feel free to reach out to existing committers to have a conversation about that.

## Security issues

Do not create a public GitHub issue for any suspected security vulnerabilities. Instead, please file an issue through [Adobe's HackerOne page](https://hackerone.com/adobe?type=team). 
For more information on reporting security issues, see [SECURITY.md](SECURITY.md).
