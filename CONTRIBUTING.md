# Contributing

We welcome contributions to this project!

Before you start, we ask that you understand the following guidelines.

## Code of conduct

This project adheres to the Adobe [code of conduct](../CODE_OF_CONDUCT.md). By participating,
you are expected to uphold this code. Please report unacceptable behavior to
[Grp-opensourceoffice@adobe.com](mailto:Grp-opensourceoffice@adobe.com).

## Have a question?

Start by filing an issue. The existing committers on this project work to reach
consensus around project direction and issue solutions within issue threads
(when appropriate).

### Current areas of work

The Adobe CAI team has been using this crate as the foundation of Adobe's Content Authenticity Initiative-related products and services since late 2020. As we shift toward making this crate available for open usage, we're aware that there is quite a bit of work to do to create what we'd feel comfortable calling a 1.0 release. We've decided to err on the side of releasing earlier so that people can experiment with it and give us feedback.

We expect to do work on a number of areas in the next few months while we remain in prerelease (0.x) versions. Some broad categories of work (and thus things you might expect to change) are:

* We'll be reviewing and refining our APIs for ease of use and comprehension. We'd appreciate feedback on areas that you find confusing or unnecessarily difficult.
* We'll also be reviewing our APIs for compliance with Rust community best practices. There are some areas (for example, use of public fields and how we take ownership vs references) where we know some work is required.
* Our documentation is incomplete. We'll be working on refining the documentation.
* Our testing infrastructure is incomplete. We'll be working on improving test coverage, memory efficiency, and performance benchmarks.

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

## Code reviews

All submissions should come in the form of pull requests and need to be reviewed
by project committers. Read [GitHub's pull request documentation](https://help.github.com/articles/about-pull-requests/)
for more information on sending pull requests.

Code submissions will need to pass all automated tests in place at the time of submission.
These include such things as Rust code format, Clippy/lint checks, and unit test coverage.

We encourage you to raise an issue in GitHub before starting work on a major addition to the crate.
This will give us an opportunity to discuss API design and avoid duplicate efforts.

### Pull request titles

The build process automatically adds a pull request (PR) to the [CHANGELOG](CHANGELOG.md) unless the title of the PR begins with `(IGNORE)`. Start PR titles with `(IGNORE)` for minor documentation updates and other trivial fixes that you want to specifically exclude from the CHANGELOG.

Additionally, the build process takes specific actions if the title of a PR begins with certain special strings:
- `(MINOR)`: Increments the minor version, per [semantic versioning](https://semver.org/) convention. **IMPORTANT:** This flag should be used for any API change that breaks compatibility with previous releases while this crate is in prerelease (version 0.x) status.
- `(MAJOR)`: Increments the major version number, per [semantic versioning](https://semver.org/) convention.

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
