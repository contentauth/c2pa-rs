# Security

This C2PA open-source library is maintained in partnership with Adobe. At this time, Adobe is taking point on accepting security reports through its HackerOne portal and public bug bounty program.

## Reporting a vulnerability

Please do not create a public GitHub issue for any suspected security vulnerabilities. Instead, please file an issue through [Adobe's HackerOne page](https://hackerone.com/adobe?type=team). If for some reason this is not possible, reach out to cai-security@adobe.com.

## Vulnerability SLAs

Once we receive an actionable vulnerability (meaning there is an available patch, or a code fix is required), we will acknowledge the vulnerability within 24 hours. Our target SLAs for resolution are:

1. 72 hours for vulnerabilities with a CVSS score of 9.0-10.0
2. 2 weeks for vulnerabilities with a CVSS score of 7.0-8.9

Any vulnerability with a score below 6.9 will be resolved when possible.

## C2PA vulnerabilities

This library is not meant to address any potential vulnerabilities within the C2PA specification itself. It is only an implementation of the spec as written. Any suspected vulnerabilities within the spec can be reported [here](https://github.com/c2pa-org/specifications/issues).

## What counts as a reportable vulnerability?

We will follow this checklist when evaluating vulnerability tickets.

### ❌ Unwelcome vulnerability tickets

Tickets that match the following characteristics will generally be **rejected**:

* **Denial-of-service attacks.** For example, out-of-memory conditions caused by sending large input data. It’s the responsibility of the host application to enforce size limits on raw input data based on configuration information specific to the host. **EXCEPTION:** When a “reasonably small” input generates an unreasonably large memory allocation, such as an input file of 1MB causing a 200MB memory allocation (i.e. the c2pa-rs allocation is a very large multiple of the original input), that ticket will generally be accepted.
* **Use of non-default configuration settings to bypass security requirements** provided the consequences of those settings are sufficiently documented in our [documentation on settings](docs/settings.md).
* **Generation of invalid C2PA manifests from valid inputs or credentials.** In these scenarios, the inputs were not maliciously altered, but due to a bug in the SDK a malformed manifest has been produced. These are welcome as ordinary bug reports, but are not security vulnerabilities.
* **Use of the SDK or command-line tools on unsupported platforms or unreleased versions.** Only platforms and build configurations listed as Tier 1A, Tier 1B, or Tier 2 on [our support tiers page](docs/support-tiers.md) are explicitly supported. A security ticket must include the version number of the SDK or c2patool and the host platform that was used. Only tagged releases will be accepted. If any non-standard build process (i.e. not using current Rust cargo to build from source or not using a pre-packaged binary provided by this team), that should be disclosed and may result in a ticket not being accepted.

### ❌ _Temporarily_ unwelcome vulnerability tickets

The following characteristics represent issues that we know are problematic. Work is planned or in progress to address these issues. Tickets for such issues will be **rejected** until the work is complete and published.

* **Network calls based on C2PA manifest input data.** Work is underway to allow SDK clients to constrain or prohibit outbound network access. Once that work is published, we will welcome tickets that demonstrate network traffic that exceeds client configuration. (See [#1765: Tracking issue: SDK lacks an option to prohibit or restrict network traffic](https://github.com/contentauth/c2pa-rs/issues/1765).)
* **The CAWG X.509 trust model added in CAWG identity 1.2 is not yet enforced.** Arbitrary X.509 certificates are accepted as CAWG named actor signatures. Once the work on this issue is complete, we will welcome tickets that demonstrate failure to enforce the trust model. (See [#1764: Trust model defined in CAWG identity assertion 1.2 is not implemented](https://github.com/contentauth/c2pa-rs/issues/1764).)

### ✅ Welcome vulnerability tickets

Tickets that match the following characteristics should generally be **accepted**:

* **Parsing errors that cause crashes or undefined behavior** except as described above under "denial of service."
* **Failure to detect invalid / untrusted status in C2PA manifests** except as described above under “use of non-default configuration settings” or documented above as “temporarily unwelcome.”
* **Default settings that create vulnerabilities** except as documented above as “temporarily unwelcome.”
* **Ability to bypass C2PA manifest validation** except as described above under “use of non-default configuration settings.”
* **Ability to generate an apparently-trusted C2PA manifest with invalid credentials** except as described above under “use of non-default configuration settings.” **IMPORTANT:** Most other invalid-input → apparently-valid C2PA manifest scenarios are welcome as ordinary bug reports, but are unlikely to be accepted as security vulnerabilities.
* **Errors in cryptographic implementations.**

### Other types of issues not listed above

Tickets that don’t match the above characteristics will be handled on a case-by-case basis and may inform updates to this document.
