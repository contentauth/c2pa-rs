# Deprecation policy

## Preamble

The Content Authenticity Initiative SDKs are evolving projects. Prior to their 1.0 release, the APIs may change as we refine our design. That said, we are committed to making those changes in a transparent, predictable way so that developers can plan accordingly.

This policy applies to the Rust SDK and all language bindings (JavaScript, Node.js, C, C++, Swift, Kotlin, and Python).

## Versioning and stability guarantees

We follow [Semantic Versioning (SemVer)](https://semver.org/). Version 1.0.0 will define the public API, and after that release, the way version numbers are incremented will be dependent on how the public API changes: patch for backward-compatible bug fixes, minor for backward-compatible additions, and major for incompatible changes.

**Before 1.0:** Major version zero (`0.y.z`) is for initial development — anything may change at any time, and the public API should not be considered stable. In the Rust/Cargo ecosystem, this means that a change from `0.2.3` to `0.3.0` may include incompatible API changes. We will, however, make a good-faith effort to follow the deprecation process below even before 1.0, so that users have advance warning before breakage occurs.

## What counts as a breaking change

Not all changes are equal. Breaking changes are assumed to be major changes, but not all breaking changes are major. The goal is that the same code should be able to run against different minor revisions, and minor changes should require at most a few local annotations. (This document is Rust-specific; we will treat other languages as closely to this list as is feasible.)

Changes we consider **breaking** (requiring a major version bump post-1.0):

- Moving a public type, function, method, trait, or constant from one parent module to another
- Removing or renaming a public type, function, method, trait, or constant
- Changing the signature of a public function (parameter types, return types, or generics) except to the extent such changes are generally considered non-breaking (e.g. changing a `&mut Type` to `&Type`)
- Changing the behavior of a public API in a way that violates previously documented contracts
- Removing or renaming public enum variants or struct fields
- Adding public enum variants or struct fields (unless `#[non_exhaustive]` was applied)
- Breaking changes to upstream or third-party libraries to the extent that those APIs are re-published by our library and thus break our own API compatibility
- Any other change flagged by `cargo-server-checks` (or an equivalent tool for any other language) as breaking compatibility

Changes we consider **non-breaking** (minor or patch):

- Adding new public items (types, functions, trait impls)
- Deprecating a public item without removing it
- Bug fixes that restore documented behavior

## The deprecation process

When we decide to remove or replace part of the public API, we follow a three-stage process:

### Stage 1: Deprecation notice (minor release)

- The item is marked deprecated in source code using the appropriate language mechanism. (See "Language-specific deprecation annotations" below.)
- The deprecation message includes: what is deprecated, why, what to use instead, and the earliest planned removal timeline. (See stage 2.)
- The change is documented in the CHANGELOG under a `### Deprecated` heading.
- An announcement is posted in the project's Discord and, where applicable, linked from the relevant GitHub issue or PR.

### Stage 2: Grace period

The grace period is a timeframe during which the deprecated API remains operational before being retired. Our minimums are:

| SDK maturity | Minimum grace period |
| -- | -- |
| Pre-1.0 | 60 days |
| Post-1.0 | 90 days |

During the grace period, the deprecated API will continue to work without functional regression. **Exception:** We may remove deprecated APIs before this window expires if needed to address serious security issues or vulnerabilities.

### Stage 3: Removal

- The deprecated item is removed in the next major release after the announced grace period has elapsed. **Exception:** A minor release may be used for these cases:
    -  The item was marked as deprecated prior to the 1.0.0 release.
    -  The item was only ever made public via a non-default feature/build configuration.
- The migration guide (see "Migration guides", below) is updated to reflect the removal as permanent.

## Language-specific deprecation annotations

Deprecation warnings will be expressed using each language's idiomatic mechanism so that developers are alerted by their compiler or toolchain.

### Rust

```rust
#[deprecated(since = "0.5.0", note = "Use `Builder::new_v2()` instead. Will be removed in 0.7.0.")]
pub fn old_builder() -> Builder { ... }
```

### Python

Use `warnings.warn()` with `DeprecationWarning` (or the `@warnings.deprecated` decorator introduced in Python 3.13 / available via `typing_extensions`):

```python
import warnings

def old_function():
    warnings.warn(
        "old_function() is deprecated since 0.5.0; use new_function() instead." " Will be removed in 0.7.0.", DeprecationWarning, stacklevel=2,
    )
```

The `@warnings.deprecated()` decorator can be used on a class, function, or method to mark it as deprecated. By default, it raises a runtime `DeprecationWarning` and also enables static type checkers to surface the deprecation at the call site. [Python](https://peps.python.org/pep-0702/)

### JavaScript / Node.js

Use the `/** @deprecated */` JSDoc tag for IDE/toolchain visibility, and optionally emit a `console.warn` or Node.js `process.emitWarning` at runtime for dynamic detection.

### C / C++

```C++
__attribute__((deprecated("message")))``[[deprecated("message")]]
```

Also use `__declspec(deprecated)` to ensure deprecations are visible on Windows platforms.

### Swift

Use `@available(*, deprecated, renamed: "newFunction", message: "Use newFunction() instead.")`.

### Kotlin

Use `@Deprecated(message = "...", replaceWith = ReplaceWith("newFunction()"))`.

## Migration guides

Every deprecation will be accompanied by a migration guide. We will provide alternatives or newer versions for deprecated features — if an item is scheduled for removal, users should know the recommended replacement.

Migration guides should be published as:

- A section in the CHANGELOG entry for the deprecating release
- A page or section in the SDK documentation site (linking from the deprecated symbol's doc comment)
- A note in any relevant GitHub issue or discussion thread

Guides will include: the reason for the change, a before/after code comparison, any behavioral differences to be aware of, and the removal timeline.

## Communication channels

Send announcements about deprecations through channels where the developer community is active — mailing lists, forums, and platforms like GitHub. Our standard channels are:

- **CHANGELOG.md:** required for every deprecation
- **GitHub Release Notes:** summary of deprecations in each release. These are also reproduced in the doc site.
- **Doc site:** deprecated symbols are visually flagged in all API references where the deprecated APIs are documented.

## Security and bug-fix exceptions

If a deprecated API contains a security vulnerability, we reserve the right to either patch it in place or accelerate its removal, with as much notice as is practical given the severity. In such cases, we will coordinate with known downstream users and post a security advisory.

## Feedback and exceptions

If the deprecation timeline creates a significant hardship for your project, please open a GitHub issue. We will consider extension requests, particularly for users with demonstrated adoption. Our goal is to evolve the SDK without leaving the community behind.
