# Deprecation policy

The Content Authenticity Initiative SDK is an evolving project. Prior to our 1.0 release, the APIs may change as we refine our design. That said, we are committed to making those changes in a transparent, predictable way so that developers can plan accordingly.

This policy applies to the Rust library and all language bindings (JavaScript, Node.js, C, C++, Swift, Kotlin, and Python).

## Versioning and stability guarantees

We follow [Semantic Versioning (SemVer)](https://semver.org/). Version 1.0.0 will define the public API; subsequent version numbers will be based on how the public API changes in the release: 

- **Patch** release for backward-compatible bug fixes.
- **Minor** release for backward-compatible additions.
- **Major** release for incompatible changes.

**Before 1.0:** Major version zero (`0.y.z`) is for initial development: Anything may change at any time, and the public API should not be considered stable. In the Rust/Cargo ecosystem, this means that a change from `0.2.3` to `0.3.0` may include incompatible API changes. We will, however, make a good-faith effort to follow the deprecation process below even before 1.0, so that users have advance warning before breakage occurs.

Pre-1.0 this fits with our two-track [release process](release-process.md): a **deprecation is additive**, so it ships quickly on the current release train as a patch release (the `y` in `0.x.y`) and starts the grace-period clock immediately. The eventual **removal is breaking**, so it rides the next scheduled breaking "train" (a bump of the middle number, `0.x.0`) once the grace period has elapsed. Users therefore get the replacement API and the deprecation warning right away, with a known schedule for when the old API disappears.

> [!IMPORTANT]
> We deprecate an API **only once its replacement is available**. A deprecation notice must always point users to a supported alternative, so there is never a window in which the recommended path is "stop using this, and wait." (If an API is dangerous enough that we want to steer people away before a replacement exists, that is a documentation/advisory matter, or, for a security issue, the [security exception](#security-and-bug-fix-exceptions), not a routine deprecation.)

> [!NOTE]
> Pre-1.0, this policy is applied on a best-effort basis. We may not always be able to provide a full deprecation cycle for every change as the API converges on its 1.0 shape. In particular, the `c2pa::Error` type is expected to undergo non-trivial refactoring prior to 1.0: variants may be added, removed, renamed, or have their payloads reshaped between minor releases, and downstream code that matches on specific variants should expect churn until 1.0.

**After 1.0:** Breaking changes will only ship in major version increments. Before completely removing functionality in a new major release, there will be at least one minor release that contains the deprecation so that API consumers can smoothly transition to the new API. We will publish and retain historical documentation for at least each minor point release.

## What counts as a breaking change

Not all changes are equal. 

A breaking change always results in a major version increment, but a major version increment does not always require a breaking change. A major version can also be used to release a rewritten API or significant new features: It primarily serves as a signal that the update requires careful review for compatibility. 

The goal is that the same code should be able to run against different minor revisions, and minor changes require at most a few local annotations. (This document is Rust-specific; we will treat other languages as closely to this list as is feasible.)

Changes considered **breaking** (requiring a major version increment post-1.0):

- Moving a public type, function, method, trait, or constant from one parent module to another
    - **EXCEPTION:** APIs that are not _publicly documented_ may be removed prior to 1.0 without following this policy.
- Removing or renaming a public type, function, method, trait, or constant
- Changing the signature of a public function (parameter types, return types, or generics) except to the extent such changes are generally considered non-breaking (e.g. changing a `&mut Type` to `&Type`)
- Changing the behavior of a public API in a way that violates previously documented contracts
- Removing or renaming public enum variants or struct fields
- Adding public enum variants or struct fields (unless `#[non_exhaustive]` was applied)
- Breaking changes to upstream or third-party libraries to the extent that those APIs are re-published by our library and thus break our own API compatibility
- Any other change flagged by `cargo-semver-checks` (or an equivalent tool for any other language) as breaking compatibility

Changes considered **non-breaking** (minor or patch release):

- Adding new public items (types, functions, trait implementation)
- Deprecating a public item without removing it
- Bug fixes that restore documented behavior

## The deprecation process

When we decide to remove or replace part of the public API, we follow a three-stage process:

1. [Deprecation notice](#stage-1-deprecation-notice)
2. [Grace period](#stage-2-grace-period)
3. [Removal](#stage-3-removal)

### Stage 1: Deprecation notice

The initial stage, delivered in a minor release, provides advance notice of the deprecation:

1. The item is marked deprecated in source code using the [appropriate language mechanism](#language-specific-deprecation-annotations).
1. The deprecation message includes: 
    - What is deprecated
    - Why it is being deprecated
    - What to use instead
    - If possible, the planned removal timeline (see stage 2). In any case, removal must not occur until after the minimum grace period.
1. The change is documented in the `CHANGELOG` under a `### Deprecated` heading, along with additional [migration documentation](#migration-guides).
1. An announcement is posted in the project's Discord and, where applicable, linked from the relevant GitHub issue or PR.

### Stage 2: Grace period

During the grace period, the deprecated API remains operational without functional regression before being retired. The _minimum_ grace periods are shown here:

| SDK maturity | Minimum grace period |
| -- | -- |
| Pre-1.0 | 60 days |
| Post-1.0 | 90 days |

**Exception:** We may remove deprecated APIs before this window expires if needed to address serious security issues or vulnerabilities.

### Stage 3: Removal

In the final stage, the item is actually removed from the API.

After the grace period:

- **Post-1.0:** the deprecated item is removed in the next major release.
- **Pre-1.0:** the removal is a breaking change, so it ships on the next scheduled breaking [release train](release-process.md#track-2--the-breaking-train-0x0), a bump of the middle version number (`0.x.0`). (This is the pre-1.0 analogue of "the next major release.") The same applies to an item that was only ever made public via a non-default feature/build configuration.
- The full [migration guide](#migration-guides) is provided and reflects the removal as permanent.

## Language-specific deprecation annotations

Deprecation warnings are expressed using each language's idiomatic mechanism so that developers are alerted by their compiler or toolchain.

### Rust

```rust
#[deprecated(since = "0.5.0", note = "Use `Builder::new_v2()` instead. Will be removed on or after 2026-10-31.")]
pub fn old_builder() -> Builder { ... }
```

### Python

Use `warnings.warn()` with `DeprecationWarning`:

```python
import warnings

def old_function():
    warnings.warn(
        "old_function() is deprecated since 0.5.0; use new_function() instead." " Will be removed on or after 2026-10-31.", DeprecationWarning, stacklevel=2,
    )
```

You can use the `@warnings.deprecated()` decorator on a class, function, or method to mark it as deprecated. By default, it raises a runtime `DeprecationWarning` and also enables static type checkers to surface the deprecation at the call site. See [PEP 702](https://peps.python.org/pep-0702/) for details.

### JavaScript / Node.js

Use the `/** @deprecated */` JSDoc tag for IDE/toolchain visibility, and optionally emit a `console.warn` or Node.js `process.emitWarning` at runtime for dynamic detection.

### C / C++

```C++
__attribute__((deprecated("message")))
[[deprecated("message")]]
```

Also use `__declspec(deprecated)` to ensure deprecations are visible on Windows platforms.

### Swift

Use `@available(*, deprecated, renamed: "newFunction", message: "Use newFunction() instead.")`.

### Kotlin

Use `@Deprecated(message = "...", replaceWith = ReplaceWith("newFunction()"))`.

## Migration guides

Every deprecation includes a migration guide. We provide alternatives or newer versions for deprecated features: if an item is scheduled for removal, developers should know the recommended replacement.

A migration guide includes:

- A section in the `CHANGELOG` entry for the deprecating release
- A page or section in the SDK documentation site (linking from the deprecated symbol's doc comment)
- A note in any relevant GitHub issue or discussion thread

The migration guide also explains the reason for the change and any behavioral differences to be aware of. Ideally, it also includes a before and after code comparison and the removal timeline, if available.

## Communication channels

Send announcements about deprecations through channels where the developer community is active: mailing lists, forums, and platforms like GitHub. Our standard channels are:

- **`CHANGELOG.md`:** required for every deprecation
- **GitHub Release Notes:** summary of deprecations in each release. These are also reproduced in the doc site.
- **Doc site:** deprecated symbols are visually flagged in all API references where the deprecated APIs are documented.

## Security and bug-fix exceptions

If a deprecated API contains a security vulnerability, we reserve the right to either patch it in place or accelerate its removal, with as much notice as is practical given the severity. In such cases, we will coordinate with known downstream users and post a security advisory.

## Feedback and exceptions

If the deprecation timeline creates a significant hardship for your project, please open a GitHub issue. We will consider extension requests, particularly for users with demonstrated adoption. Our goal is to evolve the SDK without leaving the community behind.
