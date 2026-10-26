# Repository contribution guidance

Before editing code, read [CONTRIBUTING.md](CONTRIBUTING.md), especially
[Code formatting](CONTRIBUTING.md#code-formatting). These conventions apply to
AI-generated changes as well as human contributions.

In particular, separate multi-line blocks from adjacent statements and sibling
blocks with a blank line wherever rustfmt permits. Also separate sibling struct
fields and enum variants by one blank line, keeping each member's documentation
comments and attributes attached to that member.

Use the repository's pinned nightly rustfmt command from CI:

```sh
cargo +nightly-2026-07-12 fmt --all -- --check
```
