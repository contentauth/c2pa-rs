# Repository contribution guidance

Before editing code, read [CONTRIBUTING.md](CONTRIBUTING.md), especially
[Code formatting](CONTRIBUTING.md#code-formatting). These conventions apply to
AI-generated changes as well as human contributions.

In particular, separate multi-line blocks from adjacent statements and sibling
blocks with a blank line wherever rustfmt permits. For struct fields and enum
variants with comments, separate each comment/member group from adjacent members
by one blank line, keeping comments and attributes attached to their member.
Blank lines between adjacent members without comments are optional; attributes
alone do not require blank lines.

Use the repository's pinned nightly rustfmt command from CI:

```sh
cargo +nightly-2026-07-12 fmt --all -- --check
```
