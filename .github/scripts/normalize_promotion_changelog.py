#!/usr/bin/env python3
"""Normalize the newest changelog section to a train's forced final version.

During promotion (see .github/workflows/release-promote.yml) we let release-plz
generate the changelog while the crate versions are temporarily reset to the
last published release, then force the crate versions to the train's chosen
final numbers. release-plz cannot know the train's forced-minor / lockstep
versioning policy, so the changelog header it wrote may not match the forced
version:

  * A crate with real commits gets a section headed with release-plz's *computed*
    version (e.g. `c2patool 0.26.73`) -- we rewrite the header to the forced
    final version (e.g. `0.27.0`).
  * A crate with no releasable commits of its own gets no new section at all --
    we insert a header-only section for the final version (matching how
    release-plz renders a no-change release, e.g. the existing c2patool 0.26.72
    entry).
  * If release-plz already wrote the final version, we leave it alone.

Whether release-plz added a section is detected by comparing the current top
version against the top version captured *before* release-plz ran (`pretop`),
which is robust even when a crate's changelog is already behind its published
version (e.g. c2pa-c-ffi, whose no-change releases get no changelog entry).

Each CLI argument is `CHANGELOG_PATH:CRATE:PREV_VERSION:FINAL_VERSION:PRETOP`,
where PREV_VERSION is the last published version (the compare-link baseline),
CRATE is the crates.io / git-tag crate name (e.g. `c2pa-c-ffi`), and PRETOP is
the newest section's version before release-plz ran.
"""

from __future__ import annotations

import datetime
import re
import sys

REPO = "https://github.com/contentauth/c2pa-rs"
HEADER_RE = re.compile(r"^## \[([^\]]+)\]")


def compare_link(crate: str, prev: str, new: str) -> str:
    return f"{REPO}/compare/{crate}-v{prev}...{crate}-v{new}"


def header_line(crate: str, prev: str, final: str) -> str:
    return f"## [{final}]({compare_link(crate, prev, final)})"


def normalize(path: str, crate: str, prev: str, final: str, pretop: str) -> None:
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()

    # Locate "## [Unreleased]" and the first concrete version header after it.
    unreleased = next(
        (i for i, ln in enumerate(lines) if ln.strip().startswith("## [Unreleased]")),
        None,
    )
    if unreleased is None:
        raise SystemExit(f"{path}: no '## [Unreleased]' marker found")

    top = None
    top_ver = None
    for i in range(unreleased + 1, len(lines)):
        m = HEADER_RE.match(lines[i])
        if m:
            top, top_ver = i, m.group(1)
            break
    if top is None:
        raise SystemExit(f"{path}: no version section found after '## [Unreleased]'")

    if top_ver == final:
        print(f"{path}: newest section already {final}; no change.")
        return

    if top_ver == pretop:
        # release-plz added nothing new for this crate -> insert a header-only
        # entry (baselined at the last published release, PREV).
        today = datetime.datetime.now(datetime.timezone.utc).strftime("_%d %B %Y_")
        lines[top:top] = [header_line(crate, prev, final), today, ""]
        print(f"{path}: inserted header-only {final} section.")
    else:
        # release-plz wrote a new section at its computed version -> retitle it
        # to the forced final version, keeping the body it generated.
        lines[top] = header_line(crate, prev, final)
        print(f"{path}: retitled {top_ver} section to {final}.")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main(argv: list[str]) -> None:
    if not argv:
        raise SystemExit(
            "usage: normalize_promotion_changelog.py PATH:CRATE:PREV:FINAL:PRETOP ..."
        )
    for spec in argv:
        parts = spec.split(":")
        if len(parts) != 5:
            raise SystemExit(f"bad spec '{spec}'; expected PATH:CRATE:PREV:FINAL:PRETOP")
        normalize(*parts)


if __name__ == "__main__":
    main(sys.argv[1:])
