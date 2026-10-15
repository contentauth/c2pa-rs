#!/usr/bin/env python3
"""Verify livesim2 fixtures offline, or recapture identical bytes with --recapture."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recapture", action="store_true", help="download and verify before replacing files")
    parser.add_argument("--base-url", help="override the simulator origin, e.g. http://localhost:8888")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    record = json.loads((root / "capture.json").read_text())
    origin = (args.base_url or record["base_url"]).rstrip("/")
    verified = {}
    for entry in record["files"]:
        if args.recapture:
            data = subprocess.run(
                ["curl", "--fail", "--silent", "--show-error", "--location",
                 "--max-time", "30", origin + entry["request"]],
                check=True, stdout=subprocess.PIPE,
            ).stdout
        else:
            data = (root / entry["name"]).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if len(data) != entry["size"] or digest != entry["sha256"]:
            raise SystemExit(
                f"{entry['name']}: bytes differ from capture.json "
                f"(size={len(data)}, sha256={digest}); no files replaced"
            )
        verified[entry["name"]] = data
    # Stage all responses first so an upstream change cannot partially replace a capture.
    if args.recapture:
        for name, data in verified.items():
            (root / name).write_bytes(data)
    print(f"Verified {len(verified)} livesim2 capture files")


if __name__ == "__main__":
    main()
