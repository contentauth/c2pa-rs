import json
import os
from pathlib import Path
import re
import tomllib


source = Path("release-plz.toml").read_text()
config = tomllib.loads(source)
prefix = f"{os.environ['GITHUB_REF_NAME']}-release-plz-"
lines = []
in_workspace = False
for line in source.splitlines(keepends=True):
    if line.lstrip().startswith("["):
        in_workspace = line.strip() == "[workspace]"
        lines.append(line)
        if in_workspace:
            lines.append(f"pr_branch_prefix = {json.dumps(prefix)}\n")
    elif not (in_workspace and re.match(r"\s*pr_branch_prefix\s*=", line)):
        lines.append(line)

generated = "".join(lines)
config["workspace"]["pr_branch_prefix"] = prefix
if tomllib.loads(generated) != config:
    raise ValueError("Release configuration must change only the PR branch prefix")

Path(os.environ["RUNNER_TEMP"], "release-plz.toml").write_text(generated)
print(f"Release PR namespace: {prefix}")
