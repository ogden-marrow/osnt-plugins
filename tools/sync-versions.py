#!/usr/bin/env python3
"""Make index.toml's version for every plugin match that plugin's own plugin.toml (run before pushing)."""
import re, tomllib
from pathlib import Path

root = Path(__file__).resolve().parent.parent
text = (root / "index.toml").read_text()
changed = []
for p in tomllib.loads(text)["plugin"]:
    want = tomllib.loads((root / "plugins" / p["id"] / "plugin.toml").read_text())["version"]
    if want != p["version"]:
        a = text.index(f'id = "{p["id"]}"')
        m = re.compile(r'version = ".*"').search(text, a)
        text = text[:m.start()] + f'version = "{want}"' + text[m.end():]
        changed.append(f'{p["id"]} {p["version"]} -> {want}')
(root / "index.toml").write_text(text)
tomllib.loads(text)
print("\n".join(changed) or "index.toml already in step")
