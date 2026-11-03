#!/usr/bin/env python3
"""Add plugins to index.toml from their plugin.toml: python3 tools/add-to-index.py <id> [<id> ...]
Skips ids already listed. Keeps the package list and each plugin's own manifest in step."""
import sys, tomllib
from pathlib import Path

root = Path(__file__).resolve().parent.parent
index = root / "index.toml"
listed = {p["id"] for p in tomllib.loads(index.read_text()).get("plugin", [])}
out = ""
for pid in sys.argv[1:]:
    if pid in listed:
        print(f"{pid}: already listed"); continue
    m = tomllib.loads((root / "plugins" / pid / "plugin.toml").read_text())
    desc = m["description"].replace("\\", "\\\\").replace('"', "'")
    out += f'\n[[plugin]]\nid = "{pid}"\nname = "{m["name"]}"\ndescription = "{desc}"\nversion = "{m["version"]}"\npath = "plugins/{pid}"\n'
    print(f"{pid}: added ({m['name']}, port {m['port']})")
if out:
    index.write_text(index.read_text() + out)
tomllib.loads(index.read_text())  # must still parse
