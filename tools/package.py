#!/usr/bin/env python3
"""Build every plugin for the Raspberry Pi (aarch64 musl) and package it for the hub's web installer.

Writes dist/<id>.tar.gz (containing exactly `plugin.toml` and `plugin`, the binary) and dist/manifest.json with each
build's version and SHA-256. The hub's installer downloads manifest.json and the archive from the `latest` release,
verifies the checksum, and installs. CI runs this on every push to main; you can run it locally the same way:

    python3 tools/package.py            # all plugins
    ONLY=packages,lookup python3 tools/package.py
"""
import hashlib, io, json, os, subprocess, sys, tarfile, tomllib
from pathlib import Path

TARGET = "aarch64-unknown-linux-musl"
root = Path(__file__).resolve().parent.parent
dist = root / "dist"
target_dir = Path(os.environ.get("CARGO_TARGET_DIR", root / "target-release"))
only = set(filter(None, os.environ.get("ONLY", "").split(",")))
env = dict(os.environ, CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="rust-lld", CARGO_TARGET_DIR=str(target_dir))

dist.mkdir(exist_ok=True)
entries, failures = [], []
for folder in sorted((root / "plugins").iterdir()):
    meta_path = folder / "plugin.toml"
    if not meta_path.exists() or not (folder / "Cargo.toml").exists():
        continue
    meta = tomllib.loads(meta_path.read_text())
    pid = meta["id"]
    if only and pid not in only:
        continue
    print(f"==> {pid} {meta['version']}", flush=True)
    build = subprocess.run(["cargo", "build", "--release", "--target", TARGET, "--manifest-path", str(folder / "Cargo.toml")], env=env)
    binary = target_dir / TARGET / "release" / f"osnt-{pid}"
    if build.returncode != 0 or not binary.exists():
        failures.append(pid)
        continue
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=9) as tar:
        for name, data, mode in (("plugin.toml", meta_path.read_bytes(), 0o644), ("plugin", binary.read_bytes(), 0o755)):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime, info.uname, info.gname = len(data), mode, 0, "root", "root"
            tar.addfile(info, io.BytesIO(data))
    archive = buf.getvalue()
    (dist / f"{pid}.tar.gz").write_bytes(archive)
    entries.append({"id": pid, "name": meta["name"], "version": meta["version"], "asset": f"{pid}.tar.gz", "sha256": hashlib.sha256(archive).hexdigest(), "size": len(archive)})

(dist / "manifest.json").write_text(json.dumps({"target": TARGET, "plugins": entries}, indent=2) + "\n")
print(f"packaged {len(entries)} plugin(s)" + (f"; FAILED: {', '.join(failures)}" if failures else ""))
sys.exit(1 if failures else 0)
