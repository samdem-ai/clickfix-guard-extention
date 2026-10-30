#!/usr/bin/env python3
"""Package the extension for both stores.

Writes dist/clickfix-guard-<version>-chrome.zip and
dist/clickfix-guard-<version>-firefox.xpi (same files; the Firefox manifest
is manifest.json plus manifest.firefox.json). Only shipped files are included, never tests or tools.
Run from anywhere: python tools/build.py
"""

import json
import os
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIP = ["manifest.json", "src", "popup", "offscreen", "icons", "LICENSE"]


def files():
    for entry in SHIP:
        path = os.path.join(ROOT, entry)
        if os.path.isfile(path):
            yield entry
        elif os.path.isdir(path):
            for dirpath, _dirs, names in os.walk(path):
                for name in sorted(names):
                    yield os.path.relpath(os.path.join(dirpath, name), ROOT).replace(os.sep, "/")


def manifest_for(manifest, target):
    """manifest.json is the Chrome manifest (loadable unpacked as-is). Firefox
    gets manifest.firefox.json applied: background scripts instead of a service
    worker, its add-on id, and no Chrome-only permissions."""
    m = json.loads(json.dumps(manifest))
    if target == "firefox":
        with open(os.path.join(ROOT, "manifest.firefox.json"), encoding="utf-8") as fh:
            fx = json.load(fh)
        m["background"] = fx["background"]
        m["permissions"] = [p for p in m["permissions"] if p not in fx["remove_permissions"]]
        m["browser_specific_settings"] = fx["browser_specific_settings"]
    return (json.dumps(m, indent=2) + "\n").encode("utf-8")


def main():
    with open(os.path.join(ROOT, "manifest.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    version = manifest["version"]
    dist = os.path.join(ROOT, "dist")
    os.makedirs(dist, exist_ok=True)
    shipped = sorted(files())
    for target, ext in (("chrome", "zip"), ("firefox", "xpi")):
        out = os.path.join(dist, f"clickfix-guard-{version}-{target}.{ext}")
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            for rel in shipped:
                # Fixed timestamp: identical input gives an identical archive.
                info = zipfile.ZipInfo(rel, date_time=(2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                if rel == "manifest.json":
                    zf.writestr(info, manifest_for(manifest, target))
                    continue
                with open(os.path.join(ROOT, rel), "rb") as fh:
                    zf.writestr(info, fh.read())
        print(f"{os.path.relpath(out, ROOT)}  ({len(shipped)} files)")


if __name__ == "__main__":
    main()
