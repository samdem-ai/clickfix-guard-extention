#!/usr/bin/env python3
"""Package the extension for both stores.

Writes dist/clickfix-guard-<version>-chrome.zip and
dist/clickfix-guard-<version>-firefox.xpi (same files; one manifest serves
both browsers). Only shipped files are included, never tests or tools.
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
    """Drop the other browser's keys so neither browser warns about them.

    The repo manifest serves both (for loading unpacked); packages are per store.
    """
    m = json.loads(json.dumps(manifest))
    if target == "firefox":
        m["background"].pop("service_worker", None)
        m["permissions"] = [p for p in m["permissions"] if p != "offscreen"]
    else:
        m["background"].pop("scripts", None)
        m.pop("browser_specific_settings", None)
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
