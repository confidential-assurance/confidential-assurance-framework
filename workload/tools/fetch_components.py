"""Build-time only: download each pinned component and refuse anything whose checksum or license does not match.

Usage: python3 fetch_components.py components.lock.json /opt/scanners
"""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ALLOWED_LICENSES = {
    "Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "LGPL-2.1-only", "MPL-2.0", "data:mixed",
}


def main(lock_path: str, dest: str) -> int:
    lock = json.loads(Path(lock_path).read_text())
    out = Path(dest)
    (out / "bin").mkdir(parents=True, exist_ok=True)
    versions = {}
    for c in lock["components"]:
        if c["license"] not in ALLOWED_LICENSES:
            sys.exit(f"license not allowed for {c['name']}: {c['license']}")
        if not c["url"] or len(c["sha256"]) != 64:
            sys.exit(f"{c['name']}: url and sha256 must be pinned in the lockfile")
        data = urllib.request.urlopen(c["url"], timeout=120).read()
        if hashlib.sha256(data).hexdigest() != c["sha256"]:
            sys.exit(f"{c['name']}: checksum mismatch")
        (out / "dist" / c["name"]).mkdir(parents=True, exist_ok=True)
        (out / "dist" / c["name"] / Path(c["url"]).name).write_bytes(data)
        versions[c["name"]] = c["version"]
        # TODO: unpack archives into out/bin with fixed mtimes (SOURCE_DATE_EPOCH) for reproducibility
    (out / "VERSIONS.json").write_text(json.dumps(versions, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
