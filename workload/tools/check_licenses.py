"""CI gate: every component in the lockfile must declare an allowed license."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from fetch_components import ALLOWED_LICENSES

MODEL_LICENSES = {"Apache-2.0", "MIT", "OpenMDW-1.1", "verify"}


def main(lock_path: str) -> int:
    lock = json.loads(Path(lock_path).read_text())
    bad = [c["name"] for c in lock["components"] if c["license"] not in ALLOWED_LICENSES]
    bad += [m["name"] for m in lock["models"] if m["license"] not in MODEL_LICENSES]
    if bad:
        print("disallowed or missing licenses:", ", ".join(bad))
        return 1
    unverified = [m["name"] for m in lock["models"] if m["license"] == "verify"]
    if unverified:
        print("warning: model licenses still to verify before release:", ", ".join(unverified))
    print("licenses ok")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent))
    sys.exit(main(sys.argv[1]))
