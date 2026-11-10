#!/usr/bin/env python3
"""Fails if the Verifpal pin drifts from upstream at the pinned rev.

`cargo bin verifpal` builds upstream's own Cargo.lock (`locked = true`), so
support/verifpal/Cargo.lock must mirror it for dependency scanners to see what
we actually run. Checks:

  1. root `[workspace.metadata.bin].verifpal` and support/verifpal agree on rev,
     and the tracking lock resolves Verifpal at that rev.
  2. the pinned version matches upstream's Cargo.toml at that rev.
  3. every package in the tracking lock exists in upstream's Cargo.lock with the
     same version and checksum (wasm-only packages may be absent from ours).

Usage: scripts/check-verifpal-pin.py
"""

import sys
import tomllib
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TRACKING_DIR = REPO_ROOT / "support" / "verifpal"
UPSTREAM_GIT = "https://github.com/symbolicsoft/verifpal"
UPSTREAM_RAW = "https://raw.githubusercontent.com/symbolicsoft/verifpal"
TOOL = "verifpal"
TRACKING_CRATE = "verifpal-tracking"


def load(path: Path) -> dict:
    return tomllib.loads(path.read_text())


def fetch(rev: str, name: str) -> dict:
    with urllib.request.urlopen(f"{UPSTREAM_RAW}/{rev}/{name}") as resp:
        return tomllib.loads(resp.read().decode())


def lock_index(lock: dict) -> dict:
    # (name, version) -> checksum; git/path packages have no checksum.
    return {(p["name"], p["version"]): p.get("checksum") for p in lock["package"]}


def main() -> int:
    errors = []

    # 1. Rev agreement between root pin, tracking manifest and tracking lock.
    pin = load(REPO_ROOT / "Cargo.toml")["workspace"]["metadata"]["bin"][TOOL]
    rev = pin["rev"]
    dep = load(TRACKING_DIR / "Cargo.toml")["dependencies"][TOOL]
    if pin["git"] != UPSTREAM_GIT or dep["git"] != UPSTREAM_GIT:
        errors.append(f"git source must be {UPSTREAM_GIT}")
    if dep["rev"] != rev:
        errors.append(f"support/verifpal rev {dep['rev']} != root rev {rev}")

    tracking_lock = load(TRACKING_DIR / "Cargo.lock")
    expected_source = f"git+{UPSTREAM_GIT}?rev={rev}#{rev}"
    sources = [p.get("source") for p in tracking_lock["package"] if p["name"] == TOOL]
    if sources != [expected_source]:
        errors.append(f"tracking lock resolves {TOOL} from {sources}, expected {expected_source}")

    # 2. Version agreement with upstream manifest.
    upstream_version = fetch(rev, "Cargo.toml")["package"]["version"]
    if pin["version"] != upstream_version:
        errors.append(f"root pin version {pin['version']} != upstream {upstream_version}")

    # 3. Every locked dependency matches upstream's lock.
    upstream = lock_index(fetch(rev, "Cargo.lock"))
    for (name, version), checksum in lock_index(tracking_lock).items():
        if name in (TOOL, TRACKING_CRATE):
            continue
        if (name, version) not in upstream:
            errors.append(f"{name} {version} not in upstream Cargo.lock at {rev}")
            continue
        if upstream[(name, version)] != checksum:
            errors.append(f"{name} {version} checksum differs from upstream")

    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print(f"Verifpal pin {rev} matches upstream")
    return 0


if __name__ == "__main__":
    sys.exit(main())
