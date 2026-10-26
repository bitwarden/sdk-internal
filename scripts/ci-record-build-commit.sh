#!/usr/bin/env bash
# Records which commit the contents of `target/` were built from, for `ci-mark-changed-files.sh`.
# Run only after a successful build of the current checkout.
set -euo pipefail

mkdir -p target
git rev-parse HEAD > target/.build-cache-sha
echo "Recorded build commit $(cat target/.build-cache-sha)"
du -sh target 2>/dev/null || true
