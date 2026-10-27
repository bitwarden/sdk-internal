#!/usr/bin/env bash
# Records the content of every tracked file (as file hashes) next to the build output, so
# `ci-mark-changed-files.sh` can tell which files changed after the cache is restored.
# Run only after a successful build of the current checkout.
set -euo pipefail

mkdir -p target
# shellcheck source=scripts/ci-build-inputs.sh
. "$(dirname "$0")/ci-build-inputs.sh"
list_build_inputs > target/.build-cache-inputs
echo "Recorded $(wc -l < target/.build-cache-inputs | tr -d ' ') build inputs"
du -sh target 2>/dev/null || true
