#!/usr/bin/env bash
# Prepares a restored `target/` directory so Cargo only rebuilds what changed.
#
# Cargo decides whether a workspace crate is up to date by comparing the modification times of its
# source files with those of its build output. A fresh checkout gives every file the current time,
# which makes every workspace crate look changed. This script sets all tracked files to a fixed old
# time, then marks as new only the files that differ from the commit the cached build was made
# from (stored in `target/.build-cache-sha` by `ci-record-build-commit.sh`).
#
# If the cached commit can't be determined or fetched, every file is marked as new, so Cargo
# rebuilds all workspace crates. That is slower but never stale.
set -euo pipefail

STAMP_FILE="target/.build-cache-sha"

mark_all_new() {
  echo "Marking all files as changed: $1"
  git ls-files -z | xargs -0 touch
}

if [ ! -f "$STAMP_FILE" ]; then
  echo "No cached build commit found, nothing to adjust."
  exit 0
fi

base=$(cat "$STAMP_FILE")
if ! [[ "$base" =~ ^[0-9a-f]{40}$ ]]; then
  mark_all_new "invalid cached build commit '$base'"
  exit 0
fi

if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
  if ! git fetch --quiet --no-tags --depth=1 origin "$base"; then
    mark_all_new "could not fetch cached build commit $base"
    exit 0
  fi
fi

git ls-files -z | xargs -0 touch -t 200001010000

changed=$(mktemp)
git diff --name-only -z --diff-filter=d "$base" HEAD > "$changed"
count=$(tr -cd '\0' < "$changed" | wc -c | tr -d ' ')
echo "Cached build is from $base. Files changed since then: $count"
if [ "$count" -gt 0 ]; then
  xargs -0 touch < "$changed"
  tr '\0' '\n' < "$changed" | head -50
fi
rm -f "$changed"
