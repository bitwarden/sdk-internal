#!/usr/bin/env bash
# Prepares a restored `target/` directory so Cargo only rebuilds what changed.
#
# Cargo decides whether a workspace crate is up to date by comparing the modification times of its
# source files with those of its build output. A fresh checkout gives every file the current time,
# which makes every workspace crate look changed. This script sets all tracked files to a fixed old
# time, then marks as new only the files whose content differs from when the cached build was made.
# The content at build time is the list of file hashes written by `ci-record-build-inputs.sh`.
#
# If there is no list, every file keeps its checkout time, so Cargo rebuilds all workspace crates.
# That is slower but never stale.
set -euo pipefail

INPUTS_FILE="target/.build-cache-inputs"

if [ ! -f "$INPUTS_FILE" ]; then
  echo "No record of the cached build's inputs, building all workspace crates."
  exit 0
fi

current=$(mktemp)
changed=$(mktemp)
# shellcheck source=scripts/ci-build-inputs.sh
. "$(dirname "$0")/ci-build-inputs.sh"
list_build_inputs > "$current"

# Lines are "<blob hash>\t<path>". A file is changed if it is new or its content differs from the
# recorded list.
awk -F'\t' 'NR == FNR { recorded[$2] = $1; next } recorded[$2] != $1 { print $2 }' \
  "$INPUTS_FILE" "$current" > "$changed"

git ls-files -z | xargs -0 touch -t 200001010000

count=$(wc -l < "$changed" | tr -d ' ')
echo "Files changed since the cached build: $count"
if [ "$count" -gt 0 ]; then
  tr '\n' '\0' < "$changed" | xargs -0 touch
  head -50 "$changed"
fi
rm -f "$current" "$changed"
