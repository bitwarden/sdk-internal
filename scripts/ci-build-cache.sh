#!/usr/bin/env bash
# Lets a cached `target/` directory be reused, so Cargo only rebuilds the crates that changed.
#
# Cargo decides whether a workspace crate is up to date by comparing the modification times of its
# source files with those of its build output. A fresh checkout gives every file the current time,
# which makes every workspace crate look changed.
#
#   ci-build-cache.sh record   After a successful build: store a hash of every tracked file next to
#                              the build output.
#   ci-build-cache.sh mark     After restoring the cache: set all tracked files to a fixed old time,
#                              then mark as new only the files whose hash differs from the stored one.
#
# If there is no stored list, `mark` leaves every file at its checkout time, so Cargo rebuilds all
# workspace crates. That is slower but never stale.
set -euo pipefail

INPUTS_FILE="target/.build-cache-inputs"

# Prints "<hash>\t<path>" for every tracked file that exists in the working tree. The hash is of
# the working-tree content (not the index), so local modifications made before the build count.
list_build_inputs() {
  local paths
  paths=$(mktemp)
  git -c core.quotePath=false ls-files --cached --exclude-standard \
    | grep -vxF -f <(git -c core.quotePath=false ls-files --deleted) > "$paths" || true
  # shellcheck disable=SC2094 # both commands only read the file
  git hash-object --stdin-paths < "$paths" | paste - "$paths"
  rm -f "$paths"
}

record() {
  mkdir -p target
  list_build_inputs > "$INPUTS_FILE"
  echo "Recorded $(wc -l < "$INPUTS_FILE" | tr -d ' ') build inputs"
}

mark() {
  if [ ! -f "$INPUTS_FILE" ]; then
    echo "No record of the cached build's inputs, building all workspace crates."
    return
  fi

  local current changed count
  current=$(mktemp)
  changed=$(mktemp)
  list_build_inputs > "$current"

  # A file is changed if it is new or its content differs from the recorded list.
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
}

case "${1:-}" in
  record) record ;;
  mark) mark ;;
  *)
    echo "Usage: $0 record|mark" >&2
    exit 2
    ;;
esac
