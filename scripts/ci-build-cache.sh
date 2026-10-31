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
# Paths are read NUL-separated so they are never quoted or split. `git hash-object --stdin-paths`
# reads one path per line, so a path containing a newline can't be listed: fail in that case.
list_build_inputs() {
  local paths
  paths=$(mktemp)
  git ls-files -z --cached | while IFS= read -r -d '' path; do
    if [ -e "$path" ] || [ -L "$path" ]; then
      printf '%s\0' "$path"
    fi
  done > "$paths"
  if [ "$(tr -cd '\n' < "$paths" | wc -c)" -gt 0 ]; then
    echo "A tracked path contains a newline, can't record build inputs." >&2
    rm -f "$paths"
    return 1
  fi
  # Checked explicitly: callers run this in an `if`, where `set -e` does not apply.
  if ! tr '\0' '\n' < "$paths" | git hash-object --stdin-paths | paste - <(tr '\0' '\n' < "$paths"); then
    rm -f "$paths"
    return 1
  fi
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

  local recorded current changed count
  recorded=$(mktemp)
  current=$(mktemp)
  changed=$(mktemp)
  # The record only describes the restored build output. Remove it, so a cache saved later without
  # a fresh record makes the next run rebuild everything instead of trusting an old record.
  mv "$INPUTS_FILE" "$recorded"

  if ! list_build_inputs > "$current"; then
    echo "Building all workspace crates."
    rm -f "$recorded" "$current" "$changed"
    return
  fi

  # A file is changed if it is new or its content differs from the recorded list. The hash is
  # everything before the first tab, the path everything after it.
  awk 'NR == FNR { i = index($0, "\t"); recorded[substr($0, i + 1)] = substr($0, 1, i - 1); next }
    { i = index($0, "\t"); path = substr($0, i + 1); if (recorded[path] != substr($0, 1, i - 1)) print path }' \
    "$recorded" "$current" > "$changed"

  git ls-files -z | xargs -0 touch -h -c -t 200001010000 --

  count=$(wc -l < "$changed" | tr -d ' ')
  echo "Files changed since the cached build: $count"
  if [ "$count" -gt 0 ]; then
    tr '\n' '\0' < "$changed" | xargs -0 touch -h -c --
    head -50 "$changed"
  fi
  rm -f "$recorded" "$current" "$changed"
}

case "${1:-}" in
  record) record ;;
  mark) mark ;;
  *)
    echo "Usage: $0 record|mark" >&2
    exit 2
    ;;
esac
