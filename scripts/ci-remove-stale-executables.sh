#!/usr/bin/env bash
# Deletes executables in the coverage build output that the current build did not produce.
#
# cargo-llvm-cov reads every executable under the target directory when it builds the report. A
# cached target directory can still hold test binaries from earlier builds, for example from before
# a dependency update changed their file names. Their coverage mappings describe older versions of
# the code, so they would add regions to the report that no longer exist.
#
# Usage: ci-remove-stale-executables.sh <cargo build output with --message-format=json>
set -euo pipefail

build_json=$1
target_dir=${CARGO_LLVM_COV_TARGET_DIR:-target}

keep=$(mktemp)
jq -r 'select(.reason == "compiler-artifact") | (.filenames[]?, (.executable // empty))' \
  "$build_json" | sort -u > "$keep"

# Cargo reports binaries at their uplifted path (target/debug/<name>), which is a hard link to or a
# copy of a file in deps/. Keep the deps/ file with identical content as well.
uplifted=$(mktemp)
while IFS= read -r file; do
  case "$file" in "$target_dir/debug/deps/"* | "$target_dir/debug/examples/"*) continue ;; esac
  [ -f "$file" ] || continue
  size=$(wc -c < "$file" | tr -d ' ')
  while IFS= read -r -d '' candidate; do
    if cmp -s "$file" "$candidate"; then
      echo "$candidate"
    fi
  done < <(find "$target_dir/debug/deps" -maxdepth 1 -type f -size "${size}c" -print0)
done < "$keep" > "$uplifted"
cat "$uplifted" >> "$keep"
rm -f "$uplifted"

removed=0
for dir in "$target_dir/debug/deps" "$target_dir/debug/examples"; do
  [ -d "$dir" ] || continue
  while IFS= read -r -d '' file; do
    if ! grep -qxF "$file" "$keep"; then
      rm -f "$file"
      removed=$((removed + 1))
    fi
  done < <(find "$dir" -maxdepth 1 -type f -perm -u+x -print0)
done
rm -f "$keep"
echo "Removed $removed executables not produced by this build"
