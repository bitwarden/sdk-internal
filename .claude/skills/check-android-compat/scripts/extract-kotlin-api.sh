#!/usr/bin/env bash
set -euo pipefail

# extract-kotlin-api.sh — Diffs the public API surface of generated UniFFI Kotlin bindings.
#
# Strategy: Instead of parsing Kotlin (fragile), we diff the raw generated files
# and filter out UniFFI internal noise. Whatever remains IS the API change.
#
# Usage:
#   ./extract-kotlin-api.sh <old-dir> <new-dir>
#
# Output: Filtered unified diff showing only public API changes.

# --- Noise filter ---
# Strips lines that are UniFFI internals, not public API.
# Applied to each .kt file before diffing so ordering/whitespace noise vanishes.
filter_noise() {
    grep -v -E \
        -e '^\s*$' \
        -e 'uniffiEnsureInitialized' \
        -e '^fun uniffi_' \
        -e 'uniffi_bitwarden_uniffi_checksum' \
        -e 'uniffi_bitwarden_uniffi_fn_' \
        -e 'UniffiLib\.INSTANCE\.uniffi_' \
        -e 'FfiConverter[A-Z]' \
        -e 'RustBuffer' \
        -e 'RustCallStatus' \
        -e 'UniffiRustCall' \
        -e 'UniffiHandleMap' \
        -e 'UniffiCleaner' \
        -e 'uniffiRustCall' \
        -e 'UniffiWithHandle' \
        -e 'uniffi_out_err' \
        -e 'callWithHandle' \
        -e '^\): (Short|RustBuffer)' \
        -e '@Suppress' \
        -e '@Structure' \
        -e 'NoHandle' \
        -e 'InternalException' \
        -e 'checksum.*mismatch' \
        -e '\.toShort\(\)' \
        -e 'uniffiCleanable' \
        -e 'Pointer\.NULL' \
    | cat  # prevent grep exit code 1 on no match
}

# --- Main ---
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <old-dir> <new-dir>" >&2
    echo "       $0 --test" >&2
    exit 1
fi

OLD_DIR="$1"
NEW_DIR="$2"

if [[ ! -d "$OLD_DIR" ]]; then
    echo "ERROR: Old directory not found: $OLD_DIR" >&2
    exit 1
fi
if [[ ! -d "$NEW_DIR" ]]; then
    echo "ERROR: New directory not found: $NEW_DIR" >&2
    exit 1
fi

TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

mkdir -p "$TEMP_DIR/old" "$TEMP_DIR/new"

# Process each .kt file: normalize and filter noise
process_dir() {
    local src_dir="$1"
    local dest_dir="$2"

    while IFS= read -r kt_file; do
        # Relative path from source dir
        local rel_path="${kt_file#$src_dir/}"
        local dest_file="$dest_dir/$rel_path"
        mkdir -p "$(dirname "$dest_file")"

        # Filter noise, normalize whitespace runs
        filter_noise < "$kt_file" > "$dest_file"
    done < <(find "$src_dir" -name "*.kt" -type f | sort)
}

process_dir "$OLD_DIR" "$TEMP_DIR/old"
process_dir "$NEW_DIR" "$TEMP_DIR/new"

# Diff the filtered trees
# Use --unified=3 for context, suppress common-only messages
diff -ruN "$TEMP_DIR/old" "$TEMP_DIR/new" \
    | sed "s|$TEMP_DIR/old|a|g; s|$TEMP_DIR/new|b|g" \
    || true
