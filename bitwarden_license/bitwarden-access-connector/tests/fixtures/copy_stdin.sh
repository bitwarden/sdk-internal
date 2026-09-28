#!/bin/sh
# Fixture: reads stdin's JSON, extracts "OUT_PATH" from the credentials map, and writes the
# full stdin payload there. Invoked as: copy_stdin.sh <operation>

set -e

# Read all of stdin.
payload=$(cat)

# Extract OUT_PATH from the credentials map using basic POSIX tools.
# The value is on a line like: "OUT_PATH": "/some/path"
out_path=$(printf '%s' "$payload" \
    | grep -o '"OUT_PATH"[[:space:]]*:[[:space:]]*"[^"]*"' \
    | sed 's/"OUT_PATH"[[:space:]]*:[[:space:]]*"\([^"]*\)"/\1/')

if [ -z "$out_path" ]; then
    echo "copy_stdin.sh: OUT_PATH not found in credentials" >&2
    exit 1
fi

printf '%s' "$payload" > "$out_path"
exit 0
