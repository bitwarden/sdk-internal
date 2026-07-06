#!/bin/sh
# Fixture: reads the JSON payload from stdin, extracts the "OUT_PATH" field
# from the credentials map, and writes the full stdin payload to that path.
#
# Usage (invoked by the daemon as):  copy_stdin.sh <operation>
#
# The payload JSON is expected on stdin:
# {
#   "operation": "rotate",
#   "targetSystemId": "...",
#   "accountIdentity": "...",
#   "newPassword": "...",
#   "credentials": { "OUT_PATH": "/tmp/out.json", ... }
# }
#
# The script writes the payload to the file named by credentials.OUT_PATH.

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
