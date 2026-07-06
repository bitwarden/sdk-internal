#!/bin/sh
# Fixture: reads the JSON payload from stdin, extracts the "EXIT_CODE" field
# from the credentials map, and exits with that code.
#
# Usage (invoked by the daemon as):  exit_code.sh <operation>
#
# The payload credentials map must contain:
#   "EXIT_CODE": "<integer>"
#
# This lets tests drive any exit-code path through the custom-script integration.

set -e

payload=$(cat)

code=$(printf '%s' "$payload" \
    | grep -o '"EXIT_CODE"[[:space:]]*:[[:space:]]*"[^"]*"' \
    | sed 's/"EXIT_CODE"[[:space:]]*:[[:space:]]*"\([^"]*\)"/\1/')

if [ -z "$code" ]; then
    echo "exit_code.sh: EXIT_CODE not found in credentials" >&2
    exit 1
fi

exit "$code"
