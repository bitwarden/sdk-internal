#!/bin/sh
# Fixture: reads stdin's JSON, extracts "EXIT_CODE" from the credentials map, and exits with
# that code (invoked as `exit_code.sh <operation>`), letting tests drive any exit path.

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
