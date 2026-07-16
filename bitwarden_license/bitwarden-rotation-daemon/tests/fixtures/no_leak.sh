#!/bin/sh
# Fixture: verifies that the daemon passes credentials via stdin only.
#
# Checks:
#  1. The first (and only) argument is the operation name (no extra args).
#  2. The newPassword value from the stdin payload does NOT appear in any
#     process environment variable.
#
# Exit 0 = both checks passed (no leakage detected).
# Exit 1 = leak or unexpected args detected.
#
# The test injects a known sentinel as newPassword.  If that sentinel appears
# in the process environment, something passed it via argv or env — a bug.

set -e

# Check argument count: only one arg allowed (the operation).
if [ "$#" -ne 1 ]; then
    echo "no_leak.sh: expected exactly 1 arg, got $#: $*" >&2
    exit 1
fi

# Read stdin payload.
payload=$(cat)

# Extract newPassword from the payload.
password=$(printf '%s' "$payload" \
    | grep -o '"newPassword"[[:space:]]*:[[:space:]]*"[^"]*"' \
    | sed 's/"newPassword"[[:space:]]*:[[:space:]]*"\([^"]*\)"/\1/')

# If newPassword is absent (e.g. terminate operation), that is fine.
if [ -z "$password" ]; then
    exit 0
fi

# Scan our environment for the password value.
if env | grep -qF "$password"; then
    echo "no_leak.sh: newPassword found in environment — LEAK DETECTED" >&2
    exit 1
fi

# Verify that the daemon token is not inherited by child processes.
if env | grep -q '^BWRD_TOKEN='; then
    echo "no_leak.sh: BWRD_TOKEN found in environment" >&2
    exit 1
fi

exit 0
