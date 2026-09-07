#!/bin/sh
# Fixture: verifies the daemon passes credentials via stdin only.
#
# Checks the op name is the only arg and that newPassword never leaks into the environment;
# exits 0 on success, 1 otherwise.

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

# newPassword is absent for e.g. the terminate operation; that is fine.
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
