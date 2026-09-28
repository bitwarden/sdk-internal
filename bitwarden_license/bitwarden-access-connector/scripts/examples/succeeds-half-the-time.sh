#!/bin/sh
#
# Example rotation script: roughly half of all rotations fail. Rotates nothing.
#

set -eu

operation="${1:-}"

cat >/dev/null

[ "$operation" = "rotate" ] || exit 0

# Even or odd from the kernel CSPRNG, so parallel daemons do not correlate.
coin=$(od -An -N1 -tu1 </dev/urandom | tr -d ' ')
[ $((coin % 2)) -eq 0 ] || exit 1

exit 0
