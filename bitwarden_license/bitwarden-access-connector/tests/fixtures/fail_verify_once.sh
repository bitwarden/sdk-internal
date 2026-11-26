#!/bin/sh
# Fixture: reads stdin's JSON and writes the full payload to "<OUT_PATH>.<operation>" (each run
# overwrites the previous one). The first "verify" exits 1 and leaves the marker file
# "<OUT_PATH>.verify_failed"; every later run of any operation exits 0.
# Invoked as: fail_verify_once.sh <operation>

payload=$(cat)

# Basic POSIX tools only; prints the credential's value, or nothing when it is absent.
credential() {
    printf '%s' "$payload" \
        | grep -o "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
        | sed "s/\"$1\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\"/\\1/"
}

out_path=$(credential OUT_PATH)
if [ -z "$out_path" ]; then
    echo "fail_verify_once.sh: OUT_PATH not found in credentials" >&2
    exit 1
fi

printf '%s' "$payload" > "$out_path.$1"

if [ "$1" = "verify" ] && [ ! -e "$out_path.verify_failed" ]; then
    : > "$out_path.verify_failed"
    exit 1
fi

exit 0
