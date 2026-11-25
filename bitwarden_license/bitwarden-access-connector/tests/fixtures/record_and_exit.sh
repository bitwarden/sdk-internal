#!/bin/sh
# Fixture: reads stdin's JSON and writes the full payload to "<OUT_PATH>.<operation>", then exits
# with the credential "EXIT_CODE_<OPERATION>" (operation upper-cased), else "EXIT_CODE", else 0.
# Invoked as: record_and_exit.sh <operation>

payload=$(cat)

# Basic POSIX tools only; prints the credential's value, or nothing when it is absent.
credential() {
    printf '%s' "$payload" \
        | grep -o "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
        | sed "s/\"$1\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\"/\\1/"
}

out_path=$(credential OUT_PATH)
if [ -z "$out_path" ]; then
    echo "record_and_exit.sh: OUT_PATH not found in credentials" >&2
    exit 1
fi

printf '%s' "$payload" > "$out_path.$1"

case "$1" in
    rotate) operation=ROTATE ;;
    verify) operation=VERIFY ;;
    terminate) operation=TERMINATE ;;
    *) operation=UNKNOWN ;;
esac

code=$(credential "EXIT_CODE_$operation")
if [ -z "$code" ]; then
    code=$(credential EXIT_CODE)
fi

exit "${code:-0}"
