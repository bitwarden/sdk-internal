#!/usr/bin/env bash
# Builds bitwarden-uniffi for the host and generates Kotlin bindings for a desktop JVM, for the e2e
# tests in e2e/kotlin. Writes the bindings to jvm/bindings and the native library to jvm/lib.
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../../.. && pwd)"

if [[ "${DEBUG_MODE:-true}" = "true" ]]; then
  PROFILE="debug"
  PROFILE_FLAG=""
else
  PROFILE="release"
  PROFILE_FLAG="--release"
fi

case "$(uname -s)" in
  Darwin) LIB_EXT="dylib" ;;
  Linux) LIB_EXT="so" ;;
  *) echo "Unsupported host: $(uname -s)" >&2; exit 1 ;;
esac

OUT_DIR="$PWD/jvm"
BINDINGS_DIR="$OUT_DIR/bindings"
LIB_DIR="$OUT_DIR/lib"
CONFIG_FILE="$OUT_DIR/uniffi-jvm.toml"
LIB_FILE="libbitwarden_uniffi.$LIB_EXT"

rm -rf "$OUT_DIR"
mkdir -p "$LIB_DIR"

# 1. Build the host library
(cd "$REPO_ROOT" && cargo build --package bitwarden-uniffi $PROFILE_FLAG)
cp "$REPO_ROOT/target/$PROFILE/$LIB_FILE" "$LIB_DIR/"

# 2. Turn off `android` for every crate that sets it. The Android cleaner it selects uses
# Android-only APIs, which a desktop JVM does not have.
: > "$CONFIG_FILE"
while IFS= read -r config; do
  crate_dir="$(dirname "$config")"
  crate_name="$(sed -n 's/^name = "\(.*\)"$/\1/p' "$crate_dir/Cargo.toml" | head -n 1)"
  printf '[crates.%s.bindings.kotlin]\nandroid = false\n\n' "${crate_name//-/_}" >> "$CONFIG_FILE"
done < <(grep -rl --include=uniffi.toml '^android = true' "$REPO_ROOT/crates" "$REPO_ROOT/bitwarden_license")

# 3. Generate the bindings
(cd "$REPO_ROOT" && cargo run -p uniffi-bindgen generate \
  "$LIB_DIR/$LIB_FILE" \
  --language kotlin \
  --no-format \
  --config "$CONFIG_FILE" \
  --out-dir "$BINDINGS_DIR")

if grep -rqE '^import androidx?\.|android\.system\.' "$BINDINGS_DIR"; then
  echo "The generated bindings still use Android APIs" >&2
  exit 1
fi
