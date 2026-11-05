#!/usr/bin/env bash
# Builds bitwarden-uniffi for the host, generates Kotlin bindings for the JVM, and runs the
# e2e tests against them. Extra arguments are passed to Gradle, for example
# `./run.sh --tests '*PinLockTests*'`.
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"

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

LIB_DIR="$REPO_ROOT/target/$PROFILE"
BINDINGS_DIR="build/generated/uniffi"
CONFIG_FILE="build/uniffi-jvm.toml"

# 1. Build the host library
(cd "$REPO_ROOT" && cargo build --package bitwarden-uniffi $PROFILE_FLAG)

# 2. Turn off `android` for every crate that sets it. The Android cleaner it selects uses
# Android-only APIs, which a desktop JVM does not have.
mkdir -p build
: > "$CONFIG_FILE"
while IFS= read -r config; do
  crate_dir="$(dirname "$config")"
  crate_name="$(sed -n 's/^name = "\(.*\)"$/\1/p' "$crate_dir/Cargo.toml" | head -n 1)"
  printf '[crates.%s.bindings.kotlin]\nandroid = false\n\n' "${crate_name//-/_}" >> "$CONFIG_FILE"
done < <(grep -rl --include=uniffi.toml '^android = true' "$REPO_ROOT/crates" "$REPO_ROOT/bitwarden_license")

# 3. Generate the bindings
rm -rf "$BINDINGS_DIR"
(cd "$REPO_ROOT" && cargo run -p uniffi-bindgen generate \
  "$LIB_DIR/libbitwarden_uniffi.$LIB_EXT" \
  --language kotlin \
  --no-format \
  --config "$OLDPWD/$CONFIG_FILE" \
  --out-dir "$OLDPWD/$BINDINGS_DIR")

if grep -rqE '^import androidx?\.|android\.system\.' "$BINDINGS_DIR"; then
  echo "The generated bindings still use Android APIs" >&2
  exit 1
fi

# 4. Run the tests
"$REPO_ROOT/crates/bitwarden-uniffi/kotlin/gradlew" test -PuniffiLibDir="$LIB_DIR" "$@"
