#!/usr/bin/env bash
#
# Unified lint/format runner for the Bitwarden SDK.
# Mirrors the checks in .github/workflows/lint.yml so local runs match CI.
#
# Usage:
#   scripts/lint.sh                Run every check (check-only).
#   scripts/lint.sh --fix          Auto-fix where supported; still run check-only tools.
#   scripts/lint.sh --only <name>  Run a single check. Composes with --fix.
#
# Available checks: fmt clippy sort udeps dylint doc prettier dep-ownership cargo-lock

set -euo pipefail

CHECKS=(fmt clippy sort udeps dylint doc prettier dep-ownership cargo-lock)

FIX=0
ONLY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fix) FIX=1; shift ;;
    --only) ONLY="${2:-}"; shift 2 ;;
    --only=*) ONLY="${1#*=}"; shift ;;
    -h|--help)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -n "$ONLY" ]]; then
  if ! printf '%s\n' "${CHECKS[@]}" | grep -qx -- "$ONLY"; then
    echo "Unknown check: $ONLY" >&2
    echo "Available: ${CHECKS[*]}" >&2
    exit 2
  fi
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Portable parse (BSD grep on macOS has no -P).
RUST_NIGHTLY_TOOLCHAIN="$(awk -F'"' '/^nightly-channel/ {print $2}' rust-toolchain.toml)"
if [[ -z "$RUST_NIGHTLY_TOOLCHAIN" ]]; then
  echo "Could not read nightly-channel from rust-toolchain.toml" >&2
  exit 1
fi

export RUSTFLAGS="-D warnings"
export RUSTDOCFLAGS="-D warnings"

section() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }

should_run() {
  [[ -z "$ONLY" || "$ONLY" == "$1" ]]
}

require_tool() {
  local tool="$1" install_hint="$2"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Required tool not found on PATH: $tool" >&2
    echo "Install with: $install_hint" >&2
    exit 1
  fi
}

run_fmt() {
  if (( FIX )); then
    cargo "+$RUST_NIGHTLY_TOOLCHAIN" fmt
  else
    cargo "+$RUST_NIGHTLY_TOOLCHAIN" fmt --check
  fi
}

run_clippy() {
  if (( FIX )); then
    cargo clippy --fix --allow-dirty --allow-staged --all-features --all-targets
  else
    cargo clippy --all-features --all-targets
  fi
}

run_sort() {
  require_tool cargo-sort "cargo install cargo-sort --locked"
  if (( FIX )); then
    cargo sort --workspace --grouped
  else
    cargo sort --workspace --grouped --check
  fi
}

run_udeps() {
  require_tool cargo-udeps "cargo install cargo-udeps --locked"
  cargo "+$RUST_NIGHTLY_TOOLCHAIN" udeps --workspace --all-features
}

run_dylint() {
  require_tool cargo-dylint "cargo install cargo-dylint dylint-link --locked"
  cargo dylint --all -- --all-features --all-targets
}

run_doc() {
  cargo doc --no-deps --all-features --document-private-items
}

run_prettier() {
  if (( FIX )); then
    npm run prettier
  else
    npm run lint:prettier
  fi
}

run_dep_ownership() {
  npm run lint:dep-ownership
}

run_cargo_lock() {
  # --fix may legitimately update Cargo.lock; skip the guard in that mode.
  if (( FIX )); then
    return 0
  fi
  if ! git diff --exit-code Cargo.lock; then
    echo "Error: Cargo.lock has been modified. Run \`cargo check\` and commit the change." >&2
    return 1
  fi
}

for check in "${CHECKS[@]}"; do
  should_run "$check" || continue
  section "$check"
  case "$check" in
    fmt) run_fmt ;;
    clippy) run_clippy ;;
    sort) run_sort ;;
    udeps) run_udeps ;;
    dylint) run_dylint ;;
    doc) run_doc ;;
    prettier) run_prettier ;;
    dep-ownership) run_dep_ownership ;;
    cargo-lock) run_cargo_lock ;;
  esac
done
