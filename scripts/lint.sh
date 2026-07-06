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

require_cargo_bin() {
  if ! command -v cargo-bin >/dev/null 2>&1; then
    echo "Required tool not found on PATH: cargo-bin" >&2
    echo "Install with: cargo install cargo-run-bin --locked" >&2
    echo "(Binary tool versions are pinned in Cargo.toml under [workspace.metadata.bin].)" >&2
    exit 1
  fi
  # Guard against cargo-run-bin falling through to cargo-binstall. Source installs
  # only; see VULN-613.
  "$REPO_ROOT/scripts/check-no-binstall.sh"
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
  require_cargo_bin
  if (( FIX )); then
    cargo bin cargo-sort --workspace --grouped
  else
    cargo bin cargo-sort --workspace --grouped --check
  fi
}

run_udeps() {
  require_cargo_bin
  cargo "+$RUST_NIGHTLY_TOOLCHAIN" bin cargo-udeps --workspace --all-features
}

run_dylint() {
  require_cargo_bin
  # cargo-dylint invokes `dylint-link` as rustc's linker, found by name on PATH.
  # Running cargo-dylint through `cargo bin` doesn't work: cargo-run-bin prepends
  # a shim directory to PATH whose dylint-link shim re-runs `cargo bin
  # dylint-link`, which fails from the directories rustc links in (support/lints
  # and each dependency's source dir, none of which declare
  # [workspace.metadata.bin]). So build the tools and invoke cargo-dylint
  # directly with the real dylint-link binary on PATH, using an absolute path so
  # it resolves no matter which directory cargo-dylint links from.
  #
  # Build only the two tools dylint needs rather than `cargo bin --install`,
  # which builds every pinned tool (including some that don't compile on this
  # toolchain, e.g. cross). `cargo bin` builds a tool on first use; the throwaway
  # invocations below just trigger those builds (dylint-link has no safe no-op
  # invocation, so its run is allowed to fail; the builds are verified by the
  # `find`s that follow).
  cargo bin cargo-dylint --help >/dev/null
  cargo bin dylint-link --help >/dev/null 2>&1 || true

  local cargo_dylint dylint_link
  cargo_dylint="$(find "$REPO_ROOT/.bin" -type f -name cargo-dylint -not -path '*/.shims/*' -print -quit)"
  dylint_link="$(find "$REPO_ROOT/.bin" -type f -name dylint-link -not -path '*/.shims/*' -print -quit)"
  if [[ -z "$cargo_dylint" || -z "$dylint_link" ]]; then
    echo "Could not find cargo-dylint/dylint-link under .bin (build failed?)" >&2
    exit 1
  fi
  PATH="$(dirname "$dylint_link"):$PATH" "$cargo_dylint" dylint --all -- --all-features --all-targets
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
  # `--locked` makes cargo fail if Cargo.lock is out of sync with Cargo.toml.
  # Works in isolation (no prior cargo run needed), unlike `git diff Cargo.lock`.
  cargo metadata --locked --format-version 1 >/dev/null
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
