#!/usr/bin/env bash
#
# Verifies that cargo-run-bin will NOT use cargo-binstall to fetch tool binaries.
#
# cargo-run-bin uses binstall when EITHER:
#   1. A `binstall` alias is defined in .cargo/config.toml at the project root, OR
#   2. `cargo-binstall` is available on PATH.
#
# We require source installs from crates.io so the tools we run match the source
# we audit. See VULN-613 for the dependency review of cargo-run-bin and the
# explicit caveat against enabling binstall.
#
# Exits 0 if neither path would trigger binstall. Exits 1 if the repo defines a
# binstall alias (always blocking). In CI (GITHUB_ACTIONS=true) also exits 1 if
# `cargo-binstall` is on PATH; locally, prints a warning instead — devs may have
# binstall installed on their own machines and we don't try to police that.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$REPO_ROOT/.cargo/config.toml"
fail=0

# Match both inline form (`binstall = "..."`) and table form (`[alias.binstall]`)
# under the `[alias]` section.
if [[ -f "$CONFIG" ]] && grep -qE '^\s*(binstall\s*=|\[alias\.binstall\])' "$CONFIG"; then
  echo "ERROR: .cargo/config.toml defines a 'binstall' alias." >&2
  echo "       cargo-run-bin would use cargo-binstall to fetch pre-built tool binaries" >&2
  echo "       from third-party mirrors (QuickInstall) instead of building from crates.io" >&2
  echo "       sources. Remove the alias. See VULN-613 for context." >&2
  fail=1
fi

if command -v cargo-binstall >/dev/null 2>&1; then
  msg="cargo-binstall is on PATH; cargo-run-bin will use it to fetch pre-built tool binaries"
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    echo "ERROR: $msg." >&2
    echo "       CI must build tools from source. Do not install cargo-binstall on the runner." >&2
    echo "       See VULN-613 for context." >&2
    fail=1
  else
    echo "WARN: $msg (your local machine)." >&2
    echo "      CI builds tools from source, but your local 'cargo bin' invocations will use binstall." >&2
  fi
fi

exit $fail
