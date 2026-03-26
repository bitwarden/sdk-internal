#!/usr/bin/env bash
set -euo pipefail

# generate-diff.sh — Builds Kotlin bindings for both current and base branches,
# then produces a filtered API diff.
#
# Usage:
#   ./generate-diff.sh [--base-branch <branch>] [--dry-run]
#
# Options:
#   --base-branch <branch>  Branch to diff against (default: main)
#   --dry-run               Skip builds, assume bindings already exist at output paths.
#                           Expects /tmp/bindings-old/ and /tmp/bindings-new/ to be populated.
#
# Output:
#   /tmp/bindings-old/      Generated Kotlin bindings from the base branch
#   /tmp/bindings-new/      Generated Kotlin bindings from the current branch
#   /tmp/api-diff.txt       Filtered API diff (empty if no changes)
#   stdout                  The filtered diff (same content as /tmp/api-diff.txt)
#
# Exit codes:
#   0  Success (diff may be empty)
#   1  Build or generation failure
#
# Prerequisites:
#   - Rust toolchain with cargo
#   - uniffi-bindgen crate in workspace
#   - Must be run from the sdk-internal repo root

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
BASE_BRANCH="main"
DRY_RUN=false

# Detect shared library extension by platform
case "$(uname -s)" in
    Darwin) LIB_EXT="dylib" ;;
    Linux)  LIB_EXT="so" ;;
    *)      echo "ERROR: Unsupported platform $(uname -s)" >&2; exit 1 ;;
esac

while [[ $# -gt 0 ]]; do
    case "$1" in
        --base-branch) BASE_BRANCH="$2"; shift 2 ;;
        --dry-run)     DRY_RUN=true; shift ;;
        *)             echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

cd "$REPO_ROOT"

# --- Preflight checks ---
PREFLIGHT_FAILED=false

if ! command -v cargo &>/dev/null; then
    echo "ERROR: cargo not found. Install Rust via https://rustup.rs/" >&2
    PREFLIGHT_FAILED=true
fi

if ! command -v git &>/dev/null; then
    echo "ERROR: git not found. Install git: https://git-scm.com/downloads" >&2
    PREFLIGHT_FAILED=true
fi

if ! git rev-parse --is-inside-work-tree &>/dev/null; then
    echo "ERROR: Not inside a git repository. Run from the sdk-internal repo root." >&2
    PREFLIGHT_FAILED=true
fi

if [[ ! -f "$SCRIPT_DIR/extract-kotlin-api.sh" ]]; then
    echo "ERROR: extract-kotlin-api.sh not found at $SCRIPT_DIR/. Repo may be incomplete." >&2
    PREFLIGHT_FAILED=true
fi

if [[ "$DRY_RUN" == "false" ]]; then
    if ! git rev-parse "$BASE_BRANCH" &>/dev/null; then
        echo "ERROR: Base branch '$BASE_BRANCH' not found. Fetch it with: git fetch origin $BASE_BRANCH" >&2
        PREFLIGHT_FAILED=true
    fi

    if ! cargo metadata --format-version 1 2>/dev/null | grep -q '"name":"uniffi-bindgen"'; then
        echo "ERROR: uniffi-bindgen crate not found in workspace. Ensure Cargo.toml includes it." >&2
        PREFLIGHT_FAILED=true
    fi
fi

if [[ "$PREFLIGHT_FAILED" == "true" ]]; then
    echo "" >&2
    echo "Preflight checks failed. Fix the issues above and re-run." >&2
    exit 1
fi

# --- Helper: build bindings for a dylib ---
generate_bindings() {
    local dylib_path="$1"
    local out_dir="$2"

    rm -rf "$out_dir"
    cargo run -p uniffi-bindgen generate \
        "$dylib_path" \
        --library --language kotlin --no-format \
        --out-dir "$out_dir" 2>&1
}

if [[ "$DRY_RUN" == "true" ]]; then
    echo "=== Dry run: skipping builds ===" >&2
    if [[ ! -d /tmp/bindings-old ]] || [[ ! -d /tmp/bindings-new ]]; then
        echo "ERROR: --dry-run requires /tmp/bindings-old/ and /tmp/bindings-new/ to exist" >&2
        exit 1
    fi
else
    # --- Build current branch ---
    echo "=== Building current branch bindings ===" >&2
    cargo build -p bitwarden-uniffi --release 2>&1 | tail -3 >&2
    echo "=== Generating current branch Kotlin ===" >&2
    generate_bindings "./target/release/libbitwarden_uniffi.$LIB_EXT" /tmp/bindings-new >&2

    # --- Build base branch via worktree ---
    # Use --detach to avoid "branch already checked out" errors
    WORKTREE_DIR="/tmp/sdk-compat-worktree-$$"
    BASE_COMMIT=$(git rev-parse "$BASE_BRANCH")
    echo "=== Creating worktree for $BASE_BRANCH ($BASE_COMMIT) ===" >&2
    git worktree add --detach "$WORKTREE_DIR" "$BASE_COMMIT" 2>&1 >&2

    cleanup_worktree() {
        echo "=== Cleaning up worktree ===" >&2
        git worktree remove "$WORKTREE_DIR" 2>/dev/null || git worktree remove --force "$WORKTREE_DIR" 2>/dev/null || true
    }
    trap cleanup_worktree EXIT

    echo "=== Building $BASE_BRANCH bindings ===" >&2
    (cd "$WORKTREE_DIR" && cargo build -p bitwarden-uniffi --release 2>&1 | tail -3 >&2)
    echo "=== Generating $BASE_BRANCH Kotlin ===" >&2
    generate_bindings "$WORKTREE_DIR/target/release/libbitwarden_uniffi.$LIB_EXT" /tmp/bindings-old >&2
fi

# --- Diff ---
echo "=== Generating filtered API diff ===" >&2
bash "$SCRIPT_DIR/extract-kotlin-api.sh" /tmp/bindings-old /tmp/bindings-new > /tmp/api-diff.txt

# Report summary to stderr, output diff to stdout
OLD_COUNT=$(find /tmp/bindings-old -name "*.kt" -type f | wc -l | tr -d ' ')
NEW_COUNT=$(find /tmp/bindings-new -name "*.kt" -type f | wc -l | tr -d ' ')
DIFF_LINES=$(wc -l < /tmp/api-diff.txt | tr -d ' ')

echo "=== Summary ===" >&2
echo "  Base branch Kotlin files: $OLD_COUNT" >&2
echo "  Current branch Kotlin files: $NEW_COUNT" >&2
echo "  Diff lines: $DIFF_LINES" >&2

if [[ "$DIFF_LINES" -eq 0 ]]; then
    echo "  Result: No API changes detected" >&2
    echo "" >&2
    echo "=== Next Steps ===" >&2
    echo "No API changes detected. No further action needed." >&2
    echo "If you expected changes, verify that the UniFFI source was modified (crates/bitwarden-uniffi/)." >&2
else
    echo "  Result: API changes detected" >&2
    echo "" >&2
    echo "=== Next Steps ===" >&2
    echo "1. The filtered API diff is at /tmp/api-diff.txt (also printed to stdout below)." >&2
    echo "2. Full generated Kotlin bindings are at /tmp/bindings-old/ (base) and /tmp/bindings-new/ (current)." >&2
    echo "3. Spawn the sdk-android-analyst agent to classify changes and cross-reference Android usage." >&2
    echo "   Pass it: the diff at /tmp/api-diff.txt, and optionally an android_repo_path for compilation checks." >&2
    echo "4. After the analyst produces sdk-impact-report.md, present the summary to the user." >&2
fi

cat /tmp/api-diff.txt
