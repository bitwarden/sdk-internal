#!/usr/bin/env bash
set -euo pipefail

# test-pr.sh — End-to-end test of the Android breaking change detection pipeline.
# Fetches a PR, builds bindings for both its head and merge-base, generates the
# filtered API diff, then invokes Claude to run the sdk-android-analyst agent.
#
# Usage:
#   ./test-pr.sh <pr-number> [--base-branch <branch>] [--diff-only] [--android-repo <path>]
#
# Options:
#   --base-branch <branch>      Branch the PR targets (default: main)
#   --diff-only                 Stop after generating the diff, don't invoke analyst
#   --android-repo <path>       Path to local bitwarden/android checkout for cross-referencing
#
# Output:
#   /tmp/api-diff.txt           Filtered API diff
#   /tmp/bindings-{old,new}/    Generated Kotlin bindings
#   ./sdk-impact-report.md      Impact report (unless --diff-only)
#
# Prerequisites:
#   - gh CLI authenticated
#   - claude CLI (unless --diff-only)
#   - Rust toolchain with cargo
#   - Must be run from the sdk-internal repo root

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
BASE_BRANCH="main"
DIFF_ONLY=false
ANDROID_REPO=""

if [[ $# -lt 1 ]] || [[ "$1" == --* ]]; then
    echo "Usage: $0 <pr-number> [--base-branch <branch>] [--diff-only] [--android-repo <path>]" >&2
    exit 1
fi

PR_NUMBER="$1"
shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        --base-branch)  BASE_BRANCH="$2"; shift 2 ;;
        --diff-only)    DIFF_ONLY=true; shift ;;
        --android-repo) ANDROID_REPO="$2"; shift 2 ;;
        *)              echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

cd "$REPO_ROOT"

# --- Kirby dance spinner ---
# Runs a background animation while a command executes
KIRBY_PID=""
kirby_start() {
    local msg="$1"
    local mode="${2:-build}"
    local R=$'\033[0m'
    local colors=(
        $'\033[38;5;213m'  # pink
        $'\033[38;5;51m'   # cyan
        $'\033[38;5;201m'  # magenta
        $'\033[38;5;226m'  # yellow
        $'\033[38;5;46m'   # green
        $'\033[38;5;196m'  # red
        $'\033[38;5;99m'   # purple
        $'\033[38;5;208m'  # orange
    )
    local kirby_build=("(>'-')>" "<('-'<)" "(>'-')>" "^('-')^")
    local kirby_think=("(  'o')>" "( 'o' )?" "<('o'  )" "( 'o' )>")
    (
        i=0
        nc=${#colors[@]}
        while true; do
            local C="${colors[$((i % nc))]}"
            if [[ "$mode" == "think" ]]; then
                printf "\r  ${C}%s${R} %s " "${kirby_think[$((i % 4))]}" "$msg" >&2
            else
                printf "\r  ${C}%s${R} %s " "${kirby_build[$((i % 4))]}" "$msg" >&2
            fi
            i=$((i + 1))
            sleep 0.3
        done
    ) &
    KIRBY_PID=$!
}
kirby_stop() {
    if [[ -n "$KIRBY_PID" ]]; then
        kill "$KIRBY_PID" 2>/dev/null
        wait "$KIRBY_PID" 2>/dev/null || true
        printf "\r\033[K" >&2
        KIRBY_PID=""
    fi
}
kirby_ded() {
    if [[ -n "$KIRBY_PID" ]]; then
        kill "$KIRBY_PID" 2>/dev/null
        wait "$KIRBY_PID" 2>/dev/null || true
        printf "\r  \033[38;5;213m(x_x)\033[0m Build failed.\n" >&2
        KIRBY_PID=""
    fi
}
kirby_celebrate() {
    printf "  ☆ﾟ.*･｡ﾟ \033[38;5;213m(>'o')>\033[0m ☆ﾟ.*･｡ﾟ\n" >&2
}

# Detect shared library extension by platform
case "$(uname -s)" in
    Darwin) LIB_EXT="dylib" ;;
    Linux)  LIB_EXT="so" ;;
    *)      echo "ERROR: Unsupported platform $(uname -s)" >&2; exit 1 ;;
esac

# --- Preflight ---
PREFLIGHT_FAILED=false

if ! command -v gh &>/dev/null; then
    echo "ERROR: gh CLI not found. Install: https://cli.github.com/" >&2
    PREFLIGHT_FAILED=true
fi

if ! command -v cargo &>/dev/null; then
    echo "ERROR: cargo not found. Install Rust via https://rustup.rs/" >&2
    PREFLIGHT_FAILED=true
fi

if [[ "$DIFF_ONLY" == "false" ]] && ! command -v claude &>/dev/null; then
    echo "ERROR: claude CLI not found. Install: https://docs.anthropic.com/en/docs/claude-code" >&2
    echo "       Or use --diff-only to skip the analyst step." >&2
    PREFLIGHT_FAILED=true
fi

if ! git rev-parse --is-inside-work-tree &>/dev/null; then
    echo "ERROR: Not inside a git repository. Run from the sdk-internal repo root." >&2
    PREFLIGHT_FAILED=true
fi

if [[ "$PREFLIGHT_FAILED" == "true" ]]; then
    echo "" >&2
    echo "Preflight checks failed. Fix the issues above and re-run." >&2
    exit 1
fi

# --- Fetch PR ---
PR_REF="pr-${PR_NUMBER}-test"
echo "=== Fetching PR #${PR_NUMBER} ===" >&2
git fetch origin "pull/${PR_NUMBER}/head:${PR_REF}" >/dev/null 2>&1

cleanup() {
    kirby_ded
    echo "=== Cleaning up ===" >&2
    git worktree remove "$WORKTREE_PR" 2>/dev/null || git worktree remove --force "$WORKTREE_PR" 2>/dev/null || true
    git worktree remove "$WORKTREE_BASE" 2>/dev/null || git worktree remove --force "$WORKTREE_BASE" 2>/dev/null || true
    git branch -D "$PR_REF" 2>/dev/null || true
}
trap cleanup EXIT

# --- Resolve merge base ---
MERGE_BASE=$(git merge-base "$PR_REF" "$BASE_BRANCH")
PR_HEAD=$(git rev-parse "$PR_REF")
echo "  PR head:    $PR_HEAD" >&2
echo "  Merge base: $MERGE_BASE" >&2

# --- Build PR head bindings ---
WORKTREE_PR="/tmp/sdk-test-pr${PR_NUMBER}-head-$$"
git worktree add --detach "$WORKTREE_PR" "$PR_HEAD" >/dev/null 2>&1
kirby_start "Building PR #${PR_NUMBER} head"
(cd "$WORKTREE_PR" && cargo build -p bitwarden-uniffi --release >/dev/null 2>&1)
kirby_stop
echo "=== Built PR head ===" >&2

rm -rf /tmp/bindings-new
kirby_start "Generating PR head Kotlin bindings"
cargo run -p uniffi-bindgen generate \
    "$WORKTREE_PR/target/release/libbitwarden_uniffi.$LIB_EXT" \
    --library --language kotlin --no-format \
    --out-dir /tmp/bindings-new/ >/dev/null 2>&1
kirby_stop
echo "=== Generated PR head bindings ($(find /tmp/bindings-new -name '*.kt' -type f | wc -l | tr -d ' ') Kotlin files) ===" >&2

# --- Build merge-base bindings ---
WORKTREE_BASE="/tmp/sdk-test-pr${PR_NUMBER}-base-$$"

git worktree add --detach "$WORKTREE_BASE" "$MERGE_BASE" >/dev/null 2>&1
kirby_start "Building merge-base"
(cd "$WORKTREE_BASE" && cargo build -p bitwarden-uniffi --release >/dev/null 2>&1)
kirby_stop
echo "=== Built merge-base ===" >&2

rm -rf /tmp/bindings-old
kirby_start "Generating merge-base Kotlin bindings"
cargo run -p uniffi-bindgen generate \
    "$WORKTREE_BASE/target/release/libbitwarden_uniffi.$LIB_EXT" \
    --library --language kotlin --no-format \
    --out-dir /tmp/bindings-old/ >/dev/null 2>&1
kirby_stop
echo "=== Generated merge-base bindings ($(find /tmp/bindings-old -name '*.kt' -type f | wc -l | tr -d ' ') Kotlin files) ===" >&2

# --- Run filtered diff ---
echo "=== Running filtered diff ===" >&2
bash "$SCRIPT_DIR/generate-diff.sh" --dry-run

if [[ "$DIFF_ONLY" == "true" ]]; then
    exit 0
fi

# Check if diff is empty
if [[ ! -s /tmp/api-diff.txt ]]; then
    echo "No API changes detected. Nothing to analyze." >&2
    exit 0
fi

# --- Invoke Claude analyst ---
# Pass PR metadata explicitly so the analyst doesn't infer from the working directory
PR_TITLE=$(gh pr view "$PR_NUMBER" --json title --jq '.title' 2>/dev/null || echo "PR #${PR_NUMBER}")

ANALYST_PROMPT="Analyze the API diff at /tmp/api-diff.txt for SDK PR #${PR_NUMBER} (\"${PR_TITLE}\").
PR head: ${PR_HEAD}
Merge base: ${MERGE_BASE}
Base branch: ${BASE_BRANCH}
The generated Kotlin bindings are at /tmp/bindings-old/ (merge-base) and /tmp/bindings-new/ (PR head)."

if [[ -n "$ANDROID_REPO" ]]; then
    ANALYST_PROMPT="$ANALYST_PROMPT Cross-reference Android usage at $ANDROID_REPO."
fi

ANALYST_PROMPT="$ANALYST_PROMPT Produce sdk-impact-report.md following the template at .claude/skills/check-android-compat/templates/impact-report.md. Report your full findings."

rm -f ./sdk-impact-report.md
echo "=== Invoking Claude sdk-android-analyst ===" >&2
echo "" >&2
echo "$ANALYST_PROMPT" | claude -p \
    --output-format stream-json \
    --agent sdk-android-analyst \
    --allowedTools "Bash,Read,Write,Glob,Grep,WebFetch" \
    | bash "$SCRIPT_DIR/stream-format.sh"

echo "" >&2
kirby_celebrate
echo "=== Done ===" >&2
echo "Impact report: ./sdk-impact-report.md" >&2
