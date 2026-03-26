# Android Breaking Change Detection

Detects and analyzes breaking changes in the SDK's Kotlin (UniFFI) API surface before they reach the
Android repo.

## Quick Start

### Check your current branch

From the sdk-internal repo root:

```bash
# Full build + diff + analysis (takes ~2-3 min for builds)
/check-android-compat

# With a local Android repo for cross-referencing usage
/check-android-compat /path/to/bitwarden/android

# Skip builds, reuse bindings from a previous run
/check-android-compat --dry-run
```

### Test against a specific PR

```bash
# Diff only (no Claude analysis)
bash .claude/skills/check-android-compat/scripts/test-pr.sh 832 --diff-only

# Full analysis with Android cross-reference
bash .claude/skills/check-android-compat/scripts/test-pr.sh 832 \
  --android-repo /path/to/bitwarden/android

# Custom base branch
bash .claude/skills/check-android-compat/scripts/test-pr.sh 832 --base-branch develop
```

### Just the diff (no Claude)

```bash
# Build both branches and diff
bash .claude/skills/check-android-compat/scripts/generate-diff.sh

# Diff against a specific base
bash .claude/skills/check-android-compat/scripts/generate-diff.sh --base-branch develop

# Reuse existing /tmp/bindings-{old,new}/
bash .claude/skills/check-android-compat/scripts/generate-diff.sh --dry-run
```

## How It Works

1. **`generate-diff.sh`** builds `bitwarden-uniffi` natively for both the current branch and the
   merge-base with main, generates Kotlin bindings via `uniffi-bindgen`, then runs a filtered diff
   that strips UniFFI internals (FfiConverters, checksums, init ordering).

2. **`extract-kotlin-api.sh`** is the filter — it diffs two directories of `.kt` files and removes
   noise lines so only public API changes remain.

3. **`sdk-android-analyst`** (Claude agent) reads the filtered diff, cross-references Android usage
   (local repo or via `gh api`), classifies each change (BREAKING-COMPILE, BREAKING-BEHAVIORAL,
   ADDITIVE, REQUIRES-ATTENTION), and produces `sdk-impact-report.md`.

4. **`test-pr.sh`** wraps the whole flow for testing against merged PRs: fetches by number, resolves
   the merge-base, builds both sides, runs the diff, and invokes the analyst with streaming output.

## Output

- `/tmp/api-diff.txt` — filtered API diff
- `/tmp/bindings-old/` — merge-base Kotlin bindings
- `/tmp/bindings-new/` — current branch Kotlin bindings
- `./sdk-impact-report.md` — full impact report (when analyst runs)

## Prerequisites

- **Rust toolchain** with `cargo`
- **`uniffi-bindgen`** crate in the workspace (already included)
- **`gh` CLI** (for `test-pr.sh` only)
- **`claude` CLI** (for `test-pr.sh` without `--diff-only`)
- **`jq`** (for `stream-format.sh`)

## Scripts

| Script                  | Purpose                                                          |
| ----------------------- | ---------------------------------------------------------------- |
| `generate-diff.sh`      | Builds both branches, generates bindings, produces filtered diff |
| `extract-kotlin-api.sh` | Filters UniFFI noise from raw `.kt` file diffs                   |
| `test-pr.sh`            | End-to-end test harness for a specific PR number                 |
| `stream-format.sh`      | Formats Claude's stream-json output for terminal display         |

## Troubleshooting

**Build fails silently during `test-pr.sh`**: The Kirby spinner suppresses build output. Re-run the
cargo build manually to see errors:

```bash
cargo build -p bitwarden-uniffi --release
```

**Empty diff when changes expected**: The diff uses `git merge-base` to compare against the common
ancestor with main. If your changes haven't touched UniFFI-exposed crates, the generated Kotlin will
be identical. Check that your Rust changes are in `crates/bitwarden-uniffi/` or in crates it
re-exports.

**`uniffi-bindgen` not found**: Ensure you're running from the sdk-internal repo root. The bindgen
tool is a workspace member invoked via `cargo run -p uniffi-bindgen`.

**Linux vs macOS**: The scripts detect the platform and use `.so` (Linux) or `.dylib` (macOS)
automatically.
