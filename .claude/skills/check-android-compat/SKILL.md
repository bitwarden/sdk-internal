---
name: check-android-compat
argument-hint: "[--dry-run] [--team] [/path/to/android/repo]"
description:
  Use this skill when the user asks to "check Android compatibility", "detect Android breaking
  changes", "check if SDK changes break Android", "analyze Android impact", "check-android-compat",
  or wants to understand how their SDK changes affect the bitwarden/android project. This skill
  extracts the Kotlin API surface from generated UniFFI bindings, diffs against the main branch,
  cross-references actual Android usage patterns, and produces a structured impact report.
allowed-tools: Bash, Read, Write, Glob, Grep, Agent, Skill, WebFetch, TeamCreate, SendMessage
---

# Check Android Compatibility

Detect and analyze breaking changes in the SDK's Android (Kotlin) API surface.

## Arguments

Parse the user's input for these arguments:

- `--dry-run`: Skip AAR build, assume bindings already exist from a prior build. Just run API
  extraction + diff + analysis.
- `--team`: Run the full four-agent team pipeline (analyst → architect → implementer → reviewer).
  Requires a local Android repo path.
- Path argument: Local path to a `bitwarden/android` checkout. If not provided, the skill will fetch
  Android source files via `gh api` for analysis (no compilation check).

## Quick Validation

Before doing anything, check if there are actually any Kotlin binding changes:

```bash
# Check if generated Kotlin files differ from main branch
KOTLIN_DIR="crates/bitwarden-uniffi/kotlin/sdk/src/main/java/com/bitwarden"
if git diff main --quiet -- "$KOTLIN_DIR" 2>/dev/null; then
  echo "No Kotlin binding changes detected vs main branch."
  echo "If you have uncommitted changes, make sure bindings have been regenerated."
fi
```

If no changes are detected AND it's a dry-run, inform the user and ask if they want to build first.

## Mode 1: Analysis Only (default, or `--dry-run`)

This is the default mode. It produces an impact report without modifying any code.

### Step 1: Build Bindings (unless --dry-run)

Build fresh Kotlin bindings. Prerequisites: Docker running, `cross` installed.

```bash
cd crates/bitwarden-uniffi/kotlin && bash publish-local.sh
```

This cross-compiles for arm64-v8a, generates Kotlin bindings via `build-schemas.sh`, and publishes
to local Maven (`~/.m2/repository`) as `com.bitwarden:sdk-android:LOCAL`.

### Step 2: Run API Extraction and Diff

```bash
SCRIPT=".claude/skills/check-android-compat/scripts/extract-kotlin-api.sh"
KOTLIN_DIR="crates/bitwarden-uniffi/kotlin/sdk/src/main/java/com/bitwarden"

# Extract current API
bash "$SCRIPT" "$KOTLIN_DIR" > /tmp/api-new.txt

# Extract main branch API
TEMP_OLD=$(mktemp -d)
for kt_file in $(find "$KOTLIN_DIR" -name "*.kt" -type f); do
  DEST="$TEMP_OLD/$(dirname "$kt_file")"
  mkdir -p "$DEST"
  git show "main:$kt_file" > "$DEST/$(basename "$kt_file")" 2>/dev/null || true
done
bash "$SCRIPT" "$TEMP_OLD/$KOTLIN_DIR" > /tmp/api-old.txt
rm -rf "$TEMP_OLD"

# Generate diff
diff -u /tmp/api-old.txt /tmp/api-new.txt > /tmp/api-diff.txt || true
```

### Step 3: Dispatch SDK Analyst Agent

Spawn the `sdk-android-analyst` agent to perform the full analysis:

```
Agent: sdk-android-analyst
Inputs:
  - The API diff from /tmp/api-diff.txt
  - android_repo_path (if provided by user)
  - dry_run: true/false
  - base_branch: main
```

The agent will:

1. Analyze the diff
2. Cross-reference Android usage (local repo or via gh api)
3. Attempt compilation if Android repo is available
4. Produce `sdk-impact-report.md`

### Step 4: Present Results

After the analyst completes:

1. Read `sdk-impact-report.md`
2. Present a summary to the user:
   - Number of breaking compilation changes
   - Number of breaking behavioral changes
   - Number of additive changes
   - Number of items requiring attention
3. Show the PR description snippet
4. Ask if the user wants to:
   - View the full report
   - Copy the PR snippet
   - Run the full team pipeline (if Android repo available)

## Mode 2: Full Team Pipeline (`--team`)

Requires a local Android repo path. Orchestrates four agents across both repositories.

### Step 1: Create Team

```
TeamCreate:
  name: "sdk-android-compat-team"
  description: "SDK Android breaking change detection and migration"
```

### Step 2: Run SDK Analyst

Spawn the SDK Analyst agent as a teammate working in the sdk-internal repo:

```
Agent: sdk-android-analyst (in sdk-internal repo)
Task: Full analysis including compilation check
```

Wait for the analyst to complete and produce `sdk-impact-report.md`.

### Step 3: Hand Off to Android Architect

Send the impact report to the Android Architect agent working in the Android repo:

```
SendMessage to android-architect:
  "Here is the SDK impact report from the analyst. Please review and create a migration plan.
   [attach sdk-impact-report.md content]

   Key points:
   - {N} breaking compilation changes
   - {N} breaking behavioral changes
   - The SDK changes are on branch {branch} of sdk-internal

   Please acknowledge receipt and ask any clarifying questions before proceeding."
```

Wait for the architect to:

1. Acknowledge receipt
2. Ask clarifying questions (relay to analyst if needed)
3. Send migration plan back to analyst for verification
4. Finalize migration plan

### Step 4: Hand Off to Android Implementer

Send the verified migration plan to the implementer:

```
SendMessage to android-implementer:
  "Here is the verified migration plan from the architect.
   [attach migration plan]
   [attach impact report for reference]

   Please confirm understanding of each change before starting implementation."
```

Wait for the implementer to:

1. Confirm understanding
2. Implement changes
3. Verify compilation
4. Report completion

### Step 5: Code Review

Send to the code reviewer:

```
SendMessage to code-reviewer:
  "Implementation complete. Please review using bitwarden-code-review:code-review-local.
   [attach implementation summary]
   [attach impact report for migration correctness validation]
   [attach migration plan for plan adherence check]"
```

The reviewer and implementer then collaborate iteratively until approval.

### Step 6: Final Report

After all agents complete:

1. Summarize the full pipeline results
2. List all files changed in the Android repo
3. Show the review outcome
4. Ask user if they want to create a PR in the Android repo

## Communication Protocol

All agents MUST maintain open communication. Key checkpoints:

1. **Analyst → Architect**: Report handoff with clarifying Q&A
2. **Architect → Analyst**: Migration plan verification
3. **Architect → Implementer**: Plan handoff with understanding confirmation
4. **Implementer → Reviewer**: Implementation ready notification
5. **Reviewer ↔ Implementer**: Iterative review dialogue
6. **Reviewer → Architect**: Consultation on ambiguous findings

No agent proceeds without explicit acknowledgment from the receiving agent. The orchestrator (this
skill) monitors all messages and escalates to the user if agents cannot resolve a disagreement.

## Reference Files

- API extraction script: `.claude/skills/check-android-compat/scripts/extract-kotlin-api.sh`
- Impact report template: `.claude/skills/check-android-compat/templates/impact-report.md`
- Test fixtures: `.claude/skills/check-android-compat/templates/test-fixtures/`
