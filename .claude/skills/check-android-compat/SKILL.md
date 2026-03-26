---
name: check-android-compat
argument-hint: "[--dry-run] [--team] [/path/to/android/repo]"
description:
  Use this skill when the user asks to "check Android compatibility", "detect Android breaking
  changes", "check if SDK changes break Android", "analyze Android impact", "check-android-compat",
  or wants to understand how their SDK changes affect the bitwarden/android project. This skill
  extracts the Kotlin API surface from generated UniFFI bindings, diffs against the main branch,
  cross-references actual Android usage patterns, and produces a structured impact report.
allowed-tools:
  Bash(bash .claude/skills/check-android-compat/scripts/generate-diff.sh:*), Bash(git diff:*), Read,
  Agent, TeamCreate, SendMessage
---

# Check Android Compatibility

Detect and analyze breaking changes in the SDK's Android (Kotlin) API surface.

## Arguments

Parse the user's input for these arguments:

- `--dry-run`: Skip cargo builds, reuse existing `/tmp/bindings-old/` and `/tmp/bindings-new/`. Just
  run the filtered diff + analysis.
- `--team`: Run the full four-agent team pipeline (analyst → architect → implementer → reviewer).
  Requires a local Android repo path.
- Path argument: Local path to a `bitwarden/android` checkout. If not provided, the skill will fetch
  Android source files via `gh api` for analysis (no compilation check).

## Mode 1: Analysis Only (default, or `--dry-run`)

This is the default mode. It produces an impact report without modifying any code.

### Step 1: Generate API Diff

Run the diff generation script. This builds Kotlin bindings for both the current branch and main
(via native `cargo build` + `uniffi-bindgen`, no Docker needed), then produces a filtered diff
stripping UniFFI internals.

```bash
bash .claude/skills/check-android-compat/scripts/generate-diff.sh
# Or with options:
bash .claude/skills/check-android-compat/scripts/generate-diff.sh --base-branch main
bash .claude/skills/check-android-compat/scripts/generate-diff.sh --dry-run  # skip builds, reuse /tmp/bindings-{old,new}
```

Output files:

- `/tmp/api-diff.txt` — filtered API diff (also printed to stdout)
- `/tmp/bindings-old/` — base branch Kotlin bindings
- `/tmp/bindings-new/` — current branch Kotlin bindings

If the diff is empty, report "No API changes detected" and exit.

**Note:** For full AAR publishing to local Maven (needed for Android compilation checks in team
mode), use `cd crates/bitwarden-uniffi/kotlin && bash publish-local.sh` instead. This requires
Docker + `cross`.

### Step 2: Dispatch SDK Analyst Agent

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

### Step 3: Present Results

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

### Step 1: Generate API Diff

Same as Mode 1 Step 1 — run `generate-diff.sh` first so the diff is ready before spawning agents:

```bash
bash .claude/skills/check-android-compat/scripts/generate-diff.sh
```

If the diff is empty, report "No API changes detected" and exit — no need to create a team.

### Step 2: Create Team

```
TeamCreate:
  name: "sdk-android-compat-team"
  description: "SDK Android breaking change detection and migration"
```

### Step 3: Run SDK Analyst

Spawn the SDK Analyst agent as a teammate working in the sdk-internal repo. The diff at
`/tmp/api-diff.txt` and bindings at `/tmp/bindings-{old,new}/` are already available.

```
Agent: sdk-android-analyst (in sdk-internal repo)
Task: Analyze the diff at /tmp/api-diff.txt, cross-reference Android usage, produce impact report
```

Wait for the analyst to complete and produce `sdk-impact-report.md`.

### Step 4: Hand Off to Android Architect

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

### Step 5: Hand Off to Android Implementer

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

### Step 6: Code Review

Send to the code reviewer:

```
SendMessage to code-reviewer:
  "Implementation complete. Please review using bitwarden-code-review:code-review-local.
   [attach implementation summary]
   [attach impact report for migration correctness validation]
   [attach migration plan for plan adherence check]"
```

The reviewer and implementer then collaborate iteratively until approval.

### Step 7: Final Report

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

- Diff generation script: `.claude/skills/check-android-compat/scripts/generate-diff.sh`
- API filtering script: `.claude/skills/check-android-compat/scripts/extract-kotlin-api.sh`
- Impact report template: `.claude/skills/check-android-compat/templates/impact-report.md`
