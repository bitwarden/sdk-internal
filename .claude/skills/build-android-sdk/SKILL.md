---
name: build-android-sdk
argument-hint: "[all]"
description:
  This skill should be used when the user asks to "build the Android SDK", "build the AAR", "publish
  to local Maven", "build Android artifacts", "cross-compile for Android", or "build
  bitwarden-uniffi for Android". Pass "all" to build all architectures; defaults to arm64-v8a only.
allowed-tools: Bash(cd crates/bitwarden-uniffi/kotlin *), Read, Write
---

# Build Android SDK

Cross-compile `bitwarden-uniffi` for Android, generate Kotlin bindings, package as an AAR, and
publish to local Maven (`~/.m2/repository`).

Uses the existing repo scripts:

- `crates/bitwarden-uniffi/kotlin/publish-local.sh` — builds, generates bindings, publishes
- `crates/bitwarden-uniffi/kotlin/build-schemas.sh` — called internally by publish-local.sh

## Prerequisites

- **Docker** must be running — `cross` builds inside Docker containers with the Android NDK.
- **`cross`** must be installed at the required revision:
  ```
  cargo install cross --locked --git https://github.com/cross-rs/cross.git --rev 185398b1b885820515a212de720a306b08e2c8c9
  ```
- **`local.properties`** must exist at `crates/bitwarden-uniffi/kotlin/local.properties` with
  `sdk.dir` pointing to the Android SDK (typical macOS path: `~/Library/Android/sdk`). Create it if
  missing.

Verify prerequisites before running the build. If any are missing, help the user resolve them.

## Build

Run from the repo root:

```bash
cd crates/bitwarden-uniffi/kotlin && bash publish-local.sh $ARGUMENTS
```

- No arguments → builds **arm64-v8a only** (fastest, good for emulator testing)
- `all` → builds **all architectures** (arm64-v8a, armeabi-v7a, x86_64, x86)

## Post-Build

After the script completes successfully, report the Maven coordinates:

```
com.bitwarden:sdk-android:LOCAL
```

Then ask the user if they want to set `localSdk=true` in their Android project's `user.properties`
file. Ask for the path to their Android project directory — do not assume a hardcoded path. This
toggle enables the Android app to resolve the SDK from local Maven instead of GitHub Packages.
