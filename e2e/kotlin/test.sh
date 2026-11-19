#!/usr/bin/env bash
# Runs the Kotlin e2e tests on the host JVM. Extra arguments are passed to Gradle, for example
# `./test.sh --tests '*PinLockTests*'`.
# Expects the bindings and native library built by crates/bitwarden-uniffi/kotlin/build-jvm.sh.
set -euo pipefail

cd "$(dirname "$0")"

../../crates/bitwarden-uniffi/kotlin/gradlew test "$@"
