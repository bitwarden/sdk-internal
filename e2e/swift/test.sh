#!/usr/bin/env bash
# Runs the Swift e2e tests on the first available iPhone simulator.
# Expects BitwardenFFI.xcframework, built by crates/bitwarden-uniffi/swift/build.sh.
set -eo pipefail

cd "$(dirname "$0")"

# Picks the simulator by UDID, so the run works with any installed Xcode/iOS version.
DEVICE_ID=$(xcrun simctl list devices available | awk -F '[()]' '/iPhone/{print $2; exit}')

# SwiftPM appends `-Package` to the package name for the generated scheme.
xcodebuild test \
  -scheme E2ETests-Package \
  -destination "id=$DEVICE_ID" \
  CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO
